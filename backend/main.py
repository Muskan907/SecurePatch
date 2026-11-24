from fastapi import FastAPI, HTTPException, UploadFile, File, Form
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, StreamingResponse
from pydantic import BaseModel
import ast
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import time
import textwrap
import uuid
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeout
import zipfile

try:
    from dotenv import load_dotenv
    load_dotenv()
except Exception:
    pass
from src.llm_adapter import (
    generate as _generate_llm_raw,
    configured_models,
    fallback_chain,
    MODEL_REGISTRY,
    ollama_is_available,
    installed_models,
)
from src.repository_rag import RepositoryRAG, format_context
from src.repo_importer import ImportFailed, import_remote
from src.bandit_stream import bandit_command, iter_scan, sse
from src.sandbox_runner import describe as sandbox_describe, pytest_command
import src.semgrep_scanner as semgrep
from src.bandit_catalog import catalog as bandit_catalog, compare_findings, explain
from src.git_publisher import (
    PublishError,
    collect_changed_files,
    detect_source_remote,
    make_client,
    parse_remote_url,
    publish as publish_to_remote,
    resolve_mode,
)
import src.metrics as metrics


def generate_llm(prompt, model="qwen2.5-coder", **kwargs):
    """Ollama generation, timed for the /metrics endpoint."""
    started = time.perf_counter()
    result = None
    try:
        result = _generate_llm_raw(prompt, model=model, **kwargs)
        return result
    finally:
        metrics.record_llm_call(model, time.perf_counter() - started, result)

# =========================================================
# APP

# =========================================================
app = FastAPI(
    title="SecurePatch API",
    description="AI-assisted security vulnerability detection and repair",
    version="1.0.0",
)
app.add_middleware(
    CORSMiddleware,
    # Extra origins (e.g. the Docker frontend) via ALLOWED_ORIGINS=a,b
    allow_origins=[
        "http://localhost:5173",
        "http://localhost:5174",
        "http://localhost:5175",
        "http://127.0.0.1:5173",
        "http://127.0.0.1:5174",
        "http://127.0.0.1:5175",
        *[
            origin.strip()
            for origin in os.getenv("ALLOWED_ORIGINS", "").split(",")
            if origin.strip()
        ],
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.add_middleware(metrics.PrometheusMiddleware)
# Cached so a Prometheus scrape every few seconds does not hammer Ollama.
metrics.OLLAMA_UP._supplier = metrics.cached_probe(lambda: ollama_is_available())


@app.get("/metrics", include_in_schema=False)
def prometheus_metrics():
    """Prometheus scrape endpoint used by the live Grafana dashboard."""
    from fastapi.responses import Response
    return Response(metrics.render_all(), media_type=metrics.CONTENT_TYPE)

# =========================================================
# PATHS / STATE

# =========================================================
PROJECT_ROOT = Path(__file__).resolve().parent.parent
SANDBOX_ROOT = PROJECT_ROOT / "workspace" / "sandbox_repo"
REPOSITORY_ROOT = PROJECT_ROOT / "workspace" / "repositories"
# Persistent validation state.
# This survives Uvicorn --reload, unlike LAST_VALIDATION_STATUS.
VALIDATION_MARKER = PROJECT_ROOT / "workspace" / "validation_status.json"
SCAN_CACHE_ROOT = PROJECT_ROOT / "workspace" / "scan_cache"
REPOSITORY_ROOT.mkdir(parents=True, exist_ok=True)
# Local demo state. For a multi-user deployment this should become
# per-repository/per-validation state instead of a global variable.
LAST_VALIDATION_STATUS = None
PYTEST_TIMEOUT_SECONDS = 180

# =========================================================
# REQUEST MODELS

# =========================================================


class ScanRequest(BaseModel):
    repo_path: str = "sample_repo"
    semgrep: bool = True


class AnalyzeRequest(BaseModel):
    repo_path: str = "sample_repo"
    file_path: str
    line: int


class PatchRequest(BaseModel):
    repo_path: str = "sample_repo"
    file_path: str
    line: int
    model: str | None = None
    # Experiment / ablation switches. Defaults = the normal UI behaviour.
    use_rag: bool = True             # retrieved repository context in prompt
    prompt_mode: str = "full"        # "full" (RAG + graph + AST) or "plain"
    fallback: bool = True            # try other models when one fails
    fallback_models: list[str] | None = None   # restrict the fallback chain
    seed: int | None = None          # reproducible sampling
    temperature: float | None = None # override the model default
    rag_top_k: int | None = None     # retrieved chunks (default RAG_TOP_K)


class ValidateRequest(BaseModel):
    repo_path: str = "sample_repo"
    file_path: str
    line: int
    patch: str

# =========================================================
# PATH HELPERS

# =========================================================


def resolve_repo(repo_path: str) -> Path:
    path = Path(repo_path)
    if not path.is_absolute():
        path = PROJECT_ROOT / path
    path = path.resolve()
    if not path.exists() or not path.is_dir():
        raise HTTPException(
            status_code=404,
            detail=f"Repository not found: {repo_path}",
        )
    return path


def resolve_file(repo_path: str, file_path: str) -> Path:
    repo = resolve_repo(repo_path)
    raw = Path(file_path)
    candidates = []
    if raw.is_absolute():
        candidates.append(raw)
    candidates.append(PROJECT_ROOT / raw)
    candidates.append(repo / raw)
    normalized = str(file_path).replace("\\", "/")
    if normalized.startswith("sample_repo/"):
        candidates.append(PROJECT_ROOT / normalized)
    # Also support paths returned by Bandit such as:
    # sample_repo/services/command_service.py
    # or services/command_service.py
    relative_to_repo = Path(normalized)
    if not relative_to_repo.is_absolute():
        candidates.append(repo / relative_to_repo)
    seen = set()
    for candidate in candidates:
        try:
            candidate = candidate.resolve()
        except OSError:
            continue
        key = str(candidate).lower()
        if key in seen:
            continue
        seen.add(key)
        if candidate.exists() and candidate.is_file():
            return candidate
    raise HTTPException(
        status_code=404,
        detail=f"File not found: {file_path}",
    )

# =========================================================
# BANDIT

# =========================================================


def run_bandit(repo_path: str):
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "bandit",
            "-r",
            repo_path,
            "-f",
            "json",
            "--skip",
            "B101",
        ],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    if not result.stdout.strip():
        return {
            "results": [],
            "errors": result.stderr,
        }
    return parse_bandit_json(result.stdout, result.stderr)


def parse_bandit_json(stdout: str, stderr: str = "") -> dict:
    """Parse Bandit's JSON report.

    On larger repositories Bandit prints a progress bar ("Working... 100%")
    to stdout before the JSON. Parsing the raw output then fails and every
    finding would silently disappear, so parse from the first "{".
    """
    start = stdout.find("{")
    if start == -1:
        return {"results": [], "errors": stderr}
    try:
        return json.loads(stdout[start:])
    except json.JSONDecodeError:
        return {"results": [], "errors": stderr or "Bandit returned invalid JSON."}


def finding_summary(findings):
    return {
        "total": len(findings),
        "high": sum(
            1
            for f in findings
            if f.get("issue_severity") == "HIGH"
        ),
        "medium": sum(
            1
            for f in findings
            if f.get("issue_severity") == "MEDIUM"
        ),
        "low": sum(
            1
            for f in findings
            if f.get("issue_severity") == "LOW"
        ),
    }


def paths_match(path_a: str, path_b: str) -> bool:
    a = str(path_a).replace("\\", "/").rstrip("/")
    b = str(path_b).replace("\\", "/").rstrip("/")
    return (
        a == b
        or a.endswith("/" + b)
        or b.endswith("/" + a)
    )


def get_finding(repo_path, file_path, line):
    """Locate the Bandit finding for the requested source file and line.

    Exact file+line matching is preferred. If Bandit reports a nearby line
    because the source changed between scan and request, use the closest
    finding in the same file instead of failing with a misleading 404.
    """
    repo = resolve_repo(repo_path)
    data = run_bandit(str(repo))
    findings = data.get("results", [])
    # Semgrep findings from the last scan of this repository.
    semgrep_findings = semgrep.load_cache(repo, SCAN_CACHE_ROOT)
    target_file = resolve_file(repo_path, file_path)
    exact_matches = [
        finding
        for finding in findings
        if paths_match(
            finding.get("filename", ""),
            file_path,
        )
        and finding.get("line_number") == line
    ]
    if exact_matches:
        return exact_matches[0]
    semgrep_exact = semgrep.find_in(semgrep_findings, target_file, line, exact=True)
    if semgrep_exact:
        return semgrep_exact
    same_file = [
        finding
        for finding in findings
        if paths_match(
            finding.get("filename", ""),
            file_path,
        )
    ]
    if same_file:
        return min(
            same_file,
            key=lambda finding: abs(
                int(finding.get("line_number", 0)) - int(line)
            ),
        )
    semgrep_near = semgrep.find_in(semgrep_findings, target_file, line, exact=False)
    if semgrep_near:
        return semgrep_near
    raise HTTPException(
        status_code=404,
        detail=(
            "Vulnerability finding could not be located for "
            f"file '{file_path}'."
        ),
    )

# =========================================================
# AST ANALYSIS

# =========================================================


def get_call_name(node):
    try:
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            parts = []
            current = node
            while isinstance(current, ast.Attribute):
                parts.append(current.attr)
                current = current.value
            if isinstance(current, ast.Name):
                parts.append(current.id)
            return ".".join(reversed(parts))
    except Exception:
        pass
    return "unknown"


def extract_function(code, line):
    try:
        tree = ast.parse(code)
    except SyntaxError:
        return None
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            start = node.lineno
            end = getattr(node, "end_lineno", node.lineno)
            if start <= line <= end:
                function_code = ast.get_source_segment(code, node)
                return {
                    "name": node.name,
                    "line": start,
                    "end_line": end,
                    "code": function_code or "",
                }
    return None


def analyze_python_file(file_path: Path, line: int):
    code = file_path.read_text(
        encoding="utf-8",
        errors="replace",
    )
    try:
        tree = ast.parse(code)
    except SyntaxError as exc:
        raise HTTPException(
            status_code=400,
            detail=f"Could not parse Python file: {exc}",
        )
    imports = []
    calls = []
    tests = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for item in node.names:
                imports.append(item.name)
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                imports.append(node.module)
        elif isinstance(node, ast.Call):
            name = get_call_name(node.func)
            if name != "unknown":
                calls.append(name)
        elif isinstance(
            node,
            (ast.FunctionDef, ast.AsyncFunctionDef),
        ):
            if node.name.startswith("test_"):
                tests.append(
                    {
                        "name": node.name,
                        "line": node.lineno,
                    }
                )
    function = extract_function(code, line)
    return {
        "file": str(file_path),
        "line": line,
        "affected_function": function,
        "imports": list(dict.fromkeys(imports)),
        "function_calls": list(dict.fromkeys(calls)),
        "tests": tests,
    }

# =========================================================
# SOURCE GRAPH

# =========================================================


def build_graph(repo_path: Path):
    files = []
    functions = []
    imports = []
    nodes = []
    edges = []
    function_lookup = {}
    function_name_lookup = {}
    python_files = sorted(repo_path.rglob("*.py"))
    for file_path in python_files:
        if (
            "__pycache__" in file_path.parts
            or ".pytest_cache" in file_path.parts
            or "venv" in file_path.parts
            or ".venv" in file_path.parts
        ):
            continue
        relative = file_path.relative_to(repo_path).as_posix()
        file_id = f"file::{relative}"
        files.append(relative)
        nodes.append(file_id)
        try:
            code = file_path.read_text(
                encoding="utf-8",
                errors="replace",
            )
            tree = ast.parse(code)
        except Exception:
            continue
        for node in ast.walk(tree):
            if isinstance(
                node,
                (ast.FunctionDef, ast.AsyncFunctionDef),
            ):
                function_id = (
                    f"function::{relative}::{node.name}"
                )
                function_info = {
                    "id": function_id,
                    "name": node.name,
                    "file": relative,
                    "line": node.lineno,
                }
                functions.append(function_info)
                nodes.append(function_id)
                function_lookup[
                    (relative, node.name)
                ] = function_id
                function_name_lookup.setdefault(
                    node.name,
                    [],
                ).append(function_id)
                edges.append(
                    {
                        "source": file_id,
                        "relation": "CONTAINS",
                        "target": function_id,
                    }
                )
            elif isinstance(node, ast.Import):
                for item in node.names:
                    import_name = item.name
                    import_id = f"import::{import_name}"
                    imports.append(import_name)
                    nodes.append(import_id)
                    edges.append(
                        {
                            "source": file_id,
                            "relation": "IMPORTS",
                            "target": import_id,
                        }
                    )
            elif isinstance(node, ast.ImportFrom):
                if node.module:
                    import_name = node.module
                    import_id = f"import::{import_name}"
                    imports.append(import_name)
                    nodes.append(import_id)
                    edges.append(
                        {
                            "source": file_id,
                            "relation": "IMPORTS",
                            "target": import_id,
                        }
                    )
        # Function calls
        for node in ast.walk(tree):
            if not isinstance(
                node,
                (ast.FunctionDef, ast.AsyncFunctionDef),
            ):
                continue
            caller_id = (
                f"function::{relative}::{node.name}"
            )
            for child in ast.walk(node):
                if not isinstance(child, ast.Call):
                    continue
                call_name = get_call_name(child.func)
                if call_name == "unknown":
                    continue
                target = None
                # 1. Exact same-file function match.
                short_name = call_name.split(".")[-1]
                same_file_target = function_lookup.get(
                    (relative, short_name)
                )
                if same_file_target:
                    target = same_file_target
                # 2. Unique repository-wide function match.
                if target is None:
                    candidates = function_name_lookup.get(
                        short_name,
                        [],
                    )
                    if len(candidates) == 1:
                        target = candidates[0]
                # 3. External/library call.
                if target is None:
                    target = f"call::{call_name}"
                    nodes.append(target)
                edges.append(
                    {
                        "source": caller_id,
                        "relation": "CALLS",
                        "target": target,
                    }
                )
    # Add explicit TESTS relationships when a test function
    # references a repository function or its source file.
    for file_path in python_files:
        if (
            "__pycache__" in file_path.parts
            or ".pytest_cache" in file_path.parts
            or "venv" in file_path.parts
            or ".venv" in file_path.parts
        ):
            continue
        relative = file_path.relative_to(repo_path).as_posix()
        if "test" not in relative.lower():
            continue
        try:
            code = file_path.read_text(
                encoding="utf-8",
                errors="replace",
            )
            tree = ast.parse(code)
        except Exception:
            continue
        test_functions = [
            node
            for node in ast.walk(tree)
            if isinstance(
                node,
                (ast.FunctionDef, ast.AsyncFunctionDef),
            )
            and node.name.startswith("test_")
        ]
        for test_node in test_functions:
            test_id = (
                f"function::{relative}::{test_node.name}"
            )
            for target in functions:
                target_name = target["name"]
                target_file = target["file"]
                target_stem = Path(target_file).stem
                if (
                    target_name in code
                    or target_stem in code
                ):
                    edges.append(
                        {
                            "source": test_id,
                            "relation": "TESTS",
                            "target": target["id"],
                        }
                    )
    # Remove duplicate nodes and edges.
    unique_nodes = list(dict.fromkeys(nodes))
    unique_edges = []
    seen_edges = set()
    for edge in edges:
        key = (
            edge["source"],
            edge["relation"],
            edge["target"],
        )
        if key not in seen_edges:
            seen_edges.add(key)
            unique_edges.append(edge)
    return {
        "files": list(dict.fromkeys(files)),
        "functions": functions,
        "imports": list(dict.fromkeys(imports)),
        "nodes": unique_nodes,
        "edges": unique_edges,
    }


def graph_impact(
    graph,
    target_file,
    target_function,
):
    normalized_file = str(
        target_file
    ).replace("\\", "/")
    function_id = (
        f"function::{normalized_file}::{target_function}"
    )
    # If the target ID cannot be found exactly, resolve it
    # from the graph's function records.
    if not any(
        f["id"] == function_id
        for f in graph["functions"]
    ):
        matching = [
            f["id"]
            for f in graph["functions"]
            if (
                f["name"] == target_function
                and f["file"].replace("\\", "/")
                == normalized_file
            )
        ]
        if matching:
            function_id = matching[0]
    callers = []
    dependencies = []
    related_files = []
    related_tests = []
    for edge in graph["edges"]:
        if (
            edge["relation"] == "CALLS"
            and edge["target"] == function_id
        ):
            callers.append(edge["source"])
        if (
            edge["relation"] == "TESTS"
            and edge["target"] == function_id
        ):
            related_tests.append(edge["source"])
        if edge["source"] == function_id:
            dependencies.append(edge["target"])
    # Connected files are derived from graph relationships.
    for edge in graph["edges"]:
        source = edge["source"]
        target = edge["target"]
        if source == f"file::{normalized_file}":
            if target.startswith("file::"):
                related_files.append(target)
        if (
            source == function_id
            and target.startswith("function::")
        ):
            target_file = target.split("::", 2)[1]
            related_files.append(f"file::{target_file}")
    # Include caller files and test files as connected files.
    for caller in callers:
        if caller.startswith("function::"):
            parts = caller.split("::", 2)
            if len(parts) == 3:
                related_files.append(
                    f"file::{parts[1]}"
                )
    for test in related_tests:
        if test.startswith("function::"):
            parts = test.split("::", 2)
            if len(parts) == 3:
                related_files.append(
                    f"file::{parts[1]}"
                )
    return {
        "callers": list(dict.fromkeys(callers)),
        "dependencies": list(
            dict.fromkeys(dependencies)
        ),
        "related_files": list(
            dict.fromkeys(related_files)
        ),
        "related_tests": list(
            dict.fromkeys(related_tests)
        ),
    }

# =========================================================
# PROMPT ENGINEERING

# =========================================================


def build_patch_prompt(
    finding,
    analysis,
    graph,
    impact,
):
    function = (
        analysis.get("affected_function")
        or {}
    )
    function_code = function.get(
        "code",
        "",
    )
    return f"""
You are SecurePatch, a security-aware software repair agent.
SECURITY FINDING
Rule: {finding.get("test_id")}
Severity: {finding.get("issue_severity")}
CWE: {finding.get("issue_cwe", {}).get("id", "N/A")}
Issue: {finding.get("issue_text")}
File: {finding.get("filename")}
Line: {finding.get("line_number")}
VULNERABLE FUNCTION
{function_code}
IMPORTS
{analysis.get("imports", [])}
FUNCTION CALLS
{analysis.get("function_calls", [])}
RELATED TESTS
{analysis.get("related_tests", analysis.get("tests", []))}
SOURCE GRAPH
Files: {len(graph.get("files", []))}
Functions: {len(graph.get("functions", []))}
Nodes: {len(graph.get("nodes", []))}
Edges: {len(graph.get("edges", []))}
IMPACT
Callers: {impact.get("callers", [])}
Dependencies: {impact.get("dependencies", [])}
Connected Files: {impact.get("related_files", [])}
Graph Tests: {impact.get("related_tests", [])}
STRICT REQUIREMENTS
1. Fix the reported security vulnerability.
2. Preserve the original functionality.
3. Make the smallest possible code change.
4. Do not modify tests.
5. Do not modify unrelated code.
6. Return ONLY the complete corrected function.
7. Do not return markdown.
8. Do not return explanations.
9. Do not introduce undefined variables or imports.
10. Do not change the function signature unless required for security.
""".strip()

# =========================================================
# MOCK AI PATCH GENERATOR

# =========================================================


def generate_mock_patch(
    finding,
    function_code,
    imports=None,
):
    rule = finding.get("test_id")
    if not function_code:
        raise HTTPException(
            status_code=400,
            detail="Could not extract vulnerable function.",
        )
    imports = imports or []
    # B602: subprocess call with shell=True.
    if rule == "B602":
        # Prefer shlex when the file already imports it.
        # This preserves quoted arguments better than plain split().
        if "shlex" in imports:
            patched = re.sub(
                r"subprocess\.call\((.*?),\s*shell\s*=\s*True\)",
                r"subprocess.call(shlex.split(\1), shell=False)",
                function_code,
                count=1,
            )
        else:
            patched = re.sub(
                r"subprocess\.call\((.*?),\s*shell\s*=\s*True\)",
                r"subprocess.call(\1.split(), shell=False)",
                function_code,
                count=1,
            )
        if patched == function_code:
            patched = function_code.replace(
                "shell=True",
                "shell=False",
                1,
            )
        return {
            "original": function_code,
            "function": patched,
            "patch": patched,
            "provider": "mock",
            "model": "securepatch-mock",
        }
    # Other rules intentionally require a real LLM.
    return {
        "original": function_code,
        "function": function_code,
        "patch": function_code,
        "provider": "mock",
        "model": "securepatch-mock",
    }

# =========================================================
# SANDBOX

# =========================================================

def create_sandbox(repo: Path) -> Path:
    """Create a clean sandbox copy without Git metadata."""
    if SANDBOX_ROOT.exists():
        try:
            shutil.rmtree(SANDBOX_ROOT)
        except PermissionError:
            # Windows may keep .git files locked.
            # Remove only the locked Git metadata separately.
            git_dir = SANDBOX_ROOT / ".git"
            if git_dir.exists():
                shutil.rmtree(git_dir, ignore_errors=True)

            if SANDBOX_ROOT.exists():
                shutil.rmtree(SANDBOX_ROOT, ignore_errors=True)

    SANDBOX_ROOT.mkdir(parents=True, exist_ok=True)

    shutil.copytree(
        repo,
        SANDBOX_ROOT,
        dirs_exist_ok=True,
        ignore=shutil.ignore_patterns(
            ".git",
            "__pycache__",
            ".pytest_cache",
            ".mypy_cache",
            ".ruff_cache",
        ),
    )

    return SANDBOX_ROOT


def apply_function_patch(
    repo_path: Path,
    sandbox: Path,
    file_path: Path,
    old_function: str,
    new_function: str,
):
    """Safely replace a Python function using its AST source range."""
    relative = file_path.relative_to(repo_path)
    target = sandbox / relative
    if not target.exists():
        raise ValueError(f"Target file does not exist in sandbox: {relative}")
    code = target.read_text(encoding="utf-8", errors="replace")
    if not old_function.strip():
        raise ValueError("Original vulnerable function is empty.")
    if not new_function.strip():
        raise ValueError("Generated patch is empty.")
    try:
        tree = ast.parse(code)
    except SyntaxError as exc:
        raise ValueError(f"Original sandbox file is not valid Python: {exc}") from exc
    candidate = textwrap.dedent(new_function).strip()
    try:
        new_tree = ast.parse(candidate)
    except SyntaxError as exc:
        raise ValueError(f"Generated patch has invalid Python syntax: {exc}") from exc
    generated = [
        n for n in new_tree.body
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
    ]
    if len(generated) != 1:
        raise ValueError("Generated patch must contain exactly one Python function.")
    generated_node = generated[0]
    old_name = None
    try:
        old_tree = ast.parse(textwrap.dedent(old_function).strip())
        old_functions = [
            n for n in old_tree.body
            if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
        ]
        if old_functions:
            old_name = old_functions[0].name
    except SyntaxError:
        pass
    if old_name and generated_node.name != old_name:
        raise ValueError(
            f"Generated function name '{generated_node.name}' "
            f"does not match original function '{old_name}'."
        )
    candidates = [
        n for n in ast.walk(tree)
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
        and (old_name is None or n.name == old_name)
    ]
    if not candidates:
        raise ValueError("Original vulnerable function was not found in sandbox.")
    old_normalized = textwrap.dedent(old_function).strip()
    target_node = None
    for node in candidates:
        segment = ast.get_source_segment(code, node) or ""
        if textwrap.dedent(segment).strip() == old_normalized:
            target_node = node
            break
    if target_node is None:
        if len(candidates) == 1:
            target_node = candidates[0]
        else:
            raise ValueError(
                f"Could not uniquely locate function '{old_name}' in sandbox."
            )
    start_line = target_node.lineno
    if target_node.decorator_list:
        start_line = min(
            [d.lineno for d in target_node.decorator_list] + [target_node.lineno]
        )
    end_line = getattr(target_node, "end_lineno", target_node.lineno)
    source_lines = code.splitlines(keepends=True)
    if not (1 <= start_line <= end_line <= len(source_lines)):
        raise ValueError("Invalid function source range.")
    indent = " " * target_node.col_offset
    generated_lines = candidate.splitlines()
    newline = "\r\n" if "\r\n" in code else "\n"
    indented = [
        (indent + line) if line.strip() else ""
        for line in generated_lines
    ]
    replacement = newline.join(indented)
    original_span = "".join(source_lines[start_line - 1:end_line])
    if original_span.endswith(("\r\n", "\n")) and not replacement.endswith(newline):
        replacement += newline
    patched = "".join(
        source_lines[:start_line - 1]
        + [replacement]
        + source_lines[end_line:]
    )
    try:
        ast.parse(patched)
    except SyntaxError as exc:
        raise ValueError(f"Patched file is not valid Python: {exc}") from exc
    target.write_text(patched, encoding="utf-8", newline="")
    return target


def run_pytest(sandbox: Path):
    """Run the sandbox's tests in Docker (preferred) or a local subprocess."""
    command, isolation = pytest_command(sandbox)
    result = _run_pytest(sandbox, command)
    result["isolation"] = isolation
    if isolation == "docker":
        result["sandbox_limits"] = sandbox_describe()["limits"]
    return result


def _run_pytest(sandbox: Path, command: list[str]):
    env = os.environ.copy()
    env.pop("PYTHONPATH", None)

    creationflags = 0
    if os.name == "nt":
        creationflags = (
            subprocess.CREATE_NEW_PROCESS_GROUP
            | subprocess.CREATE_NO_WINDOW
        )

    try:
        result = subprocess.run(
            command,
            cwd=str(sandbox),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            env=env,
            creationflags=creationflags,
            timeout=PYTEST_TIMEOUT_SECONDS,
        )

        output = (result.stdout + "\n" + result.stderr).strip()

        passed_match = re.search(r"(\d+)\s+passed", output)
        failed_match = re.search(r"(\d+)\s+failed", output)
        error_match = re.search(r"(\d+)\s+error", output)

        passed_count = int(passed_match.group(1)) if passed_match else 0
        failed_count = int(failed_match.group(1)) if failed_match else 0
        error_count = int(error_match.group(1)) if error_match else 0

        # Some security-training repositories intentionally contain
        # tests that verify the vulnerable behavior.
        expected_vulnerable_tests = {
            "test_vulnerable_product_search",
            "test_vulnerable_search_allows_sql_injection",
            "test_vulnerable_xss_reflects_unescaped_html",
        }

        failed_lines = [
            line
            for line in output.splitlines()
            if "FAILED " in line
        ]

        expected_failures = [
            test
            for test in expected_vulnerable_tests
            if any(test in line for line in failed_lines)
        ]

        unexpected_failures = [
            line
            for line in failed_lines
            if not any(test in line for test in expected_vulnerable_tests)
        ]

        regression_passed = (
            error_count == 0
            and not unexpected_failures
            and (
                result.returncode == 0
                or failed_count == len(expected_failures)
            )
        )

        return {
            "passed": regression_passed,
            "return_code": result.returncode,
            "passed_count": passed_count,
            "failed_count": failed_count,
            "error_count": error_count,
            "expected_failures": expected_failures,
            "unexpected_failures": unexpected_failures,
            "output": output,
        }

    except subprocess.TimeoutExpired as exc:
        stdout = exc.stdout or ""
        stderr = exc.stderr or ""

        if isinstance(stdout, bytes):
            stdout = stdout.decode("utf-8", errors="replace")

        if isinstance(stderr, bytes):
            stderr = stderr.decode("utf-8", errors="replace")

        return {
            "passed": False,
            "return_code": -1,
            "passed_count": 0,
            "failed_count": 0,
            "error_count": 1,
            "expected_failures": [],
            "unexpected_failures": [],
            "output": (
                "Pytest timed out after 180 seconds.\n"
                + stdout
                + "\n"
                + stderr
            ).strip(),
        }

    except Exception as exc:
        return {
            "passed": False,
            "return_code": -1,
            "passed_count": 0,
            "failed_count": 0,
            "error_count": 1,
            "expected_failures": [],
            "unexpected_failures": [],
            "output": f"Pytest execution error: {exc}",
        }

def function_span(file_path: Path, name: str):
    """(first, last) line of a top-level or nested function, or None."""
    try:
        tree = ast.parse(file_path.read_text(encoding="utf-8", errors="replace"))
    except (OSError, SyntaxError):
        return None
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == name:
            first = min([d.lineno for d in node.decorator_list] + [node.lineno])
            return first, getattr(node, "end_lineno", node.lineno)
    return None


def undefined_names(file_path: Path, function_name: str) -> list[str]:
    """Global names the patched function uses that the module never defines.

    Catches patches that call e.g. ``token_urlsafe`` or ``shlex.quote``
    without the import: the file still parses, Bandit is satisfied and tests
    that never call the function pass, but it would crash at runtime.
    """
    import builtins
    import symtable

    try:
        code = file_path.read_text(encoding="utf-8", errors="replace")
        module = symtable.symtable(code, str(file_path), "exec")
    except (OSError, SyntaxError, ValueError):
        return []
    defined = {s.get_name() for s in module.get_symbols() if s.is_assigned() or s.is_imported()}
    defined |= set(dir(builtins)) | {"__file__", "__name__", "__doc__", "__builtins__"}
    # Star imports make every name potentially defined: do not guess.
    if "*" in code and re.search(r"^\s*from\s+\S+\s+import\s+\*", code, re.M):
        return []

    def find(table):
        for child in table.get_children():
            if child.get_type() == "function" and child.get_name() == function_name:
                return child
            found = find(child)
            if found is not None:
                return found
        return None

    def referenced_globals(table):
        names = set()
        for sym in table.get_symbols():
            if sym.is_referenced() and (sym.is_global() or sym.is_free()) and not sym.is_assigned():
                names.add(sym.get_name())
        for child in table.get_children():
            names |= referenced_globals(child)
        return names

    target = find(module)
    if target is None:
        return []
    return sorted(name for name in referenced_globals(target) if name not in defined)


def run_semgrep_file_check(
    original_file: Path,
    patched_file: Path,
    target_rule: str,
    function_name: str | None = None,
):
    """Semgrep the vulnerable file before and after the patch (one run).

    The target counts as removed only if it no longer appears inside the
    patched function: the same rule may legitimately fire elsewhere.
    """
    try:
        result = semgrep.run_semgrep([original_file, patched_file])
    except semgrep.SemgrepUnavailable as exc:
        return {"available": False, "error": str(exc)}
    original, patched = original_file.resolve(), patched_file.resolve()
    before = [f for f in result["findings"] if Path(f["filename"]).resolve() == original]
    after = [f for f in result["findings"] if Path(f["filename"]).resolve() == patched]
    span = function_span(patched, function_name) if function_name else None
    target_after = [
        f for f in after
        if f["test_id"] == target_rule
        and (span is None or span[0] <= f["line_number"] <= span[1])
    ]
    return {
        "available": True,
        "file": original_file.name,
        "comparison": compare_findings(before, after, original.parent, patched.parent),
        "target_removed": not target_after,
        "target_findings": target_after,
    }


def run_security_validation(
    sandbox: Path,
    target_rule: str,
    target_file: Path | None = None,
    function_name: str | None = None,
):
    """Re-scan the patched sandbox with Bandit.

    The target counts as removed only if the rule no longer fires INSIDE the
    patched function. The same rule may legitimately appear elsewhere in the
    repository (e.g. several hardcoded passwords); those are other findings
    and must not make a correct fix look like a failure.
    """
    data = run_bandit(str(sandbox))
    findings = data.get(
        "results",
        [],
    )
    same_rule = [
        finding
        for finding in findings
        if finding.get("test_id") == target_rule
    ]
    target_findings = same_rule
    scope = "repository"
    if target_file is not None:
        target_resolved = Path(target_file).resolve()
        span = function_span(target_resolved, function_name) if function_name else None

        def in_scope(finding):
            try:
                same_file = Path(finding.get("filename", "")).resolve() == target_resolved
            except OSError:
                same_file = False
            if not same_file:
                return False
            if span is None:
                return True
            return span[0] <= int(finding.get("line_number") or 0) <= span[1]

        target_findings = [finding for finding in same_rule if in_scope(finding)]
        scope = f"function {function_name}" if span else "file"
    output_lines = [
        f"Total findings after patch: {len(findings)}",
        f"Target rule {target_rule} in patched {scope}: "
        + (
            "FOUND"
            if target_findings
            else "REMOVED"
        ),
        "Same rule elsewhere in the repository (not targeted): "
        f"{len(same_rule) - len(target_findings)}",
    ]
    return {
        "passed": len(target_findings) == 0,
        "target_removed": len(target_findings) == 0,
        "findings_after": len(findings),
        "target_findings": target_findings,
        "same_rule_elsewhere": len(same_rule) - len(target_findings),
        "scope": scope,
        "all_findings": findings,
        "output": "\n".join(output_lines),
    }

# =========================================================
# REPOSITORY IMPORT

# =========================================================


@app.post("/api/repositories/github")
@app.post("/api/repositories/git")
def import_github_repository(data: dict):
    """Clone a public GitHub or GitLab repository."""
    try:
        remote = parse_remote_url(data.get("url", ""))
    except PublishError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    owner = remote.owner.replace("/", "_")
    repo_name = remote.name
    clean_url = remote.clone_url
    repo_id = uuid.uuid4().hex[:8]
    destination = (
        REPOSITORY_ROOT
        / f"{owner}_{repo_name}_{repo_id}"
    )
    try:
        imported = import_remote(remote, destination)
    except ImportFailed as exc:
        raise HTTPException(
            status_code=400,
            detail=f"Could not import {clean_url}. {exc}",
        )
    return {
        "success": True,
        "name": repo_name,
        "source": remote.provider,
        "repo_path": str(destination),
        "import_method": imported["method"],
        "import_log": imported["log"],
        "message": (
            f"{remote.provider.title()} repository imported successfully"
            + (" (ZIP fallback)." if imported["method"] == "zip" else ".")
        ),
    }


@app.post("/api/repositories/upload")
async def upload_repository(
    file: UploadFile = File(...),
):
    if not file.filename:
        raise HTTPException(
            status_code=400,
            detail="No file selected.",
        )
    if not file.filename.lower().endswith(".zip"):
        raise HTTPException(
            status_code=400,
            detail="Please upload a .zip repository.",
        )
    repo_id = uuid.uuid4().hex[:8]
    upload_dir = (
        REPOSITORY_ROOT
        / f"uploaded_{repo_id}"
    )
    upload_dir.mkdir(
        parents=True,
        exist_ok=True,
    )
    safe_filename = Path(file.filename).name
    zip_path = upload_dir / safe_filename
    try:
        contents = await file.read()
        # 100 MB upload limit.
        if len(contents) > 100 * 1024 * 1024:
            raise HTTPException(
                status_code=413,
                detail=(
                    "Repository ZIP is too large. "
                    "Maximum size is 100 MB."
                ),
            )
        zip_path.write_bytes(contents)
        with zipfile.ZipFile(
            zip_path,
            "r",
        ) as archive:
            upload_root = upload_dir.resolve()
            # ZIP traversal protection.
            for member in archive.infolist():
                member_path = (
                    upload_dir / member.filename
                ).resolve()
                try:
                    member_path.relative_to(
                        upload_root
                    )
                except ValueError:
                    raise HTTPException(
                        status_code=400,
                        detail="Unsafe ZIP structure detected.",
                    )
            archive.extractall(upload_dir)
        zip_path.unlink(missing_ok=True)
        extracted_items = [
            item
            for item in upload_dir.iterdir()
            if item.name != safe_filename
        ]
        directories = [
            item
            for item in extracted_items
            if item.is_dir()
        ]
        if len(directories) == 1:
            actual_repo = directories[0]
        else:
            actual_repo = upload_dir
        return {
            "success": True,
            "name": file.filename,
            "source": "upload",
            "repo_path": str(actual_repo),
            "message": "Repository uploaded successfully.",
        }
    except zipfile.BadZipFile:
        if upload_dir.exists():
            shutil.rmtree(upload_dir)
        raise HTTPException(
            status_code=400,
            detail="Invalid ZIP file.",
        )
    except HTTPException:
        if upload_dir.exists():
            shutil.rmtree(upload_dir)
        raise

FOLDER_SKIP_PARTS = {
    ".git", "node_modules", "venv", ".venv", "__pycache__",
    ".pytest_cache", ".mypy_cache", ".tox", "dist", "build",
}
MAX_FOLDER_BYTES = 100 * 1024 * 1024


@app.post("/api/repositories/upload-folder")
async def upload_folder(
    files: list[UploadFile] = File(...),
    paths: list[str] = Form(...),
):
    """Upload a local folder (browser folder picker) without zipping it."""
    if not files or len(files) != len(paths):
        raise HTTPException(status_code=400, detail="No folder files received.")
    repo_id = uuid.uuid4().hex[:8]
    upload_dir = REPOSITORY_ROOT / f"folder_{repo_id}"
    root = upload_dir.resolve()
    total = 0
    written = 0
    try:
        for upload, relative in zip(files, paths):
            parts = [p for p in relative.replace("\\", "/").split("/") if p]
            if not parts or any(p in {".", ".."} for p in parts):
                raise HTTPException(status_code=400, detail="Unsafe file path.")
            if FOLDER_SKIP_PARTS.intersection(parts):
                continue
            target = (upload_dir / Path(*parts)).resolve()
            if root not in target.parents:
                raise HTTPException(status_code=400, detail="Unsafe file path.")
            content = await upload.read()
            total += len(content)
            if total > MAX_FOLDER_BYTES:
                raise HTTPException(
                    status_code=413,
                    detail="Folder is too large. Maximum size is 100 MB.",
                )
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(content)
            written += 1
    except HTTPException:
        shutil.rmtree(upload_dir, ignore_errors=True)
        raise
    if not written:
        shutil.rmtree(upload_dir, ignore_errors=True)
        raise HTTPException(status_code=400, detail="The folder contains no files.")
    entries = list(upload_dir.iterdir())
    actual_repo = entries[0] if len(entries) == 1 and entries[0].is_dir() else upload_dir
    return {
        "success": True,
        "name": actual_repo.name,
        "source": "folder",
        "repo_path": str(actual_repo),
        "files": written,
        "message": f"Folder uploaded ({written} files).",
    }

# =========================================================
# DOWNLOAD VERIFIED REPOSITORY

# =========================================================


@app.get("/api/download-fixed")
def download_fixed_repository():
    """

    Download ONLY the repository that passed validation.

    Validation is performed on SANDBOX_ROOT.

    The original imported repository is never modified.

    """
    # Do not rely only on in-memory state because Uvicorn --reload
    # can restart the backend when the sandbox files are modified.
    verified = False
    if VALIDATION_MARKER.exists():
        try:
            marker = json.loads(
                VALIDATION_MARKER.read_text(encoding="utf-8")
            )
            marker_status = marker.get("status")
            marker_sandbox = marker.get("sandbox_path", "")
            verified = (
                marker_status == "VERIFIED"
                and marker_sandbox
                and Path(marker_sandbox).resolve()
                == SANDBOX_ROOT.resolve()
                and SANDBOX_ROOT.exists()
            )
        except Exception:
            verified = False
    if not verified:
        raise HTTPException(
            status_code=403,
            detail=(
                "Repository download is available only "
                "after a VERIFIED validation."
            ),
        )
    if not SANDBOX_ROOT.exists():
        raise HTTPException(
            status_code=404,
            detail="Validated sandbox not found.",
        )
    timestamp = time.strftime(
        "%Y%m%d_%H%M%S"
    )
    archive_base = (
        PROJECT_ROOT
        / "workspace"
        / f"securepatch_fixed_{timestamp}"
    )
    archive_path = Path(
        shutil.make_archive(
            str(archive_base),
            "zip",
            root_dir=str(SANDBOX_ROOT),
        )
    )
    return FileResponse(
        path=str(archive_path),
        media_type="application/zip",
        filename=(
            f"securepatch_fixed_{timestamp}.zip"
        ),
    )

# =========================================================
# SCAN

# =========================================================


@app.post("/api/scan")
def scan(request: ScanRequest):
    repo = resolve_repo(
        request.repo_path
    )
    result = run_bandit(
        str(repo)
    )
    findings = result.get(
        "results",
        [],
    )
    semgrep_info = {"enabled": request.semgrep}
    if request.semgrep:
        try:
            sg = semgrep.run_semgrep([repo])
            semgrep.save_cache(repo, sg["findings"], SCAN_CACHE_ROOT)
            findings = semgrep.merge(findings, sg["findings"])
            semgrep_info.update(count=len(sg["findings"]), errors=sg["errors"])
        except semgrep.SemgrepUnavailable as exc:
            semgrep_info["error"] = str(exc)
    metrics.record_scan(findings)
    return {
        "summary": finding_summary(findings),
        "findings": findings,
        "command": bandit_command(repo),
        "bandit_version": bandit_version(),
        "semgrep": semgrep_info,
        "metrics": (result.get("metrics") or {}).get("_totals", {}),
        "errors": result.get("errors", []),
    }


def bandit_version() -> str:
    try:
        import bandit
        return bandit.__version__
    except Exception:
        return "unknown"


@app.get("/api/bandit/rules")
def bandit_rules():
    """Plain-English explanation of Bandit rules, severity and confidence."""
    return {**bandit_catalog(), "bandit_version": bandit_version()}


@app.get("/api/bandit/explain/{test_id}")
def bandit_explain(test_id: str):
    return explain(test_id.upper())


@app.get("/api/scan/stream")
def scan_stream(repo_path: str, semgrep_enabled: bool = True):
    """Live scan: Server-Sent Events.

    Bandit streams one event per file while Semgrep runs in parallel in a
    background thread; the final 'done' event holds the merged findings.
    """
    repo = resolve_repo(repo_path)

    def events():
        pool = ThreadPoolExecutor(max_workers=1)
        sg_future = (
            pool.submit(semgrep.run_semgrep, [repo])
            if semgrep_enabled and semgrep.semgrep_bin()
            else None
        )
        try:
            if semgrep_enabled and sg_future is None:
                yield sse({"type": "semgrep", "status": "unavailable",
                           "message": "Semgrep not installed - Bandit only."})
            elif sg_future is not None:
                yield sse({"type": "semgrep", "status": "running",
                           "message": "Semgrep data-flow scan started in parallel"})
            done = None
            for event in iter_scan(repo):
                if event["type"] == "done":
                    done = event
                    break
                yield sse(event)
            findings = done["findings"]
            if sg_future is not None:
                waited = 0
                while not sg_future.done():
                    try:
                        sg_future.result(timeout=3)
                    except FuturesTimeout:
                        waited += 3
                        yield sse({"type": "semgrep", "status": "running",
                                   "message": f"Semgrep still analysing data flow... {waited}s"})
                    except Exception:
                        break
                try:
                    sg = sg_future.result()
                    semgrep.save_cache(repo, sg["findings"], SCAN_CACHE_ROOT)
                    merged = semgrep.merge(findings, sg["findings"])
                    confirmed = sum(1 for f in merged if f.get("confirmed_by"))
                    yield sse({
                        "type": "semgrep",
                        "status": "done",
                        "count": len(sg["findings"]),
                        "confirmed": confirmed,
                        "new": len(merged) - len(findings),
                        "findings": [
                            {"test_id": f["test_id"], "severity": f["issue_severity"],
                             "line": f["line_number"], "text": f["issue_text"][:140],
                             "file": Path(f["filename"]).name}
                            for f in sg["findings"]
                        ][:60],
                    })
                    findings = merged
                except Exception as exc:
                    yield sse({"type": "semgrep", "status": "failed", "message": str(exc)})
            done["findings"] = findings
            metrics.record_scan(findings)
            done["summary"] = finding_summary(findings)
            done["bandit_version"] = bandit_version()
            yield sse(done)
        except Exception as exc:  # report instead of dropping the stream
            yield sse({"type": "error", "message": str(exc)})
        finally:
            pool.shutdown(wait=False)

    return StreamingResponse(
        events(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )

# =========================================================
# ANALYZE

# =========================================================


@app.post("/api/analyze")
def analyze(request: AnalyzeRequest):
    repo = resolve_repo(
        request.repo_path
    )
    file_path = resolve_file(
        request.repo_path,
        request.file_path,
    )
    analysis = analyze_python_file(
        file_path,
        request.line,
    )
    function = analysis.get(
        "affected_function"
    )
    if not function:
        raise HTTPException(
            status_code=400,
            detail="Affected function could not be identified.",
        )
    graph = build_graph(repo)
    relative_file = file_path.relative_to(
        repo
    ).as_posix()
    impact = graph_impact(
        graph,
        relative_file,
        function["name"],
    )
    # Find tests actually related to the vulnerable
    # function or its source file.
    related_tests = []
    target_name = function["name"]
    target_stem = file_path.stem.lower()
    # First use explicit graph TESTS relationships.
    graph_test_ids = set(
        impact.get("related_tests", [])
    )
    for test_id in graph_test_ids:
        parts = test_id.split("::", 2)
        if len(parts) != 3:
            continue
        test_file = parts[1]
        test_name = parts[2]
        # Recover line number.
        try:
            test_path = repo / test_file
            test_analysis = analyze_python_file(
                test_path,
                1,
            )
            test_line = next(
                (
                    item["line"]
                    for item in test_analysis["tests"]
                    if item["name"] == test_name
                ),
                None,
            )
        except Exception:
            test_line = None
        related_tests.append(
            {
                "name": test_name,
                "file": test_file,
                "line": test_line,
            }
        )
    # Heuristic fallback for tests that mention the
    # vulnerable function/file but were not captured by graph edges.
    already_seen = {
        (item["file"], item["name"])
        for item in related_tests
    }
    for file in graph["files"]:
        if "test" not in file.lower():
            continue
        try:
            test_path = repo / file
            test_source = test_path.read_text(
                encoding="utf-8",
                errors="replace",
            )
            test_analysis = analyze_python_file(
                test_path,
                1,
            )
            for test in test_analysis["tests"]:
                is_related = (
                    target_name in test_source
                    or target_stem in test_source.lower()
                    or target_name.lower()
                    in test["name"].lower()
                )
                key = (
                    file,
                    test["name"],
                )
                if is_related and key not in already_seen:
                    related_tests.append(
                        {
                            "name": test["name"],
                            "file": file,
                            "line": test["line"],
                        }
                    )
                    already_seen.add(key)
        except Exception:
            continue
    return {
        **analysis,
        "repo": str(repo),
        "graph": graph,
        "impact": impact,
        "related_tests": related_tests[:30],
        "function_code": function["code"],
    }

# =========================================================
# GENERATE PATCH

# =========================================================


@app.post("/api/generate-patch")
def generate_patch(request: PatchRequest):
    repo = resolve_repo(
        request.repo_path
    )
    file_path = resolve_file(
        request.repo_path,
        request.file_path,
    )
    finding = get_finding(
        request.repo_path,
        request.file_path,
        request.line,
    )
    analysis = analyze_python_file(
        file_path,
        request.line,
    )
    function = analysis.get(
        "affected_function"
    )
    if not function:
        raise HTTPException(
            status_code=400,
            detail="Could not identify vulnerable function.",
        )
    graph = build_graph(repo)
    relative_file = file_path.relative_to(
        repo
    ).as_posix()
    impact = graph_impact(
        graph,
        relative_file,
        function["name"],
    )
    # Include improved related test information in prompt context.
    analysis["related_tests"] = impact.get(
        "related_tests",
        [],
    )
    if request.prompt_mode not in ("full", "plain"):
        raise HTTPException(
            status_code=400,
            detail="prompt_mode must be 'full' or 'plain'.",
        )
    retrieved = []
    retrieved_context = ""
    top_k = RAG_TOP_K if request.rag_top_k is None else max(0, int(request.rag_top_k))
    if request.use_rag and request.prompt_mode == "full" and top_k > 0:
        try:
            rag = get_rag(repo)
            rag_query = finding_query(finding, function.get("code", ""))
            retrieved = rag.query(rag_query, top_k, repo=repo)
            if not retrieved:
                rag.index(repo)
                retrieved = rag.query(rag_query, top_k, repo=repo)
            retrieved_context = format_context(retrieved)
        except Exception as exc:
            raise HTTPException(
                status_code=500,
                detail=f"Repository context retrieval failed: {exc}",
            )
    if request.prompt_mode == "plain":
        enriched_prompt = build_plain_repair_prompt(finding, function)
    else:
        enriched_prompt = build_ai_repair_prompt(
            finding=finding,
            analysis=analysis,
            graph=graph,
            impact=impact,
            retrieved_context=retrieved_context,
        )
    llm_result, repaired_function, attempts = generate_with_fallback(
        enriched_prompt,
        request.model or "qwen2.5-coder",
        function["name"],
        fallback=request.fallback,
        allowed=request.fallback_models,
        seed=request.seed,
        temperature=request.temperature,
        module_source=file_path.read_text(encoding="utf-8", errors="replace"),
    )
    patch = {
        "attempts": attempts,
        "fallback_used": len(attempts) > 1,
        "settings": {
            "use_rag": request.use_rag and request.prompt_mode == "full",
            "prompt_mode": request.prompt_mode,
            "fallback": request.fallback,
            "seed": request.seed,
            "temperature": request.temperature,
            "rag_chunks": len(retrieved),
            "rag_top_k": top_k if request.use_rag and request.prompt_mode == "full" else 0,
            "prompt_chars": len(enriched_prompt),
        },
        "provider": llm_result.provider,
        "model": llm_result.model,
        "latency_ms": llm_result.latency_ms,
        "input_tokens": llm_result.input_tokens,
        "output_tokens": llm_result.output_tokens,
        "function": repaired_function,
        "patch": repaired_function,
    }
    return {
        "finding": finding,
        "context": analysis,
        "graph": graph,
        "impact": impact,
        "prompt": enriched_prompt,
        "retrieved_context": retrieved,
        "patch": patch,
        "provider": llm_result.provider,
        "model": llm_result.model,
    }

# =========================================================
# VALIDATE PATCH

# =========================================================


@app.post("/api/validate")
def validate(request: ValidateRequest):
    verdict = "ERROR"
    try:
        result = _validate(request)
        if isinstance(result, dict):
            verdict = result.get("status") or "UNKNOWN"
        return result
    finally:
        metrics.record_validation(verdict)


def _validate(request: ValidateRequest):
    global LAST_VALIDATION_STATUS
    LAST_VALIDATION_STATUS = None
    # Remove any previous verification so a new validation must
    # explicitly pass before downloading is allowed again.
    VALIDATION_MARKER.unlink(missing_ok=True)
    repo = resolve_repo(
        request.repo_path
    )
    file_path = resolve_file(
        request.repo_path,
        request.file_path,
    )
    finding = get_finding(
        request.repo_path,
        request.file_path,
        request.line,
    )
    analysis = analyze_python_file(
        file_path,
        request.line,
    )
    function = analysis.get(
        "affected_function"
    )
    if not function:
        raise HTTPException(
            status_code=400,
            detail="Could not identify vulnerable function.",
        )
    patch_text = request.patch.strip()
    if not patch_text:
        raise HTTPException(
            status_code=400,
            detail="Generated patch is empty.",
        )
    # Basic syntax guard before touching the sandbox.
    try:
        ast.parse(patch_text)
    except SyntaxError as exc:
        LAST_VALIDATION_STATUS = "REJECTED"
        return {
            "status": "REJECTED",
            "regression": {
                "passed": False,
                "passed_count": 0,
                "failed_count": 0,
                "error_count": 0,
                "output": "",
            },
            "security": {
                "passed": False,
                "target_removed": False,
                "findings_after": 0,
                "target_findings": [],
                "output": f"Invalid patch syntax: {exc}",
            },
            "patch": {
                "applied": False,
            },
            "sandbox": {
                "path": str(SANDBOX_ROOT),
            },
        }
    sandbox = create_sandbox(repo)
    try:
        target = apply_function_patch(
            repo_path=repo,
            sandbox=sandbox,
            file_path=file_path,
            old_function=function["code"],
            new_function=patch_text,
        )
    except Exception as exc:
        LAST_VALIDATION_STATUS = "REJECTED"
        return {
            "status": "REJECTED",
            "regression": {
                "passed": False,
                "passed_count": 0,
                "failed_count": 0,
                "error_count": 0,
                "output": "",
            },
            "security": {
                "passed": False,
                "target_removed": False,
                "findings_after": 0,
                "target_findings": [],
                "output": str(exc),
            },
            "patch": {
                "applied": False,
            },
            "sandbox": {
                "path": str(sandbox),
            },
        }
    # Guardrail: the patched function must not use names the module never
    # defines (typically a missing import). Such a patch would crash at
    # runtime even if Bandit is satisfied and no test calls the function.
    missing = undefined_names(Path(target), function.get("name") or "")
    if missing:
        LAST_VALIDATION_STATUS = "REJECTED"
        message = (
            "Guardrail: patched function uses undefined names "
            f"{', '.join(missing)} (missing import?)"
        )
        return {
            "status": "REJECTED",
            "reason": message,
            "undefined_names": missing,
            "regression": {
                "passed": False,
                "passed_count": 0,
                "failed_count": 0,
                "error_count": 0,
                "output": "",
            },
            "security": {
                "passed": False,
                "target_removed": False,
                "findings_after": 0,
                "target_findings": [],
                "output": message,
            },
            "patch": {
                "applied": True,
            },
            "sandbox": {
                "path": str(sandbox),
            },
        }
    regression = run_pytest(
        sandbox
    )
    security = run_security_validation(
        sandbox,
        finding.get("test_id"),
        Path(target),
        function.get("name"),
    )
    semgrep_check = run_semgrep_file_check(
        file_path,
        Path(target),
        finding.get("test_id"),
        function.get("name"),
    )
    if str(finding.get("test_id", "")).startswith("SG-"):
        # Bandit cannot see Semgrep rules: Semgrep must confirm the fix.
        removed = semgrep_check.get("available") and semgrep_check["target_removed"]
        security.update(
            passed=bool(removed),
            target_removed=bool(removed),
            target_findings=semgrep_check.get("target_findings", []),
            output=(
                f"Semgrep target rule {finding['test_id']}: "
                + ("REMOVED" if removed else "FOUND / not verifiable")
                + ("" if semgrep_check.get("available") else f" ({semgrep_check.get('error')})")
            ),
        )
    comparison = compare_findings(
        run_bandit(str(repo)).get("results", []),
        security.pop("all_findings", []),
        repo,
        sandbox,
    )
    verified = (
        regression["passed"]
        and security["passed"]
        and security["target_removed"]
    )
    LAST_VALIDATION_STATUS = (
        "VERIFIED"
        if verified
        else "REJECTED"
    )
    if verified:
        VALIDATION_MARKER.parent.mkdir(
            parents=True,
            exist_ok=True,
        )
        VALIDATION_MARKER.write_text(
            json.dumps(
                {
                    "status": "VERIFIED",
                    "sandbox_path": str(
                        SANDBOX_ROOT.resolve()
                    ),
                    # Everything needed to publish this exact fix later.
                    "repo_path": str(repo),
                    "target_file": Path(target)
                    .resolve()
                    .relative_to(sandbox.resolve())
                    .as_posix(),
                    "function": function.get("name"),
                    "finding": {
                        key: finding.get(key)
                        for key in (
                            "test_id",
                            "test_name",
                            "issue_severity",
                            "issue_confidence",
                            "issue_cwe",
                            "issue_text",
                            "line_number",
                            "more_info",
                        )
                    },
                    "regression": {
                        key: regression.get(key)
                        for key in ("passed_count", "failed_count")
                    },
                    "security": {
                        key: security.get(key)
                        for key in ("target_removed", "findings_after")
                    },
                    "comparison": {
                        "before": comparison["before"],
                        "after": comparison["after"],
                        "removed": comparison["removed"],
                        "introduced": comparison["introduced"],
                    },
                    "semgrep": (
                        {
                            "before": semgrep_check["comparison"]["before"],
                            "after": semgrep_check["comparison"]["after"],
                        }
                        if semgrep_check.get("available")
                        else None
                    ),
                },
                indent=2,
            ),
            encoding="utf-8",
        )
    else:
        VALIDATION_MARKER.unlink(missing_ok=True)
    return {
        "status": LAST_VALIDATION_STATUS,
        "regression": regression,
        "security": security,
        "comparison": comparison,
        "semgrep_check": semgrep_check,
        "patch": {
            "applied": True,
            "target_file": str(target),
        },
        "sandbox": {
            "path": str(sandbox),
        },
    }

# =========================================================
# ROOT / HEALTH

# =========================================================


# =========================================================
# PUBLISH VERIFIED FIX TO GITHUB / GITLAB

# =========================================================
# Outside the project so `uvicorn --reload` never restarts mid-publish.
PUBLISH_ROOT = Path(tempfile.gettempdir()) / "securepatch_publish"


class PublishRequest(BaseModel):
    repo_path: str
    provider: str  # "github" | "gitlab"
    token: str
    mode: str = "auto"  # auto | branch | fork | new_repo
    new_repo_name: str | None = None
    private: bool = True
    open_request: bool = True
    request_to_upstream: bool = False


def load_verified_marker(repo_path: str) -> dict:
    """Return the validation marker if this repo has a VERIFIED fix."""
    repo = resolve_repo(repo_path)
    try:
        marker = json.loads(VALIDATION_MARKER.read_text(encoding="utf-8"))
    except Exception:
        marker = {}
    if marker.get("status") != "VERIFIED" or not SANDBOX_ROOT.exists():
        raise HTTPException(
            status_code=403,
            detail="Publishing is available only after a VERIFIED validation.",
        )
    if Path(marker.get("repo_path", "")).resolve() != repo:
        raise HTTPException(
            status_code=409,
            detail=(
                "The verified fix belongs to a different repository. "
                "Validate a patch for this repository first."
            ),
        )
    return marker


@app.get("/api/publish/source")
def publish_source(repo_path: str):
    """Where did this code come from? (no token needed)"""
    remote = detect_source_remote(resolve_repo(repo_path))
    return {
        "has_remote": remote is not None,
        "source": remote.to_dict() if remote else None,
        "suggested_provider": remote.provider if remote else "github",
    }


@app.post("/api/publish/preview")
def publish_preview(request: PublishRequest):
    """Check the token and explain what publishing would do."""
    repo = resolve_repo(request.repo_path)
    try:
        plan = resolve_mode(
            request.mode,
            detect_source_remote(repo),
            request.provider,
            make_client(request.provider, request.token),
        )
    except PublishError as exc:
        raise HTTPException(status_code=exc.status_code, detail=str(exc))
    plan.pop("author", None)
    return plan


@app.post("/api/publish")
def publish_fix(request: PublishRequest):
    """Push the verified fix as a branch / fork / new repo + PR/MR."""
    marker = load_verified_marker(request.repo_path)
    repo = resolve_repo(request.repo_path)
    files = collect_changed_files(
        repo,
        SANDBOX_ROOT,
        [marker["target_file"]],
    )
    if not files:
        raise HTTPException(
            status_code=409,
            detail="The verified sandbox has no changes to publish.",
        )
    try:
        return publish_to_remote(
            repo=repo,
            work_root=PUBLISH_ROOT,
            files=files,
            summary={**marker, "target_file": marker["target_file"]},
            provider=request.provider,
            token=request.token,
            mode=request.mode,
            new_repo_name=request.new_repo_name,
            private=request.private,
            open_request=request.open_request,
            request_to_upstream=request.request_to_upstream,
        )
    except PublishError as exc:
        raise HTTPException(status_code=exc.status_code, detail=str(exc))


@app.get("/")
def root():
    return {
        "name": "SecurePatch",
        "status": "running",
    }


@app.get("/api/health")
def health():
    return {
        "status": "healthy",
        "service": "SecurePatch Backend",
        "version": app.version,
        "sandbox": sandbox_describe(),
        "semgrep": semgrep.status(),
        "ollama": ollama_is_available(),
    }

# =========================================================
# AI / RAG MID-SEM FEATURES

# =========================================================
RAG_TOP_K = 6  # retrieved chunks per repair prompt
RAG_ROOT = PROJECT_ROOT / "workspace" / "rag_chroma"
GENERATED_TEST_ROOT = PROJECT_ROOT / "workspace" / "generated_tests"
RAG_ROOT.mkdir(parents=True, exist_ok=True)
GENERATED_TEST_ROOT.mkdir(parents=True, exist_ok=True)


def get_rag(repo: Path) -> RepositoryRAG:
    # A single persistent Chroma store is intentionally used; every query is
    # filtered by repository path so imported repositories do not mix.
    return RepositoryRAG(RAG_ROOT)


def validate_patch_guardrails(patch: str, expected_function: str) -> None:
    """Reject malformed or obviously unsafe AI-generated patches."""

    if not patch or not patch.strip():
        raise ValueError("Guardrail blocked: empty patch.")

    try:
        tree = ast.parse(patch)
    except SyntaxError as exc:
        raise ValueError(
            f"Guardrail blocked: invalid Python syntax: {exc}"
        ) from exc

    # Only one function is permitted in the generated patch.
    if len(tree.body) != 1 or not isinstance(
        tree.body[0], (ast.FunctionDef, ast.AsyncFunctionDef)
    ):
        raise ValueError(
            "Guardrail blocked: output must contain exactly one function."
        )

    function = tree.body[0]

    if function.name != expected_function:
        raise ValueError(
            "Guardrail blocked: generated function name does not match "
            "the expected function."
        )

    # Inspect Python syntax rather than relying on text matching.
    for node in ast.walk(function):
        if not isinstance(node, ast.Call):
            continue

        func = node.func
        call_name = (
            func.id if isinstance(func, ast.Name)
            else f"{func.value.id}.{func.attr}"
            if isinstance(func, ast.Attribute)
            and isinstance(func.value, ast.Name)
            else None
        )

        if call_name in {"eval", "exec"}:
            raise ValueError(
                f"Guardrail blocked: unsafe call to {call_name}()."
            )

        if call_name in {
            "os.system",
            "pickle.loads",
            "marshal.loads",
        }:
            raise ValueError(
                f"Guardrail blocked: unsafe call to {call_name}()."
            )

        if call_name and call_name.startswith("subprocess."):
            for keyword in node.keywords:
                if (
                    keyword.arg == "shell"
                    and isinstance(keyword.value, ast.Constant)
                    and keyword.value.value is True
                ):
                    raise ValueError(
                        "Guardrail blocked: subprocess shell=True."
                    )

def generate_with_fallback(
    prompt: str,
    model: str,
    function_name: str,
    *,
    fallback: bool = True,
    allowed: list[str] | None = None,
    seed: int | None = None,
    temperature: float | None = None,
    module_source: str | None = None,
):
    """Try the requested model, then lighter installed models.

    A model "fails" when Ollama errors (500 / crash / timeout), or when its
    output is not the expected function or is blocked by the guardrails.
    ``fallback=False`` uses only the requested model (fair per-model
    benchmarks); ``allowed`` restricts which models the chain may use.
    Returns (llm_result, repaired_function, attempts).
    """
    if fallback:
        chain = fallback_chain(
            model,
            installed_models() if ollama_is_available() else None,
        )
        if allowed:
            chain = [model] + [m for m in chain[1:] if m in allowed]
    else:
        chain = [model]
    attempts = []
    for model_key in chain:
        try:
            llm_result = generate_llm(
                prompt,
                model=model_key,
                seed=seed,
                temperature=temperature,
            )
            print("\n" + "=" * 80)
            print(f"RAW LLM RESPONSE ({model_key})")
            print("=" * 80)
            print(llm_result.text)
            print("=" * 80 + "\n")
            repaired = normalize_function_output(llm_result.text, function_name)
            repaired = carry_over_imports(llm_result.text, repaired, module_source or "")
            validate_patch_guardrails(repaired, function_name)
            attempts.append({"model": model_key, "ok": True, "error": None})
            metrics.record_patch_attempt(model_key, None)
            if len(attempts) > 1:
                metrics.FALLBACKS.inc()
            return llm_result, repaired, attempts
        except Exception as exc:
            attempts.append({"model": model_key, "ok": False, "error": str(exc)})
            metrics.record_patch_attempt(model_key, str(exc))
            # Ollama unreachable: other models will fail the same way.
            if "Could not connect to Ollama" in str(exc):
                break
    summary = "; ".join(f"{a['model']}: {a['error']}" for a in attempts)
    raise HTTPException(
        status_code=502,
        detail=f"LLM generation failed for all models. {summary}",
    )


IMPORT_LINE = re.compile(r"^(import\s+[\w.]+(\s+as\s+\w+)?(\s*,\s*[\w.]+(\s+as\s+\w+)?)*"
                         r"|from\s+[\w.]+\s+import\s+[\w*, ()]+?(\s+as\s+\w+)?)\s*$")


def carry_over_imports(llm_text: str, function_code: str, module_source: str) -> str:
    """Keep the imports a model wrote ABOVE the repaired function.

    Only the function is patched into the file, so top-level imports in the
    model output would be lost and a correct fix (e.g. ``secrets.token_urlsafe``)
    would fail with a missing name. Imports whose names the function uses and
    the module does not already define are moved to the top of the function
    body. Returns the function unchanged when nothing needs to be added.
    """
    try:
        fn_tree = ast.parse(textwrap.dedent(function_code))
    except SyntaxError:
        return function_code
    fn = next((n for n in fn_tree.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))), None)
    if fn is None or not fn.body:
        return function_code

    used = {n.id for n in ast.walk(fn) if isinstance(n, ast.Name)}
    already = set()
    try:
        for node in ast.parse(module_source).body:
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                already |= {(a.asname or a.name).split(".")[0] for a in node.names}
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                already.add(node.name)
            elif isinstance(node, ast.Assign):
                already |= {t.id for t in node.targets if isinstance(t, ast.Name)}
    except SyntaxError:
        pass
    for node in ast.walk(fn):  # imports the model already put inside
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            already |= {(a.asname or a.name).split(".")[0] for a in node.names}

    needed = []
    for raw in str(llm_text).replace("\r\n", "\n").split("\n"):
        line = raw.strip()
        if raw[:1].isspace() or not IMPORT_LINE.match(line):
            continue
        try:
            node = ast.parse(line).body[0]
        except (SyntaxError, IndexError):
            continue
        names = {(a.asname or a.name).split(".")[0] for a in node.names}
        if names & used and not names <= already and line not in needed:
            needed.append(line)
            already |= names
    if not needed:
        return function_code

    lines = textwrap.dedent(function_code).split("\n")
    first = fn.body[0]
    if first.lineno == fn.lineno:  # one-line function: leave it alone
        return function_code
    has_doc = (isinstance(first, ast.Expr) and isinstance(getattr(first, "value", None), ast.Constant)
               and isinstance(first.value.value, str))
    insert_at = (first.end_lineno if has_doc else first.lineno - 1)
    indent = " " * first.col_offset
    return "\n".join(lines[:insert_at] + [indent + imp for imp in needed] + lines[insert_at:])


def normalize_function_output(text: str, function_name: str) -> str:
    """
    Extract exactly one valid Python function from an LLM response.

    Handles:
    - Markdown code fences
    - Explanations before/after the function
    - Unicode/escaped whitespace
    - def name() and def name ()
    - async functions
    - repeated/duplicate model output

    Returns only the requested function.
    """

    if text is None:
        raise ValueError("LLM did not return any Python code.")

    cleaned = str(text).strip()

    if not cleaned:
        raise ValueError("LLM did not return any Python code.")

    # Normalize characters sometimes produced by copied/model output.
    cleaned = (
        cleaned
        .replace("\ufeff", "")
        .replace("\u200b", "")
        .replace("\u200c", "")
        .replace("\u200d", "")
        .replace("\u00a0", " ")
        .replace("\\r\\n", "\n")
        .replace("\\n", "\n")
    )

    # Remove Markdown code fences.
    cleaned = re.sub(
        r"```(?:python|py)?\s*",
        "",
        cleaned,
        flags=re.IGNORECASE,
    )

    cleaned = cleaned.replace("```", "").strip()

    # Handle literal escaped backticks.
    cleaned = cleaned.replace("\\`\\`\\`python", "")
    cleaned = cleaned.replace("\\`\\`\\`", "").strip()

    # ---------------------------------------------------------
    # Find the requested function.
    # ---------------------------------------------------------

    pattern = re.compile(
        rf"(?m)^[ \t]*(?:async[ \t]+)?def[ \t]+"
        rf"{re.escape(function_name)}[ \t]*\("
    )

    match = pattern.search(cleaned)

    # Fallback if explanation text appears directly before `def`.
    if match is None:
        pattern = re.compile(
            rf"\b(?:async[ \t]+)?def[ \t]+"
            rf"{re.escape(function_name)}[ \t]*\("
        )

        match = pattern.search(cleaned)

    if match is None:
        raise ValueError(
            f"LLM did not return the expected function "
            f"'{function_name}'."
        )

    candidate = cleaned[match.start():].strip()

    # ---------------------------------------------------------
    # Parse the candidate.
    # ---------------------------------------------------------

    try:
        tree = ast.parse(candidate)

    except SyntaxError:

        # DeepSeek may append explanation or malformed extra text
        # after an otherwise valid function. Try progressively
        # shorter prefixes and keep the first valid prefix that
        # contains the requested function.
        lines = candidate.splitlines()

        valid_tree = None
        valid_end = None

        for end in range(len(lines), 0, -1):

            prefix = "\n".join(
                lines[:end]
            ).rstrip()

            try:
                parsed = ast.parse(prefix)

            except SyntaxError:
                continue

            matching = [
                node
                for node in parsed.body
                if isinstance(
                    node,
                    (
                        ast.FunctionDef,
                        ast.AsyncFunctionDef,
                    ),
                )
                and node.name == function_name
            ]

            if matching:
                valid_tree = parsed
                valid_end = end
                break

        if valid_tree is None:
            raise ValueError(
                f"LLM returned invalid Python for function "
                f"'{function_name}'."
            )

        candidate = "\n".join(
            lines[:valid_end]
        ).rstrip()

        tree = valid_tree

    # ---------------------------------------------------------
    # Find requested function in AST.
    # ---------------------------------------------------------

    functions = [
        node
        for node in tree.body
        if isinstance(
            node,
            (
                ast.FunctionDef,
                ast.AsyncFunctionDef,
            ),
        )
    ]

    target = next(
        (
            node
            for node in functions
            if node.name == function_name
        ),
        None,
    )

    if target is None:
        raise ValueError(
            f"LLM returned Python, but not the expected "
            f"function '{function_name}'."
        )

    # ---------------------------------------------------------
    # Extract ONLY the target function.
    # ---------------------------------------------------------

    lines = candidate.splitlines()

    start_line = target.lineno
    end_line = getattr(
        target,
        "end_lineno",
        target.lineno,
    )

    if not (
        1 <= start_line <= end_line <= len(lines)
    ):
        raise ValueError(
            "Could not determine the complete generated "
            "function boundaries."
        )

    result = "\n".join(
        lines[start_line - 1:end_line]
    ).strip()

    # ---------------------------------------------------------
    # Final safety validation.
    # ---------------------------------------------------------

    try:
        final_tree = ast.parse(result)

    except SyntaxError as exc:
        raise ValueError(
            f"Extracted function has invalid Python syntax: "
            f"{exc}"
        ) from exc

    final_functions = [
        node
        for node in final_tree.body
        if isinstance(
            node,
            (
                ast.FunctionDef,
                ast.AsyncFunctionDef,
            ),
        )
    ]

    if len(final_functions) != 1:
        raise ValueError(
            "Generated patch must contain exactly one "
            "Python function."
        )

    if final_functions[0].name != function_name:
        raise ValueError(
            f"Generated function name "
            f"'{final_functions[0].name}' does not match "
            f"expected function '{function_name}'."
        )

    return result


def build_ai_repair_prompt(finding, analysis, graph, impact, retrieved_context):
    function = analysis.get("affected_function") or {}
    imports = analysis.get("imports") or []
    callers = impact.get("callers") or impact.get("function_calls") or []
    related_tests = analysis.get("related_tests") or analysis.get("tests") or []
    # Order matters: background context first, the task and vulnerable
    # function last. If a local model's context window overflows, the
    # start of the prompt is dropped - never the actual task.
    return f"""
You are SecurePatch, a security-focused Python vulnerability repair engine.
RETRIEVED REPOSITORY CONTEXT (background only - do not rewrite this code)
{retrieved_context or "(No semantic context was supplied for this request.)"}
SOURCE GRAPH SUMMARY
Files: {len(graph.get("files", []))}
Functions: {len(graph.get("functions", []))}
Nodes: {len(graph.get("nodes", []))}
Edges: {len(graph.get("edges", []))}
REPOSITORY IMPACT
Callers / connected functions:
{json.dumps(callers, indent=2)}
Related tests:
{json.dumps(related_tests, indent=2)}
TASK
Repair ONLY the vulnerable function below.
SECURITY FINDING
Rule: {finding.get("test_id")}
Severity: {finding.get("issue_severity")}
Confidence: {finding.get("issue_confidence")}
CWE: {finding.get("issue_cwe")}
Issue: {finding.get("issue_text")}
File: {finding.get("filename")}
Line: {finding.get("line_number")}
IMPORTS
{json.dumps(imports, indent=2)}
VULNERABLE FUNCTION (name: {function.get("name", "")})
{function.get("code", "")}
STRICT SECURITY REQUIREMENTS
1. Fix the reported vulnerability.
2. Preserve intended application behavior.
3. Make the smallest safe change.
4. Do not modify tests.
5. Do not modify unrelated code.
6. Do not introduce new vulnerabilities.
7. Do not invent variables. Use only names that are imported or defined in the file; if the fix needs another module (e.g. secrets, tempfile, shlex), import it INSIDE the function body.
8. Keep the existing function signature unless a signature change is required for security.
9. Return ONLY the complete corrected Python function.
10. Return plain Python code, with no markdown fences and no explanation.
11. The function MUST be named exactly `{function.get("name", "")}`.
""".strip()


def build_plain_repair_prompt(finding, function):
    """Baseline prompt: only the finding and the function.

    No retrieved context, source graph, callers, tests or imports. Used to
    measure what SecurePatch's context engineering adds over asking an LLM
    directly.
    """
    name = function.get("name", "")
    return f"""
Fix this security vulnerability in the Python function below.
Rule: {finding.get("test_id")}
Issue: {finding.get("issue_text")}

{function.get("code", "")}

Return ONLY the complete corrected Python function, named exactly `{name}`,
as plain Python code with no markdown fences and no explanation.
""".strip()


def finding_query(finding, function_code=""):
    return (
        f"security vulnerability {finding.get('test_id')} "
        f"{finding.get('issue_text')} "
        f"file {finding.get('filename')} "
        f"function {function_code[:250]}"
    )


class AIIndexRequest(BaseModel):
    repo_path: str = "sample_repo"


class AIQueryRequest(BaseModel):
    repo_path: str = "sample_repo"
    query: str
    k: int = 6
    model: str | None = None


class AITestRequest(BaseModel):
    repo_path: str = "sample_repo"
    file_path: str
    line: int
    patch: str
    model: str | None = None


class AIReviewRequest(BaseModel):
    repo_path: str = "sample_repo"
    file_path: str
    line: int
    patch: str
    model: str | None = None


class AICompareRequest(BaseModel):
    repo_path: str = "sample_repo"
    file_path: str
    line: int
    models: list[str] | None = None


@app.get("/api/experiment/environment")
def experiment_environment():
    """Every version and setting an experiment depends on (reproducibility)."""
    import platform
    from importlib import metadata

    import src.llm_adapter as llm
    import src.repository_rag as rag_mod

    def version(dist):
        try:
            return metadata.version(dist)
        except metadata.PackageNotFoundError:
            return None

    ollama_version = None
    model_digests = {}
    try:
        import requests as _rq
        ollama_version = _rq.get(f"{llm.OLLAMA_BASE_URL}/api/version", timeout=5).json().get("version")
        for item in _rq.get(f"{llm.OLLAMA_BASE_URL}/api/tags", timeout=5).json().get("models", []):
            model_digests[item.get("name")] = {
                "digest": (item.get("digest") or "")[:12],
                "size_gb": round((item.get("size") or 0) / 1e9, 2),
                "quantization": (item.get("details") or {}).get("quantization_level"),
                "parameters": (item.get("details") or {}).get("parameter_size"),
            }
    except Exception:
        pass

    return {
        "python": platform.python_version(),
        "platform": platform.platform(),
        "processor": platform.processor(),
        "packages": {
            name: version(name)
            for name in (
                "fastapi", "bandit", "chromadb", "sentence-transformers",
                "langchain-text-splitters", "langchain-core", "torch",
                "pytest", "requests",
            )
        },
        "semgrep": semgrep.status(),
        "ollama_version": ollama_version,
        "models": {
            key: {"ollama_name": name, **model_digests.get(name, {})}
            for key, name in llm.ALL_MODELS.items()
        },
        "generation_options": llm.MODEL_OPTIONS,
        "fallback_order": llm.FALLBACK_ORDER,
        "rag": {
            "embedding_model": rag_mod.DEFAULT_EMBEDDING_MODEL,
            "chunk_size_chars": rag_mod.CHUNK_SIZE,
            "chunk_overlap_chars": rag_mod.CHUNK_OVERLAP,
            "top_k": RAG_TOP_K,
            "max_context_chars": rag_mod.MAX_CONTEXT_CHARS,
            "max_chunk_chars": rag_mod.MAX_EVIDENCE_CHARS,
        },
        "sandbox": sandbox_describe(),
        "pytest_timeout_seconds": PYTEST_TIMEOUT_SECONDS,
    }


@app.get("/api/ai/status")
def ai_status():
    return {
        "ollama_available": ollama_is_available(),
        "configured_models": configured_models(),
        "model_registry": MODEL_REGISTRY,
        "installed_models": installed_models() if ollama_is_available() else [],
        "rag": True,
        "embedding_model": os.getenv(
            "SECUREPATCH_EMBEDDING_MODEL",
            "sentence-transformers/all-MiniLM-L6-v2",
        ),
    }


@app.post("/api/ai/index")
def ai_index(request: AIIndexRequest):
    repo = resolve_repo(request.repo_path)
    rag = get_rag(repo)
    try:
        return {"success": True, **rag.index(repo)}
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"RAG indexing failed: {exc}")


@app.post("/api/ai/query")
def ai_query(request: AIQueryRequest):
    repo = resolve_repo(request.repo_path)
    rag = get_rag(repo)
    try:
        retrieved = rag.query(request.query, request.k, repo=repo)
        if not retrieved:
            return {
                "query": request.query,
                "retrieved": [],
                "answer": "No indexed repository context was found. Build the RAG index first.",
            }
        context = format_context(retrieved)
        prompt = f"""
You are SecurePatch Code Intelligence.
Answer the repository question using ONLY the retrieved repository context.
If the answer is not supported by the context, say so.
QUESTION:
{request.query}
RETRIEVED CONTEXT:
{context}
""".strip()
        result = generate_llm(prompt, model=request.model or "qwen2.5-coder")
        return {
            "query": request.query,
            "answer": result.text,
            "retrieved": retrieved,
            "provider": result.provider,
            "model": result.model,
            "latency_ms": result.latency_ms,
        }
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"RAG Q&A failed: {exc}")


@app.post("/api/ai/generate-patch")
def ai_generate_patch(request: PatchRequest):
    # Explicit AI endpoint; this is the recommended new UI endpoint.
    return generate_patch(request)


@app.post("/api/ai/generate-tests")
def ai_generate_tests(request: AITestRequest):

    # ---------------------------------------------------------
    # Resolve repository and target file
    # ---------------------------------------------------------

    repo = resolve_repo(request.repo_path)

    file_path = resolve_file(
        request.repo_path,
        request.file_path,
    )

    # ---------------------------------------------------------
    # The exact generated patch MUST be supplied by the frontend.
    # ---------------------------------------------------------

    if not request.patch or not request.patch.strip():
        raise HTTPException(
            status_code=400,
            detail="A generated patch is required for test generation.",
        )

    # ---------------------------------------------------------
    # Analyze the original source file.
    # This does NOT depend on get_finding() succeeding.
    # ---------------------------------------------------------

    analysis = analyze_python_file(
        file_path,
        request.line,
    )

    function = analysis.get("affected_function")

    if not function:
        raise HTTPException(
            status_code=400,
            detail="Could not identify affected function.",
        )

    # ---------------------------------------------------------
    # Try to recover the Bandit finding.
    #
    # If the finding cannot be located because the repository
    # path changed between scan and AI Lab request, continue
    # using the available source information instead of failing.
    # ---------------------------------------------------------

    try:

        finding = get_finding(
            request.repo_path,
            request.file_path,
            request.line,
        )

    except HTTPException:

        finding = {
            "test_id": "UNKNOWN",
            "issue_severity": "UNKNOWN",
            "issue_confidence": "UNKNOWN",
            "issue_cwe": {},
            "issue_text": (
                "Security vulnerability reported at "
                f"{request.file_path}:{request.line}"
            ),
            "filename": request.file_path,
            "line_number": request.line,
        }

    # ---------------------------------------------------------
    # Repository RAG context
    # ---------------------------------------------------------

    rag = get_rag(repo)

    try:

        query = finding_query(
            finding,
            function.get("code", ""),
        )

        retrieved = rag.query(
            query,
            6,
            repo=repo,
        )

        context = format_context(
            retrieved
        )

    except Exception:

        # Test generation should still work even if
        # semantic retrieval is unavailable.
        context = "(No semantic repository context was retrieved.)"

    # ---------------------------------------------------------
    # AI TEST GENERATION PROMPT
    # ---------------------------------------------------------

    prompt = f"""
You are SecurePatch's AI Test Generator.

Generate a focused pytest test module for the EXACT GENERATED PATCH
provided below.

The tests are evaluation artifacts only.
They must NOT modify production source files.

============================================================
SECURITY FINDING
============================================================

{json.dumps(finding, indent=2)}

============================================================
ORIGINAL TARGET FUNCTION
============================================================

{function.get("code", "")}

============================================================
EXACT GENERATED PATCH UNDER TEST
============================================================

{request.patch}

============================================================
REPOSITORY CONTEXT
============================================================

{context}

============================================================
STRICT TEST REQUIREMENTS
============================================================

1. Return ONLY complete Python pytest code.

2. Test the EXACT generated patch supplied above.

3. Use the ACTUAL function name from the original target function.

4. Do NOT invent new production methods such as:
   execute_safe(), secure_execute(), etc.

5. Do NOT invent attributes such as:
   last_output, command_result, etc.

6. Do NOT assume APIs that are not present in the
   original function or repository context.

7. Test intended normal behavior.

8. Test the security property relevant to the finding.

9. Test an invalid or malicious input where appropriate.

10. Preserve the existing public API.

11. Avoid network access.

12. Avoid destructive system actions.

13. Do not modify production files.

14. Do not claim that a test passes unless the supplied
    source and patch support that behavior.

15. If the patch uses a whitelist, test that allowed
    commands work and disallowed commands are rejected.

16. If the patch changes subprocess behavior, test that
    shell execution is disabled or safely constrained.

17. Import only modules and functions that are actually
    present or standard pytest dependencies.

18. The generated tests must be runnable with pytest.

19. Do not return markdown fences.

20. Do not return explanations outside the Python code.

Return ONLY the pytest source code.
""".strip()

    # ---------------------------------------------------------
    # Generate tests with selected local Ollama model
    # ---------------------------------------------------------

    try:

        result = generate_llm(
            prompt,
            model=request.model or "qwen2.5-coder",
        )

    except Exception as exc:

        raise HTTPException(
            status_code=502,
            detail=f"Test generation failed: {exc}",
        )

    # ---------------------------------------------------------
    # Save generated test artifact
    # ---------------------------------------------------------

    safe_name = re.sub(
        r"[^A-Za-z0-9_.-]+",
        "_",
        Path(request.file_path).stem,
    )

    model_name = re.sub(
        r"[^A-Za-z0-9_.-]+",
        "_",
        request.model or "qwen2.5-coder",
    )

    timestamp = time.strftime(
        "%Y%m%d_%H%M%S"
    )

    out = (
        GENERATED_TEST_ROOT
        / (
            f"test_generated_"
            f"{safe_name}_"
            f"{model_name}_"
            f"{timestamp}.py"
        )
    )

    out.write_text(
        result.text,
        encoding="utf-8",
    )

    # ---------------------------------------------------------
    # Return result
    # ---------------------------------------------------------

    return {
        "success": True,
        "path": str(out),
        "provider": result.provider,
        "model": result.model,
        "latency_ms": result.latency_ms,
        "tests": result.text,
        "patch_model": request.model or "qwen2.5-coder",
        "patch_used": request.patch,
    }


@app.post("/api/ai/review")
def ai_review(request: AIReviewRequest):

    # ---------------------------------------------------------
    # Resolve repository and target file
    # ---------------------------------------------------------

    repo = resolve_repo(
        request.repo_path
    )

    file_path = resolve_file(
        request.repo_path,
        request.file_path,
    )

    # ---------------------------------------------------------
    # Exact patch is mandatory
    # ---------------------------------------------------------

    if not request.patch or not request.patch.strip():
        raise HTTPException(
            status_code=400,
            detail="A generated patch is required for security review.",
        )

    # ---------------------------------------------------------
    # Analyze original source
    # ---------------------------------------------------------

    analysis = analyze_python_file(
        file_path,
        request.line,
    )

    function = analysis.get(
        "affected_function"
    )

    if not function:
        raise HTTPException(
            status_code=400,
            detail="Could not identify affected function.",
        )

    # ---------------------------------------------------------
    # Recover Bandit finding
    # ---------------------------------------------------------

    try:

        finding = get_finding(
            request.repo_path,
            request.file_path,
            request.line,
        )

    except HTTPException:

        finding = {
            "test_id": "UNKNOWN",
            "issue_severity": "UNKNOWN",
            "issue_confidence": "UNKNOWN",
            "issue_cwe": {},
            "issue_text": (
                "Security vulnerability reported at "
                f"{request.file_path}:{request.line}"
            ),
            "filename": request.file_path,
            "line_number": request.line,
        }

    # ---------------------------------------------------------
    # RAG context
    # ---------------------------------------------------------

    rag = get_rag(repo)

    try:

        retrieved = rag.query(
            finding_query(
                finding,
                function.get("code", ""),
            ),
            6,
            repo=repo,
        )

        context = format_context(
            retrieved
        )

    except Exception:

        context = (
            "(No semantic repository context "
            "was retrieved.)"
        )

    # ---------------------------------------------------------
    # SECURITY REVIEW PROMPT
    # ---------------------------------------------------------

    prompt = f"""
You are SecurePatch's AI Security Reviewer.

Your job is ONLY to REVIEW the proposed patch.

You are NOT a patch generator.

Do NOT modify, rewrite, or regenerate the patch.

============================================================
ORIGINAL SECURITY FINDING
============================================================

{json.dumps(finding, indent=2)}

============================================================
ORIGINAL FUNCTION
============================================================

{function.get("code", "")}

============================================================
PROPOSED PATCH
============================================================

{request.patch}

============================================================
REPOSITORY CONTEXT
============================================================

{context}

============================================================
REVIEW INSTRUCTIONS
============================================================

Evaluate the proposed patch for:

1. Whether it addresses the reported security vulnerability.

2. Whether the security control is actually effective.

3. Whether the patch introduces a new security vulnerability.

4. Whether the patch preserves the original function's
   intended behavior.

5. Whether the patch introduces functional risks.

6. Whether the patch uses undefined functions,
   variables, attributes, or APIs.

7. Whether the patch changes behavior beyond what is
   necessary to fix the vulnerability.

8. Whether command execution, file access, SQL queries,
   deserialization, dynamic execution, or other
   security-sensitive operations remain unsafe.

IMPORTANT:

- Do NOT generate a replacement patch.
- Do NOT include Python code in the response.
- Do NOT suggest a new implementation.
- Do NOT claim pytest passed.
- Do NOT claim Bandit passed.
- Do NOT claim the patch is verified.
- The SecurePatch validation pipeline is the final authority.

============================================================
OUTPUT FORMAT
============================================================

Return ONLY valid JSON.

Use EXACTLY these four keys:

{{
  "approved": true,
  "security_risks": [],
  "functional_risks": [],
  "recommendation": "..."
}}

Rules:

- "approved" must be a JSON boolean.
- "security_risks" must be a JSON array of strings.
- "functional_risks" must be a JSON array of strings.
- "recommendation" must be a single concise string.
- No markdown.
- No code fences.
- No Python code.
- No additional keys.
""".strip()

    # ---------------------------------------------------------
    # Generate review
    # ---------------------------------------------------------

    try:

        result = generate_llm(
            prompt,
            model=request.model or "qwen2.5-coder",
        )

    except Exception as exc:

        raise HTTPException(
            status_code=502,
            detail=f"AI review failed: {exc}",
        )

    # ---------------------------------------------------------
    # Clean common markdown fences from model output
    # ---------------------------------------------------------

    review_text = (
        result.text or ""
    ).strip()

    if review_text.startswith("```"):

        review_text = (
            review_text
            .replace("```json", "", 1)
            .replace("```", "", 1)
            .strip()
        )

        if review_text.endswith("```"):
            review_text = review_text[:-3].strip()

    # ---------------------------------------------------------
    # Validate that the model returned JSON
    # ---------------------------------------------------------

    try:

        review_data = json.loads(
            review_text
        )

        # Ensure the expected structure exists.
        approved = review_data.get(
            "approved"
        )

        security_risks = review_data.get(
            "security_risks"
        )

        functional_risks = review_data.get(
            "functional_risks"
        )

        recommendation = review_data.get(
            "recommendation"
        )

        if not isinstance(
            approved,
            bool,
        ):
            raise ValueError(
                "approved must be boolean"
            )

        if not isinstance(
            security_risks,
            list,
        ):
            raise ValueError(
                "security_risks must be a list"
            )

        if not isinstance(
            functional_risks,
            list,
        ):
            raise ValueError(
                "functional_risks must be a list"
            )

        if not isinstance(
            recommendation,
            str,
        ):
            raise ValueError(
                "recommendation must be a string"
            )

        review_data = {
            "approved": approved,
            "security_risks": security_risks,
            "functional_risks": functional_risks,
            "recommendation": recommendation,
        }

    except Exception:

        # Do not pretend malformed model output is a valid approval.
        review_data = {
            "approved": False,
            "security_risks": [
                "AI reviewer returned invalid JSON."
            ],
            "functional_risks": [],
            "recommendation": (
                "Manual review required because "
                "the AI reviewer did not return "
                "the required structured format."
            ),
        }

    # ---------------------------------------------------------
    # Return structured review
    # ---------------------------------------------------------

    return {
        "provider": result.provider,
        "model": result.model,
        "latency_ms": result.latency_ms,
        "review": review_data,
    }


@app.post("/api/ai/compare")
def ai_compare(request: AICompareRequest):
    repo = resolve_repo(request.repo_path)
    file_path = resolve_file(request.repo_path, request.file_path)
    finding = get_finding(request.repo_path, request.file_path, request.line)
    analysis = analyze_python_file(file_path, request.line)
    function = analysis.get("affected_function")
    if not function:
        raise HTTPException(status_code=400, detail="Could not identify affected function.")
    graph = build_graph(repo)
    impact = graph_impact(
        graph,
        file_path.relative_to(repo).as_posix(),
        function["name"],
    )
    rag = get_rag(repo)
    retrieved = rag.query(
        finding_query(finding, function.get("code", "")), 6, repo=repo
    )
    context = format_context(retrieved)
    prompt = build_ai_repair_prompt(
        finding, analysis, graph, impact, context
    )
    models = request.models or list(MODEL_REGISTRY.keys())
    results = []
    for model_key in models:
        try:
            result = generate_llm(prompt, model=model_key)
            patch = normalize_function_output(result.text, function["name"])
            results.append({
                "provider": result.provider,
                "model": result.model,
                "patch": patch,
                "latency_ms": result.latency_ms,
                "input_tokens": result.input_tokens,
                "output_tokens": result.output_tokens,
                "error": None,
            })
        except Exception as exc:
            results.append({
                "provider": "ollama",
                "model": MODEL_REGISTRY.get(model_key, model_key),
                "patch": None,
                "latency_ms": None,
                "input_tokens": None,
                "output_tokens": None,
                "error": str(exc),
            })
    return {
        "finding": finding,
        "retrieved": retrieved,
        "results": results,
        "comparison_note": "All configured Ollama models received the same repair prompt and repository context. Validation is performed separately through the existing sandbox pipeline.",
    }
