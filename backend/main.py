from fastapi import FastAPI, HTTPException, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pydantic import BaseModel
from urllib.parse import urlparse
import ast
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import sys
import time
import textwrap
import uuid
import zipfile

try:
    from dotenv import load_dotenv
    load_dotenv()
except Exception:
    pass
from src.llm_adapter import (
    generate as generate_llm,
    configured_models,
    MODEL_REGISTRY,
    ollama_is_available,
    installed_models,
)
from src.repository_rag import RepositoryRAG, format_context

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
    allow_origins=[
        "http://localhost:5173",
        "http://localhost:5174",
        "http://localhost:5175",
        "http://127.0.0.1:5173",
        "http://127.0.0.1:5174",
        "http://127.0.0.1:5175",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# =========================================================
# PATHS / STATE

# =========================================================
PROJECT_ROOT = Path(__file__).resolve().parent.parent
SANDBOX_ROOT = PROJECT_ROOT / "workspace" / "sandbox_repo"
REPOSITORY_ROOT = PROJECT_ROOT / "workspace" / "repositories"
# Persistent validation state.
# This survives Uvicorn --reload, unlike LAST_VALIDATION_STATUS.
VALIDATION_MARKER = PROJECT_ROOT / "workspace" / "validation_status.json"
REPOSITORY_ROOT.mkdir(parents=True, exist_ok=True)
# Local demo state. For a multi-user deployment this should become
# per-repository/per-validation state instead of a global variable.
LAST_VALIDATION_STATUS = None

# =========================================================
# REQUEST MODELS

# =========================================================


class ScanRequest(BaseModel):
    repo_path: str = "sample_repo"


class AnalyzeRequest(BaseModel):
    repo_path: str = "sample_repo"
    file_path: str
    line: int


class PatchRequest(BaseModel):
    repo_path: str = "sample_repo"
    file_path: str
    line: int
    model: str | None = None


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
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError:
        return {
            "results": [],
            "errors": result.stderr,
        }


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
    data = run_bandit(str(resolve_repo(repo_path)))
    findings = data.get("results", [])
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
    function_by_id = {
        item["id"]: item
        for item in functions
    }
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
    """Run repository tests in an isolated Windows subprocess."""
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
            [sys.executable, "-m", "pytest", "tests", "-q"],
            cwd=str(sandbox),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            env=env,
            creationflags=creationflags,
            timeout=120,
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
                "Pytest timed out after 120 seconds.\n"
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

def run_security_validation(
    sandbox: Path,
    target_rule: str,
):
    data = run_bandit(str(sandbox))
    findings = data.get(
        "results",
        [],
    )
    target_findings = [
        finding
        for finding in findings
        if finding.get("test_id") == target_rule
    ]
    output_lines = [
        f"Total findings after patch: {len(findings)}",
        f"Target rule {target_rule}: "
        + (
            "FOUND"
            if target_findings
            else "REMOVED"
        ),
    ]
    return {
        "passed": len(target_findings) == 0,
        "target_removed": len(target_findings) == 0,
        "findings_after": len(findings),
        "target_findings": target_findings,
        "output": "\n".join(output_lines),
    }

# =========================================================
# REPOSITORY IMPORT

# =========================================================


@app.post("/api/repositories/github")
def import_github_repository(data: dict):
    url = data.get("url", "").strip()
    if not url:
        raise HTTPException(
            status_code=400,
            detail="GitHub repository URL is required.",
        )
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"}:
        raise HTTPException(
            status_code=400,
            detail="Invalid GitHub repository URL.",
        )
    if parsed.netloc.lower() not in {
        "github.com",
        "www.github.com",
    }:
        raise HTTPException(
            status_code=400,
            detail="Only GitHub repository URLs are currently supported.",
        )
    parts = parsed.path.strip("/").split("/")
    if len(parts) < 2:
        raise HTTPException(
            status_code=400,
            detail="Invalid GitHub repository URL.",
        )
    owner = parts[0]
    repo_name = parts[1]
    if repo_name.endswith(".git"):
        repo_name = repo_name[:-4]
    clean_url = (
        f"https://github.com/{owner}/{repo_name}.git"
    )
    repo_id = uuid.uuid4().hex[:8]
    destination = (
        REPOSITORY_ROOT
        / f"{owner}_{repo_name}_{repo_id}"
    )
    try:
        result = subprocess.run(
            [
                "git",
                "clone",
                "--depth",
                "1",
                clean_url,
                str(destination),
            ],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=120,
        )
        if result.returncode != 0:
            if destination.exists():
                shutil.rmtree(destination)
            raise HTTPException(
                status_code=400,
                detail=(
                    "Could not clone repository. "
                    + result.stderr[-1000:]
                ),
            )
    except subprocess.TimeoutExpired:
        if destination.exists():
            shutil.rmtree(destination)
        raise HTTPException(
            status_code=408,
            detail="Repository clone timed out.",
        )
    return {
        "success": True,
        "name": repo_name,
        "source": "github",
        "repo_path": str(destination),
        "message": "GitHub repository imported successfully.",
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
    return {
        "summary": finding_summary(findings),
        "findings": findings,
    }

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
            test_code = test_path.read_text(
                encoding="utf-8",
                errors="replace",
            )
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
    prompt = build_patch_prompt(
        finding,
        analysis,
        graph,
        impact,
    )
    try:
        rag = get_rag(repo)
        rag_query = finding_query(finding, function.get("code", ""))
        retrieved = rag.query(rag_query, 6, repo=repo)
        if not retrieved:
            rag.index(repo)
            retrieved = rag.query(rag_query, 6, repo=repo)
        retrieved_context = format_context(retrieved)
    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=f"Repository context retrieval failed: {exc}",
        )
    enriched_prompt = build_ai_repair_prompt(
        finding=finding,
        analysis=analysis,
        graph=graph,
        impact=impact,
        retrieved_context=retrieved_context,
    )
    try:
        llm_result = generate_llm(
            enriched_prompt,
            model=request.model or "qwen2.5-coder",
        )
        print("\n" + "=" * 80)
        print("RAW LLM RESPONSE")
        print("=" * 80)
        print(llm_result.text)
        print("=" * 80 + "\n")

        repaired_function = normalize_function_output(
            llm_result.text,
            function["name"],
        )
        validate_patch_guardrails(
            repaired_function,
            function["name"],
        )
    except Exception as exc:
        raise HTTPException(
            status_code=502,
            detail=f"LLM generation failed: {exc}",
        )
    patch = {
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
    regression = run_pytest(
        sandbox
    )
    security = run_security_validation(
        sandbox,
        finding.get("test_id"),
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
    }

# =========================================================
# AI / RAG MID-SEM FEATURES

# =========================================================
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
    related_tests = analysis.get("tests") or []
    return f"""
You are SecurePatch, a security-focused Python vulnerability repair engine.
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
VULNERABLE FUNCTION
{function.get("code", "")}
IMPORTS
{json.dumps(imports, indent=2)}
REPOSITORY IMPACT
Callers / connected functions:
{json.dumps(callers, indent=2)}
Related tests:
{json.dumps(related_tests, indent=2)}
SOURCE GRAPH SUMMARY
Files: {len(graph.get("files", []))}
Functions: {len(graph.get("functions", []))}
Nodes: {len(graph.get("nodes", []))}
Edges: {len(graph.get("edges", []))}
RETRIEVED REPOSITORY CONTEXT
{retrieved_context or "(No semantic context was supplied for this request.)"}
STRICT SECURITY REQUIREMENTS
1. Fix the reported vulnerability.
2. Preserve intended application behavior.
3. Make the smallest safe change.
4. Do not modify tests.
5. Do not modify unrelated code.
6. Do not introduce new vulnerabilities.
7. Do not invent imports or variables.
8. Keep the existing function signature unless a signature change is required for security.
9. Return ONLY the complete corrected Python function.
10. Return plain Python code, with no markdown fences and no explanation.
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
