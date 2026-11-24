"""
SecurePatch reproducible experiment runner (v2).

Every experiment = method x dataset x vulnerability x seed. Each run is
appended to workspace/experiments/v2/runs.jsonl immediately, so the script
can be stopped at any time and resumed: finished runs are skipped.

Sessions (run from the project root, backend running WITHOUT --reload):

    python run_experiments.py --session A     # main model comparison + rule baseline
    python run_experiments.py --session C     # ablations, plain-LLM baseline, external repo
    python run_experiments.py --session codestral   # optional, needs ~11 GB free RAM
    python run_experiments.py --list          # show all experiments and progress

Then:
    python judge_patches.py                    # LLM-as-judge on every generated patch
    python analyze_experiments.py              # tables + figures for the report
"""
from __future__ import annotations

import argparse
import ast
import json
import platform
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

import requests

ROOT = Path(__file__).resolve().parent
OUT = ROOT / "workspace" / "experiments" / "v2"
RUNS_FILE = OUT / "runs.jsonl"
ENV_FILE = OUT / "environment.json"

API = "http://127.0.0.1:8000"
SEEDS = [11, 22, 33]
TEMPERATURE = 0.2
ABLATION_MODEL = "llama3.1"      # fixed before the runs (best model in the earlier study)
DEFAULT_MODEL = "qwen2.5-coder"  # SecurePatch's default model, first in the fallback chain

# ---------------------------------------------------------------------------
# Datasets
# ---------------------------------------------------------------------------
DATASETS = {
    "D1": {
        "name": "sample_repo (synthetic benchmark)",
        "repo": "sample_repo",
        "source": "Written by the SecurePatch team; 10 planted vulnerabilities, 19 pytest regression tests",
        "vulns": [
            ("B102", "benchmark_vulnerabilities.py", 30, "MEDIUM"),
            ("B105", "benchmark_vulnerabilities.py", 111, "LOW"),
            ("B108", "benchmark_vulnerabilities.py", 97, "MEDIUM"),
            ("B202", "benchmark_vulnerabilities.py", 86, "HIGH"),
            ("B301", "services/file_service.py", 33, "MEDIUM"),
            ("B307", "benchmark_vulnerabilities.py", 21, "MEDIUM"),
            ("B324", "benchmark_vulnerabilities.py", 40, "HIGH"),
            ("B506", "benchmark_vulnerabilities.py", 51, "MEDIUM"),
            ("B602", "services/command_service.py", 18, "HIGH"),
            ("B608", "benchmark_vulnerabilities.py", 67, "MEDIUM"),
        ],
    },
    "D2": {
        "name": "OWASP PyGoat (external)",
        "repo": "workspace/repositories/OWASP_pygoat_2aa4cc14",
        "source": ("https://github.com/adeyosemanputra/pygoat (OWASP project) commit "
                   "2aa4cc14f251e4a780e94e200aed6b36a5b15c21 (2026-11-01); third-party code, "
                   "no tests cover the vulnerable lab code"),
        "vulns": [
            ("B602", "dockerized_labs/command_injection_lab/app.py", 30, "HIGH"),
            ("B324", "dockerized_labs/broken_auth_lab/app.py", 103, "HIGH"),
            ("B324", "dockerized_labs/crypto_failure_lab/app.py", 25, "HIGH"),
            ("B307", "dockerized_labs/command_injection_lab/app.py", 49, "MEDIUM"),
            ("B506", "dockerized_labs/a9_uckv_lab/app.py", 62, "MEDIUM"),
            ("B301", "dockerized_labs/insec_des_lab/main.py", 40, "MEDIUM"),
            ("B301", "dockerized_labs/software_integrity_lab/app.py", 44, "MEDIUM"),
            ("B608", "dockerized_labs/sql_injection_lab/app.py", 51, "MEDIUM"),
            ("B113", "dockerized_labs/ssrf_lab/app.py", 37, "MEDIUM"),
            ("B317", "dockerized_labs/xxe_lab/app.py", 57, "MEDIUM"),
        ],
    },
}

# ---------------------------------------------------------------------------
# Experiments
# ---------------------------------------------------------------------------
LLM_FULL = {"use_rag": True, "prompt_mode": "full", "fallback": False}

EXPERIMENTS = {
    # Main comparison: each model alone with the full SecurePatch pipeline.
    "qwen_full":      {"session": "A", "dataset": "D1", "method": "llm", "model": "qwen2.5-coder", **LLM_FULL,
                       "label": "SecurePatch + Qwen2.5-Coder 7B", "role": "method"},
    "llama_full":     {"session": "A", "dataset": "D1", "method": "llm", "model": "llama3.1", **LLM_FULL,
                       "label": "SecurePatch + Llama 3.1 8B", "role": "method"},
    "rule_d1":        {"session": "A", "dataset": "D1", "method": "rule",
                       "label": "Rule-based fixer (baseline)", "role": "baseline"},
    # Baseline: the same LLM asked directly (no RAG, graph, AST context).
    "plain_llm_d1":   {"session": "C", "dataset": "D1", "method": "llm", "model": ABLATION_MODEL,
                       "use_rag": False, "prompt_mode": "plain", "fallback": False,
                       "label": "Plain LLM, Llama 3.1 8B (baseline)", "role": "baseline"},
    # Ablations (one component removed / added at a time).
    "ablation_no_rag": {"session": "C", "dataset": "D1", "method": "llm", "model": ABLATION_MODEL,
                        "use_rag": False, "prompt_mode": "full", "fallback": False,
                        "label": "SecurePatch + Llama, without RAG", "role": "ablation"},
    # Trend: number of retrieved RAG chunks k. k=0 is ablation_no_rag and
    # k=6 (the default) is llama_full, so only k=3 needs extra runs.
    "topk_3":         {"session": "C", "dataset": "D1", "method": "llm", "model": ABLATION_MODEL, **LLM_FULL,
                       "rag_top_k": 3, "label": "SecurePatch + Llama, RAG k=3", "role": "ablation"},
    "fallback_full":  {"session": "C", "dataset": "D1", "method": "llm", "model": DEFAULT_MODEL,
                       "use_rag": True, "prompt_mode": "full", "fallback": True,
                       "fallback_models": ["llama3.1", "qwen2.5-1.5b", "phi3-mini"],
                       "label": "SecurePatch full system (Qwen -> fallback chain)", "role": "ablation"},
    # External validation.
    "llama_full_d2":  {"session": "C", "dataset": "D2", "method": "llm", "model": ABLATION_MODEL, **LLM_FULL,
                       "label": "SecurePatch + Llama 3.1 8B", "role": "method"},
    "plain_llm_d2":   {"session": "C", "dataset": "D2", "method": "llm", "model": ABLATION_MODEL,
                       "use_rag": False, "prompt_mode": "plain", "fallback": False,
                       "label": "Plain LLM, Llama 3.1 8B (baseline)", "role": "baseline"},
    "rule_d2":        {"session": "C", "dataset": "D2", "method": "rule",
                       "label": "Rule-based fixer (baseline)", "role": "baseline"},
    # Optional: needs more RAM than a 16 GB laptop usually has free.
    "codestral_full": {"session": "codestral", "dataset": "D1", "method": "llm", "model": "codestral", **LLM_FULL,
                       "label": "SecurePatch + Codestral 22B", "role": "method"},
}


class BackendDown(RuntimeError):
    """The SecurePatch backend itself is unreachable: stop, do not record."""


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def post(session: requests.Session, endpoint: str, payload: dict, timeout: int = 1800):
    started = time.perf_counter()
    try:
        response = session.post(f"{API}{endpoint}", json=payload, timeout=timeout)
    except requests.ConnectionError as exc:
        raise BackendDown(f"Backend not reachable at {API}: {exc}") from exc
    elapsed = time.perf_counter() - started
    try:
        data = response.json()
    except ValueError:
        data = {"detail": response.text[:3000]}
    if not response.ok:
        raise RuntimeError(f"{endpoint} HTTP {response.status_code}: {data.get('detail', data)}")
    return data, elapsed


def load_runs() -> list[dict]:
    if not RUNS_FILE.exists():
        return []
    rows = []
    for line in RUNS_FILE.read_text(encoding="utf-8").splitlines():
        if line.strip():
            rows.append(json.loads(line))
    return rows


def run_key(exp: str, vuln_id: str, seed: int) -> str:
    return f"{exp}|{vuln_id}|{seed}"


def vuln_id(v) -> str:
    rule, file, line, _ = v
    return f"{rule}@{file}:{line}"


def function_at(source: str, line: int) -> str | None:
    tree = ast.parse(source)
    best = None
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.lineno <= line <= node.end_lineno:
            if best is None or node.lineno > best.lineno:
                best = node
    if best is None:
        return None
    lines = source.splitlines()
    start = best.lineno - 1
    if best.decorator_list:
        start = min(d.lineno for d in best.decorator_list) - 1
    import textwrap
    return textwrap.dedent("\n".join(lines[start:best.end_lineno]))


def rule_patch(repo: Path, file: str, rule: str, line: int) -> str | None:
    """Rule-based fixer: regex rewrite of the file, return the patched function."""
    sys.path.insert(0, str(ROOT))
    from run_rule_baseline import generate_rule_patch  # noqa: E402

    source = (repo / file).read_text(encoding="utf-8")
    original_fn = function_at(source, line)
    if original_fn is None:
        return None
    # Apply the regex rules to the vulnerable function only (not the first
    # match anywhere in the file), the same unit the LLM methods repair.
    patched_fn, generated = generate_rule_patch(rule, original_fn)
    if not generated or patched_fn.strip() == original_fn.strip():
        return None
    return patched_fn


def collect_environment(session: requests.Session) -> dict:
    env: dict[str, Any] = {"collected_at": time.strftime("%Y-%m-%dT%H:%M:%S")}
    try:
        env["backend"] = session.get(f"{API}/api/experiment/environment", timeout=30).json()
    except Exception as exc:  # noqa: BLE001
        env["backend_error"] = str(exc)
    env["runner"] = {"python": platform.python_version(), "seeds": SEEDS, "temperature": TEMPERATURE,
                     "ablation_model": ABLATION_MODEL, "default_model": DEFAULT_MODEL}
    if platform.system() == "Windows":
        ps = ("$c=Get-CimInstance Win32_Processor | Select-Object -First 1;"
              "$m=Get-CimInstance Win32_ComputerSystem;"
              "$g=(Get-CimInstance Win32_VideoController | ForEach-Object {$_.Name}) -join '; ';"
              "Write-Output ($c.Name + '|' + [math]::Round($m.TotalPhysicalMemory/1GB,1) + '|' + $g)")
        try:
            out = subprocess.run(["powershell", "-NoProfile", "-Command", ps],
                                 capture_output=True, text=True, timeout=30).stdout.strip()
            cpu, ram, gpu = out.split("|", 2)
            env["hardware"] = {"cpu": cpu.strip(), "ram_gb": float(ram), "gpu": gpu.strip(),
                               "os": platform.platform()}
        except Exception as exc:  # noqa: BLE001
            env["hardware_error"] = str(exc)
    return env


# ---------------------------------------------------------------------------
# One run
# ---------------------------------------------------------------------------
def run_one(session, exp_name: str, exp: dict, v, seed: int) -> dict:
    ds = DATASETS[exp["dataset"]]
    rule, file, line, severity = v
    row: dict[str, Any] = {
        "key": run_key(exp_name, vuln_id(v), seed),
        "experiment": exp_name, "label": exp["label"], "role": exp["role"],
        "dataset": exp["dataset"], "method": exp["method"], "model": exp.get("model"),
        "use_rag": exp.get("use_rag"), "prompt_mode": exp.get("prompt_mode"),
        "fallback": exp.get("fallback"), "seed": seed,
        "temperature": TEMPERATURE if exp["method"] == "llm" else None,
        "vulnerability": rule, "vuln_id": vuln_id(v), "severity": severity,
        "file": file, "line": line, "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "patch_generated": False, "syntax_valid": False, "vulnerability_removed": False,
        "regression_passed": False, "verdict": "ERROR", "error": None,
        "generation_seconds": None, "validation_seconds": None,
    }
    patch = None
    try:
        if exp["method"] == "rule":
            t0 = time.perf_counter()
            patch = rule_patch(ROOT / ds["repo"], file, rule, line)
            row["generation_seconds"] = round(time.perf_counter() - t0, 3)
            if not patch:
                row["verdict"] = "NO_PATCH"
                row["error"] = "Rule-based fixer has no rule for this finding."
                return row
        else:
            payload = {
                "repo_path": ds["repo"], "file_path": file, "line": line,
                "model": exp["model"], "use_rag": exp["use_rag"], "prompt_mode": exp["prompt_mode"],
                "fallback": exp["fallback"], "fallback_models": exp.get("fallback_models"),
                "seed": seed, "temperature": TEMPERATURE, "rag_top_k": exp.get("rag_top_k"),
            }
            gen, elapsed = post(session, "/api/generate-patch", payload)
            meta = gen.get("patch") or {}
            patch = meta.get("function") or meta.get("patch") or ""
            finding = gen.get("finding") or {}
            row.update({
                "generation_seconds": round(elapsed, 2),
                "llm_seconds": round((meta.get("latency_ms") or 0) / 1000, 2),
                "input_tokens": meta.get("input_tokens"), "output_tokens": meta.get("output_tokens"),
                "resolved_model": meta.get("model"), "attempts": meta.get("attempts"),
                "fallback_used": meta.get("fallback_used"), "settings": meta.get("settings"),
                "finding_rule": finding.get("test_id"),
            })
            if finding.get("test_id") and finding.get("test_id") != rule:
                row["warning"] = f"Backend resolved {finding.get('test_id')} instead of {rule}"
        row["patch_generated"] = bool(patch and patch.strip())
        row["patch_text"] = patch
        try:
            tree = ast.parse(patch)
            row["syntax_valid"] = sum(isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) for n in tree.body) == 1
        except SyntaxError:
            row["syntax_valid"] = False

        val, vel = post(session, "/api/validate",
                        {"repo_path": ds["repo"], "file_path": file, "line": line, "patch": patch})
        sec = val.get("security") or {}
        reg = val.get("regression") or {}
        row.update({
            "validation_seconds": round(vel, 2),
            "verdict": val.get("status") or "ERROR",
            "vulnerability_removed": bool(sec.get("target_removed")),
            "security_passed": bool(sec.get("passed")),
            "regression_passed": bool(reg.get("passed")),
            "tests_passed": reg.get("passed_count"), "tests_failed": reg.get("failed_count"),
            "test_errors": reg.get("error_count"),
            "new_findings": len(((val.get("comparison") or {}).get("introduced")) or []),
            "bandit_findings_after": sec.get("findings_after"),
            "semgrep_check": val.get("semgrep_check"),
            "reason": val.get("reason") or val.get("message")
                      or (None if sec.get("passed") else str(sec.get("output") or "")[:300]),
        })
    except BackendDown:
        raise
    except Exception as exc:  # noqa: BLE001 - recorded as a failed run
        text = str(exc)
        # Ollama could not load the model (laptop out of RAM): an environment
        # problem, not a model failure. Stop so it is not counted; resume later.
        if exp["method"] == "llm" and ("500 Server Error" in text or "out-of-memory" in text.lower()):
            raise BackendDown(
                "Ollama could not load the model (usually not enough free RAM). "
                "Close other apps (VS Code, browser, Docker) and run the same command again."
            ) from exc
        row["error"] = text[:2000]
        if row["verdict"] == "ERROR" and not row["patch_generated"]:
            row["verdict"] = "GENERATION_FAILED"
    return row


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def selected_experiments(args) -> list[str]:
    if args.experiment:
        return args.experiment
    return [name for name, e in EXPERIMENTS.items() if e["session"] == args.session]


def show_progress():
    done = {r["key"] for r in load_runs()}
    print(f"{'experiment':<18}{'session':<11}{'dataset':<8}{'done':>10}")
    for name, e in EXPERIMENTS.items():
        total = len(DATASETS[e["dataset"]]["vulns"]) * len(SEEDS)
        n = sum(1 for v in DATASETS[e["dataset"]]["vulns"] for s in SEEDS
                if run_key(name, vuln_id(v), s) in done)
        print(f"{name:<18}{e['session']:<11}{e['dataset']:<8}{n:>5}/{total}")


def main():
    global API
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--session", choices=["A", "C", "codestral"])
    parser.add_argument("--experiment", nargs="*", choices=list(EXPERIMENTS))
    parser.add_argument("--list", action="store_true")
    parser.add_argument("--api", default=API)
    parser.add_argument("--limit", type=int, default=None, help="Stop after N new runs (smoke test).")
    args = parser.parse_args()
    API = args.api.rstrip("/")

    if args.list:
        show_progress()
        return
    if not args.session and not args.experiment:
        parser.error("use --session A|C|codestral, --experiment NAME, or --list")

    OUT.mkdir(parents=True, exist_ok=True)
    session = requests.Session()
    try:
        session.get(f"{API}/api/health", timeout=30).raise_for_status()
    except Exception as exc:  # noqa: BLE001
        sys.exit(f"Backend not available at {API}: {exc}")

    # Environment snapshot (every session appends one).
    envs = json.loads(ENV_FILE.read_text(encoding="utf-8")) if ENV_FILE.exists() else []
    envs.append(collect_environment(session))
    ENV_FILE.write_text(json.dumps(envs, indent=2, default=str), encoding="utf-8")

    names = selected_experiments(args)
    done = {r["key"] for r in load_runs()}
    plan = []
    for name in names:
        e = EXPERIMENTS[name]
        for seed in SEEDS:  # model-major order keeps Ollama model swaps rare
            for v in DATASETS[e["dataset"]]["vulns"]:
                if run_key(name, vuln_id(v), seed) not in done:
                    plan.append((name, v, seed))
    if args.limit:
        plan = plan[: args.limit]

    # Scan each dataset once so Semgrep findings are cached for lookups.
    for ds_key in sorted({EXPERIMENTS[n]["dataset"] for n, _, _ in plan}):
        print(f"Scanning {DATASETS[ds_key]['repo']} (Bandit + Semgrep)...", flush=True)
        post(session, "/api/scan", {"repo_path": DATASETS[ds_key]["repo"], "semgrep": True}, timeout=900)

    print(f"{len(plan)} runs to do ({len(done)} already recorded). Results: {RUNS_FILE}\n")
    started = time.time()
    for i, (name, v, seed) in enumerate(plan, 1):
        eta = ""
        if i > 1:
            per = (time.time() - started) / (i - 1)
            eta = f"  ~{(len(plan) - i + 1) * per / 60:.0f} min left"
        print(f"[{i}/{len(plan)}] {name:<16} seed={seed} {vuln_id(v)}{eta}", flush=True)
        try:
            row = run_one(session, name, EXPERIMENTS[name], v, seed)
        except BackendDown as exc:
            sys.exit(f"\nSTOPPED: {exc}\nRestart the backend and run the same command again to resume.")
        with RUNS_FILE.open("a", encoding="utf-8") as f:
            f.write(json.dumps(row, default=str) + "\n")
        extra = f" ({row['error'][:120]})" if row.get("error") else ""
        print(f"        -> {row['verdict']}  removed={row['vulnerability_removed']} "
              f"tests={row['regression_passed']}{extra}", flush=True)

    print(f"\nDone in {(time.time() - started) / 60:.1f} min.")
    show_progress()


if __name__ == "__main__":
    main()
