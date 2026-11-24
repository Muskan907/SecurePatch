"""Semgrep as a second SAST engine next to Bandit.

Bandit matches risky *patterns*; Semgrep adds *data-flow* rules (e.g.
request data reaching an SQL string or render_template_string). Semgrep
findings are converted to the same shape as Bandit findings so the whole
SecurePatch pipeline (analysis, AI repair, validation) works on them.

Semgrep is installed in its own environment (it pins library versions
that conflict with ChromaDB), found via SEMGREP_BIN, ./.tools/semgrep or
PATH. Rules are cached in one Python-only file (SEMGREP_RULES), built from
the Semgrep registry packs p/default, p/python and p/flask, so scans work
offline after the first download.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
from pathlib import Path
from typing import Optional

import requests
import yaml

PROJECT_ROOT = Path(__file__).resolve().parent.parent
TOOLS_DIR = PROJECT_ROOT / ".tools"
RULE_PACKS = ("default", "python", "flask")
SCAN_TIMEOUT = int(os.getenv("SEMGREP_TIMEOUT", "300"))

SEVERITY_MAP = {"ERROR": "HIGH", "WARNING": "MEDIUM", "INFO": "LOW"}


class SemgrepUnavailable(Exception):
    pass


# =========================================================
# Locating the binary and rules
# =========================================================


def semgrep_bin() -> Optional[str]:
    candidates = [
        os.getenv("SEMGREP_BIN"),
        TOOLS_DIR / "semgrep" / "Scripts" / "semgrep.exe",
        TOOLS_DIR / "semgrep" / "bin" / "semgrep",
        shutil.which("semgrep"),
    ]
    for candidate in candidates:
        if candidate and Path(candidate).is_file():
            return str(candidate)
    return None


def rules_path() -> Path:
    return Path(os.getenv("SEMGREP_RULES") or TOOLS_DIR / "python-rules.yml")


def build_rules(destination: Optional[Path] = None, session=None) -> Path:
    """Download registry packs and keep only Python rules in one file."""

    destination = destination or rules_path()
    session = session or requests.Session()
    rules: dict[str, dict] = {}
    for pack in RULE_PACKS:
        response = session.get(f"https://semgrep.dev/c/p/{pack}", timeout=60)
        response.raise_for_status()
        for rule in yaml.safe_load(response.text).get("rules", []):
            languages = [str(lang).lower() for lang in rule.get("languages", [])]
            if "python" in languages:
                rules[rule["id"]] = rule
    if not rules:
        raise SemgrepUnavailable("No Python rules downloaded from the Semgrep registry.")
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(
        yaml.safe_dump({"rules": list(rules.values())}, sort_keys=False),
        encoding="utf-8",
    )
    return destination


def ensure_rules() -> Path:
    path = rules_path()
    if not path.is_file():
        try:
            build_rules(path)
        except Exception as exc:  # network down, registry change...
            raise SemgrepUnavailable(f"Semgrep rules unavailable: {exc}") from exc
    return path


def status() -> dict:
    binary = semgrep_bin()
    return {
        "available": bool(binary),
        "binary": binary,
        "rules_cached": rules_path().is_file(),
    }


# =========================================================
# Running and normalising
# =========================================================


def short_id(check_id: str) -> str:
    return "SG-" + check_id.rsplit(".", 1)[-1]


def _cwe_id(metadata: dict) -> Optional[int]:
    cwe = metadata.get("cwe")
    if isinstance(cwe, list):
        cwe = cwe[0] if cwe else None
    match = re.search(r"CWE-(\d+)", str(cwe or ""))
    return int(match.group(1)) if match else None


def _code(path: Path, start: int, end: int) -> str:
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return ""
    first = max(start - 1, 1)
    return "\n".join(
        f"{n} {lines[n - 1]}" for n in range(first, min(end + 1, len(lines)) + 1)
    )


def normalize(result: dict) -> dict:
    """Convert one Semgrep result into a Bandit-shaped finding."""

    extra = result.get("extra", {})
    metadata = extra.get("metadata", {}) or {}
    path = Path(result["path"]).resolve()
    start = result["start"]["line"]
    end = result["end"]["line"]
    cwe = _cwe_id(metadata)
    return {
        "source": "semgrep",
        "test_id": short_id(result["check_id"]),
        "test_name": result["check_id"].rsplit(".", 1)[-1].replace("-", "_"),
        "rule_id": result["check_id"],
        "filename": str(path),
        "line_number": start,
        "line_range": list(range(start, end + 1)),
        "col_offset": result["start"].get("col", 1) - 1,
        "issue_severity": SEVERITY_MAP.get(extra.get("severity", ""), "MEDIUM"),
        "issue_confidence": str(metadata.get("confidence") or "MEDIUM").upper(),
        "issue_cwe": {"id": cwe, "link": f"https://cwe.mitre.org/data/definitions/{cwe}.html"} if cwe else {},
        "issue_text": extra.get("message", "").strip(),
        "code": _code(path, start, end),
        "more_info": metadata.get("shortlink") or metadata.get("source") or "https://semgrep.dev/r",
        "owasp": metadata.get("owasp") or [],
        "bandit_equivalent": metadata.get("bandit-code"),
    }


def run_semgrep(paths: list[Path], timeout: int = SCAN_TIMEOUT) -> dict:
    """Scan files/directories. Returns {'findings': [...], 'errors': [...]}."""

    binary = semgrep_bin()
    if not binary:
        raise SemgrepUnavailable(
            "Semgrep is not installed (see docs/devops.md: Semgrep setup)."
        )
    rules = ensure_rules()
    command = [
        binary, "scan",
        "--config", str(rules),
        "--metrics=off",
        "--disable-version-check",
        "--json", "--quiet",
        *[str(p) for p in paths],
    ]
    env = {**os.environ, "SEMGREP_SEND_METRICS": "off", "PYTHONIOENCODING": "utf-8"}
    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            env=env,
            stdin=subprocess.DEVNULL,
        )
    except subprocess.TimeoutExpired as exc:
        raise SemgrepUnavailable(f"Semgrep timed out after {timeout}s.") from exc
    try:
        data = json.loads(completed.stdout or "{}")
    except json.JSONDecodeError as exc:
        raise SemgrepUnavailable(
            f"Semgrep returned invalid output: {completed.stderr.strip()[-300:]}"
        ) from exc
    return {
        "findings": [normalize(r) for r in data.get("results", [])],
        "errors": [e.get("message", "")[:300] for e in data.get("errors", [])],
    }


# =========================================================
# Combining with Bandit
# =========================================================


def _same_place(a: dict, b: dict, tolerance: int = 2) -> bool:
    return (
        Path(a["filename"]).resolve() == Path(b["filename"]).resolve()
        and abs(int(a["line_number"]) - int(b["line_number"])) <= tolerance
    )


# Semgrep rules that report the same problem as a Bandit test.
EQUIVALENT_BANDIT = {
    "eval-detected": {"B307"},
    "exec-detected": {"B102"},
    "avoid-pyyaml-load": {"B506"},
    "avoid-pickle": {"B301", "B403"},
    "avoid-cPickle": {"B301", "B403"},
    "insecure-deserialization": {"B301", "B506"},
    "insecure-hash-algorithm-md5": {"B303", "B324"},
    "insecure-hash-algorithm-sha1": {"B303", "B324"},
    "md5-used-as-password": {"B303", "B324"},
    "subprocess-shell-true": {"B602", "B604"},
    "dangerous-system-call": {"B605"},
    "tarfile-extractall-traversal": {"B202"},
    "sqlalchemy-execute-raw-query": {"B608"},
    "formatted-sql-query": {"B608"},
    "tainted-sql-string": {"B608"},
    "debug-enabled": {"B201"},
    "avoid_hardcoded_config_SECRET_KEY": {"B105"},
    "disabled-cert-validation": {"B501"},
    "request-session-with-http": {"B113"},
    "use-defused-xml": {"B314", "B405"},
    "insecure-temp-file": {"B108", "B306"},
}


def _same_issue(bandit: dict, semgrep: dict) -> bool:
    if semgrep.get("bandit_equivalent") == bandit.get("test_id"):
        return True
    rule = semgrep.get("test_id", "").removeprefix("SG-")
    if bandit.get("test_id") in EQUIVALENT_BANDIT.get(rule, set()):
        return True
    bandit_cwe = (bandit.get("issue_cwe") or {}).get("id")
    semgrep_cwe = (semgrep.get("issue_cwe") or {}).get("id")
    return bool(bandit_cwe and bandit_cwe == semgrep_cwe)


def merge(bandit_findings: list[dict], semgrep_findings: list[dict]) -> list[dict]:
    """Bandit findings (marked when Semgrep agrees) + Semgrep-only findings."""

    merged = [{**f, "source": "bandit", "confirmed_by": []} for f in bandit_findings]
    for sg in semgrep_findings:
        # Tools report different lines of one issue (e.g. Bandit flags the
        # SQL string, Semgrep the execute() call), so allow a small window.
        match = next(
            (
                b for b in merged
                if b["source"] == "bandit"
                and _same_place(b, sg, tolerance=6)
                and _same_issue(b, sg)
            ),
            None,
        )
        if match is not None:
            if "semgrep" not in match["confirmed_by"]:
                match["confirmed_by"].append("semgrep")
            match.setdefault("semgrep_rules", []).append(sg["rule_id"])
        else:
            merged.append({**sg, "confirmed_by": []})
    return merged


# =========================================================
# Per-repository cache (lets later API calls find Semgrep findings)
# =========================================================


def _cache_file(repo: Path, cache_root: Path) -> Path:
    key = hashlib.sha256(str(repo.resolve()).encode("utf-8")).hexdigest()[:16]
    return cache_root / f"{key}.json"


def save_cache(repo: Path, findings: list[dict], cache_root: Path) -> None:
    cache_root.mkdir(parents=True, exist_ok=True)
    _cache_file(repo, cache_root).write_text(json.dumps(findings), encoding="utf-8")


def load_cache(repo: Path, cache_root: Path) -> list[dict]:
    try:
        return json.loads(_cache_file(repo, cache_root).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return []


def find_in(findings: list[dict], file_path: Path, line: int, exact: bool) -> Optional[dict]:
    target = file_path.resolve()
    same_file = [f for f in findings if Path(f["filename"]).resolve() == target]
    if exact:
        return next((f for f in same_file if f["line_number"] == line), None)
    if not same_file:
        return None
    return min(same_file, key=lambda f: abs(int(f["line_number"]) - int(line)))
