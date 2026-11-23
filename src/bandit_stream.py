"""Stream a Bandit scan file-by-file (used for the live scan terminal).

The result is identical to ``bandit -r <repo> -f json --skip B101``: the
same Bandit engine runs in-process, just in small batches so progress can
be streamed to the UI with Server-Sent Events.
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Iterator

from bandit.core import config as bandit_config
from bandit.core import docs_utils
from bandit.core import manager as bandit_manager

SKIPPED_TESTS = {"B101"}  # assert_used: noisy in test files
BATCH_SIZE = 4


def bandit_command(repo: Path) -> str:
    return f"bandit -r {repo} -f json --skip {','.join(sorted(SKIPPED_TESTS))}"


def _manager() -> bandit_manager.BanditManager:
    return bandit_manager.BanditManager(
        bandit_config.BanditConfig(),
        "file",
        profile={"include": set(), "exclude": set(SKIPPED_TESTS)},
    )


def discover_files(repo: Path) -> list[str]:
    mgr = _manager()
    mgr.discover_files([str(repo)], True)
    return list(mgr.files_list)


def _issue_dict(issue) -> dict:
    data = issue.as_dict()
    data["more_info"] = docs_utils.get_url(data["test_id"])
    return data


def iter_scan(repo: Path, batch_size: int = BATCH_SIZE) -> Iterator[dict]:
    """Yield progress events; the last one has type 'done' with all findings."""

    started = time.perf_counter()
    files = discover_files(repo)
    yield {
        "type": "start",
        "command": bandit_command(repo),
        "files": len(files),
        "message": f"Discovered {len(files)} Python files",
    }

    findings: list[dict] = []
    errors: list[dict] = []
    for start in range(0, len(files), batch_size):
        batch = files[start:start + batch_size]
        mgr = _manager()
        mgr.discover_files(batch, False)
        mgr.run_tests()
        issues = [_issue_dict(i) for i in mgr.get_issue_list()]
        errors.extend(
            {"filename": f, "reason": r} for f, r in mgr.skipped
        )
        by_file: dict[str, list[dict]] = {}
        for issue in issues:
            by_file.setdefault(issue["filename"], []).append(issue)
        for offset, filename in enumerate(batch):
            file_issues = by_file.get(filename, [])
            findings.extend(file_issues)
            yield {
                "type": "file",
                "index": start + offset + 1,
                "total": len(files),
                "file": _relative(filename, repo),
                "count": len(file_issues),
                "findings": [
                    {
                        "test_id": i["test_id"],
                        "severity": i["issue_severity"],
                        "line": i["line_number"],
                        "text": i["issue_text"],
                    }
                    for i in file_issues
                ],
            }

    yield {
        "type": "done",
        "findings": findings,
        "errors": errors,
        "duration_ms": int((time.perf_counter() - started) * 1000),
        "command": bandit_command(repo),
    }


def _relative(filename: str, repo: Path) -> str:
    try:
        return Path(filename).resolve().relative_to(repo.resolve()).as_posix()
    except ValueError:
        return filename


def sse(event: dict) -> str:
    return f"data: {json.dumps(event)}\n\n"
