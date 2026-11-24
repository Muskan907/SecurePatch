"""The Bandit re-scan must judge only the patched function.

The same rule firing elsewhere in the repository (e.g. another MD5 call)
must not turn a correct fix into "vulnerability still present".
"""
from pathlib import Path

from backend.main import run_security_validation

PATCHED = '''import hashlib


def fixed(data):
    return hashlib.sha256(data).hexdigest()


def untouched(data):
    return hashlib.md5(data).hexdigest()
'''

STILL_VULNERABLE = PATCHED.replace("hashlib.sha256(data)", "hashlib.md5(data)")


def write_repo(tmp_path: Path, code: str) -> Path:
    (tmp_path / "app.py").write_text(code, encoding="utf-8")
    (tmp_path / "other.py").write_text("import hashlib\nh = hashlib.md5(b'x')\n", encoding="utf-8")
    return tmp_path / "app.py"


def test_fix_counts_even_if_rule_fires_elsewhere(tmp_path):
    target = write_repo(tmp_path, PATCHED)
    result = run_security_validation(tmp_path, "B324", target, "fixed")
    assert result["target_removed"] is True
    assert result["same_rule_elsewhere"] == 2  # untouched() and other.py


def test_unfixed_function_is_still_reported(tmp_path):
    target = write_repo(tmp_path, STILL_VULNERABLE)
    result = run_security_validation(tmp_path, "B324", target, "fixed")
    assert result["target_removed"] is False
    assert len(result["target_findings"]) == 1


def test_repository_scope_without_target_is_unchanged(tmp_path):
    write_repo(tmp_path, PATCHED)
    result = run_security_validation(tmp_path, "B324")
    assert result["target_removed"] is False
