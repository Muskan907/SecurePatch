from pathlib import Path

import pytest

import src.semgrep_scanner as sg

SAMPLE = Path(__file__).resolve().parent.parent / "sample_repo"
COMMAND_SERVICE = SAMPLE / "services" / "command_service.py"


def semgrep_result(path=COMMAND_SERVICE, line=18, check="python.lang.security.audit.subprocess-shell-true.subprocess-shell-true",
                   severity="ERROR", cwe="CWE-78: OS Command Injection", bandit=None):
    metadata = {"cwe": [cwe], "confidence": "HIGH", "shortlink": "https://sg.run/abc"}
    if bandit:
        metadata["bandit-code"] = bandit
    return {
        "check_id": check,
        "path": str(path),
        "start": {"line": line, "col": 16},
        "end": {"line": line, "col": 50},
        "extra": {"severity": severity, "message": "Found shell=True.", "metadata": metadata, "lines": "requires login"},
    }


def bandit_finding(test_id="B602", line=18, cwe=78, path=COMMAND_SERVICE):
    return {"test_id": test_id, "filename": str(path), "line_number": line,
            "issue_severity": "HIGH", "issue_cwe": {"id": cwe}}


def test_normalize_matches_bandit_shape():
    finding = sg.normalize(semgrep_result())
    assert finding["source"] == "semgrep"
    assert finding["test_id"] == "SG-subprocess-shell-true"
    assert finding["issue_severity"] == "HIGH"
    assert finding["issue_confidence"] == "HIGH"
    assert finding["issue_cwe"]["id"] == 78
    assert finding["line_number"] == 18
    # Code is read from the file because Semgrep hides it without login.
    assert "shell=True" in finding["code"]
    assert finding["more_info"] == "https://sg.run/abc"


@pytest.mark.parametrize("severity, expected", [("ERROR", "HIGH"), ("WARNING", "MEDIUM"), ("INFO", "LOW")])
def test_severity_mapping(severity, expected):
    assert sg.normalize(semgrep_result(severity=severity))["issue_severity"] == expected


def test_merge_marks_bandit_finding_confirmed():
    merged = sg.merge([bandit_finding()], [sg.normalize(semgrep_result())])
    assert len(merged) == 1
    assert merged[0]["source"] == "bandit"
    assert merged[0]["confirmed_by"] == ["semgrep"]


def test_merge_keeps_semgrep_only_findings():
    other = sg.normalize(semgrep_result(line=5, check="x.tainted-sql-string", cwe="CWE-89: SQL Injection"))
    merged = sg.merge([bandit_finding()], [other])
    assert [f["source"] for f in merged] == ["bandit", "semgrep"]
    assert merged[0]["confirmed_by"] == []


def test_merge_uses_bandit_code_metadata():
    # Different CWE, but Semgrep says it is the same Bandit rule.
    result = semgrep_result(cwe="CWE-1: x", bandit="B602")
    merged = sg.merge([bandit_finding()], [sg.normalize(result)])
    assert len(merged) == 1 and merged[0]["confirmed_by"] == ["semgrep"]


def test_cache_roundtrip_and_lookup(tmp_path):
    finding = sg.normalize(semgrep_result())
    sg.save_cache(SAMPLE, [finding], tmp_path)
    cached = sg.load_cache(SAMPLE, tmp_path)
    assert sg.find_in(cached, COMMAND_SERVICE, 18, exact=True)["test_id"] == finding["test_id"]
    assert sg.find_in(cached, COMMAND_SERVICE, 17, exact=True) is None
    assert sg.find_in(cached, COMMAND_SERVICE, 17, exact=False) is not None
    assert sg.load_cache(tmp_path, tmp_path) == []


def test_unavailable_without_binary(monkeypatch):
    monkeypatch.setattr(sg, "semgrep_bin", lambda: None)
    with pytest.raises(sg.SemgrepUnavailable):
        sg.run_semgrep([COMMAND_SERVICE])


@pytest.mark.skipif(
    not (sg.semgrep_bin() and sg.rules_path().is_file()),
    reason="Semgrep or its cached rules are not installed",
)
def test_real_semgrep_finds_shell_true():
    result = sg.run_semgrep([COMMAND_SERVICE])
    ids = {f["test_id"] for f in result["findings"]}
    assert "SG-subprocess-shell-true" in ids


def test_merge_never_confirms_semgrep_with_semgrep():
    a = sg.normalize(semgrep_result(check="x.raw-html-format", cwe="CWE-79: XSS"))
    b = sg.normalize(semgrep_result(check="x.dangerous-template-string", cwe="CWE-79: XSS"))
    merged = sg.merge([], [a, b])
    assert len(merged) == 2
    assert all(f["confirmed_by"] == [] for f in merged)


def test_function_span_limits_target_check(tmp_path):
    from backend.main import function_span

    source = tmp_path / "m.py"
    source.write_text("def a():\n    return 1\n\n\n@dec\ndef b():\n    x = 1\n    return x\n")
    assert function_span(source, "b") == (5, 8)
    assert function_span(source, "missing") is None
