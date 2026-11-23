from fastapi.testclient import TestClient

from backend.main import app
from src.bandit_catalog import RULES, catalog, compare_findings, explain


def test_every_rule_is_complete():
    for test_id, rule in RULES.items():
        assert rule["name"] and rule["why"] and rule["fix"], test_id
        assert rule["vulnerable"], test_id
        assert isinstance(rule["cwe"], int), test_id


def test_explain_known_rule_has_links():
    info = explain("B602")
    assert info["known"]
    assert info["cwe"] == 78
    assert info["cwe_url"].endswith("/78.html")
    assert info["docs_url"].startswith("https://bandit.readthedocs.io")
    assert "shell" in info["vulnerable"]


def test_explain_unknown_rule_falls_back_to_finding():
    info = explain(
        "B999",
        {"test_name": "made_up_rule", "issue_text": "something", "issue_cwe": {"id": 20}},
    )
    assert not info["known"]
    assert info["name"] == "made up rule"
    assert info["cwe"] == 20


def test_catalog_has_levels():
    data = catalog()
    assert set(data["severity_levels"]) == {"HIGH", "MEDIUM", "LOW"}
    assert set(data["confidence_levels"]) == {"HIGH", "MEDIUM", "LOW"}


def f(test_id, filename, line, severity="HIGH"):
    return {
        "test_id": test_id,
        "filename": filename,
        "line_number": line,
        "issue_severity": severity,
    }


def test_compare_findings(tmp_path):
    before_root, after_root = tmp_path / "repo", tmp_path / "sandbox"
    before = [
        f("B602", str(before_root / "a.py"), 10),
        f("B105", str(before_root / "a.py"), 3, "LOW"),
    ]
    # B602 fixed; B105 moved to a new line; a new B311 introduced.
    after = [
        f("B105", str(after_root / "a.py"), 5, "LOW"),
        f("B311", str(after_root / "a.py"), 12, "LOW"),
    ]
    result = compare_findings(before, after, before_root, after_root)
    assert [r["test_id"] for r in result["removed"]] == ["B602"]
    assert [r["test_id"] for r in result["introduced"]] == ["B311"]
    assert result["unchanged_count"] == 1
    assert result["before"] == {"total": 2, "HIGH": 1, "MEDIUM": 0, "LOW": 1}
    assert result["after"]["HIGH"] == 0


def test_rules_endpoint():
    client = TestClient(app)
    data = client.get("/api/bandit/rules").json()
    assert "B608" in data["rules"]
    assert client.get("/api/bandit/explain/b608").json()["cwe"] == 89
