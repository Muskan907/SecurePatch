from backend.main import parse_bandit_json

REPORT = '{"errors": [], "results": [{"test_id": "B602", "line_number": 30}]}'


def test_plain_json():
    assert parse_bandit_json(REPORT)["results"][0]["test_id"] == "B602"


def test_progress_bar_before_json_is_ignored():
    # Bandit prints this on larger repositories before the JSON report.
    noisy = "Working... ---------------------------------------- 100% 0:00:01\n" + REPORT
    assert parse_bandit_json(noisy)["results"][0]["line_number"] == 30


def test_garbage_returns_empty_results():
    out = parse_bandit_json("Working... no json here", "boom")
    assert out == {"results": [], "errors": "boom"}
