"""The streamed scan must report exactly what the Bandit CLI reports."""

from pathlib import Path

from fastapi.testclient import TestClient

from backend.main import app, run_bandit
from src.bandit_stream import iter_scan

SAMPLE = Path(__file__).resolve().parent.parent / "sample_repo"


def key(finding):
    return (
        Path(finding["filename"]).resolve().as_posix(),
        finding["line_number"],
        finding["test_id"],
    )


def test_stream_matches_cli():
    events = list(iter_scan(SAMPLE))
    assert events[0]["type"] == "start"
    assert events[-1]["type"] == "done"
    file_events = [e for e in events if e["type"] == "file"]
    assert len(file_events) == events[0]["files"]

    streamed = sorted(key(f) for f in events[-1]["findings"])
    cli = sorted(key(f) for f in run_bandit(str(SAMPLE))["results"])
    assert streamed == cli
    assert all(f["more_info"].startswith("https://") for f in events[-1]["findings"])


def test_scan_stream_endpoint():
    client = TestClient(app)
    with client.stream(
        "GET", "/api/scan/stream", params={"repo_path": "sample_repo", "semgrep_enabled": "false"}
    ) as response:
        assert response.status_code == 200
        assert response.headers["content-type"].startswith("text/event-stream")
        body = "".join(response.iter_text())
    assert '"type": "start"' in body
    assert '"type": "done"' in body
    assert '"summary"' in body
