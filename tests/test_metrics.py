"""The /metrics endpoint feeds the live Prometheus + Grafana dashboard."""
from fastapi.testclient import TestClient

import backend.main as main
import src.metrics as metrics

EXPECTED = [
    "securepatch_http_requests_total",
    "securepatch_http_request_duration_seconds",
    "securepatch_scans_total",
    "securepatch_findings_total",
    "securepatch_patch_generations_total",
    "securepatch_llm_generation_seconds",
    "securepatch_llm_tokens_total",
    "securepatch_fallback_used_total",
    "securepatch_validations_total",
    "securepatch_ollama_up",
]


def client(monkeypatch):
    # Never contact a real Ollama from tests.
    monkeypatch.setattr(metrics.OLLAMA_UP, "_supplier", lambda: 0.0)
    return TestClient(main.app)


def test_metrics_endpoint_exposes_all_metric_families(monkeypatch):
    c = client(monkeypatch)
    response = c.get("/metrics")
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/plain")
    for name in EXPECTED:
        assert f"# TYPE {name} " in response.text, name
    assert "securepatch_ollama_up 0" in response.text


def test_requests_are_labelled_by_route_template(monkeypatch):
    c = client(monkeypatch)
    c.get("/api/bandit/explain/B101")
    text = c.get("/metrics").text
    assert 'path="/api/bandit/explain/{test_id}"' in text
    assert 'path="/metrics"' not in text  # scrapes are not counted


def test_recording_helpers():
    before = metrics.PATCH_ATTEMPTS.value(model="m", outcome="guardrail_blocked")
    metrics.record_patch_attempt("m", "Guardrail blocked: unsafe call to exec().")
    metrics.record_patch_attempt("m", None)
    metrics.record_patch_attempt("m", "Ollama 500")
    assert metrics.PATCH_ATTEMPTS.value(model="m", outcome="guardrail_blocked") == before + 1
    assert metrics.PATCH_ATTEMPTS.value(model="m", outcome="success") >= 1
    assert metrics.PATCH_ATTEMPTS.value(model="m", outcome="failed") >= 1

    scans = metrics.SCANS.value()
    metrics.record_scan([{"issue_severity": "HIGH"}, {"issue_severity": "low"}])
    assert metrics.SCANS.value() == scans + 1
    assert metrics.FINDINGS.value(severity="LOW") >= 1

    metrics.record_validation("VERIFIED")
    text = metrics.render_all()
    assert 'securepatch_validations_total{verdict="VERIFIED"}' in text


def test_histogram_buckets_are_cumulative():
    h = metrics.Histogram("test_hist_seconds", "test", ("model",), buckets=(1, 5))
    try:
        for value in (0.5, 3, 10):
            h.observe(value, model="x")
        lines = h.render()
        assert 'test_hist_seconds_bucket{model="x",le="1"} 1' in lines
        assert 'test_hist_seconds_bucket{model="x",le="5"} 2' in lines
        assert 'test_hist_seconds_bucket{model="x",le="+Inf"} 3' in lines
        assert 'test_hist_seconds_count{model="x"} 3' in lines
    finally:
        metrics._REGISTRY.remove(h)
