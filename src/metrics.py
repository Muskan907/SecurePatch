"""Prometheus metrics for the live Grafana dashboard.

A tiny, dependency-free implementation of Prometheus counters, gauges and
histograms with the text exposition format (version 0.0.4), so the backend
image does not need an extra package. Thread-safe: FastAPI runs sync
endpoints in a thread pool.
"""
from __future__ import annotations

import math
import threading
import time
from typing import Callable, Iterable

CONTENT_TYPE = "text/plain; version=0.0.4; charset=utf-8"

_LOCK = threading.Lock()
_REGISTRY: list["_Metric"] = []


def _escape(value: str) -> str:
    return str(value).replace("\\", "\\\\").replace("\n", "\\n").replace('"', '\\"')


def _labels(names: tuple[str, ...], values: tuple[str, ...], extra: str = "") -> str:
    parts = [f'{n}="{_escape(v)}"' for n, v in zip(names, values)]
    if extra:
        parts.append(extra)
    return "{" + ",".join(parts) + "}" if parts else ""


def _num(value: float) -> str:
    if value == math.inf:
        return "+Inf"
    if float(value).is_integer():
        return str(int(value))
    return repr(float(value))


class _Metric:
    kind = ""

    def __init__(self, name: str, help_text: str, labelnames: Iterable[str] = ()):
        self.name = name
        self.help = help_text
        self.labelnames = tuple(labelnames)
        _REGISTRY.append(self)

    def _key(self, labels: dict) -> tuple[str, ...]:
        return tuple(str(labels.get(n, "")) for n in self.labelnames)

    def header(self) -> list[str]:
        return [f"# HELP {self.name} {self.help}", f"# TYPE {self.name} {self.kind}"]


class Counter(_Metric):
    kind = "counter"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._values: dict[tuple[str, ...], float] = {}

    def inc(self, amount: float = 1.0, **labels) -> None:
        if amount < 0:
            raise ValueError("Counters can only increase.")
        key = self._key(labels)
        with _LOCK:
            self._values[key] = self._values.get(key, 0.0) + amount

    def value(self, **labels) -> float:
        return self._values.get(self._key(labels), 0.0)

    def render(self) -> list[str]:
        lines = self.header()
        values = self._values or ({(): 0.0} if not self.labelnames else {})
        for key, val in sorted(values.items()):
            lines.append(f"{self.name}{_labels(self.labelnames, key)} {_num(val)}")
        return lines


class Gauge(_Metric):
    kind = "gauge"

    def __init__(self, *args, supplier: Callable[[], float] | None = None, **kwargs):
        super().__init__(*args, **kwargs)
        self._values: dict[tuple[str, ...], float] = {}
        self._supplier = supplier

    def set(self, value: float, **labels) -> None:
        with _LOCK:
            self._values[self._key(labels)] = float(value)

    def render(self) -> list[str]:
        if self._supplier is not None:
            try:
                self.set(self._supplier())
            except Exception:
                pass
        lines = self.header()
        for key, val in sorted(self._values.items()):
            lines.append(f"{self.name}{_labels(self.labelnames, key)} {_num(val)}")
        return lines


class Histogram(_Metric):
    kind = "histogram"

    def __init__(self, *args, buckets: Iterable[float], **kwargs):
        super().__init__(*args, **kwargs)
        self.buckets = tuple(sorted(buckets)) + (math.inf,)
        self._counts: dict[tuple[str, ...], list[int]] = {}
        self._sums: dict[tuple[str, ...], float] = {}

    def observe(self, value: float, **labels) -> None:
        key = self._key(labels)
        with _LOCK:
            counts = self._counts.setdefault(key, [0] * len(self.buckets))
            for i, bound in enumerate(self.buckets):
                if value <= bound:
                    counts[i] += 1
            self._sums[key] = self._sums.get(key, 0.0) + value

    def render(self) -> list[str]:
        lines = self.header()
        for key in sorted(self._counts):
            counts = self._counts[key]
            for bound, count in zip(self.buckets, counts):
                le = f'le="{_num(bound)}"'
                lines.append(f"{self.name}_bucket{_labels(self.labelnames, key, le)} {count}")
            lines.append(f"{self.name}_sum{_labels(self.labelnames, key)} {_num(self._sums[key])}")
            lines.append(f"{self.name}_count{_labels(self.labelnames, key)} {counts[-1]}")
        return lines


def render_all() -> str:
    with _LOCK:
        metrics = list(_REGISTRY)
    out: list[str] = []
    for metric in metrics:
        out.extend(metric.render())
    return "\n".join(out) + "\n"


# =========================================================
# SecurePatch metrics
# =========================================================
HTTP_REQUESTS = Counter(
    "securepatch_http_requests_total",
    "HTTP requests handled by the backend.",
    ("method", "path", "status"),
)
HTTP_LATENCY = Histogram(
    "securepatch_http_request_duration_seconds",
    "HTTP request latency in seconds.",
    ("method", "path"),
    buckets=(0.01, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30, 60, 120, 300),
)
SCANS = Counter("securepatch_scans_total", "Repository scans (Bandit + optional Semgrep).")
FINDINGS = Counter(
    "securepatch_findings_total",
    "Vulnerability findings reported by scans, by severity.",
    ("severity",),
)
PATCH_ATTEMPTS = Counter(
    "securepatch_patch_generations_total",
    "Patch generation attempts per model and outcome (success, guardrail_blocked, failed).",
    ("model", "outcome"),
)
LLM_LATENCY = Histogram(
    "securepatch_llm_generation_seconds",
    "LLM generation latency in seconds, by model.",
    ("model",),
    buckets=(1, 2.5, 5, 10, 20, 30, 45, 60, 90, 120, 180, 300, 600),
)
LLM_TOKENS = Counter(
    "securepatch_llm_tokens_total",
    "Tokens processed by the LLM, by model and direction (input/output).",
    ("model", "direction"),
)
FALLBACKS = Counter(
    "securepatch_fallback_used_total",
    "Patches that were produced by a fallback model after the requested model failed.",
)
VALIDATIONS = Counter(
    "securepatch_validations_total",
    "Patch validations by verdict (VERIFIED, REJECTED, ...).",
    ("verdict",),
)
OLLAMA_UP = Gauge("securepatch_ollama_up", "1 if the Ollama server answers, else 0.")
START_TIME = Gauge("securepatch_process_start_time_seconds", "Backend start time (unix seconds).")
START_TIME.set(time.time())


# =========================================================
# Recording helpers (never raise into request handling)
# =========================================================
def record_scan(findings: Iterable[dict]) -> None:
    try:
        SCANS.inc()
        for finding in findings or []:
            severity = str(finding.get("issue_severity") or finding.get("severity") or "UNKNOWN").upper()
            FINDINGS.inc(severity=severity)
    except Exception:
        pass


def record_llm_call(model: str, seconds: float, result=None) -> None:
    try:
        LLM_LATENCY.observe(seconds, model=model)
        if result is not None:
            if result.input_tokens:
                LLM_TOKENS.inc(result.input_tokens, model=model, direction="input")
            if result.output_tokens:
                LLM_TOKENS.inc(result.output_tokens, model=model, direction="output")
    except Exception:
        pass


def record_patch_attempt(model: str, error: str | None) -> None:
    if error is None:
        outcome = "success"
    elif "guardrail" in error.lower():
        outcome = "guardrail_blocked"
    else:
        outcome = "failed"
    PATCH_ATTEMPTS.inc(model=model, outcome=outcome)


def record_validation(verdict) -> None:
    VALIDATIONS.inc(verdict=str(verdict or "UNKNOWN").upper())


def cached_probe(probe: Callable[[], bool], ttl: float = 15.0) -> Callable[[], float]:
    """Wrap a slow health probe so scrapes call it at most once per ``ttl``."""
    state = {"at": 0.0, "value": 0.0}

    def supplier() -> float:
        now = time.monotonic()
        if now - state["at"] >= ttl:
            try:
                state["value"] = 1.0 if probe() else 0.0
            except Exception:
                state["value"] = 0.0
            state["at"] = now
        return state["value"]

    return supplier


class PrometheusMiddleware:
    """Pure ASGI middleware: counts requests and times them per route template."""

    def __init__(self, app, skip_paths: Iterable[str] = ("/metrics",)):
        self.app = app
        self.skip = set(skip_paths)

    async def __call__(self, scope, receive, send):
        if scope.get("type") != "http" or scope.get("path") in self.skip:
            await self.app(scope, receive, send)
            return
        started = time.perf_counter()
        status = {"code": 500}

        async def send_wrapper(message):
            if message.get("type") == "http.response.start":
                status["code"] = message.get("status", 500)
            await send(message)

        try:
            await self.app(scope, receive, send_wrapper)
        finally:
            route = scope.get("route")
            # Route template (e.g. /api/bandit/explain/{test_id}) keeps label cardinality low.
            path = getattr(route, "path", None) or "unmatched"
            method = scope.get("method", "GET")
            HTTP_REQUESTS.inc(method=method, path=path, status=str(status["code"]))
            HTTP_LATENCY.observe(time.perf_counter() - started, method=method, path=path)
