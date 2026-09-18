"""Secret-free monotonic performance telemetry for Scout and MCP catalogs."""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass, field
import threading
import time


TIMING_FIELDS = (
    "total_runtime_ms", "scout_runtime_ms", "dedup_runtime_ms", "triage_runtime_ms",
    "portfolio_runtime_ms", "feedback_runtime_ms", "graph_runtime_ms",
)
COUNT_FIELDS = (
    "records_scanned", "records_skipped", "records_reanalyzed",
    "proposals_created", "proposals_deduped", "proposals_triaged", "proposals_selected",
    "cache_hits", "cache_misses", "model_calls", "model_failures", "tool_calls",
    "tools_exposed", "tools_used", "serialized_tool_schema_bytes",
    "sqlite_query_count", "sqlite_write_count", "sqlite_transaction_count",
    "candidate_promotions",
)


@dataclass
class PerformanceMetrics:
    """One-run counters. Inputs, credentials, sessions and payloads are never accepted."""

    _values: dict[str, float | int] = field(default_factory=dict, init=False, repr=False)
    _model_roles: set[str] = field(default_factory=set, init=False, repr=False)
    _reasoning_efforts: set[str] = field(default_factory=set, init=False, repr=False)
    _lock: threading.Lock = field(default_factory=threading.Lock, init=False, repr=False)

    def __post_init__(self):
        self.reset()

    def reset(self):
        with self._lock:
            self._values = {name: 0.0 for name in TIMING_FIELDS}
            self._values.update({name: 0 for name in COUNT_FIELDS})
            self._model_roles.clear()
            self._reasoning_efforts.clear()

    def add(self, name: str, value: int | float = 1):
        if name not in self._values or isinstance(value, bool) or not isinstance(value, (int, float)):
            raise ValueError("invalid_performance_metric")
        with self._lock:
            self._values[name] += value

    def model_route(self, role: str | None, effort: str | None):
        with self._lock:
            if role:
                self._model_roles.add(role[:64])
            if effort:
                self._reasoning_efforts.add(effort[:16])

    @contextmanager
    def stage(self, name: str):
        if name not in TIMING_FIELDS:
            raise ValueError("invalid_performance_stage")
        started = time.perf_counter_ns()
        try:
            yield
        finally:
            self.add(name, (time.perf_counter_ns() - started) / 1_000_000)

    def snapshot(self) -> dict:
        with self._lock:
            values = dict(self._values)
            roles = sorted(self._model_roles)
            efforts = sorted(self._reasoning_efforts)
        for name in TIMING_FIELDS:
            values[name] = round(max(0.0, float(values[name])), 3)
        for name in COUNT_FIELDS:
            values[name] = int(values[name])
        values["model_role"] = roles or ["deterministic_core"]
        values["reasoning_effort"] = efforts or ["not_applicable"]
        values["contains_secrets"] = False
        return values


def performance_summary(metrics: dict) -> dict:
    scanned = int(metrics.get("records_scanned", 0))
    proposals = int(metrics.get("proposals_created", 0))
    hits = int(metrics.get("cache_hits", 0))
    misses = int(metrics.get("cache_misses", 0))
    return {
        "records_scanned": scanned,
        "cache_hit_rate": round(hits / (hits + misses), 6) if hits + misses else 0.0,
        "proposal_reduction_ratio": round(
            (proposals - int(metrics.get("proposals_selected", 0))) / proposals, 6
        ) if proposals else 0.0,
        "dedup_reduction": int(metrics.get("proposals_deduped", 0)),
        "triage_reduction": max(0, proposals - int(metrics.get("proposals_triaged", 0))),
        "portfolio_reduction": max(0, int(metrics.get("proposals_triaged", 0)) -
                                   int(metrics.get("proposals_selected", 0))),
        "total_runtime_ms": metrics.get("total_runtime_ms", 0),
        "scout_runtime_ms": metrics.get("scout_runtime_ms", 0),
        "model_calls": int(metrics.get("model_calls", 0)),
        "tool_calls": int(metrics.get("tool_calls", 0)),
        "average_exposed_tools": int(metrics.get("tools_exposed", 0)),
        "sqlite_queries": int(metrics.get("sqlite_query_count", 0)),
    }
