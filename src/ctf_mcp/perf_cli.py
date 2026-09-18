"""Local performance status, isolated benchmark and comparison commands."""

from __future__ import annotations

import asyncio
from dataclasses import replace
import json
from pathlib import Path
import tempfile
import time

from .config import Rejected
from .program_store import ProgramStore
from .records import Records, valid_id
from .scout_controller import ScoutPortfolioController
from .scout_ledger import ScoutLedger
from .scout_pipeline import scout_events
from .server import create_server
from .tool_routing import tool_schema_metric


MODEL_ROLES = ("Scout", "Triage", "Portfolio", "Investigator", "Verifier", "Reporter")


def add_commands(sub):
    perf = sub.add_parser("perf", help="Read secret-free telemetry and run isolated local benchmarks")
    actions = perf.add_subparsers(dest="perf_action", required=True)
    actions.add_parser("status")
    benchmark = actions.add_parser("benchmark")
    benchmark.add_argument("--record")
    compare = actions.add_parser("compare")
    compare.add_argument("--before")
    compare.add_argument("--after")


async def _schema_metrics(settings):
    values = []
    for role in MODEL_ROLES:
        tools = await create_server(settings, "analysis", agent_role=role).list_tools()
        values.append(tool_schema_metric(role, tools))
    legacy = await create_server(settings, "analysis").list_tools()
    values.append(tool_schema_metric("legacy/default", legacy))
    return values


def schema_metrics(settings):
    return asyncio.run(_schema_metrics(settings))


def _input_record(records, program_reference, record_id=None):
    if record_id is not None:
        record = records.read(valid_id(record_id))
        if record["kind"] not in {"analysis", "session_comparison"}:
            raise Rejected("benchmark_record_kind_not_supported")
        bound = record.get("payload", {}).get("program")
        if bound is not None and bound != program_reference:
            raise Rejected("benchmark_record_program_mismatch")
        return record
    selected = []
    for ident in records.list():
        record = records.read(ident)
        if record["kind"] not in {"analysis", "session_comparison"}:
            continue
        bound = record.get("payload", {}).get("program")
        if bound is None or bound == program_reference:
            selected.append(record)
    if not selected:
        raise Rejected("benchmark_input_record_required")
    return sorted(selected, key=lambda item: (item["created_at"], item["id"]))[-1]


def _copy_active_program(source: ProgramStore, target: Path, program_id: str):
    for relative in ("active.json", f"{program_id}/program.json", f"{program_id}/approval.json"):
        destination = target / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(source._read(relative))


def benchmark(settings, record_id=None):
    source_store = ProgramStore(settings.programs_root)
    profile, approval = source_store.selected()
    reference = {"program_id": profile["program_id"], "approval_id": approval["approval_id"],
                 "sha256": approval["sha256"]}
    source_records = Records(settings.results_root, settings.limits, settings.programs_root)
    source = _input_record(source_records, reference, record_id)
    with tempfile.TemporaryDirectory(prefix="iwantgohome-perf-") as raw:
        # macOS /var is a symlink to /private/var; canonicalize before
        # ProgramStore applies its intentional O_NOFOLLOW checks.
        raw = str(Path(raw).resolve())
        root = Path(raw)
        roots = {name: root / name for name in ("inputs", "results", "grants", "browser", "programs")}
        for directory in roots.values():
            directory.mkdir()
        _copy_active_program(source_store, roots["programs"], profile["program_id"])
        isolated = replace(settings, input_root=roots["inputs"], results_root=roots["results"],
            grants_root=roots["grants"], browser_root=roots["browser"], programs_root=roots["programs"])
        saved = Records(roots["results"], settings.limits, roots["programs"]).save(
            source["kind"], source["payload"])
        controller = ScoutPortfolioController(isolated)
        started = time.perf_counter_ns()
        cold = controller.run(record_id=saved["id"])
        cold_wall = (time.perf_counter_ns() - started) / 1_000_000
        started = time.perf_counter_ns()
        warm = controller.run(record_id=saved["id"])
        warm_wall = (time.perf_counter_ns() - started) / 1_000_000
    payload = {
        "benchmark_version": "1", "program_id": profile["program_id"],
        "fixture_kind": source["kind"], "fixture_content_hash": cold["scan"]["cache_decisions"][0]["cache_key"]
            if cold["scan"]["cache_decisions"] else "not_available",
        "monotonic_clock": "time.perf_counter_ns", "cold_wall_runtime_ms": round(cold_wall, 3),
        "warm_wall_runtime_ms": round(warm_wall, 3), "cold": cold["performance"]["metrics"],
        "warm": warm["performance"]["metrics"], "tool_schemas": schema_metrics(settings),
        "billing_tokens": "not measurable in current environment", "contains_secrets": False,
    }
    record = source_records.save("performance_benchmark", payload)
    return {"record_id": record["id"], **record["payload"]}


def status(settings):
    records = Records(settings.results_root, settings.limits, settings.programs_root)
    ledger = ScoutLedger(settings.results_root)
    ledger.sync(records)
    runs = scout_events(records, "scout_performance")
    all_records = [records.read(ident) for ident in records.list()]
    benchmarks = [record for record in all_records if record["kind"] == "performance_benchmark"]
    latest = runs[-1] if runs else None
    schemas = schema_metrics(settings)
    filtered = [item["available_tool_count"] for item in schemas if item["role"] != "legacy/default"]
    return {
        "latest": ({"record_id": latest["id"], **latest["payload"]} if latest else None),
        "benchmark_count": len(benchmarks), "tool_schemas": schemas,
        "average_exposed_tools": round(sum(filtered) / len(filtered), 3) if filtered else 0.0,
        "sqlite": {"proposals": len(ledger.rows("proposals")),
            "model_usage": len(ledger.rows("model_usage")),
            "candidate_promotions": len(ledger.rows("promotions"))},
        "contains_secrets": False,
    }


def compare(settings, before_id=None, after_id=None):
    records = Records(settings.results_root, settings.limits, settings.programs_root)
    values = [records.read(ident) for ident in records.list()]
    values = [record for record in values if record["kind"] == "performance_benchmark"]
    by_id = {record["id"]: record for record in values}
    if before_id is not None or after_id is not None:
        if before_id is None or after_id is None:
            raise Rejected("benchmark_compare_requires_both_ids")
        try: selected = [by_id[valid_id(before_id)], by_id[valid_id(after_id)]]
        except KeyError: raise Rejected("performance_benchmark_not_found") from None
    elif len(values) >= 2:
        selected = sorted(values, key=lambda item: (item["created_at"], item["id"]))[-2:]
    else:
        raise Rejected("two_performance_benchmarks_required")
    before, after = (item["payload"] for item in selected)
    metrics = ("cold_wall_runtime_ms", "warm_wall_runtime_ms")
    rows = []
    for metric in metrics:
        first, second = float(before[metric]), float(after[metric])
        rows.append({"metric": metric, "before": first, "after": second,
                     "delta": round(second - first, 3),
                     "change_ratio": round((second - first) / first, 6) if first else None})
    before_schemas = {item["role"]: item for item in before.get("tool_schemas", [])}
    after_schemas = {item["role"]: item for item in after.get("tool_schemas", [])}
    for role in sorted(before_schemas.keys() & after_schemas.keys()):
        for field in ("available_tool_count", "serialized_tool_schema_bytes"):
            first, second = before_schemas[role][field], after_schemas[role][field]
            rows.append({"metric": f"{role}.{field}", "before": first, "after": second,
                         "delta": second - first})
    return {"before_record_id": selected[0]["id"], "after_record_id": selected[1]["id"],
            "rows": rows, "contains_secrets": False}


def run(args, settings):
    if args.perf_action == "status":
        result = status(settings)
    elif args.perf_action == "benchmark":
        result = benchmark(settings, args.record)
    else:
        result = compare(settings, args.before, args.after)
    print(json.dumps(result, indent=2, ensure_ascii=True))
