"""Optimization tests use only synthetic, local fixtures."""

import asyncio
import json
from pathlib import Path
from uuid import uuid4

import pytest

from ctf_mcp.config import Rejected
from ctf_mcp.perf import PerformanceMetrics
from ctf_mcp.perf_cli import benchmark, compare, schema_metrics, status
from ctf_mcp.records import Records
from ctf_mcp.scout_controller import ScoutPortfolioController
from ctf_mcp.scout_dedup import SemanticDeduplicator
from ctf_mcp.scout_graph import EvidenceGraphBuilder
from ctf_mcp.scout_ledger import ScoutLedger
from ctf_mcp.scout_pipeline import (ModelRouting, OfflineAnalysisBudget, ScoutPipeline,
                                    cache_key)
from ctf_mcp.scout_portfolio import ModelPortfolioSelector
from ctf_mcp.scouts.base import record_hash, utcnow
from ctf_mcp.server import create_server
from ctf_mcp.tool_routing import serialized_tool_schema_bytes
from test_scout import active_program, proposal
from test_programs import program_settings


def test_role_tool_filtering_and_legacy_unknown_compatibility(program_settings):
    active_program(program_settings)

    async def inspect():
        result = {}
        for role in ("Scout", "Triage", "Portfolio", "Investigator", "Verifier", "Reporter"):
            tools = await create_server(program_settings, agent_role=role).list_tools()
            result[role] = ({tool.name for tool in tools}, serialized_tool_schema_bytes(tools))
        legacy = await create_server(program_settings).list_tools()
        unknown = await create_server(program_settings, agent_role="future-role").list_tools()
        return result, legacy, unknown

    values, legacy, unknown = asyncio.run(inspect())
    legacy_names = {tool.name for tool in legacy}
    assert {tool.name for tool in unknown} == legacy_names
    assert {"inventory", "read_record", "source_search", "scope_check", "scout_status"} <= values["Scout"][0]
    assert "record_candidate" not in values["Scout"][0]
    assert {"read_record", "compare_records", "scope_check"} <= values["Verifier"][0]
    assert "record_candidate" not in values["Verifier"][0]
    assert "write_report" in values["Reporter"][0]
    assert not {"analyze_har", "review_android", "record_candidate"} & values["Reporter"][0]
    assert all(len(names) < len(legacy_names) and size < serialized_tool_schema_bytes(legacy)
               for names, size in values.values())


def test_mcp_tool_telemetry_is_secret_free(program_settings):
    active_program(program_settings)

    async def call():
        server = create_server(program_settings, agent_role="Scout")
        _, result = await server.call_tool("health", {})
        return result["tool_telemetry"]

    telemetry = asyncio.run(call())
    assert telemetry["agent_role"] == "Scout" and telemetry["tool_calls"] == 1
    assert telemetry["tools_exposed"] > telemetry["tools_used"] == 1
    assert telemetry["serialized_tool_schema_bytes"] > 0
    assert telemetry["contains_secrets"] is False


def test_model_effort_routing_aliases_budget_and_invalid_effort(monkeypatch):
    for key in list(ModelRouting.ROLES):
        assert key in ModelRouting.from_env()
    assert ModelRouting.from_env()["Scout"] == {"model": None, "effort": "medium"}
    monkeypatch.setenv("FINDER_MODEL_DEFAULT", "account-selected-model")
    monkeypatch.setenv("FINDER_MODEL_TRIAGE", "triage-model")
    monkeypatch.setenv("FINDER_EFFORT_TRIAGE", "low")
    routes = ModelRouting.from_env()
    assert routes["CheapTriager"] == {"model": "triage-model", "effort": "low"}
    assert routes["Reporter"]["model"] == "account-selected-model"
    monkeypatch.setenv("FINDER_MAX_MODEL_CALLS_PER_RUN", "2")
    monkeypatch.setenv("FINDER_MAX_MODEL_CALLS_PER_PROPOSAL", "1")
    budget = OfflineAnalysisBudget.from_env()
    assert budget.max_model_calls == 2 and budget.max_model_calls_per_proposal == 1
    monkeypatch.setenv("FINDER_EFFORT_VERIFIER", "maximum")
    with pytest.raises(Rejected, match="invalid_model_effort"):
        ModelRouting.from_env()


def test_cache_key_dimensions_stable_record_hash_and_force(program_settings):
    store, _, ref = active_program(program_settings)
    records = Records(program_settings.results_root, programs_root=store.root)
    payload = {"analyzer": "openapi", "program": ref, "result": {"observations": []}}
    first_record = records.save("analysis", payload)
    semantic_copy = {**first_record, "id": uuid4().hex, "created_at": "2099-01-01T00:00:00+00:00"}
    assert record_hash(first_record) == record_hash(semantic_copy)
    first = ScoutPipeline(program_settings).run(record_id=first_record["id"])
    second = ScoutPipeline(program_settings).run(record_id=first_record["id"])
    forced = ScoutPipeline(program_settings).run(record_id=first_record["id"], force=True)
    assert first["cache_misses"] == 7 and second["cache_hits"] == 7
    assert forced["records_evaluated"] == 7 and all(
        item["decision"] == "force_bypass" for item in forced["cache_decisions"])
    ledger = ScoutLedger(program_settings.results_root)
    cached = ledger.rows("scout_cache")[0]
    dimensions = (cached["input_record_hash"], cached["scout_type"], cached["scout_version"],
                  cached["program_policy_hash"], cached["relevant_config_hash"])
    assert ledger.was_evaluated(*dimensions)
    assert not ledger.was_evaluated("d" * 64, *dimensions[1:])
    assert not ledger.was_evaluated(dimensions[0], dimensions[1], "changed-version", *dimensions[3:])
    assert not ledger.was_evaluated(*dimensions[:3], "d" * 64, dimensions[4])
    assert not ledger.was_evaluated(*dimensions[:4], "d" * 64)
    base = cache_key("a" * 64, "hidden_api", "1", "b" * 64, "c" * 64)
    assert base != cache_key("d" * 64, "hidden_api", "1", "b" * 64, "c" * 64)
    assert base != cache_key("a" * 64, "hidden_api", "2", "b" * 64, "c" * 64)
    assert base != cache_key("a" * 64, "hidden_api", "1", "d" * 64, "c" * 64)
    assert base != cache_key("a" * 64, "hidden_api", "1", "b" * 64, "d" * 64)


def test_pipeline_short_circuits_duplicate_excluded_and_scope_before_model(program_settings):
    store, profile, ref = active_program(program_settings, excluded=("rate-limit-only",))
    records = Records(program_settings.results_root, programs_root=store.root)
    evidence = records.save("analysis", {"analyzer": "openapi", "program": ref,
        "result": {"observations": []}})
    common = {"program": ref, "source_record_ids": [evidence["id"]], "observation_ids": []}
    eligible = proposal(proposal_id="1" * 32, **common)
    duplicate = proposal(proposal_id="2" * 32, **common)
    excluded = proposal(proposal_id="3" * 32, finding_category="rate-limit-only", **common)
    blocked = proposal(proposal_id="4" * 32, asset="https://outside.example.org/x", **common)
    for value in (eligible, duplicate, excluded, blocked):
        records.save("scout_proposal", value.to_dict())
    relation = SemanticDeduplicator().compare(duplicate, eligible)
    records.save("scout_dedup", {**relation, "program_id": "example", "created_at": utcnow()})
    reviewed = []

    def reviewer(items):
        reviewed.extend(item["proposal_id"] for item in items)
        return list(reviewed)

    controller = ScoutPortfolioController(program_settings,
        selector=ModelPortfolioSelector(reviewer=reviewer))
    triage = controller.triage()
    result = controller.portfolio(slots=10)
    cached = controller.portfolio(slots=10)
    decisions = {item["proposal_id"]: item["decision"] for item in triage["results"]}
    assert duplicate.proposal_id not in decisions
    assert decisions[excluded.proposal_id] == "PROGRAM_EXCLUDED"
    assert decisions[blocked.proposal_id] == "BLOCKED_SCOPE"
    assert reviewed == [eligible.proposal_id]
    assert result["model_calls"] == 1
    assert cached["cache_hit"] and cached["model_calls_this_run"] == 0
    assert reviewed == [eligible.proposal_id]


def test_sqlite_indexes_batch_sync_graph_increment_and_telemetry(program_settings):
    store, _, ref = active_program(program_settings)
    records = Records(program_settings.results_root, programs_root=store.root)
    evidence = records.save("analysis", {"analyzer": "openapi", "program": ref,
        "result": {"observations": []}})
    records.save("scout_proposal", proposal(proposal_id="5" * 32, program=ref,
        source_record_ids=[evidence["id"]], observation_ids=[]).to_dict())
    metrics = PerformanceMetrics()
    ledger = ScoutLedger(program_settings.results_root, metrics=metrics)
    metrics.reset()
    ledger.sync(records)
    assert metrics.snapshot()["sqlite_transaction_count"] == 1
    connection = ledger._connect()
    try:
        indexes = {row[1] for row in connection.execute("PRAGMA index_list('proposals')")}
    finally:
        connection.close()
    assert "idx_proposals_program_scout_status" in indexes
    graph = EvidenceGraphBuilder(records, ledger)
    graph.refresh("example")
    records.save("scout_proposal", proposal(proposal_id="6" * 32, program=ref,
        asset="https://api.example.com/other", source_record_ids=[evidence["id"]],
        observation_ids=[]).to_dict())
    update = graph.refresh("example")
    assert update["incremental_update"] and update["proposals_added"] == 1
    snapshot = metrics.snapshot()
    assert all(snapshot[name] >= 0 for name in ("total_runtime_ms", "sqlite_query_count",
                                                 "sqlite_write_count"))
    assert "SYNTHETIC_SECRET_VALUE" not in json.dumps(snapshot)


def test_performance_benchmark_status_data_and_compare(program_settings):
    store, _, ref = active_program(program_settings)
    records = Records(program_settings.results_root, programs_root=store.root)
    evidence = records.save("analysis", {"analyzer": "openapi", "program": ref,
        "result": {"observations": [{"path": "https://api.example.com/share",
            "method": "GET", "parameters": [{"name": "token"}]}]}})
    first = benchmark(program_settings, evidence["id"])
    second = benchmark(program_settings, evidence["id"])
    result = compare(program_settings, first["record_id"], second["record_id"])
    current = status(program_settings)
    assert first["cold"]["records_scanned"] == first["warm"]["records_scanned"] == 1
    assert first["warm"]["cache_hits"] >= 1 and first["contains_secrets"] is False
    assert {item["role"] for item in schema_metrics(program_settings)} >= {"Scout", "Reporter"}
    assert result["rows"] and result["contains_secrets"] is False
    assert current["benchmark_count"] == 2 and current["average_exposed_tools"] > 0


def test_test_tiers_preserve_full_and_exclude_integration_paths():
    config = Path("pyproject.toml").read_text()
    control = Path("scripts/control.py").read_text()
    assert "fast:" in config and "integration:" in config
    assert '"full": ["-q", "tests"]' in control
    assert '"fast": ["-q", "-m", "fast", "tests"]' in control
    assert "test_persistent_sessions.py" in Path("tests/conftest.py").read_text()


def test_required_macos_worker_and_playwright_compatibility_patches(monkeypatch):
    from ctf_mcp import engine
    worker = Path("src/ctf_mcp/worker.py").read_text()
    assert 'if sys.platform != "darwin":' in worker and "resource.RLIMIT_AS" in worker
    monkeypatch.delenv("PLAYWRIGHT_BROWSERS_PATH", raising=False)
    monkeypatch.setattr(engine.sys, "platform", "darwin")
    assert engine._playwright_browsers_path().endswith("Library/Caches/ms-playwright")
    monkeypatch.setattr(engine.sys, "platform", "linux")
    assert engine._playwright_browsers_path().endswith(".cache/ms-playwright")
