"""Scout tests are local-only and never resolve or contact a target."""

import ast
import asyncio
from collections import Counter
import json
from pathlib import Path
import subprocess
import sys
from uuid import uuid4

import pytest

from ctf_mcp.config import Rejected
from ctf_mcp.programs import validate_profile
from ctf_mcp.records import Records
from ctf_mcp.scout_controller import ScoutPortfolioController
from ctf_mcp.scout_dedup import SemanticDeduplicator
from ctf_mcp.scout_ledger import ScoutLedger
from ctf_mcp.scout_pipeline import OfflineAnalysisBudget, ScoutPipeline
from ctf_mcp.scout_portfolio import ModelPortfolioSelector, PortfolioPolicy
from ctf_mcp.scout_triage import CheapTriager
from ctf_mcp.scouts import SCOUTS
from ctf_mcp.scouts.base import CandidateProposal, ExperimentRequest, ScoutContext
from ctf_mcp.server import create_server
from test_programs import approve_program, example, program_settings


def profile(**changes):
    data = example(program_id="example", scope={"in_scope": [{"host": "api.example.com", "paths": ["/*"]}]},
                   excluded_finding_categories=["self-xss", "rate-limit-only"])
    data.update(changes)
    return validate_profile(data)


def reference(program="example"):
    return {"program_id": program, "approval_id": "a" * 32, "sha256": "b" * 64}


def record(kind, payload):
    return {"id": uuid4().hex, "kind": kind, "created_at": "2026-01-01T00:00:00+00:00",
            "analyzer_version": "test", "payload": payload}


def contexts():
    p, ref = profile(), reference()
    values = {
        "auth_tenant": record("session_comparison", {"FACTS": {"user_a_evidence": "1" * 32,
            "user_b_evidence": "2" * 32}, "DIFFERENCES": [{"user_a": {
            "url": "https://api.example.com/account", "response_shape": {"fields": ["name"]}},
            "user_b": {"url": "https://api.example.com/account", "response_shape": {"fields": ["name", "role"]}}}]}),
        "capability": record("analysis", {"analyzer": "openapi", "result": {"observations": [{
            "path": "https://api.example.com/share", "method": "GET", "parameters": [{"name": "token"}]}]}}),
        "parser_boundary": record("analysis", {"analyzer": "openapi", "result": {"observations": [{
            "path": "https://api.example.com/upload", "method": "POST", "parameters": [{"name": "filename"}]}]}}),
        "outbound_http": record("analysis", {"analyzer": "openapi", "result": {"observations": [{
            "path": "https://api.example.com/preview", "method": "POST", "parameters": [{"name": "url"}]}]}}),
        "hidden_api": record("analysis", {"analyzer": "openapi", "result": {"observations": [{
            "path": "https://api.example.com/admin/users", "method": "GET",
            "security_declaration": "optional_or_none"}]}}),
        "browser_trust": record("analysis", {"analyzer": "source_context", "asset": "https://api.example.com/account",
            "result": {"lines": [{"snippet": "const role = localStorage.getItem('role')"}]}}),
    }
    return {name: ScoutContext(p, ref, value) for name, value in values.items()}


def proposal(**changes):
    values = dict(program_id="example", scout_type="hidden_api", asset="https://api.example.com/admin/users",
        title="Review authorization", finding_category="hidden-api-authorization",
        observation_ids=["1" * 32], source_record_ids=["1" * 32],
        invariant="Administrative operations require server-side authorization.",
        evidence_summary="Saved structural evidence.", observed_fact="A saved response structure was observed.",
        why_may_matter="A role boundary may need verification.", missing_evidence="Runtime policy is not verified.",
        confidence=.6, estimated_impact=.8, novelty=.7, required_followup=["Independent review"],
        identity_context="user_a", endpoint_shape="GET /admin/users", resource_type="account",
        estimated_requests=1, program=reference())
    values.update(changes)
    return CandidateProposal(**values).validated()


def active_program(program_settings, *, excluded=()):
    from ctf_mcp.program_store import ProgramStore
    store = ProgramStore(program_settings.programs_root)
    store.create(example(program_id="example", scope={"in_scope": [{"host": "api.example.com", "paths": ["/*"]}]},
                         excluded_finding_categories=list(excluded)))
    approve_program(store)
    store.use("example")
    approved, approval = store.selected()
    ref = {"program_id": "example", "approval_id": approval["approval_id"], "sha256": approval["sha256"]}
    return store, approved, ref


@pytest.mark.parametrize("scout_class", SCOUTS, ids=lambda scout: scout.scout_type)
def test_each_scout_is_bounded_and_malformed_safe(scout_class):
    scout = scout_class()
    output = scout.analyze(contexts()[scout.scout_type], 1)
    assert 0 < len(output) <= 1
    assert output[0].scout_type == scout.scout_type
    malformed = ScoutContext(profile(), reference(), record("analysis", {"result": object()}))
    try: result = scout.analyze(malformed, 1)
    except (KeyError, TypeError, ValueError): result = []
    assert len(result) <= 1


def test_proposal_redaction_and_experiment_request_has_no_authority():
    p = proposal(evidence_summary='password = "SYNTHETIC SECRET VALUE"')
    saved = p.to_dict()
    assert "SYNTHETIC" not in json.dumps(saved)
    request = ExperimentRequest(p.proposal_id, p.program_id, "user_a", "GET", p.asset,
        "Collect one bounded observation", "Compare response structure", 1).to_dict()
    assert request["authorization"] is False and request["session_grant_required"] is True
    with pytest.raises(Rejected, match="cannot_authorize"):
        ExperimentRequest(p.proposal_id, p.program_id, "user_a", "GET", p.asset,
            "Purpose", "Signal", 1, authorization=True).to_dict()

    context = contexts()["capability"]
    secret_path_record = {**context.record, "payload": {"analyzer": "openapi", "result": {
        "observations": [{"path": "https://api.example.com/share/short-secret",
                          "parameters": [{"name": "token"}]}]}}}
    capability = next(cls for cls in SCOUTS if cls.scout_type == "capability")()
    output = capability.analyze(ScoutContext(context.profile, context.program_reference, secret_path_record), 1)[0]
    assert "short-secret" not in output.to_dict()["asset"]


def test_scout_modules_have_no_network_or_device_execution_imports():
    root = Path(__file__).resolve().parents[1] / "src/ctf_mcp/scouts"
    forbidden = {"requests", "httpx", "socket", "playwright", "frida", "adb"}
    for path in root.glob("*.py"):
        tree = ast.parse(path.read_text())
        imported = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import): imported |= {alias.name.split(".")[0] for alias in node.names}
            elif isinstance(node, ast.ImportFrom) and node.module: imported.add(node.module.split(".")[0])
        assert not imported & forbidden
        assert "urlopen(" not in path.read_text()


def test_structural_dedup_program_and_invariant_boundaries():
    dedup = SemanticDeduplicator(semantic_backend=lambda *_: (_ for _ in ()).throw(RuntimeError()))
    a = proposal()
    b = proposal(proposal_id=uuid4().hex)
    assert dedup.compare(b, a)["duplicate"]
    other_program = proposal(proposal_id=uuid4().hex, program_id="second",
        program=reference("second"))
    assert not dedup.compare(other_program, a)["duplicate"]
    other_invariant = proposal(proposal_id=uuid4().hex,
        invariant="Audit logs must be complete and immutable.")
    assert not dedup.compare(other_invariant, a)["duplicate"]
    assert 0 <= dedup.similarity(a, other_invariant) <= 1


def test_triage_is_deterministic_bounded_and_policy_aware():
    triager = CheapTriager()
    p = proposal()
    assert triager.triage(p, profile()) == triager.triage(p, profile())
    assert triager.triage(proposal(finding_category="rate-limit-only"), profile())["decision"] == "PROGRAM_EXCLUDED"
    low = triager.triage(proposal(observation_ids=[], source_record_ids=[]), profile())
    assert low["decision"] == "LOW_EVIDENCE"
    uncertain = triager.triage(proposal(confidence=.1, estimated_impact=1.0), profile())
    assert uncertain["estimated_impact"] == 1.0 and uncertain["confidence"] == .1
    assert .05 <= uncertain["estimated_cost"] <= 1.0
    assert uncertain["cvss_assigned"] is False
    assert triager.triage(proposal(), profile(identities=["anonymous"]))["decision"] == "IDENTITY_UNAVAILABLE"
    assert triager.triage(proposal(estimated_requests=100), profile())["decision"] == "PROGRAM_BUDGET_EXCEEDED"


def test_portfolio_ev_exploration_diversity_cap_and_seed():
    items = []
    for index in range(20):
        p = proposal(proposal_id=f"{index + 1:032x}", program_id="a" if index < 12 else "b",
            program=reference("a" if index < 12 else "b"),
            asset=f"https://api.example.com/item/{index // 3}",
            finding_category="category-" + str(index % 3), novelty=index / 20,
            confidence=.3 + index / 40, estimated_impact=.9 - index / 100)
        items.append((p, {"decision": "ELIGIBLE", "estimated_cost": .2 + index / 100}))
    policy = PortfolioPolicy(per_program_cap=5, max_per_asset_category=1, seed=42)
    first = ModelPortfolioSelector(policy).select(items, 10)
    second = ModelPortfolioSelector(policy).select(items, 10)
    assert first == second
    assert any(item["selection_reason"] == "exploration" for item in first["members"])
    assert max(Counter(item["program_id"] for item in first["members"]).values()) <= 5
    pairs = [(next(p for p, _ in items if p.proposal_id == item["proposal_id"]).asset,
              next(p for p, _ in items if p.proposal_id == item["proposal_id"]).finding_category)
             for item in first["members"]]
    assert len(pairs) == len(set(pairs))
    fallback = ModelPortfolioSelector(policy, reviewer=lambda _items: (_ for _ in ()).throw(RuntimeError()))
    reviewed = fallback.select(items, 10)
    assert reviewed["selected_count"] == first["selected_count"] and reviewed["model_calls"] == 1


def test_pipeline_freshness_program_isolation_dedup_and_promotion(program_settings):
    store, _, ref = active_program(program_settings)
    records = Records(program_settings.results_root, programs_root=store.root)
    evidence = records.save("analysis", {"analyzer": "openapi", "program": ref,
        "result": {"observations": [{"path": "https://api.example.com/share", "method": "GET",
                                      "parameters": [{"name": "token"}]}]}})
    controller = ScoutPortfolioController(program_settings)
    first = controller.run(record_id=evidence["id"], portfolio_slots=5)
    assert first["scan"]["proposal_count"] == 1 and first["network_requests_sent"] == 0
    proposal_id = first["scan"]["proposal_ids"][0]
    promoted = controller.promote(proposal_id)
    repeated = controller.promote(proposal_id)
    assert promoted["candidate_status"] == "DISCOVERED" and not promoted["confirmed"]
    assert repeated["candidate_id"] == promoted["candidate_id"] and repeated["already_promoted"]
    second = ScoutPipeline(program_settings).run(record_id=evidence["id"])
    assert second["proposal_count"] == 0 and second["freshness_skips"] == len(SCOUTS)
    forced = ScoutPipeline(program_settings).run(record_id=evidence["id"], force=True)
    assert forced["proposal_count"] == 1
    relations = controller.dedup_status()
    assert relations["duplicate_count"] >= 1 and len(relations["relations"]) >= 2

    wrong = records.save("analysis", {"analyzer": "openapi", "program": {**ref, "program_id": "second"},
        "result": {"observations": []}})
    with pytest.raises(Rejected, match="program_mismatch"):
        ScoutPipeline(program_settings).run(record_id=wrong["id"])


def test_revoked_modified_excluded_and_out_of_scope_block_promotion(program_settings):
    store, _, ref = active_program(program_settings, excluded=("capability-token",))
    records = Records(program_settings.results_root, programs_root=store.root)
    evidence = records.save("analysis", {"analyzer": "openapi", "program": ref,
        "result": {"observations": [{"path": "https://api.example.com/share", "parameters": [{"name": "token"}]}]}})
    controller = ScoutPortfolioController(program_settings)
    run = controller.run(record_id=evidence["id"])
    proposal_id = run["scan"]["proposal_ids"][0]
    with pytest.raises(Rejected, match="program_excluded"):
        controller.promote(proposal_id)
    store.revoke("example")
    with pytest.raises(Rejected, match="revoked"):
        controller.promote(proposal_id)

    # A changed source profile invalidates its prior approval before any candidate write.
    approve_program(store)
    store.use("example")
    path = store.root / "example/program.json"
    value = json.loads(path.read_text())
    value["name"] = "changed"
    path.write_text(json.dumps(value))
    with pytest.raises(Rejected, match="reapproval"):
        controller.promote(proposal_id)


def test_out_of_scope_never_promotes(program_settings):
    store, _, ref = active_program(program_settings)
    records = Records(program_settings.results_root, programs_root=store.root)
    p = proposal(asset="https://outside.example.org/admin", program=ref,
                 observation_ids=[], source_record_ids=[])
    records.save("scout_proposal", p.to_dict())
    controller = ScoutPortfolioController(program_settings)
    with pytest.raises(Rejected, match="outside_program"):
        controller.promote(p.proposal_id)
    assert controller.proposals()["proposals"][0]["current_status"] == "BLOCKED_SCOPE"


def test_ledger_corruption_rebuild_and_transaction_rollback(program_settings):
    store, _, ref = active_program(program_settings)
    records = Records(program_settings.results_root, programs_root=store.root)
    p = proposal(program=ref)
    saved = records.save("scout_proposal", p.to_dict())
    ledger = ScoutLedger(program_settings.results_root)
    ledger.sync(records)
    assert ledger.rows("proposals")[0]["proposal_id"] == p.proposal_id
    ledger.path.write_bytes(b"not sqlite")
    recovered = ScoutLedger(program_settings.results_root)
    recovered.sync(records)
    assert recovered.recovered_corruption and records.read(saved["id"])["payload"]["proposal_id"] == p.proposal_id
    marker = uuid4().hex
    with pytest.raises(RuntimeError):
        with recovered.transaction() as connection:
            connection.execute("INSERT INTO model_usage VALUES (?,?,?,?,?,?,?,?,?)",
                (marker, None, "Scout", None, None, 0, 0, "TEST", "now"))
            raise RuntimeError()
    assert not any(row["usage_id"] == marker for row in recovered.rows("model_usage"))


def test_scout_mcp_is_readonly_and_has_no_sql_surface(program_settings):
    active_program(program_settings)
    async def run():
        server = create_server(program_settings)
        tools = {tool.name: tool for tool in await server.list_tools()}
        names = {"scout_status", "list_scout_proposals", "read_scout_proposal",
                 "scout_dedup_status", "scout_triage_status", "scout_portfolio_status"}
        assert names <= tools.keys()
        for name in names:
            assert tools[name].annotations.readOnlyHint and not tools[name].annotations.openWorldHint
            assert "sql" not in json.dumps(tools[name].inputSchema).lower()
        result = await server.call_tool("scout_status", {})
        assert not getattr(result, "isError", False)
    asyncio.run(run())


def test_scout_cli_commands_and_unrelated_cwd(program_settings, tmp_path):
    store, _, ref = active_program(program_settings)
    records = Records(program_settings.results_root, programs_root=store.root)
    evidence = records.save("analysis", {"analyzer": "openapi", "program": ref,
        "result": {"observations": [{"path": "https://api.example.com/share",
                                      "parameters": [{"name": "token"}]}]}})
    original = (program_settings.results_root / (evidence["id"] + ".json")).read_bytes()
    config = tmp_path / "settings.json"
    config.write_text(json.dumps({"input_root": str(program_settings.input_root),
        "results_root": str(program_settings.results_root), "grants_root": str(program_settings.grants_root),
        "programs_root": str(program_settings.programs_root)}))
    env = {"PYTHONPATH": str(Path(__file__).resolve().parents[1] / "src"), "FINDER_CONFIG": str(config)}
    def cli(*arguments):
        result = subprocess.run([sys.executable, "-m", "ctf_mcp.cli", "scout", *arguments], cwd=tmp_path,
            env=env, text=True, capture_output=True, timeout=20)
        assert result.returncode == 0, result.stderr
        return json.loads(result.stdout)
    run = cli("run", "--record", evidence["id"])
    proposal_id = run["scan"]["proposal_ids"][0]
    assert cli("proposal", proposal_id)["proposal"]["proposal_id"] == proposal_id
    assert cli("promote", proposal_id)["candidate_status"] == "DISCOVERED"
    for action in ("status", "proposals", "triage", "portfolio", "doctor"):
        cli(action)
    assert (program_settings.results_root / (evidence["id"] + ".json")).read_bytes() == original
    help_result = subprocess.run([sys.executable, "-m", "ctf_mcp.cli", "scout", "--help"], cwd=tmp_path,
        env=env, text=True, capture_output=True, timeout=20)
    assert all(action in help_result.stdout for action in
               ("run", "status", "proposals", "proposal", "triage", "portfolio", "promote", "doctor"))


def test_host_launcher_routes_scout_without_paths_or_shell(tmp_path):
    import importlib.util
    root = Path(__file__).resolve().parents[1]
    spec = importlib.util.spec_from_file_location("control", root / "scripts/control.py")
    control = importlib.util.module_from_spec(spec); spec.loader.exec_module(control)
    command = control.commands("scout", ["status"], {})[0]
    assert command[-3:] == ["operator", "scout", "status"]
    assert "sh" not in command and "bash" not in command
    with pytest.raises(ValueError):
        control.commands("scout", ["proposal", "../escape"], {})
