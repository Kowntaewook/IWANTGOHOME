import json
from pathlib import Path

import pytest

from ctf_mcp.full_hunt.scenario import (
    ScenarioPlan,
    TargetCapabilities,
    execute_scenario,
    not_generatable,
    redact,
    scenario_summary,
    validate_scenario_plan,
    write_scenario_artifacts,
)
from ctf_mcp.local_targets.base import LocalTargetError


CAPABILITIES = TargetCapabilities(
    fixture_actions=frozenset({"create_identity", "create_private_resource", "resolve_route"}),
    supports_read_only_probe=True,
)


def plan(**changes):
    values = {
        "candidate_id": "FX-001",
        "target_id": "fake",
        "required_identities": ("finder-local-owner", "finder-local-viewer"),
        "required_resources": ("finder-local-private-item",),
        "fixture_requirements": ("create_identity", "create_private_resource", "resolve_route"),
        "control_request": {
            "method": "GET", "url": "http://127.0.0.1:14000/control",
            "purpose": "authorized baseline", "read_only": True,
        },
        "probe_request": {
            "method": "GET", "url": "http://127.0.0.1:14000/probe",
            "purpose": "restricted comparison", "read_only": True,
        },
        "security_invariant": "Restricted content stays outside the viewer response.",
        "expected_control": {"body_contains_fixture": True},
        "violation_condition": {"probe_contains_fixture": True},
        "request_budget": 3,
        "cleanup_requirements": ("bootstrap_owned",),
        "source_assertions": {"route_resolved": True, "authorization_resolved": True},
        "confidence": "high",
        "safety_classification": "LOCAL_READ_ONLY",
        "rationale": "The route and authorization path resolve to an owned fixture.",
    }
    values.update(changes)
    return ScenarioPlan(**values)


def successful_execution(**changes):
    value = {
        "request_count": 2,
        "final_urls": ["http://127.0.0.1:14000/control", "http://127.0.0.1:14000/probe"],
        "fixture_valid": True,
        "source_assertion_valid": True,
        "control_passed": True,
        "response_status_only": False,
        "probe_deterministic": True,
        "ambiguous": False,
        "invariant_violated": True,
        "evidence_saved": True,
        "evidence": "evidence-1",
    }
    value.update(changes)
    return value


def run(value=None, execution=None):
    return execute_scenario(
        value or plan(), CAPABILITIES,
        fixture_check=lambda _: {"available": True, "marker": "finder-local-private-item"},
        execute=lambda _: execution or successful_execution(),
    )


def test_valid_scenario_generation_and_deterministic_execution():
    value = validate_scenario_plan(plan(), CAPABILITIES)
    scenario, local = run(value)
    assert scenario["status"] == "SCENARIO_EXECUTED"
    assert local["status"] == "VERIFIED_LOCAL"
    assert local["assertions"]["control_passed"] is True


def test_insufficient_source_facts_are_not_generatable():
    assert not_generatable("FX-1", "fake", "missing_source_facts") == {
        "status": "SCENARIO_NOT_GENERATABLE", "candidate_id": "FX-1",
        "target_id": "fake", "blocker": "missing_source_facts",
    }
    with pytest.raises(LocalTargetError, match="SCENARIO_UNSAFE"):
        validate_scenario_plan(plan(source_assertions={"route_resolved": False}), CAPABILITIES)


def test_unsupported_capability_is_rejected():
    with pytest.raises(LocalTargetError, match="SCENARIO_UNSAFE"):
        validate_scenario_plan(plan(fixture_requirements=("arbitrary_action",)), CAPABILITIES)


@pytest.mark.parametrize("url", [
    "https://127.0.0.1:14000/probe",
    "http://example.com/probe",
    "http://10.0.0.1/probe",
    "http://user@localhost/probe",
])
def test_localhost_enforcement_blocks_external_or_credentialed_urls(url):
    probe = {**plan().probe_request, "url": url}
    with pytest.raises(LocalTargetError, match="SCENARIO_UNSAFE"):
        validate_scenario_plan(plan(probe_request=probe), CAPABILITIES)


def test_destructive_probe_is_blocked():
    probe = {**plan().probe_request, "method": "DELETE"}
    with pytest.raises(LocalTargetError, match="SCENARIO_UNSAFE"):
        validate_scenario_plan(plan(probe_request=probe), CAPABILITIES)


def test_request_budget_blocks_execution_result_over_limit():
    scenario, local = run(execution=successful_execution(request_count=4))
    assert scenario["status"] == "SCENARIO_BLOCKED"
    assert scenario["blocker"] == "scenario_request_budget_exceeded"
    assert local is None


def test_control_failure_never_verifies_candidate():
    scenario, local = run(execution=successful_execution(control_passed=False))
    assert scenario["blocker"] == "control_failed"
    assert local is None


def test_probe_without_violation_is_intended_behavior():
    scenario, local = run(execution=successful_execution(invariant_violated=False))
    assert scenario["status"] == "SCENARIO_EXECUTED"
    assert local["status"] == "INTENDED_BEHAVIOR"


def test_status_only_empty_or_ambiguous_observation_is_blocked():
    for changes, reason in (
        ({"response_status_only": True}, "response_status_only_insufficient"),
        ({"probe_deterministic": False}, "ambiguous_probe_result"),
        ({"ambiguous": True}, "ambiguous_probe_result"),
    ):
        scenario, local = run(execution=successful_execution(**changes))
        assert scenario["blocker"] == reason
        assert local is None


def test_fixture_source_and_redirect_mismatch_abort():
    for changes, reason in (
        ({"fixture_valid": False}, "fixture_mismatch"),
        ({"source_assertion_valid": False}, "source_assertion_mismatch"),
        ({"final_urls": ["http://example.com/redirect"]}, "scenario_redirect_outside_localhost"),
    ):
        scenario, local = run(execution=successful_execution(**changes))
        assert scenario["blocker"] == reason
        assert local is None


def test_generated_but_fixture_blocked_remains_manual():
    scenario, local = execute_scenario(
        plan(), CAPABILITIES,
        fixture_check=lambda _: {"available": False, "reason": "fixture_missing"},
        execute=lambda _: pytest.fail("execution must not run"),
    )
    assert scenario["status"] == "SCENARIO_BLOCKED"
    assert scenario["blocker"] == "fixture_missing"
    assert local is None
    assert scenario_summary([{
        "scenario_synthesis": scenario, "classification": "NEEDS_MANUAL_SCENARIO",
    }])["scenario_manual_remaining"] == 1


def test_redaction_and_report_serialization(tmp_path):
    scenario, _ = run(execution=successful_execution(token="do-not-render", password="hidden"))
    assert redact({"Authorization": "Bearer secret", "nested": {"token": "x"}}) == {
        "Authorization": "[REDACTED]", "nested": {"token": "[REDACTED]"},
    }
    report = tmp_path / ".operator/reports/fake/run-1"
    report.mkdir(parents=True)
    paths = write_scenario_artifacts(
        tmp_path, ".operator/reports/fake/run-1", [{"scenario_synthesis": scenario}],
    )
    assert len(paths) == 2
    raw = (report / "scenarios/FX-001.json").read_text()
    assert "do-not-render" not in raw and "hidden" not in raw
    assert json.loads(raw)["execution_result"]["token"] == "[REDACTED]"


def test_core_scenario_module_has_no_target_specific_vocabulary():
    raw = (Path(__file__).parents[1] / "src/ctf_mcp/full_hunt/scenario.py").read_text().lower()
    for forbidden in ("acme_product", "example_vendor", "/vendor/api/", "/private/product/"):
        assert forbidden not in raw
