from pathlib import Path
import re

import pytest

from ctf_mcp.full_hunt.scenario import (
    ScenarioBinding,
    ScenarioPlan,
    TargetCapabilities,
    synthesize_from_bindings,
    validate_scenario_plan,
)
from ctf_mcp.local_targets.base import LocalTargetError


CAPABILITIES = TargetCapabilities(
    fixture_actions=frozenset({"create_identity", "create_private_resource", "resolve_route"}),
    supports_read_only_probe=True,
)


def candidate(candidate_id="FX-1"):
    return {
        "candidate_id": candidate_id,
        "route": {"method": "GET", "path": "/objects/{id}", "location": "source:10"},
        "security_invariant": "restricted marker stays hidden",
        "source_assertions": {"route": True, "auth_path": True},
        "source_facts": [{"location": "source:10", "sha256": "a" * 64}],
    }


def binding(pattern="VISIBILITY_BOUNDARY_MISMATCH", confidence="EXACT", **changes):
    def fixture(value):
        return {
            "allowed_identity": "finder-local-owner",
            "limited_identity": "finder-local-viewer",
            "restricted_object": "finder-local-private-object",
        }

    def routes(value, fixtures):
        return {
            "reviewed_source_routes": [value["route"]["path"]],
            "control_url": "http://127.0.0.1:14000/control",
            "probe_url": "http://127.0.0.1:14000/probe",
        }

    values = {
        "binding_id": "fake-binding-v1",
        "pattern": pattern,
        "required_capabilities": ("create_identity", "create_private_resource", "resolve_route"),
        "fixture_roles": ("allowed_identity", "limited_identity"),
        "resource_roles": ("restricted_object",),
        "request_budget": 3,
        "safety_requirements": ("localhost_only", "read_only", "bounded_requests", "reviewed_routes"),
        "candidate_pattern": lambda value: confidence,
        "fixture_resolver": fixture,
        "route_resolver": routes,
        "control_builder": lambda value, fixtures, resolved: {
            "method": "GET", "url": resolved["control_url"],
            "purpose": "allowed body baseline", "read_only": True,
        },
        "probe_builder": lambda value, fixtures, resolved: {
            "method": "GET", "url": resolved["probe_url"],
            "purpose": "restricted body comparison", "read_only": True,
        },
        "assertion_builder": lambda value, fixtures: {
            "security_invariant": value["security_invariant"],
            "expected_control": {"marker": fixtures["restricted_object"]},
            "violation_condition": {"marker": fixtures["restricted_object"]},
            "source_assertions": value["source_assertions"],
            "rationale": "reviewed source and fixture mapping",
        },
    }
    values.update(changes)
    return ScenarioBinding(**values)


@pytest.mark.parametrize("confidence", ["EXACT", "STRONG"])
def test_binding_exact_and_strong_match_generate_safe_plan(confidence):
    result = synthesize_from_bindings(
        candidate=candidate(), target_id="fake",
        bindings=(binding(confidence=confidence),), capabilities=CAPABILITIES,
    )
    assert isinstance(result, ScenarioPlan)
    assert result.binding_confidence == confidence
    assert result.binding_id == "fake-binding-v1"
    assert result.fixture_mapping["restricted_object"] == "finder-local-private-object"
    assert validate_scenario_plan(result, CAPABILITIES) is result


def test_binding_weak_is_generated_but_blocked_and_none_is_not_generatable():
    weak = synthesize_from_bindings(
        candidate=candidate(), target_id="fake",
        bindings=(binding(confidence="WEAK"),), capabilities=CAPABILITIES,
    )
    assert weak["status"] == "SCENARIO_BLOCKED"
    assert weak["binding_matched"] is True
    assert weak["confidence"] == "WEAK"
    none = synthesize_from_bindings(
        candidate=candidate(), target_id="fake",
        bindings=(binding(confidence="NONE"),), capabilities=CAPABILITIES,
    )
    assert none["status"] == "SCENARIO_NOT_GENERATABLE"
    assert none["binding_matched"] is False


def test_all_three_generic_patterns_are_supported_without_target_semantics():
    for pattern in (
        "BODY_FILTERING_VS_METADATA_COUNT",
        "DIRECT_OBJECT_VS_COLLECTION_AUTH",
        "VISIBILITY_BOUNDARY_MISMATCH",
    ):
        result = synthesize_from_bindings(
            candidate=candidate(pattern), target_id="fake",
            bindings=(binding(pattern=pattern),), capabilities=CAPABILITIES,
        )
        assert result.binding_pattern == pattern


def test_unsupported_capability_and_missing_fixture_block_before_plan():
    unsupported = synthesize_from_bindings(
        candidate=candidate(), target_id="fake",
        bindings=(binding(required_capabilities=("unsupported_action",)),),
        capabilities=CAPABILITIES,
    )
    assert unsupported["blocker"] == "unsupported_binding_capability"

    def missing(value):
        raise LocalTargetError("SCENARIO_FIXTURE_UNAVAILABLE")

    absent = synthesize_from_bindings(
        candidate=candidate(), target_id="fake",
        bindings=(binding(fixture_resolver=missing),), capabilities=CAPABILITIES,
    )
    assert absent["status"] == "SCENARIO_BLOCKED"
    assert absent["blocker"] == "SCENARIO_FIXTURE_UNAVAILABLE"


def test_route_must_come_from_reviewed_mapping_and_invented_route_is_rejected():
    def invented(value, fixtures):
        return {
            "reviewed_source_routes": [],
            "control_url": "http://127.0.0.1:14000/invented",
            "probe_url": "http://127.0.0.1:14000/probe",
        }

    result = synthesize_from_bindings(
        candidate=candidate(), target_id="fake",
        bindings=(binding(route_resolver=invented),), capabilities=CAPABILITIES,
    )
    assert result["blocker"] == "invalid_binding_resolution"

    valid = synthesize_from_bindings(
        candidate=candidate(), target_id="fake",
        bindings=(binding(),), capabilities=CAPABILITIES,
    )
    changed = ScenarioPlan(**{
        **valid.to_dict(),
        "route_mapping": {**valid.route_mapping, "probe_url": "http://127.0.0.1:14000/other"},
    })
    with pytest.raises(LocalTargetError, match="SCENARIO_UNSAFE"):
        validate_scenario_plan(changed, CAPABILITIES)



def test_core_binding_module_contains_no_adapter_vocabulary():
    raw = (Path(__file__).parents[1] / "src/ctf_mcp/full_hunt/scenario.py").read_text().lower()
    for forbidden in ("acme_product", "example_vendor", "/vendor/api/", "/private/product/"):
        assert forbidden not in raw
    assert re.search(r"\brepo\b|\bchannel\b", raw) is None
