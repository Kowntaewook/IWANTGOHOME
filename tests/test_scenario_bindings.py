import json
from pathlib import Path
import re

import pytest

from ctf_mcp.full_hunt.scenario import (
    ScenarioBinding,
    ScenarioPlan,
    TargetCapabilities,
    execute_scenario,
    synthesize_from_bindings,
    validate_scenario_plan,
)
from ctf_mcp.local_targets.base import LocalTargetError
from ctf_mcp.local_targets.gitea_http import GiteaResponse, OWNER, REPOSITORY
from ctf_mcp.local_targets.gitea_scenario_bindings import GiteaScenarioBindings
from ctf_mcp.local_targets.mattermost_scenario_bindings import MattermostScenarioBindings


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


class FakeClient:
    def __init__(self, response):
        self.response = response
        self.request_count = 0

    def request(self, scope, method, path):
        assert scope == "scenario" and method == "GET" and path.startswith("/api/v1/")
        self.request_count += 1
        return self.response


class FakeGiteaLocal:
    runtime_commit = "1" * 40
    runtime_port = 13000

    def __init__(self, root, exposed=False):
        self.bootstrap_file = root / "bootstrap.json"
        self.evidence_root = root / "evidence"
        self.exposed = exposed
        self.bootstrap_file.write_text(json.dumps({
            "marker": "FINDER_LOCAL_GITEA_BOOTSTRAP_V1",
            "target_commit": self.runtime_commit,
            "repository_id": 17,
            "team_id": 23,
            "usernames": {
                "repo_owner": "finder-local-repo-owner",
                "collaborator": "finder-local-collaborator",
                "outsider": "finder-local-outsider",
            },
        }))

    def health(self):
        return {"healthy": True}

    def _load_secrets(self, create=False):
        return {"repo_owner": "x", "collaborator": "x", "outsider": "x"}

    def _identity_client(self, identity, passwords):
        del passwords
        marker = OWNER + "/" + REPOSITORY
        if identity == "repo_owner" or self.exposed:
            response = GiteaResponse(200, {"full_name": marker}, {"full_name": "str"})
        else:
            response = GiteaResponse(404, {"message": "not found"}, {"message": "str"})
        return FakeClient(response)


def gitea_candidate():
    assertions = {
        "route_exists": True, "handler_resolved": True,
        "model_query_resolved": True, "trace_edges_resolved": True,
        "viewer_binding_present": True, "visibility_helper_present": True,
        "candidate_pattern_observed": True,
    }
    return {
        "candidate_id": "SD-GEN-RESOURCE",
        "route": {"method": "GET", "path": "/repositories/{id}", "location": "api.go:1"},
        "security_invariant": "restricted object stays hidden",
        "source_assertions": assertions,
        "source_facts": [{"location": "api.go:1", "file_sha256": "a" * 64}],
    }


def test_gitea_fixture_and_route_resolution_execute_body_based_invariant(tmp_path):
    value = gitea_candidate()
    local = FakeGiteaLocal(tmp_path)
    bindings = GiteaScenarioBindings(local, lambda candidate_id: value)
    capabilities = TargetCapabilities(
        fixture_actions=frozenset({
            "create_identity", "create_private_resource", "remove_member",
            "resolve_route", "read_owned_fixture",
        }),
        supports_read_only_probe=True,
    )
    plan = synthesize_from_bindings(
        candidate=value, target_id="gitea", bindings=bindings.bindings(),
        capabilities=capabilities,
    )
    assert isinstance(plan, ScenarioPlan)
    assert plan.binding_confidence == "STRONG"
    assert plan.route_mapping["resolved_path"] == "/api/v1/repositories/17"
    scenario, result = execute_scenario(
        plan, capabilities, fixture_check=bindings.check, execute=bindings.execute,
    )
    assert scenario["status"] == "SCENARIO_EXECUTED"
    assert result["status"] == "INTENDED_BEHAVIOR"

    exposed_root = tmp_path / "exposed"
    exposed_root.mkdir()
    exposed = FakeGiteaLocal(exposed_root, exposed=True)
    exposed_bindings = GiteaScenarioBindings(exposed, lambda candidate_id: value)
    exposed_plan = synthesize_from_bindings(
        candidate=value, target_id="gitea", bindings=exposed_bindings.bindings(),
        capabilities=capabilities,
    )
    _, exposed_result = execute_scenario(
        exposed_plan, capabilities,
        fixture_check=exposed_bindings.check, execute=exposed_bindings.execute,
    )
    assert exposed_result["status"] == "VERIFIED_LOCAL"


def test_source_assertion_mismatch_and_control_failure_never_verify(tmp_path):
    value = gitea_candidate()
    local = FakeGiteaLocal(tmp_path)
    current = {**value, "source_assertions": {**value["source_assertions"], "route_exists": False}}
    bindings = GiteaScenarioBindings(local, lambda candidate_id: current)
    capabilities = TargetCapabilities(
        fixture_actions=frozenset({
            "create_identity", "create_private_resource", "remove_member",
            "resolve_route", "read_owned_fixture",
        }), supports_read_only_probe=True,
    )
    plan = synthesize_from_bindings(
        candidate=value, target_id="gitea", bindings=bindings.bindings(), capabilities=capabilities,
    )
    scenario, result = execute_scenario(
        plan, capabilities, fixture_check=bindings.check, execute=bindings.execute,
    )
    assert scenario["blocker"] == "source_assertion_mismatch"
    assert result is None


def test_mattermost_binding_is_isolated_and_destructive_candidate_is_weak():
    value = {
        "candidate_id": "MM-S15",
        "route": {"method": "PUT", "path": "/api/v4/users/{user_id}/teams/{team_id}/threads/read"},
        "source_assertions": {
            "route_exists": True, "handler_resolved": True,
            "authorization_path_resolved": True, "data_access_path_resolved": True,
        },
        "source_facts": [],
    }
    result = synthesize_from_bindings(
        candidate=value, target_id="mattermost",
        bindings=MattermostScenarioBindings().bindings(), capabilities=TargetCapabilities(
            fixture_actions=frozenset({
                "create_identity", "create_private_resource", "remove_member",
                "create_private_content", "resolve_route", "read_owned_fixture",
            }), supports_read_only_probe=True,
        ),
    )
    assert result["status"] == "SCENARIO_BLOCKED"
    assert result["confidence"] == "WEAK"
    assert result["blocker"] == "destructive_validation_method_not_supported"


def test_core_binding_module_contains_no_adapter_vocabulary():
    raw = (Path(__file__).parents[1] / "src/ctf_mcp/full_hunt/scenario.py").read_text().lower()
    for forbidden in ("gitea", "mattermost", "/api/v1/", "/api/v4/"):
        assert forbidden not in raw
    assert re.search(r"\brepo\b|\bchannel\b", raw) is None
