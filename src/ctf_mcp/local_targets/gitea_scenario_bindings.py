"""Reviewed fixture and route bindings for Gitea full-hunt scenarios."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Callable, Mapping

from ctf_mcp.full_hunt.scenario import ScenarioBinding, ScenarioPlan
from ctf_mcp.local_targets.base import LocalTargetError, secure_directory
from ctf_mcp.records import Records

from .gitea_http import (
    ORGANIZATION,
    ORG_PRIVATE_REPOSITORY,
    OUTSIDER,
    OWNER,
    REPOSITORY,
    team_repository_path,
)


SOURCE_ASSERTIONS = (
    "route_exists", "handler_resolved", "model_query_resolved",
    "trace_edges_resolved", "viewer_binding_present",
    "visibility_helper_present", "candidate_pattern_observed",
)


class GiteaScenarioBindings:
    def __init__(
        self,
        local_adapter: Any | None,
        candidate_lookup: Callable[[str], Mapping[str, Any] | None],
    ):
        self.local = local_adapter
        self.candidate_lookup = candidate_lookup

    def bindings(self) -> tuple[ScenarioBinding, ...]:
        common = {
            "required_capabilities": (
                "create_identity", "create_private_resource", "remove_member",
                "resolve_route", "read_owned_fixture",
            ),
            "fixture_roles": ("control_identity", "probe_identity"),
            "resource_roles": ("restricted_resource",),
            "request_budget": 2,
            "safety_requirements": (
                "localhost_only", "read_only", "bounded_requests", "reviewed_routes",
            ),
            "control_builder": _control_request,
            "probe_builder": _probe_request,
            "assertion_builder": _assertions,
        }
        return (
            ScenarioBinding(
                binding_id="gitea-resource-id-visibility-v1",
                pattern="VISIBILITY_BOUNDARY_MISMATCH",
                candidate_pattern=_resource_id_match,
                fixture_resolver=self._resource_fixture,
                route_resolver=_resource_id_routes,
                **common,
            ),
            ScenarioBinding(
                binding_id="gitea-group-resource-visibility-v1",
                pattern="VISIBILITY_BOUNDARY_MISMATCH",
                candidate_pattern=_group_resource_match,
                fixture_resolver=self._group_fixture,
                route_resolver=_group_resource_routes,
                **common,
            ),
        )

    def check(self, plan: ScenarioPlan) -> Mapping[str, Any]:
        state = self._state()
        current = self.candidate_lookup(plan.candidate_id)
        source_ok = bool(
            current
            and all(current.get("source_assertions", {}).get(key) is value
                    for key, value in plan.source_assertions.items())
            and current.get("source_facts") == list(plan.candidate_source_facts)
        )
        if not source_ok:
            return {"available": False, "reason": "source_assertion_mismatch"}
        if self.local is None or not self.local.health().get("healthy"):
            return {"available": False, "reason": "runtime_not_healthy"}
        expected = self._fixture_for_binding(plan.binding_id, state)
        if plan.fixture_mapping != expected:
            return {"available": False, "reason": "fixture_mismatch"}
        return {
            "available": True,
            "binding_id": plan.binding_id,
            "fixture_marker": expected["restricted_resource"],
            "source_assertions_valid": True,
        }

    def execute(self, plan: ScenarioPlan) -> Mapping[str, Any]:
        if self.local is None:
            raise LocalTargetError("SCENARIO_FIXTURE_UNAVAILABLE")
        state = self._state()
        expected = self._fixture_for_binding(plan.binding_id, state)
        if plan.fixture_mapping != expected:
            raise LocalTargetError("fixture_mismatch")
        passwords = self.local._load_secrets(create=False)
        control_client = self.local._identity_client(expected["control_role"], passwords)
        probe_client = self.local._identity_client(expected["probe_role"], passwords)
        path = str(plan.route_mapping["resolved_path"])
        control = control_client.request("scenario", "GET", path)
        probe = probe_client.request("scenario", "GET", path)
        marker = expected["restricted_resource"]
        control_marker = _resource_marker(control.data) == marker
        probe_marker = _resource_marker(probe.data) == marker
        control_passed = control.status == 200 and control_marker
        recognized_denial = probe.status in {401, 403, 404} and not probe_marker
        recognized_exposure = probe.status == 200 and probe_marker
        generic_error = control.status >= 500 or probe.status >= 500
        deterministic = control_passed and not generic_error and (
            recognized_denial or recognized_exposure
        )
        source_valid = self.check(plan).get("source_assertions_valid") is True
        secure_directory(self.local.evidence_root)
        evidence = Records(self.local.evidence_root).save("scenario_validation", {
            "target": "gitea",
            "candidate_id": plan.candidate_id,
            "binding_id": plan.binding_id,
            "pattern": plan.binding_pattern,
            "confidence": plan.binding_confidence,
            "fixture_marker": marker,
            "control": {
                "method": "GET", "path": path, "status": control.status,
                "response_shape": control.shape, "marker_present": control_marker,
            },
            "probe": {
                "method": "GET", "path": path, "status": probe.status,
                "response_shape": probe.shape, "marker_present": probe_marker,
            },
            "request_count": control_client.request_count + probe_client.request_count,
            "source_assertion_valid": source_valid,
            "invariant_violated": recognized_exposure,
        })
        return {
            "request_count": control_client.request_count + probe_client.request_count,
            "final_urls": [plan.control_request["url"], plan.probe_request["url"]],
            "fixture_valid": True,
            "source_assertion_valid": source_valid,
            "control_passed": control_passed,
            "response_status_only": False,
            "probe_deterministic": deterministic,
            "ambiguous": not deterministic,
            "transport_error": False,
            "generic_server_error": generic_error,
            "invariant_violated": recognized_exposure,
            "evidence_saved": isinstance(evidence.get("id"), str),
            "evidence": evidence["id"],
            "control_marker_present": control_marker,
            "probe_marker_present": probe_marker,
        }

    def _state(self) -> dict[str, Any]:
        if self.local is None:
            raise LocalTargetError("SCENARIO_FIXTURE_UNAVAILABLE")
        path: Path = self.local.bootstrap_file
        try:
            if path.is_symlink() or path.stat().st_size > 128 * 1024:
                raise LocalTargetError("SCENARIO_FIXTURE_UNAVAILABLE")
            value = json.loads(path.read_text(encoding="utf-8"))
        except LocalTargetError:
            raise
        except (OSError, ValueError, TypeError):
            raise LocalTargetError("SCENARIO_FIXTURE_UNAVAILABLE") from None
        if (not isinstance(value, dict)
                or value.get("marker") != "FINDER_LOCAL_GITEA_BOOTSTRAP_V1"
                or value.get("target_commit") != self.local.runtime_commit
                or not isinstance(value.get("repository_id"), int)
                or not isinstance(value.get("team_id"), int)
                or not isinstance(value.get("usernames"), dict)):
            raise LocalTargetError("SCENARIO_FIXTURE_UNAVAILABLE")
        return value

    def _resource_fixture(self, candidate: Mapping[str, Any]) -> Mapping[str, Any]:
        del candidate
        return self._fixture_for_binding("gitea-resource-id-visibility-v1", self._state())

    def _group_fixture(self, candidate: Mapping[str, Any]) -> Mapping[str, Any]:
        del candidate
        return self._fixture_for_binding("gitea-group-resource-visibility-v1", self._state())

    def _fixture_for_binding(self, binding_id: str | None, state: Mapping[str, Any]) -> dict[str, Any]:
        usernames = state["usernames"]
        if binding_id == "gitea-resource-id-visibility-v1":
            return {
                "control_identity": str(usernames["repo_owner"]),
                "probe_identity": str(usernames["outsider"]),
                "restricted_resource": OWNER + "/" + REPOSITORY,
                "resource_id": int(state["repository_id"]),
                "control_role": "repo_owner", "probe_role": "outsider",
                "runtime_port": int(self.local.runtime_port),
            }
        if binding_id == "gitea-group-resource-visibility-v1":
            return {
                "control_identity": str(usernames["collaborator"]),
                "probe_identity": str(usernames["outsider"]),
                "restricted_resource": ORGANIZATION + "/" + ORG_PRIVATE_REPOSITORY,
                "group_id": int(state["team_id"]),
                "control_role": "collaborator", "probe_role": "outsider",
                "runtime_port": int(self.local.runtime_port),
            }
        raise LocalTargetError("SCENARIO_FIXTURE_UNAVAILABLE")


def _resource_id_match(candidate: Mapping[str, Any]) -> str:
    if candidate.get("route") == {
        **candidate.get("route", {}), "method": "GET", "path": "/repositories/{id}",
    }:
        assertions = candidate.get("source_assertions", {})
        required = SOURCE_ASSERTIONS[:-1]
        if all(assertions.get(key) is True for key in required) and assertions.get("candidate_pattern_observed") is True:
            return "STRONG"
    return "NONE"


def _group_resource_match(candidate: Mapping[str, Any]) -> str:
    route = candidate.get("route", {})
    if (route.get("method") == "GET"
            and route.get("path") == "/teams/{teamid}/repos/{org}/{reponame}"):
        assertions = candidate.get("source_assertions", {})
        if all(assertions.get(key) is True for key in SOURCE_ASSERTIONS[:-1]):
            return "STRONG" if assertions.get("candidate_pattern_observed") is True else "WEAK"
    return "NONE"


def _resource_id_routes(candidate: Mapping[str, Any], fixture: Mapping[str, Any]) -> Mapping[str, Any]:
    path = "/api/v1/repositories/" + str(fixture["resource_id"])
    url = f"http://127.0.0.1:{fixture['runtime_port']}{path}"
    return {
        "candidate_route": candidate["route"]["path"],
        "reviewed_source_routes": [candidate["route"]["path"]],
        "resolved_path": path, "control_url": url, "probe_url": url,
    }


def _group_resource_routes(candidate: Mapping[str, Any], fixture: Mapping[str, Any]) -> Mapping[str, Any]:
    path = team_repository_path(int(fixture["group_id"]), ORG_PRIVATE_REPOSITORY)
    url = f"http://127.0.0.1:{fixture['runtime_port']}{path}"
    return {
        "candidate_route": candidate["route"]["path"],
        "reviewed_source_routes": [candidate["route"]["path"]],
        "resolved_path": path, "control_url": url, "probe_url": url,
    }


def _control_request(
    candidate: Mapping[str, Any], fixture: Mapping[str, Any], routes: Mapping[str, Any],
) -> Mapping[str, Any]:
    del candidate, fixture
    return {"method": "GET", "url": routes["control_url"],
            "purpose": "authorized fixture body baseline", "read_only": True}


def _probe_request(
    candidate: Mapping[str, Any], fixture: Mapping[str, Any], routes: Mapping[str, Any],
) -> Mapping[str, Any]:
    del candidate, fixture
    return {"method": "GET", "url": routes["probe_url"],
            "purpose": "restricted identity body visibility comparison", "read_only": True}


def _assertions(candidate: Mapping[str, Any], fixture: Mapping[str, Any]) -> Mapping[str, Any]:
    assertions = candidate.get("source_assertions", {})
    required = {
        key: assertions.get(key) is True
        for key in SOURCE_ASSERTIONS[:-1]
    }
    if assertions.get("candidate_pattern_observed") is True:
        required["candidate_pattern_observed"] = True
    return {
        "security_invariant": candidate.get("security_invariant")
        or "A restricted fixture must not be returned to the restricted identity.",
        "expected_control": {"body_marker": fixture["restricted_resource"]},
        "violation_condition": {"probe_body_marker": fixture["restricted_resource"]},
        "source_assertions": required,
        "rationale": "A reviewed source route resolves to an existing owned fixture and two fixed identities.",
    }


def _resource_marker(value: Any) -> str | None:
    if not isinstance(value, dict):
        return None
    full_name = value.get("full_name")
    return full_name if isinstance(full_name, str) else None
