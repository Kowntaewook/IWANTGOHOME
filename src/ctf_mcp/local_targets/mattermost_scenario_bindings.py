"""Reviewed Mattermost scenario bindings kept outside the generic engine."""

from __future__ import annotations

from typing import Any, Mapping

from ctf_mcp.full_hunt.scenario import ScenarioBinding
from ctf_mcp.local_targets.base import LocalTargetError


class MattermostScenarioBindings:
    def bindings(self) -> tuple[ScenarioBinding, ...]:
        return (ScenarioBinding(
            binding_id="mattermost-bulk-state-auth-v1",
            pattern="DIRECT_OBJECT_VS_COLLECTION_AUTH",
            required_capabilities=(
                "create_identity", "create_private_resource", "remove_member",
                "create_private_content", "resolve_route", "read_owned_fixture",
            ),
            fixture_roles=("control_identity", "probe_identity"),
            resource_roles=("restricted_resource",),
            request_budget=4,
            safety_requirements=(
                "localhost_only", "read_only", "bounded_requests", "reviewed_routes",
            ),
            candidate_pattern=_match_bulk_state_candidate,
            fixture_resolver=_unsupported_fixture,
            route_resolver=_unsupported_routes,
            control_builder=_unsupported_request,
            probe_builder=_unsupported_request,
            assertion_builder=_unsupported_assertions,
            weak_blocker="destructive_validation_method_not_supported",
        ),)


def _match_bulk_state_candidate(candidate: Mapping[str, Any]) -> str:
    route = candidate.get("route", {})
    assertions = candidate.get("source_assertions", {})
    if (candidate.get("candidate_id") == "MM-S15"
            and route.get("method") == "PUT"
            and route.get("path") == "/api/v4/users/{user_id}/teams/{team_id}/threads/read"
            and all(assertions.get(key) is True for key in (
                "route_exists", "handler_resolved", "authorization_path_resolved",
                "data_access_path_resolved",
            ))):
        # The source/fixture mapping is exact, but validation would mutate read
        # state.  The generic read-only safety policy therefore blocks it.
        return "WEAK"
    return "NONE"


def _unsupported_fixture(candidate: Mapping[str, Any]) -> Mapping[str, Any]:
    del candidate
    raise LocalTargetError("destructive_validation_method_not_supported")


def _unsupported_routes(
    candidate: Mapping[str, Any], fixture: Mapping[str, Any],
) -> Mapping[str, Any]:
    del candidate, fixture
    raise LocalTargetError("destructive_validation_method_not_supported")


def _unsupported_request(
    candidate: Mapping[str, Any], fixture: Mapping[str, Any], routes: Mapping[str, Any],
) -> Mapping[str, Any]:
    del candidate, fixture, routes
    raise LocalTargetError("destructive_validation_method_not_supported")


def _unsupported_assertions(
    candidate: Mapping[str, Any], fixture: Mapping[str, Any],
) -> Mapping[str, Any]:
    del candidate, fixture
    raise LocalTargetError("destructive_validation_method_not_supported")
