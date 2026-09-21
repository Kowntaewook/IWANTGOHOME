"""Target-neutral, bounded scenario synthesis and execution gates."""

from __future__ import annotations

from dataclasses import asdict, dataclass
import json
from pathlib import Path
from typing import Any, Callable, Mapping
from urllib.parse import parse_qs, urlsplit

from ctf_mcp.local_targets.base import LocalTargetError
from ctf_mcp.local_targets.base import atomic_private_json, secure_directory
from .reporting import write_private_text


SCENARIO_STATUSES = frozenset({
    "SCENARIO_GENERATED",
    "SCENARIO_NOT_GENERATABLE",
    "SCENARIO_UNSAFE",
    "SCENARIO_BLOCKED",
    "SCENARIO_READY",
    "SCENARIO_EXECUTED",
})
READ_ONLY_METHODS = frozenset({"GET", "HEAD"})
BINDING_PATTERNS = frozenset({
    "BODY_FILTERING_VS_METADATA_COUNT",
    "DIRECT_OBJECT_VS_COLLECTION_AUTH",
    "VISIBILITY_BOUNDARY_MISMATCH",
})
BINDING_CONFIDENCES = frozenset({"EXACT", "STRONG", "WEAK", "NONE"})
_SENSITIVE_KEYS = frozenset({
    "authorization", "cookie", "password", "secret", "session", "token",
})


@dataclass(frozen=True)
class TargetCapabilities:
    """Adapter supplied fixture and request capabilities.

    Capability names are deliberately resource neutral.  Adapters may expose a
    smaller set; the scenario engine never assumes a product object model.
    """

    fixture_actions: frozenset[str]
    supports_read_only_probe: bool
    runtime_hosts: frozenset[str] = frozenset({"127.0.0.1", "localhost", "::1"})
    fixture_prefix: str = "finder-local-"

    def __post_init__(self) -> None:
        if (not self.fixture_prefix.startswith("finder-local-")
                or not all(isinstance(item, str) and item for item in self.fixture_actions)
                or not self.runtime_hosts
                or not self.runtime_hosts <= {"127.0.0.1", "localhost", "::1"}):
            raise LocalTargetError("invalid_scenario_capabilities")


@dataclass(frozen=True)
class ScenarioPlan:
    candidate_id: str
    target_id: str
    required_identities: tuple[str, ...]
    required_resources: tuple[str, ...]
    fixture_requirements: tuple[str, ...]
    control_request: Mapping[str, Any]
    probe_request: Mapping[str, Any]
    security_invariant: str
    expected_control: Mapping[str, Any]
    violation_condition: Mapping[str, Any]
    request_budget: int
    cleanup_requirements: tuple[str, ...]
    source_assertions: Mapping[str, bool]
    confidence: str
    safety_classification: str
    repeated_observation_required: bool = False
    rationale: str = ""
    binding_id: str | None = None
    binding_pattern: str | None = None
    binding_confidence: str | None = None
    candidate_source_facts: tuple[Mapping[str, Any], ...] = ()
    fixture_mapping: Mapping[str, Any] | None = None
    route_mapping: Mapping[str, Any] | None = None
    safety_requirements: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class ScenarioBinding:
    """Code-owned adapter callbacks behind a target-neutral binding contract."""

    binding_id: str
    pattern: str
    required_capabilities: tuple[str, ...]
    fixture_roles: tuple[str, ...]
    resource_roles: tuple[str, ...]
    request_budget: int
    safety_requirements: tuple[str, ...]
    candidate_pattern: Callable[[Mapping[str, Any]], str]
    fixture_resolver: Callable[[Mapping[str, Any]], Mapping[str, Any]]
    route_resolver: Callable[[Mapping[str, Any], Mapping[str, Any]], Mapping[str, Any]]
    control_builder: Callable[[Mapping[str, Any], Mapping[str, Any], Mapping[str, Any]], Mapping[str, Any]]
    probe_builder: Callable[[Mapping[str, Any], Mapping[str, Any], Mapping[str, Any]], Mapping[str, Any]]
    assertion_builder: Callable[[Mapping[str, Any], Mapping[str, Any]], Mapping[str, Any]]
    weak_blocker: str = "weak_binding_confidence"

    def __post_init__(self) -> None:
        callbacks = (
            self.candidate_pattern, self.fixture_resolver, self.route_resolver,
            self.control_builder, self.probe_builder, self.assertion_builder,
        )
        if (not self.binding_id or "/" in self.binding_id
                or self.pattern not in BINDING_PATTERNS
                or not self.required_capabilities
                or not self.fixture_roles or not self.resource_roles
                or isinstance(self.request_budget, bool)
                or not 2 <= self.request_budget <= 12
                or not {"localhost_only", "read_only", "bounded_requests", "reviewed_routes"}
                <= set(self.safety_requirements)
                or not self.weak_blocker
                or not all(callable(item) for item in callbacks)):
            raise LocalTargetError("invalid_scenario_binding")


def synthesize_from_bindings(
    *,
    candidate: Mapping[str, Any],
    target_id: str,
    bindings: tuple[ScenarioBinding, ...],
    capabilities: TargetCapabilities,
) -> ScenarioPlan | dict[str, Any]:
    """Select and resolve the strongest adapter-owned binding without route invention."""
    candidate_id = candidate.get("candidate_id")
    if not isinstance(candidate_id, str) or not candidate_id:
        raise LocalTargetError("invalid_candidate_schema")
    ranked = {"NONE": 0, "WEAK": 1, "STRONG": 2, "EXACT": 3}
    matches: list[tuple[int, str, ScenarioBinding]] = []
    for binding in bindings:
        confidence = binding.candidate_pattern(candidate)
        if confidence not in BINDING_CONFIDENCES:
            raise LocalTargetError("invalid_scenario_binding")
        if confidence != "NONE":
            matches.append((ranked[confidence], confidence, binding))
    if not matches:
        value = not_generatable(candidate_id, target_id, "no_reviewed_fixture_route_mapping")
        value.update({"candidate_considered": True, "binding_matched": False})
        return value
    _, confidence, binding = sorted(matches, key=lambda item: (-item[0], item[2].binding_id))[0]
    metadata = {
        "candidate_considered": True,
        "binding_matched": True,
        "binding_id": binding.binding_id,
        "pattern": binding.pattern,
        "confidence": confidence,
    }
    if confidence == "WEAK":
        return {
            "status": "SCENARIO_BLOCKED", "candidate_id": candidate_id,
            "target_id": target_id, "blocker": binding.weak_blocker,
            "plan": None, **metadata,
        }
    if not set(binding.required_capabilities) <= capabilities.fixture_actions:
        return {
            "status": "SCENARIO_BLOCKED", "candidate_id": candidate_id,
            "target_id": target_id, "blocker": "unsupported_binding_capability",
            "plan": None, **metadata,
        }
    try:
        fixture = dict(binding.fixture_resolver(candidate))
        routes = dict(binding.route_resolver(candidate, fixture))
        control = dict(binding.control_builder(candidate, fixture, routes))
        probe = dict(binding.probe_builder(candidate, fixture, routes))
        assertions = dict(binding.assertion_builder(candidate, fixture))
    except LocalTargetError as error:
        return {
            "status": "SCENARIO_BLOCKED", "candidate_id": candidate_id,
            "target_id": target_id, "blocker": error.code,
            "plan": None, "fixture_mapping": None, "route_mapping": None,
            **metadata,
        }
    identities = tuple(fixture.get(role) for role in binding.fixture_roles)
    resources = tuple(fixture.get(role) for role in binding.resource_roles)
    required_assertions = assertions.get("source_assertions")
    source_facts = candidate.get("source_facts", [])
    if (not all(isinstance(item, str) for item in identities + resources)
            or not isinstance(required_assertions, Mapping)
            or not isinstance(source_facts, list)
            or routes.get("control_url") != control.get("url")
            or routes.get("probe_url") != probe.get("url")
            or not isinstance(routes.get("reviewed_source_routes"), (list, tuple))
            or not routes["reviewed_source_routes"]):
        return {
            "status": "SCENARIO_BLOCKED", "candidate_id": candidate_id,
            "target_id": target_id, "blocker": "invalid_binding_resolution",
            "plan": None, "fixture_mapping": redact(fixture),
            "route_mapping": redact(routes), **metadata,
        }
    return ScenarioPlan(
        candidate_id=candidate_id,
        target_id=target_id,
        required_identities=identities,
        required_resources=resources,
        fixture_requirements=binding.required_capabilities,
        control_request=control,
        probe_request=probe,
        security_invariant=str(assertions.get("security_invariant") or ""),
        expected_control=dict(assertions.get("expected_control") or {}),
        violation_condition=dict(assertions.get("violation_condition") or {}),
        request_budget=binding.request_budget,
        cleanup_requirements=("bootstrap_owned",),
        source_assertions=dict(required_assertions),
        confidence="high" if confidence == "EXACT" else "medium",
        safety_classification="LOCAL_READ_ONLY",
        rationale=str(assertions.get("rationale") or ""),
        repeated_observation_required=bool(assertions.get("repeated_observation_required", False)),
        binding_id=binding.binding_id,
        binding_pattern=binding.pattern,
        binding_confidence=confidence,
        candidate_source_facts=tuple(
            item for item in source_facts if isinstance(item, Mapping)
        ),
        fixture_mapping=redact(fixture),
        route_mapping=redact(routes),
        safety_requirements=binding.safety_requirements,
    )


def not_generatable(candidate_id: str, target_id: str, reason: str) -> dict[str, Any]:
    return {
        "status": "SCENARIO_NOT_GENERATABLE",
        "candidate_id": candidate_id,
        "target_id": target_id,
        "blocker": reason,
    }


def validate_scenario_plan(
    plan: ScenarioPlan,
    capabilities: TargetCapabilities,
) -> ScenarioPlan:
    """Apply deterministic safety and evidence gates before any request runs."""
    if (not plan.candidate_id or not plan.target_id or not plan.security_invariant
            or not plan.rationale
            or plan.confidence not in {"low", "medium", "high"}
            or plan.safety_classification != "LOCAL_READ_ONLY"
            or isinstance(plan.request_budget, bool)
            or not 2 <= plan.request_budget <= 12
            or not plan.required_identities
            or not plan.required_resources
            or not plan.fixture_requirements
            or not set(plan.fixture_requirements) <= capabilities.fixture_actions
            or not capabilities.supports_read_only_probe
            or not plan.source_assertions
            or not all(isinstance(key, str) and isinstance(value, bool)
                       for key, value in plan.source_assertions.items())
            or not all(plan.source_assertions.values())
            or not isinstance(plan.expected_control, Mapping) or not plan.expected_control
            or not isinstance(plan.violation_condition, Mapping) or not plan.violation_condition
            or not all(_safe_fixture_name(item) for item in (
                *plan.required_identities, *plan.required_resources,
            ))
            or any(item not in {"none", "bootstrap_owned"}
                   for item in plan.cleanup_requirements)):
        raise LocalTargetError("SCENARIO_UNSAFE")
    if plan.binding_id is not None:
        routes = plan.route_mapping
        if (plan.binding_pattern not in BINDING_PATTERNS
                or plan.binding_confidence not in {"EXACT", "STRONG"}
                or not isinstance(routes, Mapping)
                or routes.get("control_url") != plan.control_request.get("url")
                or routes.get("probe_url") != plan.probe_request.get("url")
                or not isinstance(routes.get("reviewed_source_routes"), (list, tuple))
                or not routes["reviewed_source_routes"]
                or not {"localhost_only", "read_only", "bounded_requests", "reviewed_routes"}
                <= set(plan.safety_requirements)):
            raise LocalTargetError("SCENARIO_UNSAFE")
    _validate_request(plan.control_request, capabilities)
    _validate_request(plan.probe_request, capabilities)
    if plan.control_request == plan.probe_request:
        raise LocalTargetError("SCENARIO_UNSAFE")
    return plan


def execute_scenario(
    plan: ScenarioPlan,
    capabilities: TargetCapabilities,
    *,
    fixture_check: Callable[[ScenarioPlan], Mapping[str, Any]],
    execute: Callable[[ScenarioPlan], Mapping[str, Any]],
) -> tuple[dict[str, Any], dict[str, Any] | None]:
    """Validate, execute through an adapter, and adjudicate without status-only inference."""
    try:
        validate_scenario_plan(plan, capabilities)
    except LocalTargetError as error:
        return _scenario_record(plan, "SCENARIO_UNSAFE", blocker=error.code), None
    try:
        fixture = fixture_check(plan)
    except LocalTargetError as error:
        return _scenario_record(plan, "SCENARIO_BLOCKED", blocker=error.code), None
    if not isinstance(fixture, Mapping) or fixture.get("available") is not True:
        reason = fixture.get("reason") if isinstance(fixture, Mapping) else None
        return _scenario_record(
            plan, "SCENARIO_BLOCKED", blocker=reason or "fixture_capability_unavailable",
            fixture=redact(dict(fixture)) if isinstance(fixture, Mapping) else None,
        ), None
    try:
        raw = execute(plan)
    except LocalTargetError as error:
        return _scenario_record(
            plan, "SCENARIO_BLOCKED", blocker=error.code,
            fixture=redact(dict(fixture)),
        ), None
    if not isinstance(raw, Mapping):
        return _scenario_record(plan, "SCENARIO_BLOCKED", blocker="invalid_execution_result"), None
    result = redact(dict(raw))
    count = raw.get("request_count")
    final_urls = raw.get("final_urls", [])
    blocked_reason: str | None = None
    if isinstance(count, bool) or not isinstance(count, int) or count < 2 or count > plan.request_budget:
        blocked_reason = "scenario_request_budget_exceeded"
    elif (not isinstance(final_urls, list)
          or any(not _is_local_url(url, capabilities) for url in final_urls)):
        blocked_reason = "scenario_redirect_outside_localhost"
    elif raw.get("fixture_valid") is not True:
        blocked_reason = "fixture_mismatch"
    elif raw.get("source_assertion_valid") is not True:
        blocked_reason = "source_assertion_mismatch"
    elif raw.get("control_passed") is not True:
        blocked_reason = "control_failed"
    elif raw.get("response_status_only") is not False:
        blocked_reason = "response_status_only_insufficient"
    elif raw.get("transport_error") is True or raw.get("generic_server_error") is True:
        blocked_reason = "non_deterministic_transport_result"
    elif raw.get("probe_deterministic") is not True or raw.get("ambiguous") is not False:
        blocked_reason = "ambiguous_probe_result"
    elif plan.repeated_observation_required and raw.get("repeated_observation") is not True:
        blocked_reason = "repeat_observation_required"
    elif raw.get("evidence_saved") is not True:
        blocked_reason = "scenario_evidence_not_saved"
    if blocked_reason:
        return _scenario_record(
            plan, "SCENARIO_BLOCKED", blocker=blocked_reason,
            fixture=redact(dict(fixture)), execution=result,
        ), None

    violated = raw.get("invariant_violated") is True
    local = {
        "status": "VERIFIED_LOCAL" if violated else "INTENDED_BEHAVIOR",
        "assertions": {
            "control_passed": True,
            "probe_deterministic": True,
            "invariant_violated": violated,
            "source_assertion_valid": True,
            "fixture_valid": True,
            "evidence_saved": True,
        },
    }
    evidence = raw.get("evidence")
    if isinstance(evidence, str):
        local["evidence"] = evidence
    return _scenario_record(
        plan, "SCENARIO_EXECUTED", fixture=redact(dict(fixture)), execution=result,
    ), local


def scenario_summary(outcomes: list[dict[str, Any]]) -> dict[str, int]:
    records = [item.get("scenario_synthesis") for item in outcomes]
    records = [item for item in records if isinstance(item, dict)]
    generated_statuses = {"SCENARIO_GENERATED", "SCENARIO_READY", "SCENARIO_EXECUTED", "SCENARIO_BLOCKED"}
    return {
        "scenario_candidates_considered": len(records),
        "scenario_bindings_matched": sum(item.get("binding_matched") is True for item in records),
        "scenario_generated": sum(item.get("status") in generated_statuses for item in records),
        "scenario_ready": sum(
            (item.get("safety_result") or {}).get("passed") is True
            for item in records
        ),
        "scenario_executed": sum(item.get("status") == "SCENARIO_EXECUTED" for item in records),
        "scenario_verified": sum(
            item.get("status") == "SCENARIO_EXECUTED"
            and (item.get("execution_result") or {}).get("invariant_violated") is True
            for item in records
        ),
        "scenario_intended_behavior": sum(
            item.get("status") == "SCENARIO_EXECUTED"
            and (item.get("execution_result") or {}).get("invariant_violated") is False
            for item in records
        ),
        "scenario_blocked": sum(item.get("status") in {"SCENARIO_BLOCKED", "SCENARIO_UNSAFE"} for item in records),
        "scenario_manual_remaining": sum(
            item.get("classification") == "NEEDS_MANUAL_SCENARIO" for item in outcomes
        ),
    }


def render_scenario_markdown(record: Mapping[str, Any]) -> str:
    plan = record.get("plan", {})
    details = plan if isinstance(plan, dict) else {}
    return "\n".join((
        f"# Scenario {record.get('candidate_id', 'unknown')}",
        "",
        f"- Status: {record.get('status', 'unknown')}",
        f"- Binding: {record.get('binding_id') or details.get('binding_id') or 'none'}",
        f"- Pattern: {record.get('pattern') or details.get('binding_pattern') or 'none'}",
        f"- Confidence: {record.get('confidence') or details.get('binding_confidence') or 'none'}",
        f"- Why generated: {details.get('rationale', 'not generated')}",
        f"- Candidate source facts: {_compact(details.get('candidate_source_facts'))}",
        f"- Source assertions: {_compact(details.get('source_assertions'))}",
        f"- Fixture mapping: {_compact(details.get('fixture_mapping') or record.get('fixture_mapping'))}",
        f"- Route mapping: {_compact(details.get('route_mapping') or record.get('route_mapping'))}",
        f"- Fixture requirements: {_compact(details.get('fixture_requirements'))}",
        f"- Control request: {_compact(details.get('control_request'))}",
        f"- Probe request: {_compact(details.get('probe_request'))}",
        f"- Request budget: {details.get('request_budget', 'not available')}",
        f"- Safety result: {'passed' if record.get('status') in {'SCENARIO_READY', 'SCENARIO_EXECUTED'} else 'blocked'}",
        f"- Execution result: {_compact(record.get('execution_result'))}",
        f"- Invariant evaluation: {_compact(record.get('invariant_evaluation'))}",
        f"- Blocker: {record.get('blocker') or 'none'}",
        "",
    ))


def write_scenario_artifacts(
    root: Path,
    report_directory: str,
    outcomes: list[dict[str, Any]],
) -> list[str]:
    base = (root / report_directory / "scenarios").resolve()
    report_root = (root / report_directory).resolve()
    root = root.resolve()
    if ((report_root != root and root not in report_root.parents)
            or report_root not in base.parents):
        raise LocalTargetError("hunt_report_failed")
    records = [item.get("scenario_synthesis") for item in outcomes]
    records = [item for item in records if isinstance(item, dict)]
    if not records:
        return []
    secure_directory(base)
    written: list[str] = []
    for record in records:
        candidate = record.get("candidate_id")
        if (not isinstance(candidate, str) or not candidate
                or any(character not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_"
                       for character in candidate)):
            raise LocalTargetError("hunt_report_failed")
        safe = redact(record)
        json_path = base / (candidate + ".json")
        md_path = base / (candidate + ".md")
        atomic_private_json(json_path, safe)
        write_private_text(md_path, render_scenario_markdown(safe))
        written.extend((str(json_path.relative_to(root)), str(md_path.relative_to(root))))
    return written


def redact(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {
            str(key): (
                "[REDACTED]"
                if _sensitive_key(str(key))
                else redact(item)
            )
            for key, item in value.items()
        }
    if isinstance(value, (list, tuple)):
        return [redact(item) for item in value]
    return value


def _sensitive_key(value: str) -> bool:
    normalized = value.lower().replace("-", "_")
    return bool(
        normalized in _SENSITIVE_KEYS
        or normalized.endswith(("_token", "_password", "_secret", "_cookie"))
        or normalized.startswith(("password_", "secret_", "token_", "cookie_"))
    )


def _compact(value: Any) -> str:
    if value is None:
        return "not available"
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"))


def _safe_fixture_name(value: Any) -> bool:
    return isinstance(value, str) and value.startswith("finder-local-") and len(value) <= 96


def _validate_request(value: Mapping[str, Any], capabilities: TargetCapabilities) -> None:
    if not isinstance(value, Mapping) or set(value) - {"method", "url", "purpose", "read_only"}:
        raise LocalTargetError("SCENARIO_UNSAFE")
    method = value.get("method")
    url = value.get("url")
    if (method not in READ_ONLY_METHODS or value.get("read_only") is not True
            or not isinstance(value.get("purpose"), str) or not value["purpose"]
            or not _is_local_url(url, capabilities)):
        raise LocalTargetError("SCENARIO_UNSAFE")
    query = parse_qs(urlsplit(str(url)).query, keep_blank_values=True)
    for key in ("limit", "page", "per_page"):
        for item in query.get(key, []):
            if not item.isdigit() or int(item) > 100:
                raise LocalTargetError("SCENARIO_UNSAFE")


def _is_local_url(value: Any, capabilities: TargetCapabilities) -> bool:
    if not isinstance(value, str) or len(value) > 2048 or "\r" in value or "\n" in value:
        return False
    parsed = urlsplit(value)
    return bool(
        parsed.scheme == "http"
        and parsed.hostname in capabilities.runtime_hosts
        and parsed.username is None and parsed.password is None
        and parsed.fragment == ""
        and parsed.path.startswith("/")
    )


def _scenario_record(
    plan: ScenarioPlan,
    status: str,
    *,
    blocker: str | None = None,
    fixture: Any = None,
    execution: Any = None,
) -> dict[str, Any]:
    if status not in SCENARIO_STATUSES:
        raise LocalTargetError("invalid_scenario_status")
    result = {
        "status": status,
        "candidate_id": plan.candidate_id,
        "target_id": plan.target_id,
        "plan": redact(plan.to_dict()),
        "fixture_check": fixture,
        "execution_result": execution,
        "blocker": blocker,
        "candidate_considered": True,
        "binding_matched": plan.binding_id is not None,
        "binding_id": plan.binding_id,
        "pattern": plan.binding_pattern,
        "confidence": plan.binding_confidence,
        "safety_result": {
            "passed": status == "SCENARIO_EXECUTED",
            "classification": plan.safety_classification,
        },
        "invariant_evaluation": (
            {"violated": execution.get("invariant_violated")}
            if isinstance(execution, Mapping) else None
        ),
    }
    return result


def generated_scenario_record(plan: ScenarioPlan) -> dict[str, Any]:
    value = _scenario_record(plan, "SCENARIO_GENERATED")
    value["safety_result"] = {
        "passed": True,
        "classification": plan.safety_classification,
    }
    return value
