"""Bounded source discovery and static triage for the pinned Gitea tree."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
from pathlib import Path
import re
from typing import Any, Iterable

from .base import LocalTargetError


BASELINE_REQUEST_BUDGETS = {"G04": 3, "G05": 3, "G06": 2, "G07": 2, "G08": 2}


MAX_SOURCE_FILES = 8_000
MAX_SOURCE_BYTES = 64 * 1024 * 1024
MAX_FILE_BYTES = 2 * 1024 * 1024
MAX_GENERIC_CANDIDATES = 80
STATIC_STATUSES = frozenset({
    "REJECTED_STATIC", "NEEDS_LOCAL_VALIDATION", "BLOCKED_STATIC",
})
SCENARIO_STATUSES = frozenset({"LOCAL_BASELINE_REUSE", "NEEDS_MANUAL_SCENARIO"})


@dataclass(frozen=True)
class TraceStep:
    symbol: str
    path_suffix: str


@dataclass(frozen=True)
class DiscoveryRule:
    rule_id: str
    discovery_class: str
    method: str
    route: str
    route_fragment: str
    handler_reference: str
    trace: tuple[TraceStep, ...]
    security_invariant: str
    suspected_mismatch: str
    attacker_prerequisites: str
    counterargument: str
    proposed_local_validation: str
    root_cause_key: str
    baseline_candidate: str
    signal: str


DISCOVERY_RULES: tuple[DiscoveryRule, ...] = (
    DiscoveryRule(
        "SD-G04", "public_only_restricted_token_boundary_mismatch", "GET",
        "/api/v1/users/{username}/activities/feeds", "/activities/feeds",
        "user.ListUserActivityFeeds",
        (
            TraceStep("ListUserActivityFeeds", "routers/api/v1/user/user.go"),
            TraceStep("ApplyPublicOnly", "models/activities/action.go"),
            TraceStep("GetFeeds", "services/feed/feed.go"),
            TraceStep("GetFeeds", "models/activities/action_list.go"),
        ),
        "A public-only token must not receive activity for a repository it cannot access.",
        "The feed query may derive repository activity without applying the token's organization visibility boundary.",
        "Repository owner using a public-only token; public repository under a limited organization.",
        "A route middleware or GetFeeds visibility predicate may already remove inaccessible repositories.",
        "Compare normal direct access, public-only direct denial, and the exact feed marker using finder-local fixtures.",
        "activities.GetFeeds/public-only-visibility", "G04", "derived_metadata",
    ),
    DiscoveryRule(
        "SD-G05", "activity_feed_heatmap_derived_metadata_leak", "GET",
        "/api/v1/users/{username}/heatmap", "/heatmap", "user.GetUserHeatmapData",
        (
            TraceStep("GetUserHeatmapData", "routers/api/v1/user/user.go"),
            TraceStep("GetUserHeatmapDataByUser", "models/activities/user_heatmap.go"),
            TraceStep("getUserHeatmapData", "models/activities/user_heatmap.go"),
        ),
        "A public-only token's heatmap must exclude inaccessible private repository activity.",
        "The derived heatmap query may omit the public-only repository visibility restriction.",
        "Repository owner with private activity using a public-only token.",
        "The model query may bind the requesting viewer or apply repository visibility internally.",
        "Compare the exact private-activity bucket after direct private repository access is denied.",
        "activities.GetUserHeatmapData/public-only-visibility", "G05", "derived_metadata",
    ),
    DiscoveryRule(
        "SD-G06", "response_body_metadata_count_mismatch", "GET",
        "/api/v1/users/{username}/repos", "/repos", "user.ListUserRepos",
        (
            TraceStep("ListUserRepos", "routers/api/v1/user/repo.go"),
            TraceStep("listUserRepos", "routers/api/v1/user/repo.go"),
            TraceStep("GetUserRepositories", "models/repo/repo_list.go"),
        ),
        "X-Total-Count must describe the same viewer-visible repository set as the response body.",
        "The total may be emitted before per-repository visibility filtering trims the body.",
        "Unrelated authenticated viewer lists a user with one public and one private repository.",
        "GetUserRepositories may already include the viewer visibility predicate in both data and count queries.",
        "Compare owner and unrelated-viewer bodies and X-Total-Count using finder-local repositories.",
        "listUserRepos/GetUserRepositories-count-before-filter", "G06", "count_before_filter",
    ),
    DiscoveryRule(
        "SD-G07", "organization_membership_boundary", "GET",
        "/api/v1/orgs/{org}/repos", "/repos", "user.ListOrgRepos",
        (
            TraceStep("ListOrgRepos", "routers/api/v1/user/repo.go"),
            TraceStep("listUserRepos", "routers/api/v1/user/repo.go"),
            TraceStep("GetUserRepositories", "models/repo/repo_list.go"),
        ),
        "An organization repository total must count only repositories visible to the requesting non-member.",
        "The shared listUserRepos total may retain private repositories removed from the response body.",
        "Authenticated organization non-member lists an organization with public and private repositories.",
        "Organization visibility middleware or the model query may bind the count to the viewer.",
        "Compare organization-owner and non-member bodies and X-Total-Count with finder-local fixtures.",
        "listUserRepos/GetUserRepositories-count-before-filter", "G07", "count_before_filter",
    ),
    DiscoveryRule(
        "SD-G08", "team_membership_boundary", "GET",
        "/api/v1/teams/{team_id}/repos", "/repos", "org.GetTeamRepos",
        (
            TraceStep("GetTeamRepos", "routers/api/v1/org/team.go"),
            TraceStep("GetTeamRepositories", "models/repo/org_repo.go"),
            TraceStep("CountTeamRepositories", "models/repo/org_repo.go"),
        ),
        "A team repository total must count only repositories visible to the requesting metadata viewer.",
        "CountTeamRepositories may run before per-repository access filtering trims the response body.",
        "Non-member can read team metadata but cannot access the team's private repository.",
        "Team read middleware or CountTeamRepositories may already bind the result to the requesting viewer.",
        "Compare team-member and metadata-readable non-member bodies and totals with finder-local fixtures.",
        "GetTeamRepos/CountTeamRepositories-count-before-filter", "G08", "count_before_filter",
    ),
)


@dataclass(frozen=True)
class FunctionFact:
    symbol: str
    path: str
    line: int
    body: str
    file_hash: str

    def location(self) -> str:
        return f"{self.path}:{self.line}"


def discover_and_triage(source_root: Path) -> list[dict[str, Any]]:
    """Discover source-backed candidates and deterministically triage them."""
    files = _load_go_files(source_root)
    functions = _index_functions(files)
    candidates = [_candidate_for_rule(rule, files, functions) for rule in DISCOVERY_RULES]
    candidates.extend(_discover_bound_action_routes(files, functions))
    candidates.extend(_discover_generic_candidates(files, functions, candidates))
    return [validate_candidate_document(candidate) for candidate in candidates]


def generate_scenario(candidate: dict[str, Any]) -> dict[str, Any]:
    """Generate only fixed localhost scenarios backed by an existing validator."""
    candidate = validate_candidate_document(candidate)
    baseline = candidate.get("baseline_candidate")
    if (candidate["static_status"] != "NEEDS_LOCAL_VALIDATION"
            or baseline not in {"G04", "G05", "G06", "G07", "G08"}
            or candidate["route"]["method"] != "GET"):
        return {
            "status": "NEEDS_MANUAL_SCENARIO",
            "candidate_id": candidate["candidate_id"],
            "reason": "no_fixed_safe_validator",
        }
    scenario = {
        "status": "LOCAL_BASELINE_REUSE",
        "candidate_id": candidate["candidate_id"],
        "validator_candidate": baseline,
        "target": "127.0.0.1:13000",
        "methods": ["GET"],
        "fixture_prefix": "finder-local-",
        "state_changes": "bootstrap_only",
        "direct_database_mutation": False,
        "request_budget": BASELINE_REQUEST_BUDGETS[baseline],
        "control_required": True,
        "probe_required": True,
    }
    validate_scenario(scenario)
    return scenario


def validate_scenario(value: dict[str, Any]) -> dict[str, Any]:
    if (not isinstance(value, dict) or value.get("status") != "LOCAL_BASELINE_REUSE"
            or value.get("target") != "127.0.0.1:13000"
            or value.get("methods") != ["GET"]
            or value.get("fixture_prefix") != "finder-local-"
            or value.get("state_changes") != "bootstrap_only"
            or value.get("direct_database_mutation") is not False
            or value.get("control_required") is not True
            or value.get("probe_required") is not True
            or isinstance(value.get("request_budget"), bool)
            or not isinstance(value.get("request_budget"), int)
            or not 1 <= value["request_budget"] <= 8):
        raise LocalTargetError("unsafe_generated_scenario")
    return value


def validate_candidate_document(value: dict[str, Any]) -> dict[str, Any]:
    required = {
        "candidate_id", "discovery_class", "route", "middleware", "handler",
        "model_query_path", "security_invariant", "suspected_mismatch",
        "attacker_prerequisites", "counterargument", "proposed_local_validation",
        "source_assertions", "source_facts", "static_status", "static_reasons",
        "root_cause_key", "baseline_candidate",
    }
    if not isinstance(value, dict) or set(value) != required:
        raise LocalTargetError("invalid_static_candidate")
    route = value["route"]
    assertions = value["source_assertions"]
    if (not isinstance(value["candidate_id"], str)
            or not re.fullmatch(r"SD-[A-Z0-9-]{2,48}", value["candidate_id"])
            or not isinstance(route, dict)
            or set(route) != {"method", "path", "location"}
            or route["method"] not in {"GET", "POST", "PUT", "PATCH", "DELETE"}
            or not isinstance(route["path"], str)
            or not isinstance(value["middleware"], list)
            or not all(isinstance(item, str) for item in value["middleware"])
            or not isinstance(value["handler"], dict)
            or not isinstance(value["model_query_path"], list)
            or not isinstance(assertions, dict) or not assertions
            or not all(isinstance(item, bool) for item in assertions.values())
            or value["static_status"] not in STATIC_STATUSES
            or not isinstance(value["static_reasons"], list)
            or not isinstance(value["source_facts"], list)):
        raise LocalTargetError("invalid_static_candidate")
    return value


def _candidate_for_rule(
    rule: DiscoveryRule,
    files: dict[str, str],
    functions: dict[str, list[FunctionFact]],
) -> dict[str, Any]:
    route_fact = _find_route(files, rule.handler_reference, rule.route_fragment)
    aligned_trace = [_find_function(functions, step) for step in rule.trace]
    trace_edges = [
        bool(aligned_trace[index]
             and any(previous and _calls_symbol(previous.body, rule.trace[index].symbol)
                     for previous in aligned_trace[:index]))
        for index in range(1, len(rule.trace))
    ]
    trace = [item for item in aligned_trace if item is not None]
    handler = aligned_trace[0]
    query_facts = [item for item in aligned_trace[1:] if item is not None]
    combined = "\n".join(item.body for item in trace)
    middleware = route_fact["middleware"] if route_fact else []
    count_positions = [
        position for token in ("SetTotalCountHeader", "GetUserRepositories", "CountTeamRepositories")
        if (position := combined.find(token)) >= 0
    ]
    count_position = min(count_positions) if count_positions else -1
    filter_positions = [
        position for token in (
            "HasAnyUnitAccess", "Permission", "CanRead", "IsPrivate", "Visibility",
            "AccessMode", "HasAccess", "ToRepo",
        )
        if (position := combined.find(token)) >= 0
    ]
    count_before_filter = bool(
        count_position >= 0 and filter_positions and count_position < max(filter_positions)
    )
    visibility_guard = any(token in combined for token in (
        "HasOrgOrUserVisible", "IsUserVisibleToViewer", "ApplyPublicOnly",
        "PublicOnly", "HasAccessUnit", "CanReadRepo",
    ))
    viewer_binding = bool(re.search(
        r"(?:Actor|Doer|Viewer|userID|UserID|ctx\.Doer|ctx\.User)", combined
    ))
    response_filter = _body_refilters(combined)
    count_from_unfiltered_query = bool(
        "GetUserRepositories" in combined
        and "SetTotalCountHeader(count)" in combined
        and response_filter
        and re.search(r"apiRepos\s*=\s*append", combined)
    )
    if rule.rule_id == "SD-G04":
        derived_signal = bool(
            "opts.IncludePrivate = false" in combined
            and "opts.Actor.ID == opts.RequestedUser.ID" in combined
            and 'builder.Eq{"is_private": false}' in combined
            and "PublicRepoUnderPublicOwnerCond" not in combined
        )
    elif rule.rule_id == "SD-G05":
        derived_signal = bool(
            route_fact and "checkTokenPublicOnly" in middleware
            and "GetUserHeatmapDataByUser" in combined
            and "IncludePrivate: true" in combined
            and "ctx.PublicOnly" not in combined
        )
    else:
        derived_signal = False
    if rule.signal == "count_before_filter":
        pattern = count_before_filter or count_from_unfiltered_query
        count_before_filter = pattern
    else:
        pattern = derived_signal
    assertions = {
        "route_exists": route_fact is not None,
        "handler_resolved": handler is not None,
        "model_query_resolved": bool(query_facts) and len(query_facts) == len(rule.trace) - 1,
        "trace_edges_resolved": bool(trace_edges) and all(trace_edges),
        "authorization_middleware_present": bool(middleware),
        "viewer_binding_present": viewer_binding,
        "owner_repo_binding_present": "ctx.Repo.Repository.ID" in combined,
        "response_refilter_present": response_filter,
        "visibility_helper_present": visibility_guard,
        "count_before_filter": count_before_filter,
        "candidate_pattern_observed": pattern,
    }
    static_status, reasons = _triage(assertions, action_binding=False)
    route_location = route_fact["location"] if route_fact else None
    return {
        "candidate_id": rule.rule_id,
        "discovery_class": rule.discovery_class,
        "route": {"method": rule.method, "path": rule.route, "location": route_location},
        "middleware": middleware,
        "handler": {
            "symbol": rule.handler_reference,
            "location": handler.location() if handler else None,
        },
        "model_query_path": [
            {"symbol": item.symbol, "location": item.location()} for item in query_facts
        ],
        "security_invariant": rule.security_invariant,
        "suspected_mismatch": rule.suspected_mismatch,
        "attacker_prerequisites": rule.attacker_prerequisites,
        "counterargument": rule.counterargument,
        "proposed_local_validation": rule.proposed_local_validation,
        "source_assertions": assertions,
        "source_facts": _source_facts(route_fact, trace),
        "static_status": static_status,
        "static_reasons": reasons,
        "root_cause_key": rule.root_cause_key,
        "baseline_candidate": rule.baseline_candidate,
    }


def _triage(assertions: dict[str, bool], *, action_binding: bool) -> tuple[str, list[str]]:
    if action_binding and assertions["owner_repo_binding_present"]:
        return "REJECTED_STATIC", ["repository_binding_proven_before_object_lookup"]
    required_trace = (
        "route_exists", "handler_resolved", "model_query_resolved", "trace_edges_resolved",
    )
    missing = [key for key in required_trace if not assertions[key]]
    if missing:
        return "BLOCKED_STATIC", ["missing_" + key for key in missing]
    if assertions["candidate_pattern_observed"]:
        return "NEEDS_LOCAL_VALIDATION", ["multi_hop_security_mismatch_requires_control_probe"]
    if (assertions["visibility_helper_present"]
            and assertions["viewer_binding_present"]
            and not assertions["count_before_filter"]):
        return "REJECTED_STATIC", ["viewer_bound_visibility_helper_present"]
    return "BLOCKED_STATIC", ["source_trace_present_but_mismatch_not_proven"]


def _discover_bound_action_routes(
    files: dict[str, str], functions: dict[str, list[FunctionFact]],
) -> list[dict[str, Any]]:
    found: list[dict[str, Any]] = []
    for symbol, facts in functions.items():
        if not re.search(r"(?:Action|Actions).*(?:Run|Job)|(?:Run|Job).*(?:Action|Actions)", symbol):
            continue
        for fact in facts:
            if "ctx.Repo.Repository.ID" not in fact.body:
                continue
            reference = _find_handler_reference(files, symbol)
            route_fact = _find_route(files, reference, "/") if reference else None
            if route_fact is None:
                continue
            query = _first_query_symbol(fact.body)
            query_fact = _find_function(functions, TraceStep(query, "")) if query else None
            if query_fact is None:
                continue
            assertions = {
                "route_exists": True,
                "handler_resolved": True,
                "model_query_resolved": True,
                "trace_edges_resolved": True,
                "authorization_middleware_present": bool(route_fact["middleware"]),
                "viewer_binding_present": "ctx.Doer" in fact.body,
                "owner_repo_binding_present": True,
                "response_refilter_present": False,
                "visibility_helper_present": True,
                "count_before_filter": False,
                "candidate_pattern_observed": False,
            }
            status, reasons = _triage(assertions, action_binding=True)
            digest = hashlib.sha256((fact.path + ":" + symbol).encode()).hexdigest()[:10].upper()
            found.append({
                "candidate_id": "SD-ACTION-" + digest,
                "discovery_class": "cross_repository_object_lookup",
                "route": {
                    "method": "GET", "path": route_fact["path"],
                    "location": route_fact["location"],
                },
                "middleware": route_fact["middleware"],
                "handler": {"symbol": reference, "location": fact.location()},
                "model_query_path": ([{
                    "symbol": query_fact.symbol, "location": query_fact.location(),
                }]),
                "security_invariant": "Action run and job objects must be bound to the route repository.",
                "suspected_mismatch": "A numeric object lookup could cross repository boundaries.",
                "attacker_prerequisites": "Authenticated repository reader supplies an action object identifier.",
                "counterargument": "The handler binds the query to ctx.Repo.Repository.ID.",
                "proposed_local_validation": "No local probe is needed when the repository binding is proven.",
                "source_assertions": assertions,
                "source_facts": _source_facts(route_fact, [fact, query_fact]),
                "static_status": status,
                "static_reasons": reasons,
                "root_cause_key": "actions/repository-bound-object-lookup",
                "baseline_candidate": None,
            })
    return found


def _discover_generic_candidates(
    files: dict[str, str],
    functions: dict[str, list[FunctionFact]],
    existing: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Find multi-factor risks outside the regression-baseline trace rules."""
    known_handlers = {item["handler"]["symbol"] for item in existing}
    discovered: list[dict[str, Any]] = []
    for route in _all_get_routes(files):
        if route["handler"] in known_handlers:
            continue
        handler_symbol = route["handler"].rsplit(".", 1)[-1]
        if re.search(r"(?:Action|Actions).*(?:Run|Job)|(?:Run|Job).*(?:Action|Actions)", handler_symbol):
            continue
        handler = _find_function(functions, TraceStep(handler_symbol, ""))
        if handler is None:
            continue
        query_facts = _query_facts(handler.body, functions)
        if not query_facts:
            continue
        combined = handler.body + "\n" + "\n".join(item.body for item in query_facts)
        owner_binding = any(token in handler.body for token in (
            "ctx.Repo.Repository.ID", "ctx.Repo.Repository.OwnerID", "ctx.Org.Organization.ID",
        ))
        viewer_binding = any(token in combined for token in (
            "ctx.Doer", "Viewer", "AccessibleRepositoryCondition", "GetDoerRepoPermission",
        ))
        response_filter = _body_refilters(handler.body)
        visibility_helper = any(token in combined for token in (
            "HasOrgOrUserVisible", "ApplyPublicOnly", "AccessibleRepositoryCondition",
            "GetDoerRepoPermission", "HasAnyUnitAccess", "CanReadRepo",
        ))
        header_position = handler.body.find("SetTotalCountHeader")
        filter_positions = [
            handler.body.find(token) for token in (
                "HasAnyUnitAccess", "GetDoerRepoPermission", "CanRead", "Visibility",
            ) if handler.body.find(token) >= 0
        ]
        count_mismatch = bool(header_position >= 0 and response_filter and filter_positions)
        params = re.findall(r"\{([A-Za-z_][A-Za-z0-9_-]*)\}", route["path"])
        lookup_by_id = any(re.search(r"(?:ByID|ByRepoAndID|ByOwnerAndID)$", item.symbol) for item in query_facts)
        sensitive_name = bool(re.search(
            r"(?:Admin|Token|Secret|Permission|Private|Member|Team|Org|Repo)", handler_symbol
        ))
        has_auth_middleware = any(value in route["middleware"] for value in (
            "reqToken", "reqBasicAuth", "tokenRequiresScopes", "repoAssignment",
            "orgAssignment", "reqRepoReader", "reqTeamReadAccess",
        ))
        public_only_boundary = (
            "checkTokenPublicOnly" in route["middleware"]
            and "ctx.PublicOnly" not in handler.body
            and any(token in combined for token in ("Private", "Visibility", "Repository", "Organization"))
        )
        identifier_position = min(
            (handler.body.find(token) for token in ("PathParam(", "PathParamInt64(")
             if handler.body.find(token) >= 0),
            default=-1,
        )
        authorization_positions = [
            handler.body.find(token) for token in (
                "GetDoerRepoPermission", "HasAnyUnitAccess", "CanRead", "HasAccess",
            ) if handler.body.find(token) >= 0
        ]
        identifier_before_auth = bool(
            identifier_position >= 0
            and (not authorization_positions or identifier_position < min(authorization_positions))
            and lookup_by_id
            and not owner_binding
        )
        signals: list[tuple[str, bool, bool]] = []
        if count_mismatch:
            signals.append(("pagination_header_metadata_leak", True, False))
        if params and lookup_by_id:
            category = "cross_repository_object_lookup" if any(
                value in params for value in ("owner", "repo", "reponame")
            ) else "idor_candidate"
            signals.append((category, not owner_binding, owner_binding))
        if public_only_boundary:
            route_binding = bool(
                "repoAssignment" in route["middleware"]
                and ("ctx.Repo" in handler.body or owner_binding)
            )
            signals.append(("route_middleware_model_query_mismatch", False, route_binding))
        if sensitive_name and not has_auth_middleware:
            signals.append(("authentication_bypass_candidate", False, False))
        if identifier_before_auth:
            signals.append(("user_controlled_identifier_before_authorization", True, False))
        if (any(token in combined for token in ("IsPrivate", "is_private", "Visibility"))
                and not visibility_helper and not viewer_binding):
            signals.append(("private_public_visibility_mismatch", True, False))
        for category, pattern, proven_binding in signals:
            assertions = {
                "route_exists": True,
                "handler_resolved": True,
                "model_query_resolved": True,
                "trace_edges_resolved": all(_calls_symbol(handler.body, item.symbol) for item in query_facts),
                "authorization_middleware_present": bool(route["middleware"]),
                "viewer_binding_present": viewer_binding,
                "owner_repo_binding_present": owner_binding,
                "response_refilter_present": response_filter,
                "visibility_helper_present": visibility_helper,
                "count_before_filter": count_mismatch,
                "candidate_pattern_observed": pattern,
            }
            if proven_binding:
                reason = (
                    "route_middleware_and_resource_binding_proven"
                    if category == "route_middleware_model_query_mismatch"
                    else "repository_binding_proven_before_object_lookup"
                )
                status, reasons = "REJECTED_STATIC", [reason]
            elif pattern:
                status, reasons = "NEEDS_LOCAL_VALIDATION", ["generic_multi_factor_signal_requires_control_probe"]
            else:
                status, reasons = "BLOCKED_STATIC", ["route_or_middleware_counterargument_unresolved"]
            digest = hashlib.sha256(
                (category + "\0" + route["path"] + "\0" + route["handler"]).encode()
            ).hexdigest()[:12].upper()
            counterargument, validation = _generic_guidance(category)
            discovered.append({
                "candidate_id": "SD-GEN-" + digest,
                "discovery_class": category,
                "route": {
                    "method": "GET", "path": route["path"], "location": route["location"],
                },
                "middleware": route["middleware"],
                "handler": {"symbol": route["handler"], "location": handler.location()},
                "model_query_path": [
                    {"symbol": item.symbol, "location": item.location()} for item in query_facts
                ],
                "security_invariant": _generic_invariant(category),
                "suspected_mismatch": _generic_mismatch(category),
                "attacker_prerequisites": "Authenticated low-privilege viewer with a finder-local fixture; anonymous only when the route permits it.",
                "counterargument": counterargument,
                "proposed_local_validation": validation,
                "source_assertions": assertions,
                "source_facts": _source_facts(route, [handler, *query_facts]),
                "static_status": status,
                "static_reasons": reasons,
                "root_cause_key": route["handler"] + "/" + "+".join(item.symbol for item in query_facts),
                "baseline_candidate": None,
            })
            if len(discovered) >= MAX_GENERIC_CANDIDATES:
                return discovered
    return discovered


def _all_get_routes(files: dict[str, str]) -> list[dict[str, Any]]:
    routes = []
    for path, text in files.items():
        if not path.startswith("routers/api/v1/"):
            continue
        file_hash = hashlib.sha256(text.encode()).hexdigest()
        for call in re.finditer(r"\.Get\(", text):
            opening = call.end() - 1
            end = _balanced_end(text, opening, "(", ")")
            if end is None:
                continue
            expression = text[call.start():end]
            references = re.findall(r"\b([a-z_][A-Za-z0-9_]*\.[A-Z][A-Za-z0-9_]*)\b", expression)
            if not references:
                continue
            handler = references[-1]
            local_match = re.search(r"\.Get\(\s*\"([^\"]+)\"", expression)
            if local_match:
                local_path = local_match.group(1)
            else:
                local_path = _combo_path_before(text, call.start())
            position = call.start() + expression.find(handler)
            path_value = _canonical_route_path(text, position, local_path)
            routes.append({
                "path": path_value or "/",
                "location": f"{path}:{text.count(chr(10), 0, position) + 1}",
                "middleware": sorted(
                    set(_route_call_middleware(text, position))
                    | set(_enclosing_group_middleware(text, position))
                ),
                "handler": handler,
                "file_hash": file_hash,
            })
    return routes


def _canonical_route_path(text: str, position: int, local_path: str) -> str:
    groups: list[tuple[int, str]] = []
    pattern = re.compile(r"\b\w+\.Group\(\s*\"([^\"]*)\"\s*,\s*func\(\)\s*\{")
    for match in pattern.finditer(text, 0, position):
        end = _balanced_end(text, match.end() - 1, "{", "}")
        if end is not None and match.end() - 1 < position < end:
            groups.append((match.start(), match.group(1)))
    parts = [value for _, value in sorted(groups)] + [local_path]
    joined = "".join(parts) or "/"
    return re.sub(r"/{2,}", "/", joined if joined.startswith("/") else "/" + joined)


def _combo_path_before(text: str, position: int) -> str:
    start = text.rfind(".Combo(", max(0, position - 1600), position)
    if start < 0:
        return ""
    opening = start + len(".Combo")
    end = _balanced_end(text, opening, "(", ")")
    if end is None or end > position or text[end:position].strip() not in {"", "."}:
        return ""
    match = re.match(r"\s*\"([^\"]*)\"", text[opening + 1:end - 1])
    return match.group(1) if match else ""


def _body_refilters(body: str) -> bool:
    return bool(
        re.search(r"for\s+[^\n{]*\{[\s\S]{0,2000}if\s+[^\n{]*\{[\s\S]{0,800}continue", body)
        or re.search(r"for\s+[^\n{]*\{[\s\S]{0,2000}if\s+[^\n{]*\{[\s\S]{0,800}append\(", body)
    )


def _query_facts(
    body: str, functions: dict[str, list[FunctionFact]],
) -> list[FunctionFact]:
    prefixes = ("Get", "Count", "Search", "Find", "Load", "List", "Resolve")
    ignored = {
        "GetForm", "GetListOptions", "GetContextUserByPathParam", "GetContextRepo",
        "LoadAttributes", "LoadOwner", "ListOptions",
    }
    result = []
    seen = set()
    for match in re.finditer(r"(?:\b\w+\.)+([A-Z][A-Za-z0-9_]*)\s*\(", body):
        symbol = match.group(1)
        if symbol in ignored or not symbol.startswith(prefixes) or symbol in seen:
            continue
        fact = _find_function(functions, TraceStep(symbol, ""))
        if fact is None or not fact.path.startswith(("models/", "services/")):
            continue
        seen.add(symbol)
        result.append(fact)
        if len(result) == 4:
            break
    return result


def _generic_guidance(category: str) -> tuple[str, str]:
    values = {
        "pagination_header_metadata_leak": (
            "The count query may already use the same visibility predicate as the response conversion.",
            "Compare control and low-privilege body length, markers, and X-Total-Count with a GET-only fixture.",
        ),
        "cross_repository_object_lookup": (
            "The model helper may bind the object to the route repository internally.",
            "Use two finder-local repositories and compare an authorized object ID with a cross-repository ID.",
        ),
        "idor_candidate": (
            "The lookup helper may enforce owner or tenant binding internally.",
            "Use two finder-local owners and compare control/probe object identifiers without mutation.",
        ),
        "route_middleware_model_query_mismatch": (
            "The route middleware may fully enforce the resource boundary before the handler runs.",
            "Compare direct resource denial with the derived/list endpoint under the same restricted token.",
        ),
        "authentication_bypass_candidate": (
            "The endpoint may intentionally expose public data or inherit authentication from a parent group.",
            "Trace the complete parent middleware chain before designing an anonymous/control comparison.",
        ),
        "user_controlled_identifier_before_authorization": (
            "The called query may bind and authorize the identifier atomically.",
            "Compare an authorized finder-local identifier with a second fixture's identifier using GET only.",
        ),
        "private_public_visibility_mismatch": (
            "A conversion helper or query predicate may already remove private objects.",
            "Compare owner and unrelated-viewer results for exact public/private finder-local markers.",
        ),
    }
    return values[category]


def _generic_invariant(category: str) -> str:
    return {
        "pagination_header_metadata_leak": "Pagination metadata must describe the same authorized set as the response body.",
        "cross_repository_object_lookup": "An object identifier must remain bound to the repository in the route.",
        "idor_candidate": "An object identifier must remain bound to its authorized owner or tenant.",
        "route_middleware_model_query_mismatch": "Restricted-token middleware and the model query must enforce the same resource boundary.",
        "authentication_bypass_candidate": "Sensitive data must not be returned without the route's required authentication context.",
        "user_controlled_identifier_before_authorization": "A user-controlled identifier must be authorized before object data is returned.",
        "private_public_visibility_mismatch": "Private objects must be filtered consistently in query, conversion, body, and metadata.",
    }[category]


def _generic_mismatch(category: str) -> str:
    return {
        "pagination_header_metadata_leak": "A pre-filter total may be emitted with a post-filter body.",
        "cross_repository_object_lookup": "The object lookup appears to accept an identifier before route repository binding is proven.",
        "idor_candidate": "The object lookup appears to accept an identifier before owner binding is proven.",
        "route_middleware_model_query_mismatch": "The handler query does not visibly carry the restricted-token flag used by route middleware.",
        "authentication_bypass_candidate": "A sensitive-looking handler lacks an explicit authentication fact in the resolved route chain.",
        "user_controlled_identifier_before_authorization": "The handler resolves a path identifier before an authorization helper is visible.",
        "private_public_visibility_mismatch": "The query references visibility state without a resolved viewer visibility helper.",
    }[category]


def _load_go_files(source_root: Path) -> dict[str, str]:
    try:
        root = source_root.resolve(strict=True)
    except OSError:
        raise LocalTargetError("SOURCE_NOT_PREPARED") from None
    if source_root.is_symlink() or not (root / "go.mod").is_file():
        raise LocalTargetError("SOURCE_NOT_PREPARED")
    values: dict[str, str] = {}
    total = 0
    for path in sorted(root.rglob("*.go")):
        relative = path.relative_to(root)
        if any(part in {"vendor", ".git", "node_modules"} for part in relative.parts):
            continue
        if path.is_symlink() or not path.is_file():
            raise LocalTargetError("unsafe_source_tree")
        size = path.stat().st_size
        if size > MAX_FILE_BYTES:
            continue
        total += size
        if len(values) >= MAX_SOURCE_FILES or total > MAX_SOURCE_BYTES:
            raise LocalTargetError("source_discovery_limit")
        try:
            values[relative.as_posix()] = path.read_text(encoding="utf-8")
        except (OSError, UnicodeError):
            raise LocalTargetError("source_discovery_failed") from None
    if not values:
        raise LocalTargetError("source_discovery_failed")
    return values


def _index_functions(files: dict[str, str]) -> dict[str, list[FunctionFact]]:
    result: dict[str, list[FunctionFact]] = {}
    pattern = re.compile(
        r"(?m)^func\s+(?:\([^\n)]*\)\s*)?([A-Za-z_][A-Za-z0-9_]*)\s*\([^\n)]*\)[^{\n]*\{"
    )
    for path, text in files.items():
        digest = hashlib.sha256(text.encode()).hexdigest()
        for match in pattern.finditer(text):
            end = _balanced_end(text, match.end() - 1, "{", "}")
            if end is None:
                continue
            fact = FunctionFact(
                symbol=match.group(1),
                path=path,
                line=text.count("\n", 0, match.start()) + 1,
                body=text[match.start():end],
                file_hash=digest,
            )
            result.setdefault(fact.symbol, []).append(fact)
    return result


def _balanced_end(text: str, start: int, opening: str, closing: str) -> int | None:
    depth = 0
    quote: str | None = None
    escaped = False
    line_comment = False
    block_comment = False
    index = start
    while index < len(text):
        char = text[index]
        following = text[index + 1] if index + 1 < len(text) else ""
        if line_comment:
            if char == "\n":
                line_comment = False
        elif block_comment:
            if char == "*" and following == "/":
                block_comment = False
                index += 1
        elif quote is not None:
            if escaped:
                escaped = False
            elif char == "\\" and quote != "`":
                escaped = True
            elif char == quote:
                quote = None
        elif char == "/" and following == "/":
            line_comment = True
            index += 1
        elif char == "/" and following == "*":
            block_comment = True
            index += 1
        elif char in {'"', "'", "`"}:
            quote = char
        elif char == opening:
            depth += 1
        elif char == closing:
            depth -= 1
            if depth == 0:
                return index + 1
        index += 1
    return None


def _find_route(
    files: dict[str, str], handler_reference: str, route_fragment: str,
) -> dict[str, Any] | None:
    handler = handler_reference.rsplit(".", 1)[-1]
    for path, text in files.items():
        if not path.startswith("routers/"):
            continue
        for match in re.finditer(r"\b" + re.escape(handler_reference) + r"\b", text):
            start = max(0, match.start() - 1200)
            context = text[start:match.end() + 200]
            route_path = _route_path_from_context(context, route_fragment)
            if route_path is None:
                continue
            middleware = sorted(
                set(_route_call_middleware(text, match.start()))
                | set(_enclosing_group_middleware(text, match.start()))
            )
            return {
                "path": route_path,
                "location": f"{path}:{text.count(chr(10), 0, match.start()) + 1}",
                "middleware": middleware,
                "handler": handler,
                "file_hash": hashlib.sha256(text.encode()).hexdigest(),
            }
    return None


def _route_path_from_context(context: str, route_fragment: str) -> str | None:
    combo = list(re.finditer(r"\.Combo\(\s*\"([^\"]+)\"\s*\)\s*\.Get\(", context))
    direct = list(re.finditer(r"\.Get\(\s*\"([^\"]+)\"", context))
    paths = [item.group(1) for item in (*combo, *direct)]
    for value in reversed(paths):
        if route_fragment == "/" or route_fragment in value or value in route_fragment:
            return value
    return paths[-1] if paths else None


def _enclosing_group_middleware(text: str, position: int) -> list[str]:
    values = set()
    pattern = re.compile(r"\b\w+\.Group\([^,\n]+,\s*func\(\)\s*\{")
    middleware_pattern = re.compile(
        r"\b(?:checkTokenPublicOnly|reqToken|reqBasicAuth|orgAssignment|reqOrgVisible|"
        r"reqTeamMember|reqTeamReader|reqTeamReadAccess|reqRepoReader|repoAssignment|"
        r"tokenRequiresScopes|individualPermsChecker|context\.UserAssignmentAPI)\b"
    )
    for match in pattern.finditer(text, 0, position):
        brace = match.end() - 1
        end = _balanced_end(text, brace, "{", "}")
        if end is None or not brace < position < end:
            continue
        tail_end = text.find("\n", end)
        tail = text[end:tail_end if tail_end >= 0 else min(len(text), end + 1200)]
        values.update(middleware_pattern.findall(text[match.start():brace] + tail))
    return sorted(values)


def _route_call_middleware(text: str, position: int) -> list[str]:
    start = text.rfind(".Get(", max(0, position - 1200), position)
    if start < 0:
        return []
    opening = start + len(".Get")
    end = _balanced_end(text, opening, "(", ")")
    if end is None or not start < position < end:
        return []
    return sorted(set(re.findall(
        r"\b(?:checkTokenPublicOnly|reqToken|reqBasicAuth|orgAssignment|reqOrgVisible|"
        r"reqTeamMember|reqTeamReader|reqTeamReadAccess|reqRepoReader|repoAssignment|"
        r"tokenRequiresScopes|individualPermsChecker|context\.UserAssignmentAPI)\b",
        text[start:end],
    )))


def _find_handler_reference(files: dict[str, str], symbol: str) -> str | None:
    pattern = re.compile(r"\b([a-zA-Z_][\w]*\." + re.escape(symbol) + r")\b")
    for path, text in files.items():
        if path.startswith("routers/") and (match := pattern.search(text)):
            return match.group(1)
    return None


def _find_function(
    functions: dict[str, list[FunctionFact]], step: TraceStep,
) -> FunctionFact | None:
    choices = functions.get(step.symbol, [])
    if step.path_suffix:
        choices = [item for item in choices if item.path.endswith(step.path_suffix)]
    return choices[0] if len(choices) == 1 else None


def _calls_symbol(body: str, symbol: str) -> bool:
    return re.search(r"(?:\b\w+\.)*\b" + re.escape(symbol) + r"\s*\(", body) is not None


def _first_query_symbol(body: str) -> str | None:
    ignored = {
        "Error", "JSON", "NotFound", "Status", "Get", "Params", "PathParam",
        "FormInt64", "PathParamInt64", "FormString", "FormBool",
    }
    choices = []
    for match in re.finditer(r"(?:\b\w+\.)+([A-Z][A-Za-z0-9_]*)\s*\(", body):
        if match.group(1) not in ignored:
            choices.append(match.group(1))
    return next((item for item in choices if "Repo" in item or "ByRepo" in item), None) or (
        choices[0] if choices else None
    )


def _source_facts(route: dict[str, Any] | None, trace: Iterable[FunctionFact]) -> list[dict[str, Any]]:
    facts: list[dict[str, Any]] = []
    if route is not None:
        facts.append({
            "kind": "route", "location": route["location"],
            "file_sha256": route["file_hash"],
        })
    for item in trace:
        facts.append({
            "kind": "function", "symbol": item.symbol, "location": item.location(),
            "file_sha256": item.file_hash,
        })
    return facts
