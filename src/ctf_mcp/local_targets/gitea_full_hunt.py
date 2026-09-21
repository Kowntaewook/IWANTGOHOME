"""End-to-end source discovery, research, retest, and reporting for Gitea."""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import http.client
import json
import os
from pathlib import Path
import re
import secrets
from typing import Any, Callable
from urllib.parse import quote, urlencode

from .base import LocalTargetError, atomic_private_json, secure_directory
from .gitea_discovery import discover_and_triage, generate_scenario
from .gitea_hunt import _render_poc


PUBLIC_RESEARCH_HOSTS = frozenset({"api.github.com", "services.nvd.nist.gov"})
CORE_DUPLICATE_SOURCES = (
    "github_issues", "github_prs", "github_advisories", "gitea_releases",
)
SUPPLEMENTARY_DUPLICATE_SOURCES = ("nvd",)
ALL_DUPLICATE_SOURCES = CORE_DUPLICATE_SOURCES + SUPPLEMENTARY_DUPLICATE_SOURCES
SOURCE_RESEARCH_STATUSES = frozenset({"ok", "empty", "unavailable", "error"})
MINIMUM_CORE_SOURCE_COVERAGE = 3
FINAL_STATUSES = frozenset({
    "REJECTED_STATIC", "INTENDED_BEHAVIOR", "BLOCKED_BY_LOCAL_SETUP",
    "NEEDS_MANUAL_SCENARIO", "VERIFIED_LOCAL", "KNOWN_DUPLICATE",
    "POSSIBLE_DUPLICATE", "NEW_SECURITY_CANDIDATE",
})
RETEST_STATUSES = frozenset({
    "AFFECTS_PINNED_ONLY", "AFFECTS_LATEST", "AFFECTS_MAIN",
    "FIXED_IN_LATEST", "FIXED_IN_MAIN", "RETEST_BLOCKED",
})
KNOWN_PUBLIC_MATCHES: tuple[dict[str, Any], ...] = (
    {
        "reference": "go-gitea/gitea#38726",
        "url": "https://github.com/go-gitea/gitea/issues/38726",
        "source": "github_issue",
        "candidate_ids": ("SD-G07",),
        "related_candidate_ids": ("SD-G06",),
        "endpoint": "/api/v1/orgs/{org}/repos",
        "functions": ("ListOrgRepos", "listUserRepos", "GetUserRepositories"),
        "public_disposition": "closed_as_duplicate",
        "observed_at": "2026-09-21",
    },
)


class PublicResearchClient:
    """Credential-free GET client restricted to public duplicate-research APIs."""

    def __init__(self, *, timeout: float = 8.0, max_bytes: int = 2 * 1024 * 1024):
        self.timeout = timeout
        self.max_bytes = max_bytes

    def search(self, candidate: dict[str, Any]) -> tuple[list[dict[str, Any]], dict[str, str]]:
        terms = duplicate_search_terms(candidate)
        records: list[dict[str, Any]] = []
        source_statuses: dict[str, str] = {}
        handler = candidate["handler"]["symbol"].rsplit(".", 1)[-1]
        queries = (
            ("github_issues", "api.github.com", "/search/issues?" + urlencode({
                "q": f'repo:go-gitea/gitea is:issue "{handler}"', "per_page": 20,
            })),
            ("github_prs", "api.github.com", "/search/issues?" + urlencode({
                "q": f'repo:go-gitea/gitea is:pr is:merged "{handler}"', "per_page": 20,
            })),
            ("github_advisories", "api.github.com", "/advisories?" + urlencode({
                "ecosystem": "go", "affects": "code.gitea.io/gitea", "per_page": 100,
            })),
            ("gitea_releases", "api.github.com", "/repos/go-gitea/gitea/releases?per_page=5"),
            ("nvd", "services.nvd.nist.gov", "/rest/json/cves/2.0?" + urlencode({
                "keywordSearch": "Gitea " + handler, "resultsPerPage": 100,
            })),
        )
        for source, host, path in queries:
            try:
                data = self._get_json(host, path)
                source_statuses[source] = "ok" if _source_document_count(source, data) else "empty"
                records.extend(_public_records(source, data, candidate))
            except LocalTargetError as error:
                source_statuses[source] = (
                    "unavailable" if error.code == "duplicate_research_unavailable" else "error"
                )
        return records, source_statuses

    def latest_release_version(self) -> str:
        data = self._get_json("api.github.com", "/repos/go-gitea/gitea/releases/latest")
        tag = data.get("tag_name") if isinstance(data, dict) else None
        if not isinstance(tag, str) or not re.fullmatch(r"v[0-9]+\.[0-9]+\.[0-9]+", tag):
            raise LocalTargetError("latest_release_identity_unavailable")
        return tag.removeprefix("v")

    def _get_json(self, host: str, path: str) -> Any:
        if host not in PUBLIC_RESEARCH_HOSTS or not path.startswith("/") or "\r" in path or "\n" in path:
            raise LocalTargetError("duplicate_research_scope_violation")
        connection = http.client.HTTPSConnection(host, 443, timeout=self.timeout)
        try:
            connection.request("GET", path, headers={
                "Accept": "application/vnd.github+json, application/json",
                "User-Agent": "IWANTGOHOME-local-duplicate-research",
            })
            response = connection.getresponse()
            raw = response.read(self.max_bytes + 1)
        except (OSError, http.client.HTTPException):
            raise LocalTargetError("duplicate_research_unavailable") from None
        finally:
            connection.close()
        if response.status != 200:
            code = (
                "duplicate_research_unavailable"
                if response.status in {408, 425, 429} or response.status >= 500
                else "duplicate_research_error"
            )
            raise LocalTargetError(code)
        if len(raw) > self.max_bytes:
            raise LocalTargetError("duplicate_research_error")
        try:
            return json.loads(raw)
        except (TypeError, ValueError):
            raise LocalTargetError("duplicate_research_error") from None


def duplicate_search_terms(candidate: dict[str, Any]) -> list[str]:
    terms = [
        candidate["route"]["path"],
        candidate["handler"]["symbol"].rsplit(".", 1)[-1],
        *(item["symbol"] for item in candidate["model_query_path"]),
        candidate["discovery_class"],
    ]
    return list(dict.fromkeys(term for term in terms if isinstance(term, str) and term))


def research_duplicate(
    candidate: dict[str, Any], client: PublicResearchClient | Any,
) -> dict[str, Any]:
    """Match source facts to public records; text similarity alone never decides."""
    terms = duplicate_search_terms(candidate)
    try:
        search_result = client.search(candidate)
        records, source_statuses = _coerce_search_result(search_result)
    except (LocalTargetError, OSError, ValueError, TypeError):
        records = []
        source_statuses = {source: "error" for source in ALL_DUPLICATE_SOURCES}
    source_statuses = _normalize_source_statuses(source_statuses)
    core_sources_checked = [
        source for source in CORE_DUPLICATE_SOURCES
        if source_statuses[source] in {"ok", "empty"}
    ]
    core_coverage_met = len(core_sources_checked) >= MINIMUM_CORE_SOURCE_COVERAGE
    unavailable_sources = [
        source for source in ALL_DUPLICATE_SOURCES
        if source_statuses[source] in {"unavailable", "error"}
    ]
    research_incomplete = bool(unavailable_sources)
    exact: list[dict[str, Any]] = []
    possible: list[dict[str, Any]] = []
    for known in KNOWN_PUBLIC_MATCHES:
        if candidate["candidate_id"] in known["candidate_ids"]:
            exact.append(_sanitized_match(known, [
                "exact_candidate", "exact_endpoint", "shared_query_path", "public_duplicate_disposition",
            ]))
        elif candidate["candidate_id"] in known["related_candidate_ids"]:
            possible.append(_sanitized_match(known, ["shared_query_path", "different_endpoint"]))
    for record in records:
        strength = _record_match_strength(candidate, record)
        if strength == "exact":
            exact.append(_sanitized_match(record, ["exact_endpoint", "shared_query_path"]))
        elif strength == "possible":
            possible.append(_sanitized_match(record, ["shared_query_path", "semantic_overlap"]))
    matches = _deduplicate_matches(exact + possible)
    if exact:
        status, confidence = "KNOWN_DUPLICATE", "high"
        reasoning = ["public_record_matches_endpoint_and_query_path"]
    elif possible:
        status, confidence = "POSSIBLE_DUPLICATE", "medium"
        reasoning = ["public_record_shares_query_path_but_not_all_invariants"]
    elif core_coverage_met:
        status, confidence = "NO_PUBLIC_DUPLICATE_FOUND", "low"
        reasoning = ["no_endpoint_and_query_path_match_in_checked_core_sources"]
        if research_incomplete:
            reasoning.append("research_incomplete_but_minimum_core_coverage_met")
    else:
        status, confidence = "DUPLICATE_CHECK_BLOCKED", "none"
        reasoning = ["minimum_core_duplicate_research_coverage_not_met"]
    result = {
        "candidate_id": candidate["candidate_id"],
        "duplicate_status": status,
        "possible_matches": matches,
        "searched_terms": terms,
        "searched_sources": list(ALL_DUPLICATE_SOURCES),
        "source_statuses": source_statuses,
        "unavailable_sources": unavailable_sources,
        "research_incomplete": research_incomplete,
        "core_sources_checked": core_sources_checked,
        "minimum_core_source_coverage": MINIMUM_CORE_SOURCE_COVERAGE,
        "core_coverage_met": core_coverage_met,
        "reasoning_facts": reasoning,
        "confidence": confidence,
        "no_public_match_is_not_novelty_confirmation": True,
    }
    _assert_sanitized(result)
    return result


def build_version_matrix(
    candidate: dict[str, Any],
    *,
    pinned_version: str,
    pinned_commit: str,
    pinned_digest: str,
    local_result: dict[str, Any] | None,
    retest_records: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Build an isolated three-target matrix and deterministic impact status."""
    baseline = candidate.get("baseline_candidate")
    pinned_affected = bool(local_result and local_result.get("status") == "VERIFIED_LOCAL")
    pinned = {
        "target": "pinned", "version": pinned_version, "commit": pinned_commit,
        "digest": pinned_digest, "runtime_id": "gitea-pinned-13000",
        "endpoint": "127.0.0.1:13000", "isolated": True,
        "validation_candidate": baseline,
        "result": "AFFECTED" if pinned_affected else (
            local_result.get("status") if local_result else "BLOCKED_BY_LOCAL_SETUP"
        ),
        "control_passed": bool(local_result and local_result.get("assertions", {}).get("control_passed")),
        "evidence_ids": _local_evidence_ids(local_result),
    }
    supplied = {item.get("target"): item for item in (retest_records or [])}
    latest = supplied.get("latest") or _blocked_retest_target(
        "latest", "127.0.0.1:13001", "gitea-latest-13001",
        "isolated_latest_runtime_not_available",
    )
    main = supplied.get("main") or _blocked_retest_target(
        "main", "127.0.0.1:13002", "gitea-main-13002",
        "isolated_main_runtime_not_available",
    )
    targets = [pinned, _validate_retest_target(latest), _validate_retest_target(main)]
    if len({item["runtime_id"] for item in targets}) != 3 or len({item["endpoint"] for item in targets}) != 3:
        raise LocalTargetError("retest_runtime_not_isolated")
    latest_result = targets[1]["result"]
    main_result = targets[2]["result"]
    if not pinned_affected:
        status = "RETEST_BLOCKED"
    elif latest_result == "AFFECTED" and main_result == "AFFECTED":
        status = "AFFECTS_MAIN"
    elif latest_result == "AFFECTED" and main_result == "INTENDED_BEHAVIOR":
        status = "FIXED_IN_MAIN"
    elif latest_result == "AFFECTED":
        status = "AFFECTS_LATEST"
    elif latest_result == "INTENDED_BEHAVIOR" and main_result == "INTENDED_BEHAVIOR":
        status = "FIXED_IN_LATEST"
    elif latest_result == "INTENDED_BEHAVIOR" and main_result == "AFFECTED":
        status = "AFFECTS_MAIN"
    elif latest_result == "INTENDED_BEHAVIOR" and main_result == "RETEST_BLOCKED":
        status = "FIXED_IN_LATEST"
    elif latest_result == "RETEST_BLOCKED" or main_result == "RETEST_BLOCKED":
        status = "RETEST_BLOCKED"
    else:
        status = "AFFECTS_PINNED_ONLY"
    return {
        "candidate_id": candidate["candidate_id"],
        "status": status,
        "targets": targets,
    }


def final_classification(
    candidate: dict[str, Any],
    scenario: dict[str, Any],
    local_result: dict[str, Any] | None,
    duplicate: dict[str, Any] | None,
    matrix: dict[str, Any] | None,
) -> str:
    if candidate["static_status"] == "REJECTED_STATIC":
        return "REJECTED_STATIC"
    if candidate["static_status"] == "BLOCKED_STATIC" or scenario["status"] == "NEEDS_MANUAL_SCENARIO":
        return "NEEDS_MANUAL_SCENARIO"
    if local_result is None or local_result.get("status") == "BLOCKED_BY_LOCAL_SETUP":
        return "BLOCKED_BY_LOCAL_SETUP"
    if local_result.get("status") == "INTENDED_BEHAVIOR":
        return "INTENDED_BEHAVIOR"
    if local_result.get("status") != "VERIFIED_LOCAL":
        return "NEEDS_MANUAL_SCENARIO"
    duplicate_status = duplicate.get("duplicate_status") if duplicate else "DUPLICATE_CHECK_BLOCKED"
    if duplicate_status == "KNOWN_DUPLICATE":
        return "KNOWN_DUPLICATE"
    if duplicate_status == "POSSIBLE_DUPLICATE":
        return "POSSIBLE_DUPLICATE"
    promotion_assertions = (
        "route_exists", "handler_resolved", "model_query_resolved",
        "trace_edges_resolved", "candidate_pattern_observed",
    )
    source_assertions = candidate.get("source_assertions", {})
    source_assertions_maintained = bool(
        isinstance(source_assertions, dict)
        and all(source_assertions.get(key) is True for key in promotion_assertions)
    )
    control_passed = local_result.get("assertions", {}).get("control_passed") is True
    if (duplicate_status == "NO_PUBLIC_DUPLICATE_FOUND"
            and duplicate.get("core_coverage_met") is True
            and matrix and _latest_is_affected(matrix)
            and control_passed and source_assertions_maintained):
        return "NEW_SECURITY_CANDIDATE"
    return "VERIFIED_LOCAL"


def run_full_hunt(
    *,
    root: Path,
    source_root: Path,
    ensure_source: Callable[[], Any],
    collect_local_results: Callable[[], tuple[bool, list[dict[str, Any]]]],
    pinned_version: str,
    pinned_commit: str,
    pinned_digest: str,
    duplicate_client: Any | None = None,
    retest_provider: Callable[[dict[str, Any]], list[dict[str, Any]]] | None = None,
    run_id: str | None = None,
) -> dict[str, Any]:
    """Run all full-hunt stages while preserving stage-specific blockers."""
    pipeline_blockers: list[dict[str, str]] = []
    try:
        ensure_source()
        candidates = discover_and_triage(source_root)
    except LocalTargetError as error:
        candidates = []
        pipeline_blockers.append({"stage": "source_discovery", "reason": error.code})
    scenarios = {item["candidate_id"]: generate_scenario(item) for item in candidates}
    bootstrapped = False
    try:
        bootstrapped, local_results = collect_local_results()
        local_blocker = None
    except LocalTargetError as error:
        local_results = []
        local_blocker = error.code
        pipeline_blockers.append({"stage": "local_validation", "reason": error.code})
    local_by_id = {item.get("candidate"): item for item in local_results}
    regression_baseline = [_regression_outcome(item) for item in local_results]
    research_client = duplicate_client or PublicResearchClient()
    duplicate_results: list[dict[str, Any]] = []
    version_matrices: list[dict[str, Any]] = []
    outcomes: list[dict[str, Any]] = []
    for candidate in candidates:
        scenario = scenarios[candidate["candidate_id"]]
        baseline = candidate.get("baseline_candidate")
        local = local_by_id.get(baseline)
        if local is None and local_blocker and scenario["status"] == "LOCAL_BASELINE_REUSE":
            local = {
                "candidate": baseline, "status": "BLOCKED_BY_LOCAL_SETUP",
                "assertions": {"control_passed": False}, "blocked_reason": local_blocker,
            }
        duplicate = None
        matrix = None
        if local and local.get("status") == "VERIFIED_LOCAL":
            duplicate = research_duplicate(candidate, research_client)
            duplicate_results.append(duplicate)
            if duplicate["duplicate_status"] in {"NO_PUBLIC_DUPLICATE_FOUND", "POSSIBLE_DUPLICATE"}:
                records = retest_provider(candidate) if retest_provider else []
                matrix = build_version_matrix(
                    candidate,
                    pinned_version=pinned_version,
                    pinned_commit=pinned_commit,
                    pinned_digest=pinned_digest,
                    local_result=local,
                    retest_records=records,
                )
                version_matrices.append(matrix)
        final = final_classification(candidate, scenario, local, duplicate, matrix)
        if final not in FINAL_STATUSES:
            raise LocalTargetError("invalid_full_hunt_classification")
        outcomes.append(_candidate_outcome(candidate, scenario, local, duplicate, matrix, final))
    clusters = cluster_full_findings(outcomes)
    artifacts = create_full_reports(
        root,
        target="gitea",
        pinned_version=pinned_version,
        pinned_commit=pinned_commit,
        pinned_digest=pinned_digest,
        candidates=candidates,
        outcomes=outcomes,
        clusters=clusters,
        duplicate_results=duplicate_results,
        version_matrices=version_matrices,
        regression_baseline=regression_baseline,
        pipeline_blockers=pipeline_blockers,
        run_id=run_id,
    )
    counts = _full_counts(outcomes)
    return {
        "target": "gitea",
        "pinned_version": pinned_version,
        "bootstrap_performed": bootstrapped,
        **counts,
        "root_cause_clusters": [
            {"id": item["id"], "candidates": item["candidate_ids"], "status": item["status"]}
            for item in clusters
        ],
        "affected_versions": _affected_version_summary(version_matrices, pinned_version, outcomes),
        "reports": artifacts["report_directory"],
        "json_report": artifacts["json_report"],
        "markdown_report": artifacts["markdown_report"],
        "pipeline_blockers": pipeline_blockers,
        "regression_baseline": regression_baseline,
        "human_action_required": "Review NEW_SECURITY_CANDIDATE reports before private vendor disclosure.",
        "external_submission_performed": False,
        "outcomes": outcomes,
    }


def cluster_full_findings(outcomes: list[dict[str, Any]]) -> list[dict[str, Any]]:
    groups: dict[str, list[dict[str, Any]]] = {}
    for item in outcomes:
        if item["final_status"] in {"REJECTED_STATIC", "NEEDS_MANUAL_SCENARIO", "BLOCKED_BY_LOCAL_SETUP"}:
            continue
        groups.setdefault(item["root_cause_key"], []).append(item)
    known_ids = {
        "activities.GetFeeds/public-only-visibility": "RC01",
        "activities.GetUserHeatmapData/public-only-visibility": "RC02",
        "listUserRepos/GetUserRepositories-count-before-filter": "RC03",
        "GetTeamRepos/CountTeamRepositories-count-before-filter": "RC04",
    }
    clusters = []
    for key in sorted(groups):
        items = groups[key]
        cluster_id = known_ids.get(key) or "RC-" + hashlib.sha256(key.encode()).hexdigest()[:8].upper()
        duplicate = [item["duplicate_research"] for item in items if item["duplicate_research"]]
        matrices = [item["version_matrix"] for item in items if item["version_matrix"]]
        status = _cluster_status([item["final_status"] for item in items])
        clusters.append({
            "id": cluster_id,
            "kind": "root_cause_cluster",
            "status": status,
            "candidate_ids": [item["candidate_id"] for item in items],
            "baseline_candidates": list(dict.fromkeys(
                item["baseline_candidate"] for item in items if item["baseline_candidate"]
            )),
            "affected_endpoints": list(dict.fromkeys(item["route"]["path"] for item in items)),
            "shared_function": key,
            "source_locations": list(dict.fromkeys(
                fact["location"] for item in items for fact in item["source_facts"]
            )),
            "local_evidence_ids": list(dict.fromkeys(
                evidence for item in items for evidence in item["local_evidence_ids"]
            )),
            "duplicate_research": duplicate,
            "version_matrix": matrices,
        })
    return clusters


def create_full_reports(
    root: Path,
    *,
    target: str,
    pinned_version: str,
    pinned_commit: str,
    pinned_digest: str,
    candidates: list[dict[str, Any]],
    outcomes: list[dict[str, Any]],
    clusters: list[dict[str, Any]],
    duplicate_results: list[dict[str, Any]],
    version_matrices: list[dict[str, Any]],
    regression_baseline: list[dict[str, Any]],
    pipeline_blockers: list[dict[str, str]],
    run_id: str | None = None,
) -> dict[str, Any]:
    run_id = run_id or _run_id()
    if target != "gitea" or not re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,95}", run_id):
        raise LocalTargetError("invalid_hunt_run_id")
    run_root = root / ".operator" / "reports" / target / run_id
    if run_root.exists() or run_root.is_symlink():
        raise LocalTargetError("hunt_run_exists")
    findings_root = run_root / "findings"
    poc_root = run_root / "poc"
    secure_directory(findings_root)
    secure_directory(poc_root)
    report = {
        "schema_version": 2,
        "pipeline": "full_hunt",
        "run_id": run_id,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "target": target,
        "pinned": {
            "version": pinned_version, "commit": pinned_commit, "digest": pinned_digest,
        },
        "summary": _full_counts(outcomes),
        "pipeline_blockers": pipeline_blockers,
        "local_regression_baseline": regression_baseline,
        "static_candidates": candidates,
        "candidate_outcomes": outcomes,
        "root_cause_clusters": clusters,
        "human_review_required": True,
        "external_submission_performed": False,
        "new_security_candidate_is_not_vendor_confirmation": True,
    }
    _assert_sanitized(report)
    atomic_private_json(run_root / "report.json", report)
    atomic_private_json(run_root / "duplicate-research.json", {
        "schema_version": 1, "results": duplicate_results,
    })
    atomic_private_json(run_root / "version-matrix.json", {
        "schema_version": 1, "results": version_matrices,
    })
    _write_private_text(run_root / "report.md", _render_report_markdown(report), 0o600)
    for cluster in clusters:
        _assert_sanitized(cluster)
        atomic_private_json(findings_root / (cluster["id"] + ".json"), cluster)
        _write_private_text(
            findings_root / (cluster["id"] + ".md"), _render_finding_markdown(cluster), 0o600,
        )
        baseline = tuple(cluster["baseline_candidates"])
        if baseline and all(value in {"G04", "G05", "G06", "G07", "G08"} for value in baseline):
            _write_private_text(
                poc_root / (cluster["id"] + ".py"),
                _render_poc({"candidate_ids": list(baseline)}),
                0o700,
            )
    return {
        "report_directory": str(run_root.relative_to(root)),
        "json_report": str((run_root / "report.json").relative_to(root)),
        "markdown_report": str((run_root / "report.md").relative_to(root)),
    }


def _candidate_outcome(
    candidate: dict[str, Any], scenario: dict[str, Any], local: dict[str, Any] | None,
    duplicate: dict[str, Any] | None, matrix: dict[str, Any] | None, final: str,
) -> dict[str, Any]:
    return {
        "candidate_id": candidate["candidate_id"],
        "baseline_candidate": candidate.get("baseline_candidate"),
        "discovery_class": candidate["discovery_class"],
        "route": candidate["route"],
        "root_cause_key": candidate["root_cause_key"],
        "static_status": candidate["static_status"],
        "source_assertions": candidate["source_assertions"],
        "source_facts": candidate["source_facts"],
        "scenario_status": scenario["status"],
        "local_status": local.get("status") if local else None,
        "local_evidence_ids": _local_evidence_ids(local),
        "duplicate_research": duplicate,
        "version_matrix": matrix,
        "final_status": final,
    }


def _regression_outcome(result: dict[str, Any]) -> dict[str, Any]:
    assertions = result.get("assertions", {})
    return {
        "candidate_id": result.get("candidate"),
        "status": result.get("status"),
        "request_count": result.get("request_count"),
        "assertions": {
            key: value for key, value in assertions.items()
            if isinstance(key, str) and isinstance(value, bool)
        },
        "evidence_ids": _local_evidence_ids(result),
    }


def _local_evidence_ids(local: dict[str, Any] | None) -> list[str]:
    if not local:
        return []
    return [
        local[key] for key in ("evidence", "reassessment")
        if isinstance(local.get(key), str) and re.fullmatch(r"[0-9a-f]{32}", local[key])
    ]


def _blocked_retest_target(target: str, endpoint: str, runtime_id: str, reason: str) -> dict[str, Any]:
    return {
        "target": target, "version": None, "commit": None, "digest": None,
        "runtime_id": runtime_id, "endpoint": endpoint, "isolated": True,
        "result": "RETEST_BLOCKED", "control_passed": False,
        "evidence_ids": [], "blocked_reason": reason,
    }


def _validate_retest_target(value: dict[str, Any]) -> dict[str, Any]:
    required = {
        "target", "version", "commit", "digest", "runtime_id", "endpoint",
        "isolated", "result", "control_passed", "evidence_ids",
    }
    allowed = required | {"blocked_reason"}
    if (not isinstance(value, dict) or not required <= set(value) <= allowed
            or value["target"] not in {"latest", "main"}
            or value["endpoint"] not in {"127.0.0.1:13001", "127.0.0.1:13002"}
            or value["isolated"] is not True
            or value["result"] not in {"AFFECTED", "INTENDED_BEHAVIOR", "RETEST_BLOCKED"}
            or not isinstance(value["control_passed"], bool)
            or (value["result"] == "AFFECTED" and value["control_passed"] is not True)
            or not isinstance(value["runtime_id"], str)
            or not isinstance(value["evidence_ids"], list)):
        raise LocalTargetError("invalid_retest_evidence")
    for key, pattern in (
        ("commit", r"[0-9a-f]{40}"), ("digest", r"sha256:[0-9a-f]{64}"),
    ):
        if value[key] is not None and not re.fullmatch(pattern, value[key]):
            raise LocalTargetError("invalid_retest_evidence")
    if value["result"] != "RETEST_BLOCKED" and (not value["version"] or not value["commit"] or not value["digest"]):
        raise LocalTargetError("invalid_retest_evidence")
    return value


def _record_match_strength(candidate: dict[str, Any], record: dict[str, Any]) -> str | None:
    endpoint = candidate["route"]["path"]
    functions = {
        candidate["handler"]["symbol"].rsplit(".", 1)[-1],
        *(item["symbol"] for item in candidate["model_query_path"]),
    }
    record_functions = set(record.get("functions", []))
    endpoint_match = endpoint in record.get("endpoints", [])
    function_match = bool(functions & record_functions)
    if endpoint_match and function_match:
        return "exact"
    if function_match and record.get("security_relevant") is True:
        return "possible"
    return None


def _coerce_search_result(value: Any) -> tuple[list[dict[str, Any]], dict[str, str]]:
    if (isinstance(value, tuple) and len(value) == 2
            and isinstance(value[0], list) and isinstance(value[1], dict)):
        records = [item for item in value[0] if isinstance(item, dict)]
        return records, value[1]
    # Compatibility with the original internal test/client contract.
    if (isinstance(value, tuple) and len(value) == 3
            and isinstance(value[0], list) and isinstance(value[1], list)
            and isinstance(value[2], bool)):
        status = "ok" if value[2] else "unavailable"
        return [item for item in value[0] if isinstance(item, dict)], {
            source: status for source in value[1] if source in ALL_DUPLICATE_SOURCES
        }
    raise LocalTargetError("invalid_duplicate_research_result")


def _normalize_source_statuses(value: dict[str, Any]) -> dict[str, str]:
    result = {}
    for source in ALL_DUPLICATE_SOURCES:
        status = value.get(source, "error")
        result[source] = status if status in SOURCE_RESEARCH_STATUSES else "error"
    return result


def _source_document_count(source: str, data: Any) -> int:
    if source in {"github_issues", "github_prs"} and isinstance(data, dict):
        items = data.get("items")
        return len(items) if isinstance(items, list) else 0
    if source in {"github_advisories", "gitea_releases"} and isinstance(data, list):
        return len(data)
    if source == "nvd" and isinstance(data, dict):
        values = data.get("vulnerabilities")
        return len(values) if isinstance(values, list) else 0
    return 0


def _latest_is_affected(matrix: dict[str, Any]) -> bool:
    if matrix.get("status") not in {"AFFECTS_LATEST", "AFFECTS_MAIN"}:
        return False
    targets = matrix.get("targets")
    if not isinstance(targets, list):
        return False
    return any(
        isinstance(item, dict)
        and item.get("target") == "latest"
        and item.get("result") == "AFFECTED"
        for item in targets
    )


def _public_records(source: str, data: Any, candidate: dict[str, Any]) -> list[dict[str, Any]]:
    documents: list[dict[str, Any]] = []
    if source in {"github_issues", "github_prs"} and isinstance(data, dict):
        documents = [item for item in data.get("items", []) if isinstance(item, dict)]
    elif source in {"github_advisories", "gitea_releases"} and isinstance(data, list):
        documents = [item for item in data if isinstance(item, dict)]
    elif source == "nvd" and isinstance(data, dict):
        documents = [item for item in data.get("vulnerabilities", []) if isinstance(item, dict)]
    terms = duplicate_search_terms(candidate)
    records = []
    for document in documents[:100]:
        flattened = json.dumps(document, ensure_ascii=True, sort_keys=True)[:200_000]
        functions = [term for term in terms[1:] if term in flattened]
        endpoint = candidate["route"]["path"]
        endpoints = [endpoint] if endpoint in flattened else []
        url = _public_url(document)
        reference = _public_reference(source, document)
        if not url or not reference:
            continue
        records.append({
            "source": source,
            "reference": reference,
            "url": url,
            "functions": functions,
            "endpoints": endpoints,
            "security_relevant": any(
                word in flattened.lower() for word in ("security", "private", "authorization", "visibility")
            ),
        })
    return records


def _public_url(document: dict[str, Any]) -> str | None:
    for key in ("html_url", "url"):
        value = document.get(key)
        if isinstance(value, str) and value.startswith((
            "https://github.com/go-gitea/gitea/",
            "https://github.com/advisories/",
            "https://nvd.nist.gov/vuln/detail/",
            "https://api.github.com/",
        )):
            return value
    cve = document.get("cve")
    if isinstance(cve, dict) and isinstance(cve.get("id"), str):
        return "https://nvd.nist.gov/vuln/detail/" + quote(cve["id"], safe="")
    return None


def _public_reference(source: str, document: dict[str, Any]) -> str | None:
    for key in ("ghsa_id", "tag_name", "number"):
        value = document.get(key)
        if isinstance(value, (str, int)):
            return source + ":" + str(value)[:80]
    cve = document.get("cve")
    if isinstance(cve, dict) and isinstance(cve.get("id"), str):
        return "nvd:" + cve["id"][:40]
    return None


def _sanitized_match(value: dict[str, Any], reasons: list[str]) -> dict[str, Any]:
    return {
        "source": value["source"], "reference": value["reference"],
        "url": value["url"], "match_reasons": reasons,
    }


def _deduplicate_matches(values: list[dict[str, Any]]) -> list[dict[str, Any]]:
    result = []
    seen = set()
    for item in values:
        key = (item["source"], item["reference"], item["url"])
        if key not in seen:
            seen.add(key)
            result.append(item)
    return result


def _cluster_status(statuses: list[str]) -> str:
    order = (
        "NEW_SECURITY_CANDIDATE", "KNOWN_DUPLICATE", "POSSIBLE_DUPLICATE",
        "VERIFIED_LOCAL", "INTENDED_BEHAVIOR",
    )
    return next((status for status in order if status in statuses), statuses[0])


def _full_counts(outcomes: list[dict[str, Any]]) -> dict[str, int]:
    return {
        "static_candidates": len(outcomes),
        "rejected_statically": sum(item["final_status"] == "REJECTED_STATIC" for item in outcomes),
        "validated_locally": sum(
            item["local_status"] in {"VERIFIED_LOCAL", "INTENDED_BEHAVIOR", "NEEDS_MORE_EVIDENCE"}
            for item in outcomes
        ),
        "known_duplicates": sum(item["final_status"] == "KNOWN_DUPLICATE" for item in outcomes),
        "possible_duplicates": sum(item["final_status"] == "POSSIBLE_DUPLICATE" for item in outcomes),
        "new_security_candidates": sum(item["final_status"] == "NEW_SECURITY_CANDIDATE" for item in outcomes),
        "needs_manual_scenario": sum(item["final_status"] == "NEEDS_MANUAL_SCENARIO" for item in outcomes),
    }


def _affected_version_summary(
    matrices: list[dict[str, Any]], pinned_version: str, outcomes: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    pinned_tested = any(
        item["local_status"] in {"VERIFIED_LOCAL", "INTENDED_BEHAVIOR", "NEEDS_MORE_EVIDENCE"}
        for item in outcomes
    )
    result = [{
        "target": "pinned", "version": pinned_version,
        "status": "tested_locally" if pinned_tested else "validation_blocked",
    }]
    for target in ("latest", "main"):
        values = [
            next(item for item in matrix["targets"] if item["target"] == target)
            for matrix in matrices
        ]
        result.append({
            "target": target,
            "version": next((item["version"] for item in values if item["version"]), None),
            "status": (
                "affected" if any(item["result"] == "AFFECTED" for item in values)
                else "fixed" if values and all(item["result"] == "INTENDED_BEHAVIOR" for item in values)
                else "retest_blocked"
            ),
        })
    return result


def _render_report_markdown(report: dict[str, Any]) -> str:
    summary = report["summary"]
    lines = [
        "# Gitea full hunt report", "",
        f"- Run ID: `{report['run_id']}`",
        f"- Target: `{report['target']}`",
        f"- Pinned version: `{report['pinned']['version']}`",
        f"- Pinned commit: `{report['pinned']['commit']}`", "",
        f"- Static candidates: {summary['static_candidates']}",
        f"- Rejected statically: {summary['rejected_statically']}",
        f"- Validated locally: {summary['validated_locally']}",
        f"- Known duplicates: {summary['known_duplicates']}",
        f"- Possible duplicates: {summary['possible_duplicates']}",
        f"- New security candidates: {summary['new_security_candidates']}",
        f"- Needs manual scenario: {summary['needs_manual_scenario']}", "",
        "`NEW_SECURITY_CANDIDATE` is a report-ready research candidate, not vendor confirmation.",
        "Human review is required before private vendor disclosure.", "",
        "## Candidate outcomes", "",
        "| Candidate | Static | Local | Final |", "| --- | --- | --- | --- |",
    ]
    for item in report["candidate_outcomes"]:
        lines.append(
            f"| {item['candidate_id']} | {item['static_status']} | "
            f"{item['local_status'] or 'not run'} | {item['final_status']} |"
        )
    lines.extend(["", "## G01-G08 regression baseline", ""])
    if report["local_regression_baseline"]:
        lines.extend(["| Candidate | Status | Requests |", "| --- | --- | ---: |"])
        for item in report["local_regression_baseline"]:
            lines.append(
                f"| {item['candidate_id']} | {item['status']} | {item['request_count']} |"
            )
    else:
        lines.append("Local baseline validation was blocked before candidate execution.")
    lines.extend(["", "## Root-cause clusters", ""])
    for item in report["root_cause_clusters"]:
        lines.append(
            f"- **{item['id']}** ({item['status']}): {', '.join(item['candidate_ids'])}"
        )
    if report["pipeline_blockers"]:
        lines.extend(["", "## Pipeline blockers", ""])
        for item in report["pipeline_blockers"]:
            lines.append(f"- {item['stage']}: `{item['reason']}`")
    return "\n".join(lines).rstrip() + "\n"


def _render_finding_markdown(cluster: dict[str, Any]) -> str:
    return "\n".join([
        f"# {cluster['id']} root-cause cluster", "",
        f"- Status: `{cluster['status']}`",
        f"- Candidates: {', '.join(cluster['candidate_ids'])}",
        f"- Endpoints: {', '.join(cluster['affected_endpoints'])}",
        f"- Shared function: `{cluster['shared_function']}`",
        f"- Source locations: {', '.join(cluster['source_locations'])}",
        f"- Local evidence IDs: {', '.join(cluster['local_evidence_ids']) or 'none'}", "",
        "Review duplicate research and the version matrix in the adjacent JSON before disclosure.",
    ]) + "\n"


def _write_private_text(path: Path, value: str, mode: int) -> None:
    if path.exists() or path.is_symlink():
        raise LocalTargetError("hunt_artifact_exists")
    try:
        with path.open("x", encoding="utf-8") as handle:
            os.chmod(path, mode)
            handle.write(value)
    except OSError:
        raise LocalTargetError("hunt_report_failed") from None


def _run_id() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dt%H%M%S%f") + "-full-" + secrets.token_hex(4)


def _assert_sanitized(value: Any) -> None:
    raw = json.dumps(value, ensure_ascii=True, sort_keys=True)
    forbidden = (
        '"authorization"', '"cookie"', '"password"', '"access_token"',
        '"private_key"', '"credential"', 'basic ', 'bearer ',
    )
    if any(item in raw.lower() for item in forbidden):
        raise LocalTargetError("unsafe_hunt_report")
