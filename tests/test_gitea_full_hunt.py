import importlib.util
import json
from pathlib import Path

import pytest

from ctf_mcp.local_targets import LocalTargetError
from ctf_mcp.local_targets.base import LocalTargetManifest
from ctf_mcp.local_targets.gitea import (
    GITEA_IMAGE_DIGEST,
    GITEA_IMAGE_REFERENCE,
    GITEA_VERSION,
    GiteaAdapter,
)
from ctf_mcp.local_targets.gitea_discovery import (
    discover_and_triage,
    generate_scenario,
    validate_candidate_document,
    validate_scenario,
)
from ctf_mcp.local_targets.gitea_full_hunt import (
    CORE_DUPLICATE_SOURCES,
    PublicResearchClient,
    build_version_matrix,
    cluster_full_findings,
    final_classification,
    research_duplicate,
    run_full_hunt,
)


PINNED_COMMIT = "1" * 40
PINNED_DIGEST = "sha256:" + "2" * 64


def source_tree(root: Path) -> Path:
    source = root / "source"
    files = {
        "go.mod": "module code.gitea.io/gitea\n",
        "routers/api/v1/api.go": '''package v1
func routes(m *Router) {
    m.Get("/users/{username}/activities/feeds", checkTokenPublicOnly(), user.ListUserActivityFeeds)
    m.Get("/users/{username}/heatmap", checkTokenPublicOnly(), user.GetUserHeatmapData)
    m.Get("/users/{username}/repos", reqToken(), user.ListUserRepos)
    m.Combo("/orgs/{org}/repos").Get(user.ListOrgRepos)
    m.Get("/teams/{team_id}/repos", reqTeamReader(), org.GetTeamRepos)
    m.Get("/repos/{owner}/{repo}/actions/runs/{run}/jobs/{job}", repoAssignment(), actions.GetActionRunJob)
}
''',
        "routers/api/v1/user/user.go": '''package user
func ListUserActivityFeeds(ctx *APIContext) {
    opts := activities.GetFeedsOptions{Actor: ctx.Doer, RequestedUser: ctx.ContextUser}
    opts.ApplyPublicOnly(ctx.PublicOnly)
    feed.GetFeeds(ctx, opts)
}
func GetUserHeatmapData(ctx *APIContext) {
    activities.GetUserHeatmapDataByUser(ctx, ctx.ContextUser, ctx.Doer)
}
''',
        "models/activities/action.go": '''package activities
func (opts *GetFeedsOptions) ApplyPublicOnly(publicOnly bool) {
    if publicOnly { opts.IncludePrivate = false }
}
''',
        "services/feed/feed.go": '''package feed
func GetFeeds(ctx Context, opts activities.GetFeedsOptions) {
    activities.GetFeeds(ctx, opts)
}
''',
        "models/activities/action_list.go": '''package activities
func GetFeeds(ctx Context, opts GetFeedsOptions) {
    if opts.Actor.ID == opts.RequestedUser.ID {
        cond := builder.Eq{"is_private": false}
        ActivityQueryCondition(ctx, cond)
    }
}
''',
        "models/activities/user_heatmap.go": '''package activities
func GetUserHeatmapDataByUser(ctx Context, user User, doer User) {
    getUserHeatmapData(ctx, user, doer)
}
func getUserHeatmapData(ctx Context, user User, doer User) {
    ActivityQueryCondition(ctx, GetFeedsOptions{IncludePrivate: true})
}
''',
        "routers/api/v1/user/repo.go": '''package user
func ListUserRepos(ctx *APIContext) {
    listUserRepos(ctx)
}
func ListOrgRepos(ctx *APIContext) {
    listUserRepos(ctx)
}
func listUserRepos(ctx *APIContext) {
    repos, count := repo_model.GetUserRepositories(ctx, ctx.Doer.ID)
    ctx.SetTotalCountHeader(count)
    for _, repo := range repos {
        permission := repo.Permission(ctx.Doer)
        if permission.HasAnyUnitAccess() { ctx.JSON(repo) }
    }
}
''',
        "models/repo/repo_list.go": '''package repo
func GetUserRepositories(ctx Context, viewerID int64) { Query(ctx, viewerID) }
''',
        "models/repo/org_repo.go": '''package repo
func GetTeamRepositories(ctx Context, teamID int64) { Query(ctx, teamID) }
func CountTeamRepositories(ctx Context, teamID int64) { Query(ctx, teamID) }
''',
        "routers/api/v1/org/team.go": '''package org
func GetTeamRepos(ctx *APIContext) {
    repo_model.GetTeamRepositories(ctx, ctx.Team.ID)
    count := repo_model.CountTeamRepositories(ctx, ctx.Team.ID)
    ctx.SetTotalCountHeader(count)
    for _, repo := range ctx.Team.Repos {
        if repo.Permission(ctx.Doer).HasAnyUnitAccess() { ctx.JSON(repo) }
    }
}
''',
        "routers/api/v1/actions/jobs.go": '''package actions
func GetActionRunJob(ctx *APIContext) {
    actions_model.GetRunJob(ctx, ctx.Repo.Repository.ID)
}
''',
        "models/actions/jobs.go": '''package actions
func GetRunJob(ctx Context, repoID int64) { Query(ctx, repoID) }
''',
    }
    for relative, content in files.items():
        path = source / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)
    return source


def candidate_map(source: Path):
    return {item["candidate_id"]: item for item in discover_and_triage(source)}


def local_result(candidate: str, status: str = "VERIFIED_LOCAL") -> dict:
    number = int(candidate[-1])
    return {
        "candidate": candidate,
        "status": status,
        "assertions": {"control_passed": status != "BLOCKED_BY_LOCAL_SETUP"},
        "evidence": f"{number:032x}",
        "reassessment": f"{number + 16:032x}",
        "token": "never-write-this-synthetic-secret",
    }


class CompleteNoMatchResearch:
    def search(self, candidate):
        return [], {
            "github_issues": "empty",
            "github_prs": "empty",
            "github_advisories": "ok",
            "gitea_releases": "ok",
            "nvd": "empty",
        }


class NvdUnavailableNoMatchResearch:
    def search(self, candidate):
        return [], {
            "github_issues": "empty",
            "github_prs": "empty",
            "github_advisories": "ok",
            "gitea_releases": "ok",
            "nvd": "unavailable",
        }


class CoreUnavailableResearch:
    def search(self, candidate):
        return [], {
            "github_issues": "unavailable",
            "github_prs": "error",
            "github_advisories": "unavailable",
            "gitea_releases": "error",
            "nvd": "empty",
        }


def isolated_retests(candidate):
    baseline = candidate["baseline_candidate"]
    return [
        {
            "target": "latest", "version": "1.28.1", "commit": "3" * 40,
            "digest": "sha256:" + "4" * 64, "runtime_id": "latest-" + baseline,
            "endpoint": "127.0.0.1:13001", "isolated": True, "result": "AFFECTED",
            "control_passed": True, "evidence_ids": ["5" * 32],
        },
        {
            "target": "main", "version": "main", "commit": "6" * 40,
            "digest": "sha256:" + "7" * 64, "runtime_id": "main-" + baseline,
            "endpoint": "127.0.0.1:13002", "isolated": True, "result": "AFFECTED",
            "control_passed": True, "evidence_ids": ["8" * 32],
        },
    ]


def test_source_discovery_traces_route_middleware_handler_and_model(tmp_path):
    candidates = candidate_map(source_tree(tmp_path))
    assert {"SD-G04", "SD-G05", "SD-G06", "SD-G07", "SD-G08"} <= set(candidates)
    for candidate_id in ("SD-G04", "SD-G05", "SD-G06", "SD-G07", "SD-G08"):
        candidate = candidates[candidate_id]
        assert candidate["static_status"] == "NEEDS_LOCAL_VALIDATION"
        assert candidate["source_assertions"]["route_exists"] is True
        assert candidate["source_assertions"]["handler_resolved"] is True
        assert candidate["source_assertions"]["model_query_resolved"] is True
        assert candidate["source_assertions"]["trace_edges_resolved"] is True
        assert candidate["source_facts"]
        assert validate_candidate_document(json.loads(json.dumps(candidate))) == candidate
    assert candidates["SD-G06"]["source_assertions"]["count_before_filter"] is True
    assert candidates["SD-G07"]["root_cause_key"] == candidates["SD-G06"]["root_cause_key"]


def test_actions_repository_binding_is_rejected_statically(tmp_path):
    candidates = candidate_map(source_tree(tmp_path))
    action = next(value for key, value in candidates.items() if key.startswith("SD-ACTION-"))
    assert action["static_status"] == "REJECTED_STATIC"
    assert action["source_assertions"]["owner_repo_binding_present"] is True
    assert action["static_reasons"] == ["repository_binding_proven_before_object_lookup"]
    assert generate_scenario(action)["status"] == "NEEDS_MANUAL_SCENARIO"


def test_missing_trace_is_blocked_static_and_not_promoted(tmp_path):
    source = source_tree(tmp_path)
    (source / "models/repo/repo_list.go").write_text("package repo\n")
    candidates = candidate_map(source)
    assert candidates["SD-G06"]["static_status"] == "BLOCKED_STATIC"
    assert candidates["SD-G07"]["static_status"] == "BLOCKED_STATIC"
    assert generate_scenario(candidates["SD-G06"])["status"] == "NEEDS_MANUAL_SCENARIO"


def test_generic_idor_discovery_requires_route_handler_and_model_trace(tmp_path):
    source = source_tree(tmp_path)
    route_file = source / "routers/api/v1/object.go"
    route_file.write_text('''package v1
func objectRoutes(m *Router) {
    m.Get("/objects/{id}", object.GetObject)
}
func GetObject(ctx *APIContext) {
    id := ctx.PathParamInt64("id")
    object_model.GetObjectByID(ctx, id)
}
''')
    model_file = source / "models/object/object.go"
    model_file.parent.mkdir(parents=True)
    model_file.write_text('''package object
func GetObjectByID(ctx Context, id int64) { Query(ctx, id) }
''')
    candidates = discover_and_triage(source)
    idor = next(item for item in candidates if item["discovery_class"] == "idor_candidate")
    assert idor["static_status"] == "NEEDS_LOCAL_VALIDATION"
    assert idor["route"]["path"] == "/objects/{id}"
    assert idor["handler"]["symbol"] == "object.GetObject"
    assert idor["model_query_path"][0]["symbol"] == "GetObjectByID"
    assert idor["source_assertions"]["owner_repo_binding_present"] is False
    assert generate_scenario(idor)["status"] == "NEEDS_MANUAL_SCENARIO"


def test_scenario_generation_is_fixed_get_only_and_rejects_mutation(tmp_path):
    candidate = candidate_map(source_tree(tmp_path))["SD-G05"]
    scenario = generate_scenario(candidate)
    assert scenario == validate_scenario(scenario)
    assert scenario["target"] == "127.0.0.1:13000"
    assert scenario["methods"] == ["GET"]
    assert scenario["fixture_prefix"] == "finder-local-"
    assert scenario["direct_database_mutation"] is False
    assert scenario["control_required"] is scenario["probe_required"] is True
    with pytest.raises(LocalTargetError, match="unsafe_generated_scenario"):
        validate_scenario({**scenario, "methods": ["POST"]})


def test_known_duplicate_and_related_possible_duplicate_fixtures(tmp_path):
    candidates = candidate_map(source_tree(tmp_path))
    known = research_duplicate(candidates["SD-G07"], CompleteNoMatchResearch())
    possible = research_duplicate(candidates["SD-G06"], CompleteNoMatchResearch())
    assert known["duplicate_status"] == "KNOWN_DUPLICATE"
    assert known["possible_matches"] == [{
        "source": "github_issue",
        "reference": "go-gitea/gitea#38726",
        "url": "https://github.com/go-gitea/gitea/issues/38726",
        "match_reasons": [
            "exact_candidate", "exact_endpoint", "shared_query_path", "public_duplicate_disposition",
        ],
    }]
    assert possible["duplicate_status"] == "POSSIBLE_DUPLICATE"
    assert known["no_public_match_is_not_novelty_confirmation"] is True


def test_supplementary_nvd_unavailable_does_not_block_core_no_match(tmp_path):
    candidate = candidate_map(source_tree(tmp_path))["SD-G04"]
    result = research_duplicate(candidate, NvdUnavailableNoMatchResearch())
    assert result["duplicate_status"] == "NO_PUBLIC_DUPLICATE_FOUND"
    assert result["source_statuses"] == {
        "github_issues": "empty",
        "github_prs": "empty",
        "github_advisories": "ok",
        "gitea_releases": "ok",
        "nvd": "unavailable",
    }
    assert result["core_sources_checked"] == list(CORE_DUPLICATE_SOURCES)
    assert result["core_coverage_met"] is True
    assert result["research_incomplete"] is True
    assert result["unavailable_sources"] == ["nvd"]
    assert result["no_public_match_is_not_novelty_confirmation"] is True
    assert "research_incomplete_but_minimum_core_coverage_met" in result["reasoning_facts"]


def test_all_core_sources_failed_blocks_duplicate_check(tmp_path):
    candidate = candidate_map(source_tree(tmp_path))["SD-G08"]
    result = research_duplicate(candidate, CoreUnavailableResearch())
    assert result["duplicate_status"] == "DUPLICATE_CHECK_BLOCKED"
    assert result["core_sources_checked"] == []
    assert result["core_coverage_met"] is False
    assert result["research_incomplete"] is True
    assert set(result["unavailable_sources"]) == set(CORE_DUPLICATE_SOURCES)
    assert result["reasoning_facts"] == [
        "minimum_core_duplicate_research_coverage_not_met",
    ]


def test_semantic_overlap_is_possible_duplicate(tmp_path):
    candidate = candidate_map(source_tree(tmp_path))["SD-G05"]

    class SemanticOverlapResearch(CompleteNoMatchResearch):
        def search(self, candidate):
            _, statuses = super().search(candidate)
            return [{
                "source": "github_advisories",
                "reference": "GHSA-synthetic-overlap",
                "url": "https://github.com/advisories/GHSA-synthetic-overlap",
                "functions": ["GetUserHeatmapDataByUser"],
                "endpoints": [],
                "security_relevant": True,
            }], statuses

    result = research_duplicate(candidate, SemanticOverlapResearch())
    assert result["duplicate_status"] == "POSSIBLE_DUPLICATE"
    assert result["possible_matches"][0]["match_reasons"] == [
        "shared_query_path", "semantic_overlap",
    ]


def test_duplicate_false_positive_requires_endpoint_and_query_facts(tmp_path):
    candidate = candidate_map(source_tree(tmp_path))["SD-G08"]

    class GenericCountResult:
        def search(self, candidate):
            return [{
                "source": "github_issues", "reference": "generic:1",
                "url": "https://github.com/go-gitea/gitea/issues/1",
                "functions": [], "endpoints": [candidate["route"]["path"]],
                "security_relevant": True,
            }], ["github_issues", "github_prs", "github_advisories", "gitea_releases", "nvd"], True

    result = research_duplicate(candidate, GenericCountResult())
    assert result["duplicate_status"] == "NO_PUBLIC_DUPLICATE_FOUND"
    assert result["possible_matches"] == []


def test_public_research_client_rejects_non_allowlisted_host():
    with pytest.raises(LocalTargetError, match="duplicate_research_scope_violation"):
        PublicResearchClient()._get_json("example.com", "/anything")


def test_public_research_client_records_each_source_status(tmp_path, monkeypatch):
    candidate = candidate_map(source_tree(tmp_path))["SD-G04"]
    client = PublicResearchClient()
    calls = []

    def get_json(host, path):
        calls.append((host, path))
        if host == "services.nvd.nist.gov":
            raise LocalTargetError("duplicate_research_unavailable")
        if path.startswith("/search/issues?"):
            return {"items": []}
        if path.startswith("/advisories?"):
            return [{"ghsa_id": "GHSA-synthetic", "html_url": "https://github.com/advisories/GHSA-synthetic"}]
        if path.startswith("/repos/go-gitea/gitea/releases?"):
            return []
        raise AssertionError((host, path))

    monkeypatch.setattr(client, "_get_json", get_json)
    _, statuses = client.search(candidate)
    assert statuses == {
        "github_issues": "empty",
        "github_prs": "empty",
        "github_advisories": "ok",
        "gitea_releases": "empty",
        "nvd": "unavailable",
    }
    assert any("ecosystem=go" in path for _, path in calls)
    assert (
        "api.github.com", "/repos/go-gitea/gitea/releases?per_page=5"
    ) in calls


def test_latest_release_identity_is_strict(monkeypatch):
    client = PublicResearchClient()
    monkeypatch.setattr(client, "_get_json", lambda host, path: {"tag_name": "v1.27.3"})
    assert client.latest_release_version() == "1.27.3"
    monkeypatch.setattr(client, "_get_json", lambda host, path: {"tag_name": "nightly"})
    with pytest.raises(LocalTargetError, match="latest_release_identity_unavailable"):
        client.latest_release_version()


def test_latest_main_version_matrix_and_isolation(tmp_path):
    candidate = candidate_map(source_tree(tmp_path))["SD-G04"]
    matrix = build_version_matrix(
        candidate,
        pinned_version="1.27.3",
        pinned_commit=PINNED_COMMIT,
        pinned_digest=PINNED_DIGEST,
        local_result=local_result("G04"),
        retest_records=isolated_retests(candidate),
    )
    assert matrix["status"] == "AFFECTS_MAIN"
    assert [item["target"] for item in matrix["targets"]] == ["pinned", "latest", "main"]
    assert len({item["endpoint"] for item in matrix["targets"]}) == 3
    fixed = isolated_retests(candidate)
    for item in fixed:
        item["result"] = "INTENDED_BEHAVIOR"
        item["control_passed"] = True
    assert build_version_matrix(
        candidate,
        pinned_version="1.27.3",
        pinned_commit=PINNED_COMMIT,
        pinned_digest=PINNED_DIGEST,
        local_result=local_result("G04"),
        retest_records=fixed,
    )["status"] == "FIXED_IN_LATEST"
    duplicate_runtime = isolated_retests(candidate)
    duplicate_runtime[1]["runtime_id"] = duplicate_runtime[0]["runtime_id"]
    with pytest.raises(LocalTargetError, match="retest_runtime_not_isolated"):
        build_version_matrix(
            candidate,
            pinned_version="1.27.3",
            pinned_commit=PINNED_COMMIT,
            pinned_digest=PINNED_DIGEST,
            local_result=local_result("G04"),
            retest_records=duplicate_runtime,
        )


def test_latest_runtime_profile_has_separate_port_project_state_and_client(tmp_path, monkeypatch):
    manifest = LocalTargetManifest(
        target_id="gitea",
        repository="https://github.com/go-gitea/gitea",
        revision="146cc3eec57174711eac0e0a0c7b38670c6e3922",
        host_health_url="http://127.0.0.1:13000/api/healthz",
    )
    value = GiteaAdapter(
        tmp_path,
        manifest,
        runtime_variant="latest",
        runtime_port=13001,
        runtime_version=GITEA_VERSION,
        runtime_image_reference=GITEA_IMAGE_REFERENCE,
        runtime_image_digest=GITEA_IMAGE_DIGEST,
        compose_project="iwantgohome-local-gitea-latest",
    )
    assert value.runtime_root.name == "gitea-retest-latest"
    assert value.secret_root.name == "gitea-retest-latest"
    assert value.evidence_root.name == "gitea-retest-latest"
    assert "127.0.0.1:13001:3000" in value.compose_text
    assert "name: iwantgohome-local-gitea-latest" in value.compose_text

    ports = []

    class Response:
        status = 200

        @staticmethod
        def read(size):
            return b'{"status":"pass","description":"ok","checks":{}}'

        @staticmethod
        def getheader(name):
            return None

    class Connection:
        def __init__(self, host, port, timeout):
            ports.append((host, port))

        @staticmethod
        def request(method, path, body=None, headers=None):
            pass

        @staticmethod
        def getresponse():
            return Response()

        @staticmethod
        def close():
            pass

    monkeypatch.setattr(
        "ctf_mcp.local_targets.gitea_http.http.client.HTTPConnection", Connection
    )
    assert value.client_factory(timeout=1).request("health", "GET", "/api/healthz").status == 200
    assert ports == [("127.0.0.1", 13001)]


def test_adapter_full_hunt_retests_supported_latest_in_isolated_runtime(tmp_path, monkeypatch):
    manifest = LocalTargetManifest(
        target_id="gitea",
        repository="https://github.com/go-gitea/gitea",
        revision="146cc3eec57174711eac0e0a0c7b38670c6e3922",
        host_health_url="http://127.0.0.1:13000/api/healthz",
    )
    value = GiteaAdapter(tmp_path, manifest)
    observed = {}

    monkeypatch.setattr("ctf_mcp.local_targets.gitea.shutil.which", lambda name: "/usr/bin/docker")
    monkeypatch.setattr(PublicResearchClient, "latest_release_version", lambda self: GITEA_VERSION)
    monkeypatch.setattr(GiteaAdapter, "up", lambda self, progress=print: {"status": "healthy"})
    monkeypatch.setattr(GiteaAdapter, "stop", lambda self: observed.setdefault("stopped", self.runtime_port))
    monkeypatch.setattr(GiteaAdapter, "_collect_hunt_results", lambda self: (
        False,
        [local_result("G04")],
    ))

    def fake_run_full_hunt(**kwargs):
        observed["record"] = kwargs["retest_provider"]({"baseline_candidate": "G04"})[0]
        return {"status": "done"}

    monkeypatch.setattr(
        "ctf_mcp.local_targets.gitea_full_hunt.run_full_hunt", fake_run_full_hunt
    )
    assert value.full_hunt() == {"status": "done"}
    assert observed["record"] == {
        "target": "latest",
        "version": GITEA_VERSION,
        "commit": manifest.revision,
        "digest": GITEA_IMAGE_DIGEST,
        "runtime_id": "gitea-latest-13001",
        "endpoint": "127.0.0.1:13001",
        "isolated": True,
        "result": "AFFECTED",
        "control_passed": True,
        "evidence_ids": ["00000000000000000000000000000004", "00000000000000000000000000000014"],
    }
    assert observed["stopped"] == 13001


def test_full_hunt_orchestration_clusters_reports_and_redacts(tmp_path):
    source = source_tree(tmp_path)
    results = [
        local_result(f"G{number:02d}", "INTENDED_BEHAVIOR" if number < 4 else "VERIFIED_LOCAL")
        for number in range(1, 9)
    ]
    output = run_full_hunt(
        root=tmp_path,
        source_root=source,
        ensure_source=lambda: None,
        collect_local_results=lambda: (False, results),
        pinned_version="1.27.3",
        pinned_commit=PINNED_COMMIT,
        pinned_digest=PINNED_DIGEST,
        duplicate_client=CompleteNoMatchResearch(),
        retest_provider=isolated_retests,
        run_id="full-test-run",
    )
    assert output["static_candidates"] == 6
    assert output["rejected_statically"] == 1
    assert output["validated_locally"] == 5
    assert output["known_duplicates"] == 1
    assert output["possible_duplicates"] == 1
    assert output["new_security_candidates"] == 3
    assert output["needs_manual_scenario"] == 0
    assert [(item["id"], item["candidates"]) for item in output["root_cause_clusters"]] == [
        ("RC04", ["SD-G08"]),
        ("RC01", ["SD-G04"]),
        ("RC02", ["SD-G05"]),
        ("RC03", ["SD-G06", "SD-G07"]),
    ]
    run = tmp_path / output["reports"]
    assert (run / "report.md").is_file()
    assert (run / "report.json").is_file()
    assert (run / "duplicate-research.json").is_file()
    assert (run / "version-matrix.json").is_file()
    assert sorted(path.name for path in (run / "findings").glob("*.json")) == [
        "RC01.json", "RC02.json", "RC03.json", "RC04.json",
    ]
    assert sorted(path.name for path in (run / "poc").glob("*.py")) == [
        "RC01.py", "RC02.py", "RC03.py", "RC04.py",
    ]
    for path in run.rglob("*"):
        if path.is_file():
            raw = path.read_text()
            assert "never-write-this-synthetic-secret" not in raw
            assert "Authorization" not in raw
            assert "Cookie" not in raw
    report = json.loads((run / "report.json").read_text())
    duplicate_report = json.loads((run / "duplicate-research.json").read_text())
    assert report["new_security_candidate_is_not_vendor_confirmation"] is True
    assert report["external_submission_performed"] is False
    assert [item["candidate_id"] for item in report["local_regression_baseline"]] == [
        "G01", "G02", "G03", "G04", "G05", "G06", "G07", "G08",
    ]
    assert all(item["source_assertions"] for item in report["candidate_outcomes"])
    assert duplicate_report["results"]
    assert all(
        {"source_statuses", "unavailable_sources", "research_incomplete", "core_sources_checked"}
        <= set(item)
        for item in duplicate_report["results"]
    )


def test_verified_no_public_match_runs_retest_and_can_be_new_candidate(tmp_path):
    source = source_tree(tmp_path)
    results = [
        local_result(f"G{number:02d}", "VERIFIED_LOCAL" if number == 4 else "INTENDED_BEHAVIOR")
        for number in range(1, 9)
    ]
    retested = []

    def retest(candidate):
        retested.append(candidate["candidate_id"])
        return isolated_retests(candidate)

    output = run_full_hunt(
        root=tmp_path,
        source_root=source,
        ensure_source=lambda: None,
        collect_local_results=lambda: (False, results),
        pinned_version="1.27.3",
        pinned_commit=PINNED_COMMIT,
        pinned_digest=PINNED_DIGEST,
        duplicate_client=NvdUnavailableNoMatchResearch(),
        retest_provider=retest,
        run_id="partial-research-new-candidate",
    )
    g04 = next(item for item in output["outcomes"] if item["candidate_id"] == "SD-G04")
    assert retested == ["SD-G04"]
    assert g04["duplicate_research"]["duplicate_status"] == "NO_PUBLIC_DUPLICATE_FOUND"
    assert g04["duplicate_research"]["core_coverage_met"] is True
    assert g04["duplicate_research"]["research_incomplete"] is True
    assert g04["version_matrix"]["status"] == "AFFECTS_MAIN"
    assert g04["final_status"] == "NEW_SECURITY_CANDIDATE"
    assert output["new_security_candidates"] == 1


def test_new_candidate_requires_maintained_source_assertions(tmp_path):
    candidate = candidate_map(source_tree(tmp_path))["SD-G04"]
    scenario = generate_scenario(candidate)
    duplicate = research_duplicate(candidate, NvdUnavailableNoMatchResearch())
    local = local_result("G04")
    matrix = build_version_matrix(
        candidate,
        pinned_version="1.27.3",
        pinned_commit=PINNED_COMMIT,
        pinned_digest=PINNED_DIGEST,
        local_result=local,
        retest_records=isolated_retests(candidate),
    )
    weakened = {
        **candidate,
        "source_assertions": {**candidate["source_assertions"], "candidate_pattern_observed": False},
    }
    assert final_classification(weakened, scenario, local, duplicate, matrix) == "VERIFIED_LOCAL"
    assert duplicate["no_public_match_is_not_novelty_confirmation"] is True


def test_full_hunt_keeps_source_and_local_blockers_in_report(tmp_path):
    output = run_full_hunt(
        root=tmp_path,
        source_root=tmp_path / "missing",
        ensure_source=lambda: (_ for _ in ()).throw(LocalTargetError("SOURCE_ACQUIRE_FAILED")),
        collect_local_results=lambda: (_ for _ in ()).throw(LocalTargetError("VALIDATION_BLOCKED")),
        pinned_version="1.27.3",
        pinned_commit=PINNED_COMMIT,
        pinned_digest=PINNED_DIGEST,
        duplicate_client=CompleteNoMatchResearch(),
        run_id="blocked-full-run",
    )
    assert output["static_candidates"] == 0
    assert output["pipeline_blockers"] == [
        {"stage": "source_discovery", "reason": "SOURCE_ACQUIRE_FAILED"},
        {"stage": "local_validation", "reason": "VALIDATION_BLOCKED"},
    ]
    assert (tmp_path / output["json_report"]).is_file()


def test_full_hunt_cli_flag_and_summary(tmp_path, monkeypatch, capsys):
    root = Path(__file__).resolve().parents[1]
    spec = importlib.util.spec_from_file_location("local_target_full_test", root / "scripts/local_target.py")
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)

    class Adapter:
        supported_candidates = frozenset({"G01"})

        def hunt(self):
            raise AssertionError("legacy hunt must remain separate")

        def full_hunt(self):
            return {
                "target": "gitea", "static_candidates": 6, "rejected_statically": 1,
                "validated_locally": 5, "known_duplicates": 1, "possible_duplicates": 1,
                "new_security_candidates": 3, "needs_manual_scenario": 0,
                "root_cause_clusters": [{
                    "id": "RC03", "status": "KNOWN_DUPLICATE",
                    "candidates": ["SD-G06", "SD-G07"],
                }],
                "affected_versions": [
                    {"target": "pinned", "version": "1.27.3", "status": "tested_locally"},
                    {"target": "latest", "version": "1.28.1", "status": "affected"},
                    {"target": "main", "version": "main", "status": "affected"},
                ],
                "reports": ".operator/reports/gitea/full-one",
                "human_action_required": "Review NEW_SECURITY_CANDIDATE reports before private vendor disclosure.",
            }

    monkeypatch.setattr(module, "load_adapter", lambda root, target: Adapter())
    assert module.run_local(tmp_path, ["hunt", "--full"], {"FINDER_TARGET": "gitea"}) == 0
    output = capsys.readouterr().out
    assert "Static candidates: 6" in output
    assert "New security candidates: 3" in output
    assert "- RC03 (KNOWN_DUPLICATE): SD-G06, SD-G07" in output
    assert "Reports: .operator/reports/gitea/full-one" in output
    with pytest.raises(LocalTargetError, match="invalid_local_action"):
        module.run_local(tmp_path, ["status", "--full"], {"FINDER_TARGET": "gitea"})
