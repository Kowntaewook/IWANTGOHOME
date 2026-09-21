import json
from pathlib import Path

from ctf_mcp.full_hunt.engine import FullHuntEngine
from ctf_mcp.local_targets.base import LocalTargetError
from ctf_mcp.local_targets.mattermost import ENTERPRISE_IMAGE_DIGEST, MattermostAdapter
from ctf_mcp.local_targets.mattermost_discovery import (
    discover_mattermost_candidates,
    discover_mattermost_version,
)
from ctf_mcp.local_targets.mattermost_hunt_adapter import (
    MATTERMOST_MAIN_BRANCH,
    MATTERMOST_PINNED_VERSION,
    MATTERMOST_RETEST_ENDPOINTS,
    MattermostFullHuntTargetAdapter,
)
from ctf_mcp.local_targets.mattermost_main_retest import (
    MAIN_BUILD_RECIPE,
    MAIN_ENDPOINT,
    MattermostMainRetest,
)
from ctf_mcp.local_targets.hunt_registry import get_full_hunt_registry


COMMIT = MattermostAdapter.pinned_revision
DIGEST = ENTERPRISE_IMAGE_DIGEST


SOURCE = r'''
func Init(api *API) {
    api.BaseRoutes.User.Handle("/channel_members", api.APISessionRequired(getChannelMembersForUser)).Methods(http.MethodGet)
    api.BaseRoutes.UserThreads.Handle("", api.APISessionRequired(getThreadsForUser)).Methods(http.MethodGet)
    api.BaseRoutes.UserThreads.Handle("/read", api.APISessionRequired(updateReadStateAllThreadsByUser)).Methods(http.MethodPut)
}
func getChannelMembersForUser(c *Context, w http.ResponseWriter, r *http.Request) {
    c.App.SessionHasPermissionToUser()
    c.App.GetChannelMembersWithTeamDataForUserWithPagination()
    members[i].SanitizeForCurrentUser(currentUserId)
}
func getThreadsForUser(c *Context, w http.ResponseWriter, r *http.Request) {
    c.App.SessionHasPermissionToUser()
    c.App.SessionHasPermissionToTeam()
    c.App.GetThreadsForUser()
}
func updateReadStateAllThreadsByUser(c *Context, w http.ResponseWriter, r *http.Request) {
    c.App.SessionHasPermissionToUser()
    c.App.UpdateThreadsReadForUser()
}
'''


def make_source(root):
    path = root / "server/channels/api4/user.go"
    path.parent.mkdir(parents=True)
    path.write_text(SOURCE)
    version = root / "server/public/model/version.go"
    version.parent.mkdir(parents=True)
    version.write_text('package model\nvar versions = []string{\n\t"12.0.0",\n}\n')


class FakeLocal:
    pinned_revision = COMMIT

    def __init__(self, root, *, healthy=True):
        self.target_root = root / "source"
        make_source(self.target_root)
        self.healthy = healthy
        self.prepared = self.up_called = self.bootstrapped = False

    def _source_details(self, timeout):
        return {"prepared": True, "actual_commit": COMMIT, "origin_ok": True}

    def _require_source(self):
        return None

    def prepare(self):
        self.prepared = True

    def health(self):
        return {"healthy": self.healthy}

    def up(self, progress):
        self.up_called = True
        self.healthy = True
        return {"status": "healthy"}

    def bootstrap(self):
        self.bootstrapped = True
        return {"status": "ready"}

    def validate(self, candidate):
        if candidate == "S12":
            return [{
                "status": "VERIFIED_CANDIDATE", "control": 200, "bulk": 200,
                "control_fixture_verified": True,
                "synthetic_marker_returned": True, "evidence": "evidence-s12",
                "reassessment": "reassessment-s12", "request_count": 2,
            }]
        if candidate == "S13":
            return [{
                "status": "INTENDED_BEHAVIOR", "control": 200, "candidate_result": 200,
                "control_fixture_verified": True, "synthetic_marker_returned": True,
                "evidence": "evidence-s13", "reassessment": "reassessment-s13",
                "request_count": 2,
            }]
        raise AssertionError("unsafe validator selected")


def test_source_discovery_is_backed_by_routes_auth_and_data_paths(tmp_path):
    make_source(tmp_path)
    assert discover_mattermost_version(tmp_path) == MATTERMOST_PINNED_VERSION
    candidates = discover_mattermost_candidates(tmp_path)
    assert [item["candidate_id"] for item in candidates] == ["MM-S12", "MM-S13", "MM-S15"]
    assert [item["static_status"] for item in candidates] == [
        "NEEDS_LOCAL_VALIDATION", "NEEDS_LOCAL_VALIDATION", "NEEDS_MANUAL_SCENARIO",
    ]
    for candidate in candidates:
        assert all(candidate["source_assertions"].values())
        assert candidate["source_facts"]
        assert candidate["authorization_path"] and candidate["data_access_path"]
        assert candidate["security_invariant"]
        assert candidate["control_hypothesis"] and candidate["probe_hypothesis"]


def test_source_mismatch_is_blocked_static(tmp_path):
    make_source(tmp_path)
    path = tmp_path / "server/channels/api4/user.go"
    path.write_text(SOURCE.replace("SessionHasPermissionToTeam", "missingTeamAuthorization"))
    by_id = {item["candidate_id"]: item for item in discover_mattermost_candidates(tmp_path)}
    assert by_id["MM-S12"]["static_status"] == "BLOCKED_STATIC"
    assert by_id["MM-S12"]["source_assertions"]["authorization_path_resolved"] is False


def test_mattermost_adapter_is_registered_without_core_product_logic():
    assert get_full_hunt_registry().targets == {"gitea", "mattermost"}
    assert MATTERMOST_MAIN_BRANCH == "main"
    assert MATTERMOST_RETEST_ENDPOINTS == {
        "latest": "127.0.0.1:13101", "main": "127.0.0.1:13102",
    }


def test_full_pipeline_preserves_read_only_gate_and_common_report_schema(tmp_path):
    local = FakeLocal(tmp_path)
    adapter = MattermostFullHuntTargetAdapter(local_adapter=local, now=lambda: "2026-09-21T00:00:00+00:00")
    result = FullHuntEngine(adapter).run(root=tmp_path, run_id="mattermost-unit")
    statuses = {item["candidate_id"]: item["classification"] for item in result["outcomes"]}
    assert statuses == {
        "MM-S12": "VERIFIED_LOCAL",
        "MM-S13": "INTENDED_BEHAVIOR",
        "MM-S15": "NEEDS_MANUAL_SCENARIO",
    }
    s15 = next(item for item in result["outcomes"] if item["candidate_id"] == "MM-S15")
    assert s15["scenario_synthesis"]["status"] == "SCENARIO_BLOCKED"
    assert s15["scenario_synthesis"]["blocker"] == "destructive_validation_method_not_supported"
    assert s15["scenario_synthesis"]["binding_id"] == "mattermost-bulk-state-auth-v1"
    assert s15["scenario_synthesis"]["confidence"] == "WEAK"
    report = json.loads((tmp_path / result["json_report"]).read_text())
    first = report["candidate_outcomes"][0]
    assert {
        "target", "candidate_id", "source_assertions", "static_assessment",
        "local_validation", "duplicate_research", "root_cause", "version_matrix",
        "classification", "evidence", "provenance",
    } <= set(first)
    assert report["source"] == {
        "repository": MattermostAdapter.repository,
        "version": MATTERMOST_PINNED_VERSION,
        "commit": COMMIT,
        "revision": {"commit": COMMIT},
        "fetch_timestamp": "2026-09-21T00:00:00+00:00",
        "source_identity": MattermostAdapter.repository + "@" + COMMIT,
    }
    assert result["scenario_generated"] == 1
    assert result["scenario_bindings_matched"] == 1
    assert result["scenario_blocked"] == 1
    assert result["scenario_manual_remaining"] == 1


def test_full_pipeline_preserves_candidate_specific_partial_bootstrap_blockers(tmp_path):
    class PartialLocal(FakeLocal):
        def bootstrap(self):
            self.bootstrapped = True
            return {
                "status": "partial",
                "bootstrap_status": "PARTIAL",
                "capabilities": {
                    "delegated_user_manager": {
                        "status": "unavailable",
                        "reason": "REQUIRED_ROLE_PERMISSIONS_MISSING",
                    },
                },
            }

        def validate(self, candidate):
            return [{
                "status": "BLOCKED_BY_LOCAL_SETUP",
                "blocked_reason": "REQUIRED_ROLE_PERMISSIONS_MISSING",
                "evidence": "evidence-" + candidate.lower(),
                "reassessment": "reassessment-" + candidate.lower(),
                "request_count": 0,
            }]

    local = PartialLocal(tmp_path)
    target = MattermostFullHuntTargetAdapter(local_adapter=local)
    result = FullHuntEngine(target).run(root=tmp_path, run_id="mattermost-partial")
    outcomes = {item["candidate_id"]: item for item in result["outcomes"]}

    assert result["bootstrap_performed"] is True
    for candidate in ("MM-S12", "MM-S13"):
        assert outcomes[candidate]["classification"] == "BLOCKED_BY_LOCAL_SETUP"
        assert outcomes[candidate]["local_validation"]["blocked_reason"] == (
            "REQUIRED_ROLE_PERMISSIONS_MISSING"
        )


def test_duplicate_research_uses_generic_coverage_semantics(tmp_path):
    class Client:
        def search(self, candidate):
            return [], {
                "github_issues": "empty", "github_prs": "empty",
                "github_advisories": "empty", "mattermost_releases": "unavailable",
                "nvd": "unavailable",
            }

    local = FakeLocal(tmp_path)
    adapter = MattermostFullHuntTargetAdapter(local_adapter=local, duplicate_client=Client())
    candidate = discover_mattermost_candidates(local.target_root)[0]
    result = adapter.duplicate_research(candidate)
    assert result["duplicate_status"] == "NO_PUBLIC_DUPLICATE_FOUND"
    assert result["core_coverage_met"] is True
    assert result["research_incomplete"] is True
    assert result["no_public_match_is_not_novelty_confirmation"] is True


def test_version_matrix_keeps_pinned_latest_and_main_isolated(tmp_path):
    local = FakeLocal(tmp_path)
    records = [
        {
            "target": "latest", "version": "stable", "commit": "a" * 40,
            "digest": "sha256:" + "1" * 64, "runtime_id": "mattermost-latest-13101",
            "endpoint": "127.0.0.1:13101", "isolated": True, "result": "AFFECTED",
            "control_passed": True, "evidence_ids": ["latest-evidence"],
        },
        {
            "target": "main", "version": None, "commit": "b" * 40,
            "digest": "sha256:" + "2" * 64, "runtime_id": "mattermost-main-13102",
            "endpoint": "127.0.0.1:13102", "isolated": True, "result": "AFFECTED",
            "control_passed": True, "evidence_ids": ["main-evidence"],
        },
    ]
    adapter = MattermostFullHuntTargetAdapter(
        local_adapter=local, retest_provider=lambda candidate: records,
    )
    candidate = discover_mattermost_candidates(local.target_root)[0]
    matrix = adapter.version_retest(
        candidate,
        {"status": "VERIFIED_LOCAL", "evidence": "pinned-evidence", "assertions": {"control_passed": True}},
        {"duplicate_status": "NO_PUBLIC_DUPLICATE_FOUND"},
    )
    assert matrix["status"] == "AFFECTS_MAIN"
    assert [item["target"] for item in matrix["targets"]] == ["pinned", "latest", "main"]
    assert len({item["runtime_id"] for item in matrix["targets"]}) == 3
    assert matrix["targets"][2]["commit"] == "b" * 40


def test_runtime_failure_still_writes_static_report(tmp_path):
    class BlockedLocal(FakeLocal):
        def up(self, progress):
            raise LocalTargetError("DOCKER_UNAVAILABLE")

    adapter = MattermostFullHuntTargetAdapter(local_adapter=BlockedLocal(tmp_path, healthy=False))
    result = FullHuntEngine(adapter).run(root=tmp_path, run_id="mattermost-blocked")
    assert result["static_candidates"] == 3
    assert result["pipeline_blockers"] == [
        {"stage": "local_validation", "reason": "DOCKER_UNAVAILABLE"},
    ]
    assert Path(tmp_path / result["json_report"]).is_file()


def test_main_source_identity_is_immutable_and_namespaced(tmp_path):
    value = MattermostMainRetest(tmp_path, now=lambda: "2026-09-21T00:00:00+00:00")
    value.resolver.resolve = lambda: {
        "repository": MattermostAdapter.repository, "branch": "main",
        "commit": "b" * 40, "fetched_at": "2026-09-21T00:00:00+00:00",
        "source_directory": ".operator/targets/mattermost-main/" + "b" * 40,
    }
    source = value.resolve_source()
    assert source.revision == "b" * 40 and source.branch == "main"
    assert value.runtime_root == tmp_path / ".operator/local-runtime/mattermost-main"
    assert value.secret_root == tmp_path / ".operator/local-secrets/mattermost-main"
    assert value.evidence_root == tmp_path / ".operator/local-evidence/mattermost-main"
    assert MAIN_ENDPOINT == "127.0.0.1:13102"
    assert b"COPY server /src/server" in MAIN_BUILD_RECIPE
    assert b"go build" in MAIN_BUILD_RECIPE


def test_main_retest_never_promotes_build_or_runtime_failure(tmp_path, monkeypatch):
    value = MattermostMainRetest(tmp_path)
    monkeypatch.setattr(value, "resolve_source", lambda: (_ for _ in ()).throw(
        LocalTargetError("MAIN_COMMIT_UNRESOLVED")
    ))
    result = value.retest({"candidate_id": "MM-S12"})
    assert result["result"] == "RETEST_BLOCKED"
    assert result["control_passed"] is False
    assert result["blocked_reason"] == "MAIN_COMMIT_UNRESOLVED"
