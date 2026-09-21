import json
from pathlib import Path

import pytest

from ctf_mcp.full_hunt.duplicate import DuplicateResearchPolicy, evaluate_duplicate_research
from ctf_mcp.full_hunt.engine import FullHuntEngine
from ctf_mcp.full_hunt.registry import FullHuntRegistry
from ctf_mcp.full_hunt.reporting import ReportWriter
from ctf_mcp.full_hunt.runtime import IsolatedRuntimeLifecycle
from ctf_mcp.full_hunt.scenario import ScenarioPlan, TargetCapabilities
from ctf_mcp.full_hunt.schema import (
    DuplicateQuery,
    RuntimeRequest,
    SourceIdentity,
    validate_candidate_schema,
)
from ctf_mcp.full_hunt.version_retest import (
    ImmutableBuildCache,
    compose_version_matrix,
    configuration_hash,
    content_hash,
    immutable_build_cache_key,
    immutable_image_identity,
)
from ctf_mcp.local_targets.base import LocalTargetError


COMMIT = "1" * 40
DIGEST = "sha256:" + "2" * 64


class FakeTarget:
    target_id = "fake"

    def __init__(self):
        self.events = []

    def resolve_source(self):
        self.events.append("resolve_source")
        return SourceIdentity("https://example.invalid/owned-fixture", COMMIT)

    def discover_candidates(self, source):
        assert source.revision == COMMIT
        self.events.append("discover_candidates")
        return [
            {
                "candidate_id": "FX-001",
                "static_status": "NEEDS_LOCAL_VALIDATION",
                "root_cause_key": "parser/shared-boundary",
                "evidence": ["source:10"],
                "provenance": {"revision": COMMIT},
            },
            {
                "candidate_id": "FX-002",
                "static_status": "REJECTED_STATIC",
                "root_cause_key": "parser/rejected",
                "evidence": [],
                "provenance": {"revision": COMMIT},
            },
        ]

    def static_triage(self, candidate):
        self.events.append("static_triage:" + candidate["candidate_id"])
        return candidate

    def build_prepare_runtime(self, request):
        assert request == RuntimeRequest("pinned")
        self.events.append("prepare_runtime")
        return {"status": "ready"}

    def bootstrap(self, request):
        assert request == RuntimeRequest("pinned")
        self.events.append("bootstrap")
        return {"status": "ready"}

    def validate_candidate(self, candidate, request):
        assert request.candidate_id == candidate["candidate_id"]
        self.events.append("validate_candidate:" + candidate["candidate_id"])
        return {
            "status": "VERIFIED_LOCAL",
            "assertions": {"control_passed": True},
            "evidence": "3" * 32,
            "token": "must-never-reach-report",
        }

    def duplicate_queries(self, candidate):
        self.events.append("duplicate_queries:" + candidate["candidate_id"])
        return [DuplicateQuery("tracker", "FX-001", True)]

    def duplicate_research(self, candidate):
        self.events.append("duplicate_research:" + candidate["candidate_id"])
        return {
            "candidate_id": candidate["candidate_id"],
            "duplicate_status": "NO_PUBLIC_DUPLICATE_FOUND",
            "core_coverage_met": True,
            "no_public_match_is_not_novelty_confirmation": True,
        }

    def version_retest(self, candidate, local_validation, duplicate_research):
        assert local_validation["status"] == "VERIFIED_LOCAL"
        assert duplicate_research["duplicate_status"] == "NO_PUBLIC_DUPLICATE_FOUND"
        self.events.append("version_retest:" + candidate["candidate_id"])
        return {
            "candidate_id": candidate["candidate_id"],
            "status": "AFFECTS_MAIN",
            "targets": [
                {"kind": "pinned", "status": "tested_locally"},
                {"kind": "latest", "status": "affected"},
                {"kind": "main", "status": "affected", "commit": COMMIT, "image_id": DIGEST},
            ],
        }

    @staticmethod
    def cluster_key(candidate):
        return candidate["root_cause_key"]

    @staticmethod
    def root_cause_metadata(key, outcomes):
        return {
            "root_cause_id": "ROOT-" + key.rsplit("/", 1)[-1].upper(),
            "classification": (
                "NEW_SECURITY_CANDIDATE"
                if any(item["classification"] == "NEW_SECURITY_CANDIDATE" for item in outcomes)
                else "REJECTED_STATIC"
            ),
        }

    @staticmethod
    def classify(candidate, local_validation, duplicate_research, version_matrix):
        if candidate["static_status"] == "REJECTED_STATIC":
            return "REJECTED_STATIC"
        if (local_validation and local_validation["status"] == "VERIFIED_LOCAL"
                and duplicate_research["duplicate_status"] == "NO_PUBLIC_DUPLICATE_FOUND"
                and version_matrix["status"] == "AFFECTS_MAIN"):
            return "NEW_SECURITY_CANDIDATE"
        return "VERIFIED_LOCAL"

    def write_report(self, *, root, source, candidates, outcomes, clusters, blockers, run_id):
        writer = ReportWriter(root, self.target_id, run_id or "fake-run")
        writer.initialize()
        report = {
            "schema_version": 1,
            "target": self.target_id,
            "source": {"repository": source.repository, "revision": source.revision},
            "candidate_outcomes": outcomes,
            "root_cause_clusters": clusters,
            "pipeline_blockers": blockers,
            "external_submission_performed": False,
        }
        writer.json("report.json", report)
        writer.text("report.md", "# Fake full hunt\n")
        writer.write_findings(clusters, render=lambda item: "# " + item["root_cause_id"] + "\n")
        self.events.append("report")
        return writer.result()


def test_generic_fake_target_runs_entire_pipeline_without_product_code(tmp_path):
    target = FakeTarget()
    result = FullHuntEngine(target).run(root=tmp_path, run_id="fake-full-run")
    assert [item["classification"] for item in result["outcomes"]] == [
        "NEW_SECURITY_CANDIDATE", "REJECTED_STATIC",
    ]
    assert target.events == [
        "resolve_source",
        "discover_candidates",
        "static_triage:FX-001",
        "static_triage:FX-002",
        "prepare_runtime",
        "bootstrap",
        "validate_candidate:FX-001",
        "duplicate_queries:FX-001",
        "duplicate_research:FX-001",
        "version_retest:FX-001",
        "report",
    ]
    report = json.loads((tmp_path / result["json_report"]).read_text())
    first = report["candidate_outcomes"][0]
    assert {
        "target", "candidate_id", "root_cause_id", "local_validation",
        "duplicate_research", "version_matrix", "classification", "evidence", "provenance",
    } <= set(first)
    assert "must-never-reach-report" not in (tmp_path / result["json_report"]).read_text()
    assert report["external_submission_performed"] is False


def test_generic_fake_target_runs_scenario_before_duplicate_and_retest(tmp_path):
    class ScenarioTarget(FakeTarget):
        def discover_candidates(self, source):
            self.events.append("discover_candidates")
            return [{
                "candidate_id": "FX-003", "static_status": "NEEDS_MANUAL_SCENARIO",
                "root_cause_key": "parser/scenario", "evidence": ["source:20"],
                "provenance": {"revision": source.revision},
            }]

        @staticmethod
        def scenario_capabilities():
            return TargetCapabilities(
                fixture_actions=frozenset({"create_identity", "resolve_route"}),
                supports_read_only_probe=True,
            )

        @staticmethod
        def synthesize_scenario(candidate, capabilities):
            return ScenarioPlan(
                candidate_id=candidate["candidate_id"], target_id="fake",
                required_identities=("finder-local-owner", "finder-local-viewer"),
                required_resources=("finder-local-resource",),
                fixture_requirements=("create_identity", "resolve_route"),
                control_request={"method": "GET", "url": "http://127.0.0.1:14000/control",
                                 "purpose": "control", "read_only": True},
                probe_request={"method": "GET", "url": "http://127.0.0.1:14000/probe",
                               "purpose": "probe", "read_only": True},
                security_invariant="restricted fixture remains hidden",
                expected_control={"visible": True}, violation_condition={"visible": True},
                request_budget=2, cleanup_requirements=("bootstrap_owned",),
                source_assertions={"route": True, "auth_path": True},
                confidence="high", safety_classification="LOCAL_READ_ONLY",
                rationale="source route and authorization path are deterministic",
            )

        def check_scenario_fixtures(self, scenario):
            self.events.append("scenario_fixture_check")
            return {"available": True}

        def execute_scenario(self, scenario, request):
            self.events.append("scenario_execute")
            return {
                "request_count": 2,
                "final_urls": [scenario.control_request["url"], scenario.probe_request["url"]],
                "fixture_valid": True, "source_assertion_valid": True,
                "control_passed": True, "response_status_only": False,
                "probe_deterministic": True, "ambiguous": False,
                "invariant_violated": True, "evidence_saved": True,
                "evidence": "scenario-evidence",
            }

        @classmethod
        def classify_with_scenario(cls, candidate, local, duplicate, matrix, scenario):
            assert scenario["status"] == "SCENARIO_EXECUTED"
            return cls.classify(
                {**candidate, "static_status": "NEEDS_LOCAL_VALIDATION"},
                local, duplicate, matrix,
            )

    target = ScenarioTarget()
    result = FullHuntEngine(target).run(root=tmp_path, run_id="fake-scenario-run")
    assert result["outcomes"][0]["classification"] == "NEW_SECURITY_CANDIDATE"
    assert result["outcomes"][0]["scenario_synthesis"]["status"] == "SCENARIO_EXECUTED"
    assert target.events.index("scenario_execute") < target.events.index("duplicate_research:FX-003")
    assert result["scenario_generated"] == result["scenario_executed"] == 1
    assert result["scenario_manual_remaining"] == 0


def test_generic_core_contains_no_product_specific_vocabulary():
    root = Path(__file__).resolve().parents[1] / "src/ctf_mcp/full_hunt"
    raw = "\n".join(path.read_text().lower() for path in root.glob("*.py"))
    for forbidden in ("acme_product", "/vendor/api/", "vendor_only_token", "vendor.repo.model"):
        assert forbidden not in raw


def test_registry_selects_explicit_target_and_rejects_unknown():
    registry = FullHuntRegistry()
    registry.register("fake", lambda value: {"value": value})
    assert registry.targets == frozenset({"fake"})
    assert registry.create("fake", 4) == {"value": 4}
    with pytest.raises(LocalTargetError, match="FULL_HUNT_UNAVAILABLE"):
        registry.create("unknown")


def test_candidate_schema_rejects_target_payload_without_neutral_status():
    with pytest.raises(LocalTargetError, match="invalid_candidate_schema"):
        validate_candidate_schema({"candidate_id": "FX-1", "static_status": "MAYBE"})


def test_generic_duplicate_engine_separates_core_coverage_from_supplementary_failure():
    result = evaluate_duplicate_research(
        candidate_id="FX-1",
        terms=["symbol"],
        policy=DuplicateResearchPolicy(("tracker", "advisory", "supplement"), ("tracker", "advisory"), 2),
        records=[],
        source_statuses={"tracker": "empty", "advisory": "ok", "supplement": "unavailable"},
        match_strength=lambda record: None,
        sanitize_match=lambda record, reasons: record,
        deduplicate=lambda records: records,
    )
    assert result["duplicate_status"] == "NO_PUBLIC_DUPLICATE_FOUND"
    assert result["research_incomplete"] is True
    assert result["core_coverage_met"] is True


def test_generic_version_matrix_and_build_cache_primitives_are_target_neutral():
    recipe = content_hash(b"FROM scratch\n", "rootless-build-v1")
    config = configuration_hash({"port": 14000, "database": "sqlite"})
    assert immutable_build_cache_key(COMMIT, recipe, config) == immutable_build_cache_key(
        COMMIT, recipe, config,
    )
    pinned = {
        "target": "pinned", "version": "1.0.0", "commit": COMMIT,
        "digest": DIGEST, "runtime_id": "pinned-runtime", "endpoint": "127.0.0.1:14000",
        "isolated": True, "result": "AFFECTED", "control_passed": True, "evidence_ids": [],
    }
    supplied = [{
        "target": "main", "version": None, "commit": COMMIT,
        "digest": DIGEST, "runtime_id": "main-runtime", "endpoint": "127.0.0.1:14001",
        "isolated": True, "result": "AFFECTED", "control_passed": True, "evidence_ids": [],
    }]
    matrix = compose_version_matrix(
        candidate_id="FX-1",
        pinned=pinned,
        target_kinds=("main",),
        supplied=supplied,
        blocked_target=lambda kind: pytest.fail("unexpected blocked target"),
        validate_target=lambda value: value,
        classify=lambda targets: "AFFECTS_MAIN" if targets["main"]["result"] == "AFFECTED" else "RETEST_BLOCKED",
    )
    assert matrix["status"] == "AFFECTS_MAIN"
    assert [item["target"] for item in matrix["targets"]] == ["pinned", "main"]


def test_generic_immutable_build_cache_checks_identity_before_hit(tmp_path):
    cache = ImmutableBuildCache(tmp_path / "runtime/build-cache.json")
    recipe = content_hash(b"recipe", "v1")
    config = configuration_hash({"port": 14000})
    cache.write({
        "cache_key": immutable_build_cache_key(COMMIT, recipe, config),
        "commit": COMMIT,
        "recipe_hash": recipe,
        "configuration_hash": config,
        "image_tag": "owned/image:" + COMMIT[:12],
        "image_id": DIGEST,
        "success": True,
    })
    assert cache.matching(
        commit=COMMIT,
        recipe_hash=recipe,
        configuration_hash=config,
        image_tag="owned/image:" + COMMIT[:12],
        inspect=lambda: {"image_id": DIGEST, "repo_digest": None},
    )["cache_hit"] is True
    assert cache.matching(
        commit=COMMIT,
        recipe_hash=recipe,
        configuration_hash=config,
        image_tag="owned/image:" + COMMIT[:12],
        inspect=lambda: {"image_id": "sha256:" + "3" * 64, "repo_digest": None},
    ) is None
    assert immutable_image_identity([{
        "Id": DIGEST,
        "RepoDigests": [],
        "Config": {"Labels": {"owner.commit": COMMIT}},
    }], expected_labels={"owner.commit": COMMIT}) == {
        "image_id": DIGEST, "repo_digest": None,
    }


def test_generic_runtime_lifecycle_enforces_ownership_and_stage_errors():
    events = []
    lifecycle = IsolatedRuntimeLifecycle(
        port_in_use=lambda: False,
        owned_healthy=lambda: False,
        start=lambda: events.append("start"),
        bootstrap=lambda: events.append("bootstrap"),
        stop=lambda: events.append("stop"),
    )
    assert lifecycle.prepare() == "ready"
    assert events == ["start", "bootstrap"]

    conflict = IsolatedRuntimeLifecycle(
        port_in_use=lambda: True,
        owned_healthy=lambda: False,
        start=lambda: pytest.fail("must not start"),
        bootstrap=lambda: pytest.fail("must not bootstrap"),
        stop=lambda: None,
    )
    with pytest.raises(LocalTargetError, match="RUNTIME_PORT_CONFLICT"):
        conflict.prepare()
