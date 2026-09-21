"""Gitea-specific implementation of the target-neutral full-hunt protocol."""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any, Callable

from ctf_mcp.full_hunt.schema import DuplicateQuery, RuntimeRequest, SourceIdentity
from ctf_mcp.full_hunt.registry import FULL_HUNT_REGISTRY
from ctf_mcp.full_hunt.scenario import TargetCapabilities, not_generatable

from .base import LocalTargetError
from .gitea_discovery import discover_and_triage, generate_scenario
from .gitea_scenario_bindings import GiteaScenarioBindings
from .gitea_full_hunt import (
    ALL_DUPLICATE_SOURCES,
    _affected_version_summary,
    _candidate_outcome,
    _cluster_status,
    _full_counts,
    _regression_outcome,
    build_version_matrix,
    cluster_full_findings,
    create_full_reports,
    duplicate_search_terms,
    final_classification,
    research_duplicate,
)


class GiteaFullHuntTargetAdapter:
    target_id = "gitea"
    repository = "https://github.com/go-gitea/gitea"

    def __init__(
        self,
        *,
        source_root: Path,
        ensure_source: Callable[[], Any],
        collect_local_results: Callable[[], tuple[bool, list[dict[str, Any]]]],
        pinned_version: str,
        pinned_commit: str,
        pinned_digest: str,
        duplicate_client: Any,
        retest_provider: Callable[[dict[str, Any]], list[dict[str, Any]]] | None,
        local_adapter: Any | None = None,
    ):
        self.source_root = source_root
        self.ensure_source_callback = ensure_source
        self.collect_local_results = collect_local_results
        self.pinned_version = pinned_version
        self.pinned_commit = pinned_commit
        self.pinned_digest = pinned_digest
        self.duplicate_client = duplicate_client
        self.retest_provider = retest_provider
        self.local_adapter = local_adapter
        self.bootstrapped = False
        self.local_results: list[dict[str, Any]] = []
        self.local_by_id: dict[str, dict[str, Any]] = {}
        self.legacy_outcomes: list[dict[str, Any]] = []
        self.legacy_clusters: list[dict[str, Any]] = []
        self.artifacts: dict[str, Any] = {}
        self.candidates_by_id: dict[str, dict[str, Any]] = {}
        self.binding_adapter = GiteaScenarioBindings(
            local_adapter,
            lambda candidate_id: self.candidates_by_id.get(candidate_id),
        )

    def resolve_source(self) -> SourceIdentity:
        self.ensure_source_callback()
        return SourceIdentity(
            repository=self.repository,
            revision=self.pinned_commit,
            directory=self.source_root,
        )

    def discover_candidates(self, source: SourceIdentity) -> list[dict[str, Any]]:
        if source.directory != self.source_root:
            raise LocalTargetError("SOURCE_ACQUIRE_FAILED")
        candidates = discover_and_triage(self.source_root)
        self.candidates_by_id = {item["candidate_id"]: item for item in candidates}
        return candidates

    @staticmethod
    def static_triage(candidate: dict[str, Any]) -> dict[str, Any]:
        return candidate

    @staticmethod
    def build_prepare_runtime(request: RuntimeRequest) -> dict[str, Any]:
        if request.kind != "pinned" or request.candidate_id is not None:
            raise LocalTargetError("VALIDATION_BLOCKED")
        return {"status": "prepared"}

    def bootstrap(self, request: RuntimeRequest) -> dict[str, Any]:
        if request.kind != "pinned" or request.candidate_id is not None:
            raise LocalTargetError("VALIDATION_BLOCKED")
        self.bootstrapped, self.local_results = self.collect_local_results()
        self.local_by_id = {item.get("candidate"): item for item in self.local_results}
        return {"status": "ready", "performed": self.bootstrapped}

    @staticmethod
    def should_validate_candidate(candidate: dict[str, Any]) -> bool:
        return generate_scenario(candidate)["status"] == "LOCAL_BASELINE_REUSE"

    def validate_candidate(
        self, candidate: dict[str, Any], request: RuntimeRequest,
    ) -> dict[str, Any] | None:
        if request.kind != "pinned" or request.candidate_id != candidate["candidate_id"]:
            raise LocalTargetError("VALIDATION_BLOCKED")
        return self.local_by_id.get(candidate.get("baseline_candidate"))

    @staticmethod
    def scenario_capabilities() -> TargetCapabilities:
        return TargetCapabilities(
            fixture_actions=frozenset({
                "create_identity", "create_public_resource", "create_private_resource",
                "add_member", "remove_member", "create_private_content",
                "resolve_route", "read_owned_fixture",
            }),
            supports_read_only_probe=True,
        )

    @staticmethod
    def should_synthesize_scenario(candidate: dict[str, Any]) -> bool:
        return (
            candidate["static_status"] != "REJECTED_STATIC"
            and generate_scenario(candidate)["status"] == "NEEDS_MANUAL_SCENARIO"
        )

    def synthesize_scenario(
        self, candidate: dict[str, Any], capabilities: TargetCapabilities,
    ) -> dict[str, Any]:
        del capabilities
        # Generic discovery candidates do not carry a reviewed mapping from
        # arbitrary route placeholders to the fixed synthetic fixture.  Refuse
        # to invent one; the five baseline-backed candidates use the existing
        # fixed validators through validate_candidate instead.
        return not_generatable(
            candidate["candidate_id"], self.target_id,
            "no_reviewed_fixture_route_mapping",
        )

    def scenario_bindings(self):
        return self.binding_adapter.bindings()

    def check_scenario_fixtures(self, plan):
        return self.binding_adapter.check(plan)

    def execute_scenario(self, plan, request: RuntimeRequest):
        if request.kind != "pinned" or request.candidate_id != plan.candidate_id:
            raise LocalTargetError("VALIDATION_BLOCKED")
        return self.binding_adapter.execute(plan)

    @staticmethod
    def duplicate_queries(candidate: dict[str, Any]) -> list[DuplicateQuery]:
        terms = duplicate_search_terms(candidate)
        locator = " | ".join(terms)
        return [
            DuplicateQuery(source, locator, source != "nvd")
            for source in ALL_DUPLICATE_SOURCES
        ]

    def duplicate_research(self, candidate: dict[str, Any]) -> dict[str, Any]:
        return research_duplicate(candidate, self.duplicate_client)

    def version_retest(
        self,
        candidate: dict[str, Any],
        local_validation: dict[str, Any],
        duplicate_research: dict[str, Any],
    ) -> dict[str, Any]:
        del duplicate_research
        records = self.retest_provider(candidate) if self.retest_provider else []
        return build_version_matrix(
            candidate,
            pinned_version=self.pinned_version,
            pinned_commit=self.pinned_commit,
            pinned_digest=self.pinned_digest,
            local_result=local_validation,
            retest_records=records,
        )

    @staticmethod
    def cluster_key(candidate: dict[str, Any]) -> str:
        return candidate["root_cause_key"]

    @staticmethod
    def root_cause_metadata(
        key: str, outcomes: list[dict[str, Any]],
    ) -> dict[str, Any]:
        known = {
            "activities.GetFeeds/public-only-visibility": "RC01",
            "activities.GetUserHeatmapData/public-only-visibility": "RC02",
            "listUserRepos/GetUserRepositories-count-before-filter": "RC03",
            "GetTeamRepos/CountTeamRepositories-count-before-filter": "RC04",
        }
        statuses = [item["classification"] for item in outcomes]
        return {
            "root_cause_id": known.get(key) or "RC-" + hashlib.sha256(key.encode()).hexdigest()[:8].upper(),
            "classification": _cluster_status(statuses) if statuses else "VERIFIED_LOCAL",
        }

    @staticmethod
    def classify(
        candidate: dict[str, Any],
        local_validation: dict[str, Any] | None,
        duplicate_research: dict[str, Any] | None,
        version_matrix: dict[str, Any] | None,
    ) -> str:
        return final_classification(
            candidate,
            generate_scenario(candidate),
            local_validation,
            duplicate_research,
            version_matrix,
        )

    @staticmethod
    def classify_with_scenario(
        candidate: dict[str, Any],
        local_validation: dict[str, Any] | None,
        duplicate_research: dict[str, Any] | None,
        version_matrix: dict[str, Any] | None,
        scenario_synthesis: dict[str, Any] | None,
    ) -> str:
        scenario = generate_scenario(candidate)
        if (scenario_synthesis and scenario_synthesis.get("status") == "SCENARIO_EXECUTED"
                and local_validation is not None):
            scenario = {"status": "LOCAL_BASELINE_REUSE"}
        return final_classification(
            candidate, scenario, local_validation, duplicate_research, version_matrix,
        )

    def enrich_outcome(self, outcome: dict[str, Any]) -> dict[str, Any]:
        candidate = outcome["candidate"]
        outcome["evidence"] = candidate.get("source_facts", [])
        outcome["provenance"] = {
            "repository": self.repository,
            "revision": self.pinned_commit,
            "source_assertions": candidate.get("source_assertions", {}),
        }
        local = outcome["local_validation"]
        if local:
            local = dict(local)
            identifiers = local.pop("evidence_ids", [])
            for key, value in zip(("evidence", "reassessment"), identifiers):
                local[key] = value
        legacy = _candidate_outcome(
            candidate,
            generate_scenario(candidate),
            local,
            outcome["duplicate_research"],
            outcome["version_matrix"],
            outcome["classification"],
        )
        return {**outcome, **legacy}

    def write_report(
        self,
        *,
        root: Path,
        source: SourceIdentity | None,
        candidates: list[dict[str, Any]],
        outcomes: list[dict[str, Any]],
        clusters: list[dict[str, Any]],
        blockers: list[dict[str, str]],
        run_id: str | None,
    ) -> dict[str, Any]:
        del source, clusters
        self.legacy_outcomes = outcomes
        self.legacy_clusters = cluster_full_findings(outcomes)
        duplicates = [item["duplicate_research"] for item in outcomes if item["duplicate_research"]]
        matrices = [item["version_matrix"] for item in outcomes if item["version_matrix"]]
        self.artifacts = create_full_reports(
            root,
            target=self.target_id,
            pinned_version=self.pinned_version,
            pinned_commit=self.pinned_commit,
            pinned_digest=self.pinned_digest,
            candidates=candidates,
            outcomes=outcomes,
            clusters=self.legacy_clusters,
            duplicate_results=duplicates,
            version_matrices=matrices,
            regression_baseline=[_regression_outcome(item) for item in self.local_results],
            pipeline_blockers=blockers,
            run_id=run_id,
        )
        return self.artifacts

    def result_summary(
        self,
        source: SourceIdentity | None,
        candidates: list[dict[str, Any]],
        outcomes: list[dict[str, Any]],
        clusters: list[dict[str, Any]],
        blockers: list[dict[str, str]],
        artifacts: dict[str, Any],
    ) -> dict[str, Any]:
        del source, candidates, clusters
        matrices = [item["version_matrix"] for item in outcomes if item["version_matrix"]]
        return {
            "target": self.target_id,
            "pinned_version": self.pinned_version,
            "bootstrap_performed": self.bootstrapped,
            **_full_counts(outcomes),
            "root_cause_clusters": [
                {"id": item["id"], "candidates": item["candidate_ids"], "status": item["status"]}
                for item in self.legacy_clusters
            ],
            "affected_versions": _affected_version_summary(
                matrices, self.pinned_version, outcomes,
            ),
            "reports": artifacts["report_directory"],
            "json_report": artifacts["json_report"],
            "markdown_report": artifacts["markdown_report"],
            "pipeline_blockers": blockers,
            "regression_baseline": [_regression_outcome(item) for item in self.local_results],
            "human_action_required": "Review NEW_SECURITY_CANDIDATE reports before private vendor disclosure.",
            "external_submission_performed": False,
            "outcomes": outcomes,
        }


GITEA_FULL_HUNT_REGISTRY = FULL_HUNT_REGISTRY
GITEA_FULL_HUNT_REGISTRY.register("gitea", GiteaFullHuntTargetAdapter)
