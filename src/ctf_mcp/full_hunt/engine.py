"""Generic full-hunt pipeline independent of any target API or runtime."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from ctf_mcp.local_targets.base import LocalTargetError

from .clustering import cluster_outcomes
from .schema import (
    FullHuntTargetAdapter,
    RuntimeRequest,
    SourceIdentity,
    normalized_outcome,
    validate_candidate_schema,
)


class FullHuntEngine:
    def __init__(self, adapter: FullHuntTargetAdapter):
        self.adapter = adapter

    def run(self, *, root: Path, run_id: str | None = None) -> dict[str, Any]:
        blockers: list[dict[str, str]] = []
        source: SourceIdentity | None = None
        candidates: list[dict[str, Any]] = []
        try:
            source = self.adapter.resolve_source()
            candidates = [
                validate_candidate_schema(self.adapter.static_triage(candidate))
                for candidate in self.adapter.discover_candidates(source)
            ]
        except LocalTargetError as error:
            blockers.append({"stage": "source_discovery", "reason": error.code})

        runtime_ready = False
        runtime_error: str | None = None
        try:
            self.adapter.build_prepare_runtime(RuntimeRequest("pinned"))
            self.adapter.bootstrap(RuntimeRequest("pinned"))
            runtime_ready = True
        except LocalTargetError as error:
            runtime_error = error.code
            blockers.append({"stage": "local_validation", "reason": error.code})

        outcomes = []
        for candidate in candidates:
            local = None
            selector = getattr(self.adapter, "should_validate_candidate", None)
            should_validate = (
                selector(candidate) if callable(selector)
                else candidate["static_status"] == "NEEDS_LOCAL_VALIDATION"
            )
            if should_validate:
                if runtime_ready:
                    try:
                        local = self.adapter.validate_candidate(
                            candidate, RuntimeRequest("pinned", candidate["candidate_id"]),
                        )
                    except LocalTargetError as error:
                        local = {
                            "status": "BLOCKED_BY_LOCAL_SETUP",
                            "blocked_reason": error.code,
                        }
                else:
                    local = {
                        "status": "BLOCKED_BY_LOCAL_SETUP",
                        "assertions": {"control_passed": False},
                        "blocked_reason": runtime_error or "VALIDATION_BLOCKED",
                    }
            duplicate = None
            matrix = None
            if local and local.get("status") == "VERIFIED_LOCAL":
                queries = self.adapter.duplicate_queries(candidate)
                if not queries:
                    raise LocalTargetError("invalid_duplicate_query")
                duplicate = self.adapter.duplicate_research(candidate)
                if duplicate and duplicate.get("duplicate_status") in {
                    "NO_PUBLIC_DUPLICATE_FOUND", "POSSIBLE_DUPLICATE",
                }:
                    matrix = self.adapter.version_retest(candidate, local, duplicate)
            classification = self.adapter.classify(candidate, local, duplicate, matrix)
            root_key = self.adapter.cluster_key(candidate)
            root_metadata = self.adapter.root_cause_metadata(root_key, [])
            outcome = normalized_outcome(
                target=self.adapter.target_id,
                candidate=candidate,
                root_cause_id=root_metadata["root_cause_id"],
                local_validation=local,
                duplicate_research=duplicate,
                version_matrix=matrix,
                classification=classification,
            )
            outcome["candidate"] = candidate
            enrich = getattr(self.adapter, "enrich_outcome", None)
            if callable(enrich):
                outcome = enrich(outcome)
            outcomes.append(outcome)

        def key_for(outcome: dict[str, Any]) -> str:
            return self.adapter.cluster_key(outcome["candidate"])

        clusters = cluster_outcomes(
            outcomes,
            key_for=key_for,
            metadata_for=self.adapter.root_cause_metadata,
        )
        for outcome in outcomes:
            outcome.pop("candidate", None)
        for cluster in clusters:
            for outcome in cluster["outcomes"]:
                outcome.pop("candidate", None)
        artifacts = self.adapter.write_report(
            root=root,
            source=source,
            candidates=candidates,
            outcomes=outcomes,
            clusters=clusters,
            blockers=blockers,
            run_id=run_id,
        )
        summary = getattr(self.adapter, "result_summary", None)
        if callable(summary):
            return summary(source, candidates, outcomes, clusters, blockers, artifacts)
        return {
            "target": self.adapter.target_id,
            "source": source,
            "candidates": candidates,
            "outcomes": outcomes,
            "clusters": clusters,
            "pipeline_blockers": blockers,
            **artifacts,
        }
