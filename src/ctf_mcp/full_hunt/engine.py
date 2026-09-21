"""Generic full-hunt pipeline independent of any target API or runtime."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from ctf_mcp.local_targets.base import LocalTargetError

from .clustering import cluster_outcomes
from .scenario import (
    ScenarioPlan,
    execute_scenario,
    generated_scenario_record,
    not_generatable,
    scenario_summary,
    synthesize_from_bindings,
    validate_scenario_plan,
    write_scenario_artifacts,
)
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
            scenario = None
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
            scenario_selector = getattr(self.adapter, "should_synthesize_scenario", None)
            should_synthesize = (
                scenario_selector(candidate) if callable(scenario_selector)
                else candidate["static_status"] in {"BLOCKED_STATIC", "NEEDS_MANUAL_SCENARIO"}
            )
            synthesizer = getattr(self.adapter, "synthesize_scenario", None)
            binding_provider = getattr(self.adapter, "scenario_bindings", None)
            capability_provider = getattr(self.adapter, "scenario_capabilities", None)
            fixture_check = getattr(self.adapter, "check_scenario_fixtures", None)
            scenario_executor = getattr(self.adapter, "execute_scenario", None)
            if (should_synthesize and callable(capability_provider)
                    and (callable(synthesizer) or callable(binding_provider))):
                capabilities = capability_provider()
                generated = (
                    synthesize_from_bindings(
                        candidate=candidate,
                        target_id=self.adapter.target_id,
                        bindings=tuple(binding_provider()),
                        capabilities=capabilities,
                    )
                    if callable(binding_provider)
                    else synthesizer(candidate, capabilities)
                )
                if isinstance(generated, ScenarioPlan):
                    try:
                        validate_scenario_plan(generated, capabilities)
                        scenario = generated_scenario_record(generated)
                    except LocalTargetError as error:
                        scenario = generated_scenario_record(generated)
                        scenario["status"] = "SCENARIO_UNSAFE"
                        scenario["blocker"] = error.code
                        scenario["safety_result"]["passed"] = False
                    if (scenario["status"] == "SCENARIO_GENERATED" and runtime_ready
                            and callable(fixture_check) and callable(scenario_executor)):
                        scenario, scenario_local = execute_scenario(
                            generated,
                            capabilities,
                            fixture_check=fixture_check,
                            execute=lambda plan: scenario_executor(
                                plan, RuntimeRequest("pinned", candidate["candidate_id"]),
                            ),
                        )
                        if scenario_local is not None:
                            local = scenario_local
                    elif scenario["status"] == "SCENARIO_GENERATED":
                        scenario["status"] = "SCENARIO_BLOCKED"
                        scenario["blocker"] = runtime_error or "VALIDATION_BLOCKED"
                elif isinstance(generated, dict):
                    scenario = generated
                else:
                    scenario = not_generatable(
                        candidate["candidate_id"], self.adapter.target_id,
                        "adapter_returned_no_source_backed_plan",
                    )
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
            scenario_classifier = getattr(self.adapter, "classify_with_scenario", None)
            if callable(scenario_classifier):
                classification = scenario_classifier(candidate, local, duplicate, matrix, scenario)
            else:
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
                scenario_synthesis=scenario,
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
        report_directory = artifacts.get("report_directory")
        if isinstance(report_directory, str):
            artifacts["scenario_artifacts"] = write_scenario_artifacts(
                root, report_directory, outcomes,
            )
        summary = getattr(self.adapter, "result_summary", None)
        if callable(summary):
            result = summary(source, candidates, outcomes, clusters, blockers, artifacts)
            result.update(scenario_summary(outcomes))
            return result
        return {
            "target": self.adapter.target_id,
            "source": source,
            "candidates": candidates,
            "outcomes": outcomes,
            "clusters": clusters,
            "pipeline_blockers": blockers,
            **scenario_summary(outcomes),
            **artifacts,
        }
