"""Target-neutral schemas and adapter protocol for full-hunt pipelines."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol, runtime_checkable

from ctf_mcp.local_targets.base import LocalTargetError


STATIC_STATUSES = frozenset({"REJECTED_STATIC", "NEEDS_LOCAL_VALIDATION", "BLOCKED_STATIC"})
LOCAL_STATUSES = frozenset({
    "VERIFIED_LOCAL", "INTENDED_BEHAVIOR", "BLOCKED_BY_LOCAL_SETUP", "NEEDS_MORE_EVIDENCE",
})
DUPLICATE_STATUSES = frozenset({
    "KNOWN_DUPLICATE", "POSSIBLE_DUPLICATE", "NO_PUBLIC_DUPLICATE_FOUND",
    "DUPLICATE_CHECK_BLOCKED",
})
CLASSIFICATIONS = frozenset({
    "REJECTED_STATIC", "INTENDED_BEHAVIOR", "BLOCKED_BY_LOCAL_SETUP",
    "NEEDS_MANUAL_SCENARIO", "VERIFIED_LOCAL", "KNOWN_DUPLICATE",
    "POSSIBLE_DUPLICATE", "NEW_SECURITY_CANDIDATE",
})
RETEST_RESULTS = frozenset({"AFFECTED", "INTENDED_BEHAVIOR", "RETEST_BLOCKED"})


@dataclass(frozen=True)
class SourceIdentity:
    repository: str
    revision: str
    fetched_at: str | None = None
    branch: str | None = None
    directory: Path | None = None

    def __post_init__(self) -> None:
        if not self.repository.startswith("https://") or not self.revision:
            raise LocalTargetError("invalid_hunt_source_identity")


@dataclass(frozen=True)
class DuplicateQuery:
    source: str
    locator: str
    core: bool

    def __post_init__(self) -> None:
        if not self.source or not self.locator:
            raise LocalTargetError("invalid_duplicate_query")


@dataclass(frozen=True)
class RuntimeRequest:
    kind: str
    candidate_id: str | None = None

    def __post_init__(self) -> None:
        if not self.kind or self.candidate_id == "":
            raise LocalTargetError("invalid_runtime_request")


@runtime_checkable
class FullHuntTargetAdapter(Protocol):
    """Operations supplied by a target without exposing target concepts to core."""

    target_id: str

    def resolve_source(self) -> SourceIdentity: ...

    def discover_candidates(self, source: SourceIdentity) -> list[dict[str, Any]]: ...

    def static_triage(self, candidate: dict[str, Any]) -> dict[str, Any]: ...

    def build_prepare_runtime(self, request: RuntimeRequest) -> dict[str, Any]: ...

    def bootstrap(self, request: RuntimeRequest) -> dict[str, Any]: ...

    def validate_candidate(
        self, candidate: dict[str, Any], request: RuntimeRequest,
    ) -> dict[str, Any] | None: ...

    def duplicate_queries(self, candidate: dict[str, Any]) -> list[DuplicateQuery]: ...

    def duplicate_research(self, candidate: dict[str, Any]) -> dict[str, Any] | None: ...

    def version_retest(
        self,
        candidate: dict[str, Any],
        local_validation: dict[str, Any],
        duplicate_research: dict[str, Any],
    ) -> dict[str, Any] | None: ...

    def cluster_key(self, candidate: dict[str, Any]) -> str: ...

    def root_cause_metadata(
        self, key: str, outcomes: list[dict[str, Any]],
    ) -> dict[str, Any]: ...

    def classify(
        self,
        candidate: dict[str, Any],
        local_validation: dict[str, Any] | None,
        duplicate_research: dict[str, Any] | None,
        version_matrix: dict[str, Any] | None,
    ) -> str: ...

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
    ) -> dict[str, Any]: ...


def validate_candidate_schema(value: dict[str, Any]) -> dict[str, Any]:
    if (not isinstance(value, dict)
            or not isinstance(value.get("candidate_id"), str)
            or not value["candidate_id"]
            or value.get("static_status") not in STATIC_STATUSES):
        raise LocalTargetError("invalid_candidate_schema")
    return value


def normalized_outcome(
    *,
    target: str,
    candidate: dict[str, Any],
    root_cause_id: str,
    local_validation: dict[str, Any] | None,
    duplicate_research: dict[str, Any] | None,
    version_matrix: dict[str, Any] | None,
    classification: str,
) -> dict[str, Any]:
    if classification not in CLASSIFICATIONS:
        raise LocalTargetError("invalid_hunt_classification")
    local_projection = None
    if local_validation is not None:
        assertions = local_validation.get("assertions", {})
        local_projection = {
            "status": local_validation.get("status"),
            "assertions": {
                key: item for key, item in assertions.items()
                if isinstance(key, str) and isinstance(item, bool)
            } if isinstance(assertions, dict) else {},
            "evidence_ids": [
                local_validation[key]
                for key in ("evidence", "reassessment")
                if isinstance(local_validation.get(key), str)
            ],
            "blocked_reason": local_validation.get("blocked_reason"),
        }
    return {
        "target": target,
        "candidate_id": candidate["candidate_id"],
        "root_cause_id": root_cause_id,
        "local_validation": local_projection,
        "duplicate_research": duplicate_research,
        "version_matrix": version_matrix,
        "classification": classification,
        "evidence": candidate.get("evidence", []),
        "provenance": candidate.get("provenance", {}),
    }
