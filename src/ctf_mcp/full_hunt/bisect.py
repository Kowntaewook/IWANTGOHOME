"""Target-neutral version boundary search over immutable adapter revisions."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import json
from pathlib import Path
import re
from typing import Any, Mapping, Protocol

from ctf_mcp.local_targets.base import (
    LocalTargetError,
    atomic_private_json,
    secure_directory,
)

from .reporting import write_private_text


REVISION_STATUSES = frozenset({"UNAFFECTED", "AFFECTED", "BLOCKED", "INCONCLUSIVE"})
BISECT_STATUSES = frozenset({
    "FIRST_AFFECTED_FOUND", "FIRST_FIXED_FOUND", "BISECT_BLOCKED",
    "NON_MONOTONIC", "BOUNDARY_NOT_FOUND",
})
BISECT_MODES = frozenset({"introduced", "fixed"})
REQUIRED_BISECT_CAPABILITIES = frozenset({
    "deterministic_validation", "source_assertions", "immutable_revisions",
    "revision_ordering", "safety_gate",
})
COMMIT_SHA = re.compile(r"[0-9a-f]{40}\Z")


@dataclass(frozen=True)
class BisectRevision:
    revision: str
    version: str | None
    commit: str
    immutable_identity: str
    order_key: int | str

    def __post_init__(self) -> None:
        if (not self.revision or not COMMIT_SHA.fullmatch(self.commit)
                or not self.immutable_identity
                or not isinstance(self.order_key, (int, str))):
            raise LocalTargetError("INVALID_BISECT_REVISION")

    def to_dict(self) -> dict[str, Any]:
        return {
            "revision": self.revision,
            "version": self.version,
            "commit": self.commit,
            "immutable_identity": self.immutable_identity,
            "order_key": self.order_key,
        }


@dataclass(frozen=True)
class BisectObservation:
    revision: BisectRevision
    status: str
    control_status: str
    candidate_status: str
    evidence: tuple[str, ...] = ()
    runtime_identity: str | None = None
    blocker: str | None = None

    def __post_init__(self) -> None:
        if (self.status not in REVISION_STATUSES or not self.control_status
                or not self.candidate_status
                or not all(isinstance(item, str) and item for item in self.evidence)):
            raise LocalTargetError("INVALID_BISECT_OBSERVATION")
        if self.status in {"AFFECTED", "UNAFFECTED"} and (
            not self.runtime_identity or not self.evidence
        ):
            raise LocalTargetError("INVALID_BISECT_OBSERVATION")
        if self.status in {"BLOCKED", "INCONCLUSIVE"} and not self.blocker:
            raise LocalTargetError("INVALID_BISECT_OBSERVATION")

    def to_dict(self) -> dict[str, Any]:
        return {
            "revision": self.revision.to_dict(),
            "status": self.status,
            "control_status": self.control_status,
            "candidate_status": self.candidate_status,
            "evidence": list(self.evidence),
            "runtime_identity": self.runtime_identity,
            "blocker": self.blocker,
        }


@dataclass(frozen=True)
class BisectResult:
    mode: str
    lower_bound: BisectRevision | None
    upper_bound: BisectRevision | None
    boundary_revision: BisectRevision | None
    observations: tuple[BisectObservation, ...]
    monotonic: bool | None
    status: str
    blocker: str | None = None
    cache_hits: int = 0

    def __post_init__(self) -> None:
        if self.mode not in BISECT_MODES or self.status not in BISECT_STATUSES:
            raise LocalTargetError("INVALID_BISECT_RESULT")

    def to_dict(self) -> dict[str, Any]:
        return {
            "mode": self.mode,
            "lower_bound": self.lower_bound.to_dict() if self.lower_bound else None,
            "upper_bound": self.upper_bound.to_dict() if self.upper_bound else None,
            "boundary_revision": (
                self.boundary_revision.to_dict() if self.boundary_revision else None
            ),
            "observations": [item.to_dict() for item in self.observations],
            "monotonic": self.monotonic,
            "status": self.status,
            "blocker": self.blocker,
            "tested_revisions": len(self.observations),
            "blocked_revisions": sum(
                item.status in {"BLOCKED", "INCONCLUSIVE"}
                for item in self.observations
            ),
            "cache_hits": self.cache_hits,
        }


class VersionProvider(Protocol):
    """Adapter-owned revision, source, runtime, validation, and cleanup hooks."""

    def bisect_capabilities(self, candidate_id: str) -> Mapping[str, bool]: ...
    def ordered_revisions(
        self, candidate_id: str, start: str, end: str,
    ) -> list[BisectRevision]: ...
    def resolve_revision(self, revision: BisectRevision) -> BisectRevision: ...
    def checkout_source(self, revision: BisectRevision) -> Any: ...
    def build_runtime(self, revision: BisectRevision, source: Any) -> Any: ...
    def bootstrap_runtime(self, revision: BisectRevision, runtime: Any) -> None: ...
    def validate_candidate(
        self, candidate_id: str, revision: BisectRevision, runtime: Any,
    ) -> BisectObservation: ...
    def cleanup_revision(self, revision: BisectRevision) -> None: ...


class RevisionObserver(Protocol):
    """Compact provider facade when the adapter already owns the full lifecycle."""

    def observe_revision(
        self, candidate_id: str, revision: BisectRevision,
    ) -> BisectObservation: ...


class VersionBisector:
    """Binary-search orchestration; source/build/runtime behavior stays in provider."""

    def __init__(self, provider: VersionProvider, *, neighbor_window: int = 2):
        if not 1 <= neighbor_window <= 3:
            raise LocalTargetError("INVALID_BISECT_WINDOW")
        self.provider = provider
        self.neighbor_window = neighbor_window
        self._cache: dict[tuple[str, str], BisectObservation] = {}
        self._cache_hits = 0

    def run(
        self,
        *,
        candidate_id: str,
        mode: str,
        start: str,
        end: str,
    ) -> BisectResult:
        if mode not in BISECT_MODES or not candidate_id or not start or not end:
            raise LocalTargetError("INVALID_BISECT_REQUEST")
        try:
            capabilities = self.provider.bisect_capabilities(candidate_id)
        except LocalTargetError as error:
            return self._result(mode, "BISECT_BLOCKED", None, None, None, None, error.code)
        if (not isinstance(capabilities, Mapping)
                or any(capabilities.get(key) is not True for key in REQUIRED_BISECT_CAPABILITIES)):
            return self._result(mode, "BISECT_BLOCKED", None, None, None, None,
                                "BISECT_PRECONDITION_FAILED")
        try:
            revisions = self.provider.ordered_revisions(candidate_id, start, end)
            revisions = _validate_revisions(revisions, start, end)
        except LocalTargetError:
            return self._result(mode, "BISECT_BLOCKED", None, None, None, None,
                                "IMMUTABLE_REVISION_REQUIRED")
        left = self._observe(candidate_id, revisions[0])
        right = self._observe(candidate_id, revisions[-1])
        initial, terminal = (
            ("UNAFFECTED", "AFFECTED") if mode == "introduced"
            else ("AFFECTED", "UNAFFECTED")
        )
        endpoint_problem = _observation_problem(left) or _observation_problem(right)
        if endpoint_problem:
            return self._result(
                mode, "BISECT_BLOCKED", revisions[0], revisions[-1], None,
                None, endpoint_problem,
            )
        if left.status != initial or right.status != terminal:
            return self._result(
                mode, "BOUNDARY_NOT_FOUND", revisions[0], revisions[-1], None,
                True, "ENDPOINT_STATUS_MISMATCH",
            )
        low, high = 0, len(revisions) - 1
        while high - low > 1:
            middle = (low + high) // 2
            observed = self._observe(candidate_id, revisions[middle])
            problem = _observation_problem(observed)
            if problem:
                return self._result(
                    mode, "BISECT_BLOCKED", revisions[low], revisions[high], None,
                    None, problem,
                )
            if observed.status == terminal:
                high = middle
            elif observed.status == initial:
                low = middle
            else:
                return self._result(
                    mode, "BISECT_BLOCKED", revisions[low], revisions[high], None,
                    None, "INCONCLUSIVE_REVISION",
                )
        first = max(0, high - self.neighbor_window)
        last = min(len(revisions), high + self.neighbor_window + 1)
        for index in range(first, last):
            observed = self._observe(candidate_id, revisions[index])
            problem = _observation_problem(observed)
            if problem:
                return self._result(
                    mode, "BISECT_BLOCKED", revisions[low], revisions[high], None,
                    None, problem,
                )
            expected = initial if index < high else terminal
            if observed.status != expected:
                return self._result(
                    mode, "NON_MONOTONIC", revisions[low], revisions[high], None,
                    False, "NON_MONOTONIC_OBSERVATION",
                )
        status = "FIRST_AFFECTED_FOUND" if mode == "introduced" else "FIRST_FIXED_FOUND"
        return self._result(
            mode, status, revisions[high - 1], revisions[high], revisions[high],
            True, None,
        )

    def _observe(
        self, candidate_id: str, revision: BisectRevision,
    ) -> BisectObservation:
        cache_key = (candidate_id, revision.immutable_identity)
        cached = self._cache.get(cache_key)
        if cached is not None:
            self._cache_hits += 1
            return cached
        cleanup_error: str | None = None
        try:
            observer = getattr(self.provider, "observe_revision", None)
            if callable(observer):
                observed = observer(candidate_id, revision)
            else:
                resolved = self.provider.resolve_revision(revision)
                if resolved != revision:
                    raise LocalTargetError("IMMUTABLE_REVISION_REQUIRED")
                source = self.provider.checkout_source(revision)
                runtime = self.provider.build_runtime(revision, source)
                self.provider.bootstrap_runtime(revision, runtime)
                observed = self.provider.validate_candidate(
                    candidate_id, revision, runtime,
                )
            if not isinstance(observed, BisectObservation):
                raise LocalTargetError("INVALID_BISECT_OBSERVATION")
            if observed.revision != revision:
                raise LocalTargetError("INVALID_BISECT_OBSERVATION")
        except LocalTargetError as error:
            observed = BisectObservation(
                revision=revision,
                status="BLOCKED",
                control_status="BLOCKED",
                candidate_status="BLOCKED",
                blocker=error.code,
            )
        except Exception:
            observed = BisectObservation(
                revision=revision,
                status="BLOCKED",
                control_status="BLOCKED",
                candidate_status="BLOCKED",
                blocker="REVISION_PROVIDER_FAILED",
            )
        finally:
            cleanup = getattr(self.provider, "cleanup_revision", None)
            if callable(cleanup):
                try:
                    cleanup(revision)
                except LocalTargetError as error:
                    cleanup_error = error.code
                except Exception:
                    cleanup_error = "REVISION_CLEANUP_FAILED"
        if cleanup_error is not None:
            observed = BisectObservation(
                revision=revision,
                status="BLOCKED",
                control_status="BLOCKED",
                candidate_status="BLOCKED",
                blocker=cleanup_error,
            )
        self._cache[cache_key] = observed
        return observed

    def _result(
        self,
        mode: str,
        status: str,
        lower: BisectRevision | None,
        upper: BisectRevision | None,
        boundary: BisectRevision | None,
        monotonic: bool | None,
        blocker: str | None,
    ) -> BisectResult:
        observations = tuple(sorted(
            self._cache.values(), key=lambda item: item.revision.order_key,
        ))
        return BisectResult(
            mode=mode,
            lower_bound=lower,
            upper_bound=upper,
            boundary_revision=boundary,
            observations=observations,
            monotonic=monotonic,
            status=status,
            blocker=blocker,
            cache_hits=self._cache_hits,
        )


def write_bisect_report(
    *,
    root: Path,
    target_id: str,
    candidate_id: str,
    result: BisectResult,
    run_id: str | None = None,
) -> dict[str, Any]:
    run = run_id or datetime.now(timezone.utc).strftime("%Y%m%dt%H%M%S%fZ")
    if not all(re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", item) for item in (
        target_id, candidate_id, run,
    )):
        raise LocalTargetError("INVALID_BISECT_RUN_ID")
    run_root = root / ".operator" / "bisect" / target_id / candidate_id / run
    if run_root.exists() or run_root.is_symlink():
        raise LocalTargetError("BISECT_RUN_EXISTS")
    observations_root = secure_directory(run_root / "observations")
    payload = {
        "schema_version": 1,
        "target": target_id,
        "candidate_id": candidate_id,
        **result.to_dict(),
    }
    atomic_private_json(run_root / "bisect.json", payload)
    matrix = {
        "candidate_id": candidate_id,
        "targets": [
            {
                "revision": item.revision.to_dict(),
                "status": item.status,
                "control_status": item.control_status,
                "candidate_status": item.candidate_status,
                "runtime_identity": item.runtime_identity,
            }
            for item in result.observations
        ],
    }
    atomic_private_json(run_root / "version-matrix.json", matrix)
    for index, observation in enumerate(result.observations):
        atomic_private_json(
            observations_root / f"{index:03d}-{observation.revision.commit[:12]}.json",
            observation.to_dict(),
        )
    write_private_text(run_root / "bisect.md", _render_bisect(candidate_id, result))
    return {
        "report_directory": str(run_root.relative_to(root)),
        "bisect_json": str((run_root / "bisect.json").relative_to(root)),
        "bisect_markdown": str((run_root / "bisect.md").relative_to(root)),
        "version_matrix": str((run_root / "version-matrix.json").relative_to(root)),
        "status": result.status,
    }


def _validate_revisions(
    revisions: list[BisectRevision], start: str, end: str,
) -> list[BisectRevision]:
    if not isinstance(revisions, list) or len(revisions) < 2:
        raise LocalTargetError("INVALID_BISECT_REVISION")
    if not all(isinstance(item, BisectRevision) for item in revisions):
        raise LocalTargetError("INVALID_BISECT_REVISION")
    if any(not COMMIT_SHA.fullmatch(item.commit) or not item.immutable_identity
           or item.commit not in item.immutable_identity
           for item in revisions):
        raise LocalTargetError("INVALID_BISECT_REVISION")
    keys = [item.order_key for item in revisions]
    if any(type(item) is not type(keys[0]) for item in keys) or keys != sorted(keys):
        raise LocalTargetError("INVALID_BISECT_REVISION")
    if len(set(keys)) != len(keys):
        raise LocalTargetError("INVALID_BISECT_REVISION")
    identities = [item.immutable_identity for item in revisions]
    if len(set(identities)) != len(identities):
        raise LocalTargetError("INVALID_BISECT_REVISION")
    if start not in {revisions[0].revision, revisions[0].commit}:
        raise LocalTargetError("INVALID_BISECT_REVISION")
    if end not in {revisions[-1].revision, revisions[-1].commit}:
        raise LocalTargetError("INVALID_BISECT_REVISION")
    return revisions


def _observation_problem(value: BisectObservation) -> str | None:
    if value.status == "BLOCKED":
        return value.blocker or "REVISION_BLOCKED"
    if value.status == "INCONCLUSIVE":
        return value.blocker or "INCONCLUSIVE_REVISION"
    if value.control_status not in {"PASS", "PASSED"}:
        return "CONTROL_FAILED"
    return None


def _render_bisect(candidate_id: str, result: BisectResult) -> str:
    boundary = result.boundary_revision
    previous = result.lower_bound
    label = "First affected" if result.mode == "introduced" else "First fixed"
    previous_label = (
        "Previous known unaffected" if result.mode == "introduced"
        else "Previous known affected"
    )
    return "\n".join((
        f"# Version boundary: {candidate_id}", "",
        f"- Mode: {result.mode}",
        f"- Status: {result.status}",
        f"- {label}: {boundary.version or boundary.commit if boundary else 'unknown'}",
        f"- {previous_label}: {previous.version or previous.commit if previous else 'unknown'}",
        f"- Tested revisions: {len(result.observations)}",
        f"- Blocked revisions: {sum(item.status in {'BLOCKED', 'INCONCLUSIVE'} for item in result.observations)}",
        f"- Monotonic: {str(result.monotonic).lower() if result.monotonic is not None else 'unknown'}",
        "",
    ))
