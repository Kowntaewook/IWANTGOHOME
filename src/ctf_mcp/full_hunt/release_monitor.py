"""Generic release discovery and deterministic local candidate retesting."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
from typing import Any, Callable, Mapping, Protocol
from urllib.parse import urlsplit

from ctf_mcp.full_hunt.runtime import assert_secret_free
from ctf_mcp.local_targets.base import (
    LocalTargetError,
    atomic_private_json,
    secure_directory,
)
from ctf_mcp.redaction import clean

from .regression import RUNNER_CAPABILITIES, RegressionSpecStore


RELEASE_CANDIDATE_STATUSES = frozenset({
    "AFFECTED", "FIXED", "BLOCKED", "INCONCLUSIVE", "REGRESSION",
})
PATCH_CORRELATION_STATUSES = frozenset({
    "PATCH_CORRELATION_AVAILABLE", "PATCH_CORRELATION_UNAVAILABLE",
})
RELEASE_FAILURE_REASONS = frozenset({
    "RELEASE_PROVIDER_UNAVAILABLE", "RELEASE_IDENTITY_UNRESOLVED",
    "REVISION_PREPARE_FAILED", "RUNTIME_BUILD_FAILED", "RUNTIME_START_FAILED",
    "BOOTSTRAP_FAILED", "CONTROL_FAILED", "SCENARIO_INCOMPATIBLE",
    "SOURCE_ASSERTION_CHANGED", "RETEST_INCONCLUSIVE",
})
ELIGIBLE_PRIOR_STATUSES = frozenset({
    "VERIFIED_LOCAL", "NEW_SECURITY_CANDIDATE", "READY_FOR_HUMAN_REVIEW",
})
COMMIT_SHA = re.compile(r"[0-9a-f]{40}\Z")
HASH = re.compile(r"[0-9a-f]{64}\Z")
IMAGE_ID = re.compile(r"sha256:[0-9a-f]{64}\Z")
SAFE_ID = re.compile(r"[A-Za-z0-9_.-]{1,128}\Z")
FLOATING_IDENTITIES = frozenset({"latest", "main", "master", "head", "stable"})


@dataclass(frozen=True)
class ReleaseIdentity:
    target_id: str
    version: str
    revision: str
    immutable_commit: str | None
    released_at: str
    source: str
    metadata_hash: str
    source_identity: str | None = None
    image_identity: str | None = None

    def __post_init__(self) -> None:
        if (not SAFE_ID.fullmatch(self.target_id) or not self.version
                or not self.revision or not self.released_at or not self.source
                or not HASH.fullmatch(self.metadata_hash)):
            raise LocalTargetError("RELEASE_IDENTITY_UNRESOLVED")
        if self.immutable_commit is not None and not COMMIT_SHA.fullmatch(self.immutable_commit):
            raise LocalTargetError("RELEASE_IDENTITY_UNRESOLVED")
        if self.image_identity is not None and not IMAGE_ID.fullmatch(self.image_identity):
            raise LocalTargetError("RELEASE_IDENTITY_UNRESOLVED")
        if not any((self.immutable_commit, self.source_identity, self.image_identity)):
            raise LocalTargetError("RELEASE_IDENTITY_UNRESOLVED")
        if self.source_identity is not None and not self.source_identity.strip():
            raise LocalTargetError("RELEASE_IDENTITY_UNRESOLVED")
        source_tail = (
            re.split(r"[:/@]", self.source_identity.strip().lower())[-1]
            if self.source_identity is not None else None
        )
        if (self.revision.strip().lower() in FLOATING_IDENTITIES
                or source_tail in FLOATING_IDENTITIES):
            raise LocalTargetError("RELEASE_IDENTITY_UNRESOLVED")

    @property
    def fingerprint(self) -> str:
        raw = json.dumps(self.to_dict(), ensure_ascii=True, sort_keys=True,
                         separators=(",", ":")).encode()
        return hashlib.sha256(raw).hexdigest()

    def to_dict(self) -> dict[str, Any]:
        return {
            "target_id": self.target_id,
            "version": self.version,
            "revision": self.revision,
            "immutable_commit": self.immutable_commit,
            "released_at": self.released_at,
            "source": self.source,
            "metadata_hash": self.metadata_hash,
            "source_identity": self.source_identity,
            "image_identity": self.image_identity,
        }


@dataclass(frozen=True)
class ReleaseObservation:
    release: ReleaseIdentity
    observed_at: str
    previous_known_release: dict[str, Any] | None
    is_new: bool
    provenance: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {
            "release": {**self.release.to_dict(), "fingerprint": self.release.fingerprint},
            "observed_at": self.observed_at,
            "previous_known_release": self.previous_known_release,
            "is_new": self.is_new,
            "provenance": self.provenance,
        }


@dataclass
class MonitorState:
    target_id: str
    last_checked_at: str | None = None
    known_releases: list[dict[str, Any]] = field(default_factory=list)
    latest_seen: dict[str, Any] | None = None
    candidate_states: dict[str, list[dict[str, Any]]] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": 1,
            "target_id": self.target_id,
            "last_checked_at": self.last_checked_at,
            "known_releases": self.known_releases,
            "latest_seen": self.latest_seen,
            "candidate_states": self.candidate_states,
        }

    @classmethod
    def from_dict(cls, value: Any, target_id: str) -> "MonitorState":
        if value is None:
            return cls(target_id)
        if (not isinstance(value, dict) or value.get("schema_version") != 1
                or value.get("target_id") != target_id
                or not isinstance(value.get("known_releases"), list)
                or not isinstance(value.get("candidate_states"), dict)):
            raise LocalTargetError("RELEASE_MONITOR_STATE_INVALID")
        return cls(
            target_id=target_id,
            last_checked_at=value.get("last_checked_at"),
            known_releases=value["known_releases"],
            latest_seen=value.get("latest_seen"),
            candidate_states=value["candidate_states"],
        )


class ReleaseProvider(Protocol):
    """Target-owned metadata and isolated revision lifecycle."""

    def list_releases(self) -> list[ReleaseIdentity]: ...
    def resolve_release(self, version: str) -> ReleaseIdentity: ...
    def latest_stable(self) -> ReleaseIdentity: ...
    def revision_identity(self, release: ReleaseIdentity) -> Mapping[str, Any]: ...
    def retest_candidates(self, candidate_id: str | None = None) -> list[dict[str, Any]]: ...
    def prepare_revision(self, release: ReleaseIdentity) -> Any: ...
    def bootstrap_revision(self, release: ReleaseIdentity, prepared: Any) -> None: ...
    def validate_release_candidate(
        self, candidate: Mapping[str, Any], release: ReleaseIdentity, prepared: Any,
    ) -> Mapping[str, Any]: ...
    def cleanup_revision(self, release: ReleaseIdentity, prepared: Any) -> None: ...


class ReleaseMonitor:
    def __init__(
        self,
        *,
        root: Path,
        target_id: str,
        provider: ReleaseProvider,
        now: Callable[[], str] | None = None,
    ) -> None:
        if not SAFE_ID.fullmatch(target_id):
            raise LocalTargetError("INVALID_RELEASE_MONITOR_TARGET")
        self.root = root.resolve()
        self.target_id = target_id
        self.provider = provider
        self.now = now or (lambda: datetime.now(timezone.utc).isoformat())
        self.monitor_root = self.root / ".operator" / "monitor" / target_id
        self.state_file = self.monitor_root / "state.json"
        self.history_file = self.monitor_root / "history.jsonl"

    def status(self) -> dict[str, Any]:
        return self._load_state().to_dict()

    def history(self) -> list[dict[str, Any]]:
        if not self.history_file.exists():
            return []
        try:
            if self.history_file.is_symlink() or self.history_file.stat().st_size > 32 * 1024 * 1024:
                raise LocalTargetError("RELEASE_MONITOR_STATE_INVALID")
            values = [json.loads(line) for line in self.history_file.read_text().splitlines() if line]
        except LocalTargetError:
            raise
        except (OSError, ValueError, TypeError):
            raise LocalTargetError("RELEASE_MONITOR_STATE_INVALID") from None
        return values

    def check(self, candidate_id: str | None = None, *, run_id: str | None = None) -> dict[str, Any]:
        if candidate_id is not None and not SAFE_ID.fullmatch(candidate_id):
            raise LocalTargetError("INVALID_RELEASE_MONITOR_CANDIDATE")
        state = self._load_state()
        checked_at = self.now()
        try:
            releases = self.provider.list_releases()
        except Exception:
            return self._blocked_run(
                state, checked_at, "RELEASE_PROVIDER_UNAVAILABLE", run_id,
            )
        try:
            releases = _validate_release_list(releases, self.target_id)
        except LocalTargetError:
            return self._blocked_run(
                state, checked_at, "RELEASE_IDENTITY_UNRESOLVED", run_id,
            )
        known = {
            item.get("fingerprint") for item in state.known_releases
            if isinstance(item, dict)
        }
        new_releases = [item for item in releases if item.fingerprint not in known]
        if not new_releases:
            state.last_checked_at = checked_at
            if releases:
                state.latest_seen = _release_record(releases[-1])
            atomic_private_json(self.state_file, state.to_dict())
            return self._write_run(state, checked_at, [], [], "NO_NEW_RELEASE", run_id)
        try:
            candidates = self.provider.retest_candidates(candidate_id)
        except Exception:
            return self._blocked_run(
                state, checked_at, "RELEASE_PROVIDER_UNAVAILABLE", run_id,
            )
        eligible = [item for item in candidates if _eligible_candidate(item)]
        observations: list[dict[str, Any]] = []
        retests: list[dict[str, Any]] = []
        for release in new_releases:
            previous = state.known_releases[-1] if state.known_releases else None
            observation = ReleaseObservation(
                release=release,
                observed_at=checked_at,
                previous_known_release=previous,
                is_new=True,
                provenance={"provider": type(self.provider).__name__},
            ).to_dict()
            observations.append(observation)
            release_record = _release_record(release)
            state.known_releases.append(release_record)
            state.latest_seen = release_record
            prepared: Any = None
            preparation_error: str | None = None
            try:
                prepared = self.provider.prepare_revision(release)
            except Exception as error:
                preparation_error = _reason(error, "REVISION_PREPARE_FAILED")
            if preparation_error is None:
                try:
                    self.provider.bootstrap_revision(release, prepared)
                except Exception as error:
                    preparation_error = _reason(error, "BOOTSTRAP_FAILED")
            for candidate in eligible:
                if preparation_error:
                    record = _blocked_retest(candidate, release, checked_at, preparation_error)
                else:
                    record = self._retest_candidate(state, candidate, release, prepared, checked_at)
                prior = state.candidate_states.get(candidate["candidate_id"], [])
                if record["status"] in {"FIXED", "REGRESSION"}:
                    try:
                        record["regression"] = self._generate_regression(
                            candidate, record, prior,
                        )
                    except (LocalTargetError, ValueError, TypeError):
                        record["regression"] = {
                            "status": "REGRESSION_SPEC_UNAVAILABLE",
                            "reason": "SCENARIO_INCOMPATIBLE",
                        }
                retests.append(record)
                state.candidate_states.setdefault(candidate["candidate_id"], []).append(record)
            if prepared is not None:
                try:
                    self.provider.cleanup_revision(release, prepared)
                except Exception:
                    pass
        state.last_checked_at = checked_at
        atomic_private_json(self.state_file, state.to_dict())
        for observation in observations:
            self._append_history({"kind": "release_observation", **observation})
        for retest in retests:
            self._append_history({"kind": "candidate_retest", **retest})
        return self._write_run(state, checked_at, observations, retests, "RELEASES_PROCESSED", run_id)

    def _retest_candidate(
        self,
        state: MonitorState,
        candidate: Mapping[str, Any],
        release: ReleaseIdentity,
        prepared: Any,
        checked_at: str,
    ) -> dict[str, Any]:
        try:
            evidence = self.provider.validate_release_candidate(candidate, release, prepared)
        except Exception as error:
            return _blocked_retest(
                candidate, release, checked_at, _reason(error, "RETEST_INCONCLUSIVE"),
            )
        classification, blocker = _classify_retest(evidence, candidate)
        previous_values = state.candidate_states.get(candidate["candidate_id"], [])
        prior_fixed = next((
            item for item in reversed(previous_values)
            if item.get("status") == "FIXED" and _same_invariant(item, candidate)
        ), None)
        if classification == "AFFECTED" and prior_fixed:
            classification = "REGRESSION"
        patch = {"status": "PATCH_CORRELATION_UNAVAILABLE"}
        if classification == "FIXED":
            correlator = getattr(self.provider, "patch_correlation", None)
            if callable(correlator) and state.known_releases:
                try:
                    previous_release = state.known_releases[-2] if len(state.known_releases) > 1 else None
                    correlated = correlator(previous_release, _release_record(release))
                    patch = _patch_correlation(correlated, candidate)
                except Exception:
                    patch = {"status": "PATCH_CORRELATION_UNAVAILABLE"}
        safe_evidence = clean(dict(evidence)) if isinstance(evidence, Mapping) else {}
        return {
            "candidate_id": candidate["candidate_id"],
            "release": _release_record(release),
            "observed_at": checked_at,
            "status": classification,
            "blocker": blocker,
            "root_cause_id": candidate["root_cause_id"],
            "scenario_id": candidate["scenario_id"],
            "invariant_hash": candidate["invariant_hash"],
            "evidence": safe_evidence,
            "patch_correlation": patch,
        }

    def _generate_regression(
        self,
        candidate: Mapping[str, Any],
        latest: Mapping[str, Any],
        history: list[Mapping[str, Any]],
    ) -> dict[str, Any]:
        scenario = candidate.get("deterministic_scenario")
        if not isinstance(scenario, Mapping):
            raise LocalTargetError("SCENARIO_INCOMPATIBLE")
        control = candidate.get("control_expectation")
        if not isinstance(control, Mapping):
            control = scenario.get("control_expectation", scenario.get("expected_control"))
        probe = candidate.get("probe_expectation")
        if not isinstance(probe, Mapping):
            probe = scenario.get("probe_expectation", scenario.get("violation_condition"))
        invariant = candidate.get("invariant")
        if not isinstance(invariant, Mapping):
            invariant = {"kind": "invariant-hash", "hash": candidate["invariant_hash"]}
        evidence = latest.get("evidence")
        evidence_ids = candidate.get("evidence_ids")
        if not isinstance(evidence_ids, list) and isinstance(evidence, Mapping):
            evidence_ids = evidence.get("evidence_ids")
        regression_candidate = {
            **candidate,
            "required_capabilities": list(candidate.get(
                "required_capabilities", RUNNER_CAPABILITIES,
            )),
            "control_expectation": control,
            "probe_expectation": probe,
            "invariant": invariant,
            "evidence_ids": evidence_ids,
        }
        return RegressionSpecStore(self.root).generate(
            target_id=self.target_id,
            candidate=regression_candidate,
            latest_retest=latest,
            history=history,
        )

    def _load_state(self) -> MonitorState:
        if not self.state_file.exists():
            return MonitorState(self.target_id)
        try:
            if self.state_file.is_symlink() or self.state_file.stat().st_size > 8 * 1024 * 1024:
                raise LocalTargetError("RELEASE_MONITOR_STATE_INVALID")
            value = json.loads(self.state_file.read_text())
        except LocalTargetError:
            raise
        except (OSError, ValueError, TypeError):
            raise LocalTargetError("RELEASE_MONITOR_STATE_INVALID") from None
        return MonitorState.from_dict(value, self.target_id)

    def _append_history(self, value: dict[str, Any]) -> None:
        safe = clean(value)
        assert_secret_free(safe)
        secure_directory(self.monitor_root)
        try:
            if self.history_file.is_symlink():
                raise LocalTargetError("RELEASE_MONITOR_STATE_INVALID")
            with self.history_file.open("a", encoding="utf-8") as handle:
                os.chmod(self.history_file, 0o600)
                handle.write(json.dumps(safe, ensure_ascii=True, sort_keys=True) + "\n")
        except LocalTargetError:
            raise
        except OSError:
            raise LocalTargetError("RELEASE_MONITOR_STATE_INVALID") from None

    def _blocked_run(
        self, state: MonitorState, checked_at: str, reason: str, run_id: str | None,
    ) -> dict[str, Any]:
        state.last_checked_at = checked_at
        atomic_private_json(self.state_file, state.to_dict())
        return self._write_run(state, checked_at, [], [], "MONITOR_BLOCKED", run_id, reason)

    def _write_run(
        self,
        state: MonitorState,
        checked_at: str,
        observations: list[dict[str, Any]],
        retests: list[dict[str, Any]],
        status: str,
        run_id: str | None,
        blocker: str | None = None,
    ) -> dict[str, Any]:
        run = run_id or _run_id(checked_at)
        if not SAFE_ID.fullmatch(run):
            raise LocalTargetError("INVALID_RELEASE_MONITOR_RUN")
        path = self.monitor_root / "runs" / run / "monitor.json"
        if path.exists() or path.is_symlink():
            raise LocalTargetError("RELEASE_MONITOR_RUN_EXISTS")
        payload = {
            "schema_version": 1,
            "target_id": self.target_id,
            "checked_at": checked_at,
            "status": status,
            "blocker": blocker,
            "release_observations": observations,
            "candidate_retests": retests,
            "latest_seen": state.latest_seen,
        }
        safe_payload = clean(payload)
        assert_secret_free(safe_payload)
        atomic_private_json(path, safe_payload)
        return {**safe_payload, "run_artifact": str(path.relative_to(self.root))}


def _validate_release_list(values: Any, target_id: str) -> list[ReleaseIdentity]:
    if not isinstance(values, list) or any(not isinstance(item, ReleaseIdentity) for item in values):
        raise LocalTargetError("RELEASE_IDENTITY_UNRESOLVED")
    fingerprints = [item.fingerprint for item in values]
    if any(item.target_id != target_id for item in values) or len(fingerprints) != len(set(fingerprints)):
        raise LocalTargetError("RELEASE_IDENTITY_UNRESOLVED")
    return values


def _eligible_candidate(value: Any) -> bool:
    return bool(
        isinstance(value, dict)
        and SAFE_ID.fullmatch(str(value.get("candidate_id", "")))
        and value.get("prior_status") in ELIGIBLE_PRIOR_STATUSES
        and isinstance(value.get("deterministic_scenario"), dict)
        and value["deterministic_scenario"]
        and isinstance(value.get("source_assertions"), dict)
        and value["source_assertions"]
        and all(item is True for item in value["source_assertions"].values())
        and value.get("revision_supported") is True
        and value.get("safety_gate") is True
        and isinstance(value.get("root_cause_id"), str) and value["root_cause_id"]
        and isinstance(value.get("scenario_id"), str) and value["scenario_id"]
        and HASH.fullmatch(str(value.get("invariant_hash", "")))
        and isinstance(value.get("request_budget"), int)
        and 1 <= value["request_budget"] <= 12
    )


def _classify_retest(
    value: Any, candidate: Mapping[str, Any],
) -> tuple[str, str | None]:
    if not isinstance(value, Mapping):
        return "INCONCLUSIVE", "RETEST_INCONCLUSIVE"
    if value.get("fixture_valid") is not True:
        return "BLOCKED", "SCENARIO_INCOMPATIBLE"
    if value.get("control_passed") is not True:
        return "BLOCKED", "CONTROL_FAILED"
    if value.get("source_assertion_valid") is not True:
        return "BLOCKED", "SOURCE_ASSERTION_CHANGED"
    if (value.get("probe_status") == 404 or value.get("probe_empty") is True
            or value.get("response_status_only") is True
            or value.get("timeout") is True or value.get("api_error") is True
            or value.get("route_changed") is True
            or value.get("deterministic") is not True
            or value.get("ambiguous") is True
            or value.get("probe_valid") is not True):
        return "INCONCLUSIVE", "RETEST_INCONCLUSIVE"
    count = value.get("request_count")
    if not isinstance(count, int) or not 0 <= count <= candidate["request_budget"]:
        return "BLOCKED", "SCENARIO_INCOMPATIBLE"
    if not _local_final_urls(value.get("final_urls")):
        return "BLOCKED", "SCENARIO_INCOMPATIBLE"
    violation = value.get("violation_observed")
    if violation is True:
        return "AFFECTED", None
    if violation is False:
        return "FIXED", None
    return "INCONCLUSIVE", "RETEST_INCONCLUSIVE"


def _local_final_urls(value: Any) -> bool:
    if not isinstance(value, list) or not value:
        return False
    for item in value:
        if not isinstance(item, str):
            return False
        parsed = urlsplit(item)
        if (parsed.scheme != "http" or parsed.hostname not in {"127.0.0.1", "::1", "localhost"}
                or parsed.username is not None or parsed.password is not None
                or parsed.fragment):
            return False
    return True


def _same_invariant(previous: Mapping[str, Any], current: Mapping[str, Any]) -> bool:
    return all(previous.get(key) == current.get(key) for key in (
        "root_cause_id", "scenario_id", "invariant_hash",
    ))


def _blocked_retest(
    candidate: Mapping[str, Any], release: ReleaseIdentity, observed_at: str, reason: str,
) -> dict[str, Any]:
    return {
        "candidate_id": candidate["candidate_id"],
        "release": _release_record(release),
        "observed_at": observed_at,
        "status": "BLOCKED",
        "blocker": reason if reason in RELEASE_FAILURE_REASONS else "RETEST_INCONCLUSIVE",
        "root_cause_id": candidate["root_cause_id"],
        "scenario_id": candidate["scenario_id"],
        "invariant_hash": candidate["invariant_hash"],
        "evidence": {},
        "patch_correlation": {"status": "PATCH_CORRELATION_UNAVAILABLE"},
    }


def _patch_correlation(value: Any, candidate: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        return {"status": "PATCH_CORRELATION_UNAVAILABLE"}
    permitted = {
        key: clean(value[key]) for key in (
            "previous_commit", "new_commit", "changed_files", "diff_summary", "commit_range",
        ) if key in value
    }
    if not permitted:
        return {"status": "PATCH_CORRELATION_UNAVAILABLE"}
    bisect = candidate.get("bisect")
    if isinstance(bisect, Mapping):
        boundary = bisect.get("boundary_revision")
        if bisect.get("mode") == "fixed" and isinstance(boundary, Mapping):
            permitted["first_fixed_commit"] = boundary.get("commit")
            permitted["first_fixed_version"] = boundary.get("version")
        else:
            permitted["first_fixed_commit"] = bisect.get("first_fixed_commit")
            permitted["first_fixed_version"] = bisect.get("first_fixed_version")
    return {"status": "PATCH_CORRELATION_AVAILABLE", **permitted,
            "security_patch_confirmed": False}


def _release_record(value: ReleaseIdentity) -> dict[str, Any]:
    return {**value.to_dict(), "fingerprint": value.fingerprint}


def _reason(error: Exception, fallback: str) -> str:
    code = getattr(error, "code", None)
    return code if code in RELEASE_FAILURE_REASONS else fallback


def _run_id(value: str) -> str:
    compact = re.sub(r"[^0-9A-Za-z]", "", value)
    return (compact or hashlib.sha256(value.encode()).hexdigest())[:64]
