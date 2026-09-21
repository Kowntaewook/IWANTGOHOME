"""Declarative, target-owned regression replay specifications."""

from __future__ import annotations

from dataclasses import dataclass
import json
import os
from pathlib import Path
import re
from typing import Any, Mapping

from ctf_mcp.full_hunt.runtime import assert_secret_free
from ctf_mcp.local_targets.base import (
    LocalTargetError,
    atomic_private_json,
    secure_directory,
)
from ctf_mcp.redaction import clean
from ctf_mcp.targets import TargetPluginError, TargetRegistry

SAFE_ID = re.compile(r"[A-Za-z0-9_.-]{1,128}\Z")
HASH = re.compile(r"[0-9a-f]{64}\Z")
FORBIDDEN_KEY = re.compile(
    r"(?i)(?:command|cmd|shell|python|expression|subprocess|executable|url|uri|"
    r"path|file|directory|cwd|environment|env)"
)
URL = re.compile(r"(?i)\b(?:https?|ftp|file)://")
ABSOLUTE_PATH = re.compile(
    r"(?:^|\s)(?:/[^\s]+|[A-Za-z]:[\\/][^\s]+|\.\.?[\\/][^\s]+|"
    r"~[\\/][^\s]+|[A-Za-z0-9_.-]+[\\/][A-Za-z0-9_.\\/-]+)"
)
SHELL = re.compile(r"(?:`|\$\(|&&|\|\||\n\s*(?:sh|bash|python|pwsh)\b)")
PYTHON_EXPRESSION = re.compile(
    r"(?i)(?:\b(?:__import__|eval|exec|compile|open)\s*\(|\b(?:os|subprocess|pathlib)\.)"
)
REQUIRED_SAFETY = (
    "local_only", "no_external_redirects", "nondestructive",
    "no_credential_guessing", "redact_secrets",
)
RUNNER_CAPABILITIES = (
    "local_runtime", "safety_gate", "fixture", "deterministic_replay",
)


@dataclass(frozen=True)
class RegressionSpec:
    schema_version: int
    target_id: str
    candidate_id: str
    root_cause_id: str
    scenario_id: str
    required_capabilities: tuple[str, ...]
    source_assertions: dict[str, bool]
    control_expectation: dict[str, Any]
    probe_expectation: dict[str, Any]
    invariant: dict[str, Any]
    request_budget: int
    safety_policy: dict[str, bool]
    known_affected: tuple[dict[str, Any], ...]
    known_fixed: tuple[dict[str, Any], ...]
    generated_from_evidence: tuple[str, ...]

    @classmethod
    def from_dict(cls, value: Any) -> "RegressionSpec":
        _reject_active_content(value)
        if not isinstance(value, dict) or value.get("schema_version") != 1:
            raise LocalTargetError("INVALID_REGRESSION_SPEC")
        ids = ("target_id", "candidate_id", "root_cause_id", "scenario_id")
        if any(not isinstance(value.get(key), str) or not SAFE_ID.fullmatch(value[key]) for key in ids):
            raise LocalTargetError("INVALID_REGRESSION_SPEC")
        capabilities = value.get("required_capabilities")
        if (not isinstance(capabilities, list) or not capabilities
                or any(not isinstance(item, str) or not SAFE_ID.fullmatch(item) for item in capabilities)
                or len(capabilities) != len(set(capabilities))):
            raise LocalTargetError("INVALID_REGRESSION_SPEC")
        assertions = value.get("source_assertions")
        if (not isinstance(assertions, dict) or not assertions
                or any(not isinstance(key, str) or not SAFE_ID.fullmatch(key)
                       or item is not True for key, item in assertions.items())):
            raise LocalTargetError("INVALID_REGRESSION_SPEC")
        control = _declarative_mapping(value.get("control_expectation"))
        probe = _declarative_mapping(value.get("probe_expectation"))
        invariant = _declarative_mapping(value.get("invariant"))
        budget = value.get("request_budget")
        if not isinstance(budget, int) or isinstance(budget, bool) or not 1 <= budget <= 12:
            raise LocalTargetError("INVALID_REGRESSION_SPEC")
        policy = value.get("safety_policy")
        if (not isinstance(policy, dict) or any(policy.get(key) is not True for key in REQUIRED_SAFETY)
                or any(not isinstance(key, str) or item is not True for key, item in policy.items())):
            raise LocalTargetError("INVALID_REGRESSION_SPEC")
        affected = _release_records(value.get("known_affected"))
        fixed = _release_records(value.get("known_fixed"))
        evidence = value.get("generated_from_evidence")
        if (not isinstance(evidence, list) or not evidence
                or any(not isinstance(item, str) or not SAFE_ID.fullmatch(item) for item in evidence)):
            raise LocalTargetError("INVALID_REGRESSION_SPEC")
        return cls(
            schema_version=1,
            target_id=value["target_id"],
            candidate_id=value["candidate_id"],
            root_cause_id=value["root_cause_id"],
            scenario_id=value["scenario_id"],
            required_capabilities=tuple(capabilities),
            source_assertions=dict(assertions),
            control_expectation=control,
            probe_expectation=probe,
            invariant=invariant,
            request_budget=budget,
            safety_policy=dict(policy),
            known_affected=tuple(affected),
            known_fixed=tuple(fixed),
            generated_from_evidence=tuple(evidence),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "target_id": self.target_id,
            "candidate_id": self.candidate_id,
            "root_cause_id": self.root_cause_id,
            "scenario_id": self.scenario_id,
            "required_capabilities": list(self.required_capabilities),
            "source_assertions": self.source_assertions,
            "control_expectation": self.control_expectation,
            "probe_expectation": self.probe_expectation,
            "invariant": self.invariant,
            "request_budget": self.request_budget,
            "safety_policy": self.safety_policy,
            "known_affected": list(self.known_affected),
            "known_fixed": list(self.known_fixed),
            "generated_from_evidence": list(self.generated_from_evidence),
        }


class RegressionSpecStore:
    def __init__(self, root: Path):
        self.root = root.resolve()
        self.base = self.root / ".operator" / "regressions"

    def generate(
        self,
        *,
        target_id: str,
        candidate: Mapping[str, Any],
        latest_retest: Mapping[str, Any],
        history: list[Mapping[str, Any]] | None = None,
    ) -> dict[str, Any]:
        if latest_retest.get("status") not in {"FIXED", "REGRESSION"}:
            raise LocalTargetError("REGRESSION_SPEC_STATUS_INELIGIBLE")
        candidate_id = candidate.get("candidate_id")
        if not isinstance(candidate_id, str):
            raise LocalTargetError("INVALID_REGRESSION_SPEC")
        records = list(history or ())
        if not records or records[-1] != latest_retest:
            records.append(latest_retest)
        if (latest_retest.get("status") == "REGRESSION"
                and not any(item.get("status") == "FIXED" for item in records[:-1])):
            raise LocalTargetError("REGRESSION_SPEC_STATUS_INELIGIBLE")
        spec = RegressionSpec.from_dict({
            "schema_version": 1,
            "target_id": target_id,
            "candidate_id": candidate_id,
            "root_cause_id": candidate.get("root_cause_id"),
            "scenario_id": candidate.get("scenario_id"),
            "required_capabilities": list(candidate.get("required_capabilities", RUNNER_CAPABILITIES)),
            "source_assertions": candidate.get("source_assertions"),
            "control_expectation": candidate.get("control_expectation"),
            "probe_expectation": candidate.get("probe_expectation"),
            "invariant": candidate.get("invariant"),
            "request_budget": candidate.get("request_budget"),
            "safety_policy": candidate.get("safety_policy", {
                key: True for key in REQUIRED_SAFETY
            }),
            "known_affected": [
                _release_reference(item) for item in records
                if item.get("status") in {"AFFECTED", "REGRESSION"}
            ],
            "known_fixed": [
                _release_reference(item) for item in records
                if item.get("status") == "FIXED"
            ],
            "generated_from_evidence": list(candidate.get("evidence_ids", ())),
        })
        safe = clean(spec.to_dict())
        assert_secret_free(safe)
        validated = RegressionSpec.from_dict(safe)
        directory = self._directory(target_id, candidate_id)
        atomic_private_json(directory / "regression.json", validated.to_dict())
        _atomic_private_text(
            directory / "README.md", _readme(validated, latest_retest["status"]),
        )
        return {
            "status": "REGRESSION_SPEC_GENERATED",
            "target_id": target_id,
            "candidate_id": candidate_id,
            "latest_status": latest_retest["status"],
            "regression_json": str((directory / "regression.json").relative_to(self.root)),
            "readme": str((directory / "README.md").relative_to(self.root)),
        }

    def load(self, target_id: str, candidate_id: str) -> RegressionSpec:
        path = self._directory(target_id, candidate_id) / "regression.json"
        try:
            if path.is_symlink() or path.stat().st_size > 1024 * 1024:
                raise LocalTargetError("INVALID_REGRESSION_SPEC")
            return RegressionSpec.from_dict(json.loads(path.read_text(encoding="utf-8")))
        except LocalTargetError:
            raise
        except FileNotFoundError:
            raise LocalTargetError("REGRESSION_SPEC_NOT_FOUND") from None
        except (OSError, ValueError, TypeError):
            raise LocalTargetError("INVALID_REGRESSION_SPEC") from None

    def inspect(self, target_id: str, candidate_id: str) -> dict[str, Any]:
        return self.load(target_id, candidate_id).to_dict()

    def list(self, target_id: str) -> list[dict[str, Any]]:
        if not SAFE_ID.fullmatch(target_id):
            raise LocalTargetError("INVALID_REGRESSION_SPEC")
        target_root = self.base / target_id
        if not target_root.is_dir() or target_root.is_symlink():
            return []
        result = []
        for item in sorted(target_root.iterdir()):
            if item.is_dir() and not item.is_symlink():
                try:
                    spec = self.load(target_id, item.name)
                except LocalTargetError:
                    continue
                result.append({
                    "target_id": target_id,
                    "candidate_id": spec.candidate_id,
                    "request_budget": spec.request_budget,
                })
        return result

    def _directory(self, target_id: str, candidate_id: str) -> Path:
        if not SAFE_ID.fullmatch(target_id) or not SAFE_ID.fullmatch(candidate_id):
            raise LocalTargetError("INVALID_REGRESSION_SPEC")
        return self.base / target_id / candidate_id


class RegressionRunner:
    def __init__(self, root: Path, registry: TargetRegistry | None = None):
        self.root = root.resolve()
        self.registry = registry or TargetRegistry()
        self.store = RegressionSpecStore(root)

    def run(self, target_id: str, candidate_id: str) -> dict[str, Any]:
        spec = self.store.load(target_id, candidate_id)
        try:
            adapter = self.registry.load(target_id, root=self.root)
        except TargetPluginError as error:
            code = (
                "REGRESSION_TARGET_UNAVAILABLE"
                if error.code == "TARGET_NOT_FOUND" else "REGRESSION_TARGET_INCOMPATIBLE"
            )
            raise LocalTargetError(code) from None
        capabilities_method = getattr(adapter, "regression_capabilities", None)
        replay = getattr(adapter, "run_regression", None)
        if not callable(capabilities_method) or not callable(replay):
            raise LocalTargetError("REGRESSION_TARGET_INCOMPATIBLE")
        try:
            capabilities = capabilities_method(candidate_id)
        except Exception:
            raise LocalTargetError("REGRESSION_TARGET_INCOMPATIBLE") from None
        required = set(spec.required_capabilities) | set(RUNNER_CAPABILITIES)
        if (not isinstance(capabilities, Mapping)
                or any(capabilities.get(item) is not True for item in required)):
            raise LocalTargetError("REGRESSION_CAPABILITY_MISSING")
        try:
            result = replay(spec.to_dict())
        except Exception:
            raise LocalTargetError("REGRESSION_REPLAY_BLOCKED") from None
        status, reason = _validate_replay(result, spec)
        safe_result = clean(dict(result)) if isinstance(result, Mapping) else {}
        assert_secret_free(safe_result)
        return {
            "target_id": target_id,
            "candidate_id": candidate_id,
            "status": status,
            "blocker": reason,
            "request_budget": spec.request_budget,
            "result": safe_result,
        }


def _validate_replay(value: Any, spec: RegressionSpec) -> tuple[str, str | None]:
    if not isinstance(value, Mapping):
        return "BLOCKED", "REGRESSION_REPLAY_BLOCKED"
    for key in ("fixture_valid", "control_passed", "source_assertion_valid", "deterministic"):
        if value.get(key) is not True:
            return "BLOCKED", "REGRESSION_REPLAY_BLOCKED"
    count = value.get("request_count")
    if not isinstance(count, int) or isinstance(count, bool) or not 0 <= count <= spec.request_budget:
        return "BLOCKED", "REGRESSION_REQUEST_BUDGET_EXCEEDED"
    urls = value.get("final_urls")
    if not isinstance(urls, list) or not urls or any(not _loopback_url(item) for item in urls):
        return "BLOCKED", "REGRESSION_EXTERNAL_REDIRECT"
    observed = value.get("violation_observed")
    if observed is True:
        return "FAIL", None
    if observed is False:
        return "PASS", None
    return "INCONCLUSIVE", "REGRESSION_REPLAY_INCONCLUSIVE"


def _loopback_url(value: Any) -> bool:
    from urllib.parse import urlsplit

    if not isinstance(value, str):
        return False
    parsed = urlsplit(value)
    return bool(
        parsed.scheme == "http"
        and parsed.hostname in {"127.0.0.1", "::1", "localhost"}
        and parsed.username is None and parsed.password is None and not parsed.fragment
    )


def _declarative_mapping(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict) or not value:
        raise LocalTargetError("INVALID_REGRESSION_SPEC")
    _reject_active_content(value)
    return dict(value)


def _release_records(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        raise LocalTargetError("INVALID_REGRESSION_SPEC")
    result = []
    for item in value:
        if (not isinstance(item, dict) or not isinstance(item.get("version"), str)
                or not isinstance(item.get("fingerprint"), str)
                or not HASH.fullmatch(item["fingerprint"])):
            raise LocalTargetError("INVALID_REGRESSION_SPEC")
        result.append({"version": item["version"], "fingerprint": item["fingerprint"]})
    return result


def _release_reference(value: Mapping[str, Any]) -> dict[str, Any]:
    release = value.get("release")
    if not isinstance(release, Mapping):
        raise LocalTargetError("INVALID_REGRESSION_SPEC")
    return {"version": release.get("version"), "fingerprint": release.get("fingerprint")}


def _reject_active_content(value: Any) -> None:
    if isinstance(value, Mapping):
        for key, item in value.items():
            if not isinstance(key, str) or FORBIDDEN_KEY.search(key):
                raise LocalTargetError("REGRESSION_SPEC_ACTIVE_CONTENT_REJECTED")
            _reject_active_content(item)
            if key.endswith("_id") and (
                not isinstance(item, str) or not SAFE_ID.fullmatch(item)
            ):
                raise LocalTargetError("INVALID_REGRESSION_SPEC")
    elif isinstance(value, (list, tuple)):
        for item in value:
            _reject_active_content(item)
    elif isinstance(value, str):
        if URL.search(value):
            raise LocalTargetError("REGRESSION_SPEC_URL_REJECTED")
        if ABSOLUTE_PATH.search(value):
            raise LocalTargetError("REGRESSION_SPEC_PATH_REJECTED")
        if SHELL.search(value) or any(item in value for item in (";", "|", ">", "<")):
            raise LocalTargetError("REGRESSION_SPEC_SHELL_REJECTED")
        if PYTHON_EXPRESSION.search(value):
            raise LocalTargetError("REGRESSION_SPEC_ACTIVE_CONTENT_REJECTED")
    elif value is not None and not isinstance(value, (bool, int, float)):
        raise LocalTargetError("INVALID_REGRESSION_SPEC")


def _readme(spec: RegressionSpec, latest_status: str) -> str:
    return "\n".join((
        f"# Regression check: {spec.candidate_id}", "",
        f"- Target: {spec.target_id}",
        f"- Latest monitor status: {latest_status}",
        f"- Request budget: {spec.request_budget}",
        "- Execution: installed target adapter on an authorized local runtime", "",
        "The JSON file is declarative. It contains no command, URL, or filesystem path.", "",
    ))


def _atomic_private_text(path: Path, value: str) -> None:
    secure_directory(path.parent)
    if path.is_symlink():
        raise LocalTargetError("unsafe_local_path")
    temporary = path.parent / (".pending-" + os.urandom(8).hex())
    try:
        with temporary.open("x", encoding="utf-8") as handle:
            os.chmod(temporary, 0o600)
            handle.write(value)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        os.chmod(path, 0o600)
    finally:
        temporary.unlink(missing_ok=True)
