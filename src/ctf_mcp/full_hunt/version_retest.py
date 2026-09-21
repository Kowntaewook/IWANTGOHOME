"""Immutable identity, cache, runtime, and version matrix primitives."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import re
import secrets
import shutil
import subprocess
from typing import Any, Callable, Iterable, Mapping

from ctf_mcp.local_targets.base import (
    FixedCommandRunner,
    LocalTargetError,
    atomic_private_json,
    reject_active_git_extensions,
    repository_origin_matches,
    run_confined_git,
    secure_directory,
)

from .runtime import IsolatedRuntime
from .schema import RETEST_RESULTS


COMMIT_SHA = re.compile(r"[0-9a-f]{40}")
IMAGE_ID = re.compile(r"sha256:[0-9a-f]{64}")


def require_commit_sha(value: str, *, error: str) -> str:
    if not isinstance(value, str) or not COMMIT_SHA.fullmatch(value):
        raise LocalTargetError(error)
    return value


def require_image_id(value: str, *, error: str) -> str:
    if not isinstance(value, str) or not IMAGE_ID.fullmatch(value):
        raise LocalTargetError(error)
    return value


def content_hash(content: bytes, descriptor: str) -> str:
    if not isinstance(content, bytes) or not isinstance(descriptor, str) or not descriptor:
        raise LocalTargetError("invalid_build_cache_material")
    return hashlib.sha256(content + b"\0" + descriptor.encode()).hexdigest()


def configuration_hash(value: Mapping[str, Any]) -> str:
    try:
        encoded = json.dumps(
            dict(value), ensure_ascii=True, sort_keys=True, separators=(",", ":"),
        ).encode()
    except (TypeError, ValueError):
        raise LocalTargetError("invalid_build_cache_material") from None
    return hashlib.sha256(encoded).hexdigest()


def immutable_build_cache_key(commit: str, recipe: str, configuration: str) -> str:
    require_commit_sha(commit, error="invalid_build_cache_material")
    if not all(re.fullmatch(r"[0-9a-f]{64}", item) for item in (recipe, configuration)):
        raise LocalTargetError("invalid_build_cache_material")
    return hashlib.sha256((commit + recipe + configuration).encode()).hexdigest()


@dataclass(frozen=True)
class RetestFailureModel:
    reasons: frozenset[str]
    fallback: str

    def __post_init__(self) -> None:
        if not self.reasons or self.fallback not in self.reasons:
            raise LocalTargetError("invalid_retest_failure_model")

    def normalize(self, reason: str | None) -> str:
        return reason if reason in self.reasons else self.fallback


@dataclass(frozen=True)
class SourceResolutionFailures:
    fetch: str
    unresolved: str


class ImmutableGitSourceResolver:
    """Resolve a branch to a commit and cache a detached, pristine checkout."""

    def __init__(
        self,
        *,
        root: Path,
        targets_root: Path,
        source_root: Path,
        repository: str,
        branch: str,
        runner: FixedCommandRunner,
        now: Callable[[], str],
        required_files: tuple[str, ...],
        failures: SourceResolutionFailures,
    ):
        self.root = root
        self.targets_root = targets_root
        self.source_root = source_root
        self.repository = repository
        self.branch = branch
        self.runner = runner
        self.now = now
        self.required_files = required_files
        self.failures = failures

    def _git(
        self, argv: list[str], cwd: Path, timeout: float = 30,
    ) -> subprocess.CompletedProcess[str]:
        return run_confined_git(
            self.runner, self.targets_root, argv, cwd=cwd, timeout=timeout,
        )

    def resolve(self) -> dict[str, Any]:
        secure_directory(self.targets_root)
        secure_directory(self.source_root)
        fetched_at = self.now()
        reference = "refs/heads/" + self.branch
        try:
            remote = self._git(
                ["ls-remote", "--exit-code", self.repository, reference],
                self.targets_root,
                60,
            ).stdout.strip().splitlines()
        except LocalTargetError:
            raise LocalTargetError(self.failures.fetch) from None
        matches = []
        for line in remote:
            fields = line.split()
            if len(fields) == 2 and fields[1] == reference and COMMIT_SHA.fullmatch(fields[0]):
                matches.append(fields[0])
        if len(matches) != 1:
            raise LocalTargetError(self.failures.unresolved)
        commit = matches[0]
        source = self.source_root / commit
        if source.exists() or source.is_symlink():
            self.validate(source, commit)
        else:
            temporary = self.source_root / (".preparing-" + secrets.token_hex(8))
            try:
                self._git(
                    ["clone", "--filter=blob:none", "--no-checkout", self.repository, str(temporary)],
                    self.source_root,
                    1800,
                )
                reject_active_git_extensions(temporary)
                try:
                    self._git(["cat-file", "-e", commit + "^{commit}"], temporary, 30)
                except LocalTargetError:
                    self._git(["fetch", "--depth", "1", "origin", commit], temporary, 600)
                self._git(["checkout", "--detach", commit], temporary, 180)
                self.validate(temporary, commit)
                temporary.rename(source)
            except LocalTargetError as error:
                if error.code in {"REPOSITORY_MISMATCH", "REVISION_MISMATCH", "SOURCE_DIRTY"}:
                    raise LocalTargetError(self.failures.unresolved) from None
                raise LocalTargetError(self.failures.fetch) from None
            finally:
                if temporary.exists():
                    shutil.rmtree(temporary)
        return {
            "branch": self.branch,
            "commit": commit,
            "fetched_at": fetched_at,
            "repository": self.repository,
            "source_directory": str(source.relative_to(self.root)),
        }

    def validate(self, source: Path, commit: str) -> None:
        git_dir = source / ".git"
        if source.is_symlink() or not source.is_dir() or git_dir.is_symlink() or not git_dir.is_dir():
            raise LocalTargetError("REPOSITORY_MISMATCH")
        for relative in self.required_files:
            path = source / relative
            if path.is_symlink() or not path.is_file():
                raise LocalTargetError("REPOSITORY_MISMATCH")
        reject_active_git_extensions(source)
        origin = self._git(["remote", "get-url", "origin"], source, 10).stdout.strip()
        head = self._git(["rev-parse", "HEAD"], source, 10).stdout.strip()
        dirty = self._git(
            ["status", "--porcelain", "--untracked-files=normal"], source, 30,
        ).stdout.strip()
        if not repository_origin_matches(origin, self.repository):
            raise LocalTargetError("REPOSITORY_MISMATCH")
        if head != commit:
            raise LocalTargetError("REVISION_MISMATCH")
        if dirty:
            raise LocalTargetError("SOURCE_DIRTY")


class ImmutableBuildCache:
    """Persist build success/failure and validate a reusable immutable image."""

    def __init__(self, cache_file: Path):
        self.cache_file = cache_file

    def read(self) -> dict[str, Any] | None:
        try:
            if self.cache_file.is_symlink() or self.cache_file.stat().st_size > 128 * 1024:
                return None
            value = json.loads(self.cache_file.read_text(encoding="utf-8"))
            return value if isinstance(value, dict) else None
        except (OSError, ValueError, TypeError):
            return None

    def matching(
        self,
        *,
        commit: str,
        recipe_hash: str,
        configuration_hash: str,
        image_tag: str,
        inspect: Callable[[], dict[str, Any] | None],
    ) -> dict[str, Any] | None:
        cache_key = immutable_build_cache_key(commit, recipe_hash, configuration_hash)
        cache = self.read()
        if not cache or not all(cache.get(key) == value for key, value in {
            "cache_key": cache_key,
            "commit": commit,
            "recipe_hash": recipe_hash,
            "configuration_hash": configuration_hash,
            "image_tag": image_tag,
            "success": True,
        }.items()):
            return None
        inspected = inspect()
        if not inspected or inspected.get("image_id") != cache.get("image_id"):
            return None
        return {**cache, **inspected, "cache_hit": True}

    def write(self, value: dict[str, Any]) -> None:
        atomic_private_json(self.cache_file, value)


def immutable_image_identity(
    values: Any,
    *,
    expected_labels: Mapping[str, str],
) -> dict[str, str | None] | None:
    if not isinstance(values, list) or len(values) != 1 or not isinstance(values[0], dict):
        return None
    value = values[0]
    image_id = value.get("Id")
    config = value.get("Config")
    labels = config.get("Labels") if isinstance(config, dict) else None
    if (not isinstance(image_id, str) or not IMAGE_ID.fullmatch(image_id)
            or not isinstance(labels, dict)
            or any(labels.get(key) != expected for key, expected in expected_labels.items())):
        return None
    repo_digest = None
    for item in value.get("RepoDigests") or []:
        if isinstance(item, str) and "@" in item:
            candidate = item.rsplit("@", 1)[1]
            if IMAGE_ID.fullmatch(candidate):
                repo_digest = candidate
                break
    return {"image_id": image_id, "repo_digest": repo_digest}


def validate_retest_target(
    value: dict[str, Any],
    *,
    kinds: frozenset[str],
    endpoints: Mapping[str, str],
    failure_model: RetestFailureModel | None = None,
) -> dict[str, Any]:
    required = {
        "target", "version", "commit", "digest", "runtime_id", "endpoint",
        "isolated", "result", "control_passed", "evidence_ids",
    }
    if (not isinstance(value, dict) or not required <= set(value)
            or value["target"] not in kinds
            or value["endpoint"] != endpoints[value["target"]]
            or value["isolated"] is not True
            or value["result"] not in RETEST_RESULTS
            or not isinstance(value["control_passed"], bool)
            or (value["result"] != "RETEST_BLOCKED" and value["control_passed"] is not True)
            or not isinstance(value["runtime_id"], str)
            or not isinstance(value["evidence_ids"], list)):
        raise LocalTargetError("invalid_retest_evidence")
    IsolatedRuntime(
        value["target"], value["runtime_id"], value["endpoint"], value.get("digest")
    )
    for key, validator in (("commit", COMMIT_SHA), ("digest", IMAGE_ID)):
        if value[key] is not None and not validator.fullmatch(str(value[key])):
            raise LocalTargetError("invalid_retest_evidence")
    if value["result"] == "RETEST_BLOCKED" and failure_model is not None:
        reason = value.get("blocked_reason")
        if reason is not None and reason not in failure_model.reasons:
            raise LocalTargetError("invalid_retest_evidence")
    return value


def compose_version_matrix(
    *,
    candidate_id: str,
    pinned: dict[str, Any],
    target_kinds: tuple[str, ...],
    supplied: Iterable[dict[str, Any]],
    blocked_target: Callable[[str], dict[str, Any]],
    validate_target: Callable[[dict[str, Any]], dict[str, Any]],
    classify: Callable[[dict[str, dict[str, Any]]], str],
) -> dict[str, Any]:
    by_kind = {item.get("target"): item for item in supplied}
    ordered = [pinned]
    for kind in target_kinds:
        ordered.append(validate_target(by_kind.get(kind) or blocked_target(kind)))
    runtimes = [item["runtime_id"] for item in ordered]
    endpoints = [item["endpoint"] for item in ordered]
    if len(set(runtimes)) != len(runtimes) or len(set(endpoints)) != len(endpoints):
        raise LocalTargetError("retest_runtime_not_isolated")
    indexed = {item["target"]: item for item in ordered}
    return {
        "candidate_id": candidate_id,
        "status": classify(indexed),
        "targets": ordered,
    }
