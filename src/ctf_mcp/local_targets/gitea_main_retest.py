"""Immutable upstream-main build and localhost retest support for Gitea."""

from __future__ import annotations

from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import socket
import subprocess
import time
from typing import Any, Callable

from ctf_mcp.full_hunt.version_retest import (
    ImmutableBuildCache,
    ImmutableGitSourceResolver,
    RetestFailureModel,
    SourceResolutionFailures,
    configuration_hash,
    content_hash,
    immutable_image_identity,
    immutable_build_cache_key,
)
from ctf_mcp.full_hunt.runtime import IsolatedRuntimeLifecycle

from .base import (
    FixedCommandRunner,
    LocalTargetError,
    LocalTargetManifest,
    atomic_private_json,
    secure_directory,
)
from .gitea import GiteaAdapter


MAIN_REPOSITORY = "https://github.com/go-gitea/gitea"
MAIN_BRANCH = "main"
MAIN_PORT = 13002
MAIN_ENDPOINT = "127.0.0.1:13002"
MAIN_RUNTIME_HOST = "http://127.0.0.1:13002"
MAIN_COMPOSE_PROJECT = "iwantgohome-local-gitea-main"
MAIN_RUNTIME_ID = "gitea-main-13002"
MAIN_RETEST_CANDIDATES = frozenset({"SD-G04", "SD-G08"})
MAIN_FAILURE_REASONS = frozenset({
    "MAIN_FETCH_FAILED",
    "MAIN_COMMIT_UNRESOLVED",
    "MAIN_BUILD_FAILED",
    "MAIN_IMAGE_IDENTITY_FAILED",
    "MAIN_PORT_CONFLICT",
    "MAIN_RUNTIME_FAILED",
    "MAIN_BOOTSTRAP_FAILED",
    "MAIN_API_INCOMPATIBLE",
    "MAIN_CONTROL_FAILED",
})
_IMAGE_TAG = re.compile(r"iwantgohome/gitea-main:[0-9a-f]{12}")
_SECRET_LINE = re.compile(
    r"(?i)(authorization\s*:|set-cookie\s*:|cookie\s*:|bearer\s+|basic\s+|"
    r"password\s*=|token\s*=|gh[pousr]_[A-Za-z0-9_]{20,})"
)
_FAILURE_MODEL = RetestFailureModel(MAIN_FAILURE_REASONS, "MAIN_RUNTIME_FAILED")


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _port_in_use() -> bool:
    try:
        with socket.create_connection(("127.0.0.1", MAIN_PORT), timeout=0.2):
            return True
    except OSError:
        return False


def _private_text(path: Path, value: str) -> None:
    secure_directory(path.parent)
    temporary = path.parent / (".pending-" + secrets.token_hex(8))
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


def _sanitized_build_log(stdout: str | None, stderr: str | None) -> str:
    lines = []
    for stream, value in (("stdout", stdout or ""), ("stderr", stderr or "")):
        lines.append(f"[{stream}]")
        for line in value.splitlines():
            lines.append("[REDACTED SECRET-LIKE LINE]" if _SECRET_LINE.search(line) else line)
    return "\n".join(lines) + "\n"


class GiteaMainRetest:
    """Resolve, build, run, and selectively validate one immutable main commit."""

    def __init__(
        self,
        root: Path,
        manifest: LocalTargetManifest,
        *,
        runner: FixedCommandRunner | None = None,
        sleep: Callable[[float], None] = time.sleep,
        now: Callable[[], str] = _utc_now,
        monotonic: Callable[[], float] = time.monotonic,
        port_in_use: Callable[[], bool] = _port_in_use,
        adapter_factory: Callable[..., GiteaAdapter] = GiteaAdapter,
    ):
        self.root = root.resolve()
        self.manifest = manifest
        self.runner = runner or FixedCommandRunner()
        self.sleep = sleep
        self.now = now
        self.monotonic = monotonic
        self.port_in_use = port_in_use
        self.adapter_factory = adapter_factory
        self.operator = self.root / ".operator"
        self.targets_root = self.operator / "targets"
        self.source_root = self.targets_root / "gitea-main"
        self.runtime_root = self.operator / "local-runtime" / "gitea-main"
        self.secret_root = self.operator / "local-secrets" / "gitea-main"
        self.evidence_root = self.operator / "local-evidence" / "gitea-main"
        self.cache_file = self.runtime_root / "build-cache.json"
        self.source_record = self.runtime_root / "source.json"
        self.source_resolver = ImmutableGitSourceResolver(
            root=self.root,
            targets_root=self.targets_root,
            source_root=self.source_root,
            repository=MAIN_REPOSITORY,
            branch=MAIN_BRANCH,
            runner=self.runner,
            now=self.now,
            required_files=("go.mod", "Dockerfile.rootless"),
            failures=SourceResolutionFailures(
                fetch="MAIN_FETCH_FAILED",
                unresolved="MAIN_COMMIT_UNRESOLVED",
            ),
        )
        self.build_cache = ImmutableBuildCache(self.cache_file)
        self._source: dict[str, Any] | None = None
        self._build: dict[str, Any] | None = None
        self._adapter: GiteaAdapter | None = None
        self._bootstrap_status = "not_started"
        self._failure: str | None = None
        self._results: dict[str, dict[str, Any]] = {}

    @staticmethod
    def supports(candidate: dict[str, Any]) -> bool:
        return candidate.get("candidate_id") in MAIN_RETEST_CANDIDATES

    def resolve_source(self) -> dict[str, Any]:
        if self._source is not None:
            return self._source
        self._source = self.source_resolver.resolve()
        atomic_private_json(self.source_record, self._source)
        return self._source

    def _build_keys(self, source: dict[str, Any]) -> tuple[str, str, str]:
        directory = self.root / source["source_directory"]
        dockerfile = directory / "Dockerfile.rootless"
        try:
            if dockerfile.is_symlink() or dockerfile.stat().st_size > 512 * 1024:
                raise OSError
            recipe = dockerfile.read_bytes()
        except OSError:
            raise LocalTargetError("MAIN_BUILD_FAILED") from None
        recipe_hash = content_hash(
            recipe, "docker-build-rootless-v1/version-from-immutable-git-head",
        )
        config_hash = configuration_hash({
            "compose_project": MAIN_COMPOSE_PROJECT,
            "dockerfile": "Dockerfile.rootless",
            "port": MAIN_PORT,
            "rootless": True,
            "ssh_publish": False,
            "sqlite": True,
        })
        tag = "iwantgohome/gitea-main:" + source["commit"][:12]
        return recipe_hash, config_hash, tag

    def ensure_image(self, source: dict[str, Any] | None = None) -> dict[str, Any]:
        if self._build is not None:
            return self._build
        source = source or self.resolve_source()
        recipe_hash, configuration_hash, tag = self._build_keys(source)
        cache_key = immutable_build_cache_key(
            source["commit"], recipe_hash, configuration_hash,
        )
        cached = self.build_cache.matching(
            commit=source["commit"],
            recipe_hash=recipe_hash,
            configuration_hash=configuration_hash,
            image_tag=tag,
            inspect=lambda: self._inspect_image(
                tag, source["commit"], recipe_hash, configuration_hash,
            ),
        )
        if cached:
            self._build = cached
            return self._build
        if shutil.which("docker") is None:
            raise LocalTargetError("MAIN_BUILD_FAILED")
        directory = self.root / source["source_directory"]
        dockerfile = directory / "Dockerfile.rootless"
        labels = {
            "iwantgohome.gitea.main.commit": source["commit"],
            "iwantgohome.gitea.main.recipe": recipe_hash,
            "iwantgohome.gitea.main.config": configuration_hash,
        }
        argv = ["docker", "build", "--file", str(dockerfile), "--tag", tag]
        for key in sorted(labels):
            argv.extend(["--label", key + "=" + labels[key]])
        argv.append(str(directory))
        started = self.monotonic()
        build_log = self.runtime_root / ("build-" + source["commit"][:12] + ".log")
        success = False
        stdout = ""
        stderr = ""
        try:
            completed = self.runner.run(
                argv,
                cwd=directory,
                timeout=7200,
                env=dict(os.environ),
            )
            stdout, stderr = completed.stdout, completed.stderr
            success = True
        except (OSError, subprocess.SubprocessError) as error:
            stdout = getattr(error, "stdout", "") or ""
            stderr = getattr(error, "stderr", "") or ""
        elapsed = max(0.0, self.monotonic() - started)
        _private_text(build_log, _sanitized_build_log(stdout, stderr))
        if not success:
            self.build_cache.write({
                "cache_key": cache_key,
                "commit": source["commit"],
                "recipe_hash": recipe_hash,
                "configuration_hash": configuration_hash,
                "image_tag": tag,
                "success": False,
                "build_timestamp": self.now(),
                "build_log_path": str(build_log.relative_to(self.root)),
                "build_elapsed_seconds": round(elapsed, 3),
            })
            raise LocalTargetError("MAIN_BUILD_FAILED")
        inspected = self._inspect_image(tag, source["commit"], recipe_hash, configuration_hash)
        if inspected is None:
            self.build_cache.write({
                "cache_key": cache_key,
                "commit": source["commit"],
                "recipe_hash": recipe_hash,
                "configuration_hash": configuration_hash,
                "image_tag": tag,
                "success": False,
                "build_completed": True,
                "build_timestamp": self.now(),
                "build_log_path": str(build_log.relative_to(self.root)),
                "build_elapsed_seconds": round(elapsed, 3),
            })
            raise LocalTargetError("MAIN_IMAGE_IDENTITY_FAILED")
        self._build = {
            "cache_key": cache_key,
            "commit": source["commit"],
            "recipe_hash": recipe_hash,
            "configuration_hash": configuration_hash,
            "image_tag": tag,
            **inspected,
            "success": True,
            "cache_hit": False,
            "build_timestamp": self.now(),
            "build_log_path": str(build_log.relative_to(self.root)),
            "build_elapsed_seconds": round(elapsed, 3),
        }
        self.build_cache.write(self._build)
        return self._build

    def _read_cache(self) -> dict[str, Any] | None:
        return self.build_cache.read()

    def _inspect_image(
        self, tag: str, commit: str, recipe_hash: str, configuration_hash: str,
    ) -> dict[str, str | None] | None:
        if not _IMAGE_TAG.fullmatch(tag):
            raise LocalTargetError("MAIN_IMAGE_IDENTITY_FAILED")
        try:
            output = self.runner.run(
                ["docker", "image", "inspect", tag],
                cwd=self.root,
                timeout=15,
                env=dict(os.environ),
            ).stdout
            values = json.loads(output)
        except (OSError, subprocess.SubprocessError, ValueError, TypeError):
            return None
        return immutable_image_identity(values, expected_labels={
            "iwantgohome.gitea.main.commit": commit,
            "iwantgohome.gitea.main.recipe": recipe_hash,
            "iwantgohome.gitea.main.config": configuration_hash,
        })

    def _blocked_record(self, candidate_id: str, reason: str) -> dict[str, Any]:
        reason = _FAILURE_MODEL.normalize(reason)
        source = self._source or {}
        cached = self._read_cache() or {}
        build = self._build or (
            cached
            if cached.get("success") is False and cached.get("commit") == source.get("commit")
            else {}
        )
        return {
            "target": "main",
            "version": None,
            "commit": source.get("commit"),
            "digest": build.get("repo_digest") or build.get("image_id"),
            "runtime_id": MAIN_RUNTIME_ID,
            "endpoint": MAIN_ENDPOINT,
            "isolated": True,
            "result": "RETEST_BLOCKED",
            "control_passed": False,
            "evidence_ids": [],
            "blocked_reason": reason,
            "source_branch": source.get("branch"),
            "source_repository": source.get("repository"),
            "source_fetched_at": source.get("fetched_at"),
            "image_tag": build.get("image_tag"),
            "image_id": build.get("image_id"),
            "build_timestamp": build.get("build_timestamp"),
            "build_log_path": build.get("build_log_path"),
            "build_elapsed_seconds": build.get("build_elapsed_seconds"),
            "build_cache_hit": build.get("cache_hit", False),
            "runtime_host": MAIN_RUNTIME_HOST,
            "bootstrap_status": self._bootstrap_status,
            "control_result": "blocked",
            "candidate_result": "blocked",
            "candidate_id": candidate_id,
        }

    def _ensure_runtime(self) -> None:
        if self._adapter is not None or self._failure is not None:
            return
        try:
            source = self.resolve_source()
            build = self.ensure_image(source)
        except LocalTargetError as error:
            self._failure = error.code if error.code in MAIN_FAILURE_REASONS else "MAIN_RUNTIME_FAILED"
            return
        try:
            adapter = self.adapter_factory(
                self.root,
                self.manifest,
                runner=self.runner,
                sleep=self.sleep,
                runtime_variant="main",
                runtime_port=MAIN_PORT,
                runtime_version="main",
                runtime_image_reference=build["image_tag"],
                runtime_image_digest=build["image_id"],
                runtime_image_id=build["image_id"],
                runtime_source_root=self.root / source["source_directory"],
                runtime_source_commit=source["commit"],
                compose_project=MAIN_COMPOSE_PROJECT,
            )
            self._adapter = adapter
            lifecycle = IsolatedRuntimeLifecycle(
                port_in_use=self.port_in_use,
                owned_healthy=lambda: bool(adapter.health(timeout=0.5).get("healthy")),
                start=lambda: adapter.up(progress=lambda _: None),
                bootstrap=lambda: adapter.bootstrap(),
                stop=lambda: adapter.stop(),
            )
            try:
                self._bootstrap_status = lifecycle.prepare()
            except LocalTargetError as error:
                self._bootstrap_status = (
                    "not_started" if error.code in {"RUNTIME_PORT_CONFLICT", "RUNTIME_START_FAILED"}
                    else "blocked"
                )
                self._failure = {
                    "RUNTIME_PORT_CONFLICT": "MAIN_PORT_CONFLICT",
                    "RUNTIME_START_FAILED": "MAIN_RUNTIME_FAILED",
                    "RUNTIME_API_INCOMPATIBLE": "MAIN_API_INCOMPATIBLE",
                    "RUNTIME_BOOTSTRAP_FAILED": "MAIN_BOOTSTRAP_FAILED",
                }.get(error.code, "MAIN_RUNTIME_FAILED")
                return
        except (KeyError, TypeError, ValueError):
            self._failure = "MAIN_IMAGE_IDENTITY_FAILED"

    def retest(self, candidate: dict[str, Any]) -> dict[str, Any]:
        candidate_id = candidate.get("candidate_id")
        baseline = candidate.get("baseline_candidate")
        if candidate_id not in MAIN_RETEST_CANDIDATES or baseline not in {"G04", "G08"}:
            raise LocalTargetError("invalid_main_retest_candidate")
        self._ensure_runtime()
        if self._failure or self._adapter is None:
            return self._blocked_record(candidate_id, self._failure or "MAIN_RUNTIME_FAILED")
        if baseline not in self._results:
            try:
                values = self._adapter.validate(baseline)
                result = values[0] if len(values) == 1 else None
            except LocalTargetError:
                result = None
            if not isinstance(result, dict):
                self._failure = "MAIN_API_INCOMPATIBLE"
                return self._blocked_record(candidate_id, self._failure)
            self._results[baseline] = result
        result = self._results[baseline]
        control_passed = result.get("assertions", {}).get("control_passed") is True
        if not control_passed:
            return self._blocked_record(candidate_id, "MAIN_CONTROL_FAILED")
        if result.get("status") == "VERIFIED_LOCAL":
            outcome = "AFFECTED"
            candidate_result = "security_invariant_violation_reproduced"
        elif result.get("status") == "INTENDED_BEHAVIOR":
            outcome = "INTENDED_BEHAVIOR"
            candidate_result = "candidate_behavior_not_reproduced"
        else:
            return self._blocked_record(candidate_id, "MAIN_API_INCOMPATIBLE")
        assert self._source is not None and self._build is not None
        return {
            "target": "main",
            "version": None,
            "commit": self._source["commit"],
            "digest": self._build.get("repo_digest") or self._build["image_id"],
            "runtime_id": MAIN_RUNTIME_ID,
            "endpoint": MAIN_ENDPOINT,
            "isolated": True,
            "result": outcome,
            "control_passed": True,
            "evidence_ids": [
                result[key] for key in ("evidence", "reassessment")
                if isinstance(result.get(key), str)
            ],
            "source_branch": self._source["branch"],
            "source_repository": self._source["repository"],
            "source_fetched_at": self._source["fetched_at"],
            "image_tag": self._build["image_tag"],
            "image_id": self._build["image_id"],
            "build_timestamp": self._build["build_timestamp"],
            "build_log_path": self._build["build_log_path"],
            "build_elapsed_seconds": self._build["build_elapsed_seconds"],
            "build_cache_hit": self._build["cache_hit"],
            "runtime_host": MAIN_RUNTIME_HOST,
            "bootstrap_status": self._bootstrap_status,
            "control_result": "passed",
            "candidate_result": candidate_result,
            "candidate_id": candidate_id,
        }

    def stop(self) -> None:
        if self._adapter is not None:
            try:
                self._adapter.stop()
            except LocalTargetError:
                pass
