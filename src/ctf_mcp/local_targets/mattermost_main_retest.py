"""Immutable upstream-main source and image preparation for Mattermost retests."""

from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path
import re
import shutil
import subprocess
from typing import Any, Callable

from ctf_mcp.full_hunt.schema import SourceIdentity
from ctf_mcp.full_hunt.version_retest import (
    ImmutableBuildCache,
    ImmutableGitSourceResolver,
    SourceResolutionFailures,
    configuration_hash,
    content_hash,
    immutable_build_cache_key,
    immutable_image_identity,
)

from .base import FixedCommandRunner, LocalTargetError, secure_directory


REPOSITORY = "https://github.com/mattermost/mattermost"
MAIN_BRANCH = "main"
MAIN_PORT = 13102
MAIN_ENDPOINT = f"127.0.0.1:{MAIN_PORT}"
MAIN_RUNTIME_ID = "mattermost-main-13102"
MAIN_BUILD_BASE = "docker.io/library/golang:1.26.7-alpine3.22"
MAIN_RUNTIME_BASE = "docker.io/library/alpine:3.22"
MAIN_BUILD_RECIPE = b"""ARG BUILD_BASE
ARG RUNTIME_BASE
FROM ${BUILD_BASE} AS builder
COPY server /src/server
WORKDIR /src/server
RUN CGO_ENABLED=0 go build -trimpath -tags sourceavailable -o /out/mattermost ./cmd/mattermost
FROM ${RUNTIME_BASE}
RUN addgroup -g 2000 mattermost && adduser -D -u 2000 -G mattermost mattermost && mkdir -p /mattermost/data && chown -R mattermost:mattermost /mattermost
COPY --from=builder --chown=2000:2000 /out/mattermost /mattermost/bin/mattermost
USER mattermost
WORKDIR /mattermost
EXPOSE 8065
ENTRYPOINT [\"/mattermost/bin/mattermost\"]
"""


class MattermostMainRetest:
    """Resolve main to a SHA and build an identity-checked local image.

    Runtime validation remains separately gated.  A successful image build
    alone never produces an affected or fixed result.
    """

    def __init__(
        self,
        root: Path,
        *,
        runner: FixedCommandRunner | None = None,
        now: Callable[[], str] | None = None,
    ):
        self.root = root.resolve()
        self.runner = runner or FixedCommandRunner()
        self.now = now or (lambda: datetime.now(timezone.utc).isoformat())
        self.targets_root = self.root / ".operator/targets"
        self.source_root = self.targets_root / "mattermost-main"
        self.runtime_root = self.root / ".operator/local-runtime/mattermost-main"
        self.secret_root = self.root / ".operator/local-secrets/mattermost-main"
        self.evidence_root = self.root / ".operator/local-evidence/mattermost-main"
        self.recipe_file = self.runtime_root / "Dockerfile.main"
        self.cache = ImmutableBuildCache(self.runtime_root / "build-cache.json")
        self.resolver = ImmutableGitSourceResolver(
            root=self.root,
            targets_root=self.targets_root,
            source_root=self.source_root,
            repository=REPOSITORY,
            branch=MAIN_BRANCH,
            runner=self.runner,
            now=self.now,
            required_files=("server/go.mod", "server/channels/api4/user.go"),
            failures=SourceResolutionFailures("MAIN_SOURCE_FETCH_FAILED", "MAIN_COMMIT_UNRESOLVED"),
        )

    @staticmethod
    def supports(candidate: dict[str, Any]) -> bool:
        return (
            candidate.get("baseline_candidate") in {"S12", "S13"}
            and candidate.get("route", {}).get("method") == "GET"
        )

    def resolve_source(self) -> SourceIdentity:
        value = self.resolver.resolve()
        return SourceIdentity(
            repository=value["repository"], revision=value["commit"],
            fetched_at=value["fetched_at"], branch=value["branch"],
            directory=self.root / value["source_directory"],
        )

    def prepare_image(self, source: SourceIdentity) -> dict[str, Any]:
        if source.branch != MAIN_BRANCH or source.directory is None:
            raise LocalTargetError("MAIN_COMMIT_UNRESOLVED")
        if shutil.which("docker") is None:
            raise LocalTargetError("MAIN_DOCKER_UNAVAILABLE")
        secure_directory(self.runtime_root)
        secure_directory(self.secret_root)
        secure_directory(self.evidence_root)
        _write_exact(self.recipe_file, MAIN_BUILD_RECIPE)
        build_base = self._immutable_base(MAIN_BUILD_BASE)
        runtime_base = self._immutable_base(MAIN_RUNTIME_BASE)
        recipe_hash = content_hash(MAIN_BUILD_RECIPE, "mattermost-main-source-build-v1")
        config_hash = configuration_hash({
            "endpoint": MAIN_ENDPOINT,
            "build_base": build_base,
            "runtime_base": runtime_base,
            "recipe_version": 1,
        })
        image_tag = "iwantgohome/mattermost-main:" + source.revision[:12]
        labels = {
            "org.iwantgohome.target": "mattermost-main",
            "org.iwantgohome.commit": source.revision,
            "org.iwantgohome.recipe": recipe_hash,
            "org.iwantgohome.configuration": config_hash,
        }
        inspected = lambda: self._inspect_image(image_tag, labels)
        cached = self.cache.matching(
            commit=source.revision, recipe_hash=recipe_hash,
            configuration_hash=config_hash, image_tag=image_tag, inspect=inspected,
        )
        if cached:
            return cached
        argv = [
            "docker", "build", "--pull=false", "--network=default",
            "--file", str(self.recipe_file), "--tag", image_tag,
            "--build-arg", "BUILD_BASE=" + build_base,
            "--build-arg", "RUNTIME_BASE=" + runtime_base,
        ]
        for key, value in labels.items():
            argv.extend(("--label", key + "=" + value))
        argv.append(str(source.directory))
        try:
            self.runner.run(argv, cwd=self.runtime_root, timeout=3600)
        except (OSError, subprocess.SubprocessError):
            raise LocalTargetError("MAIN_BUILD_FAILED") from None
        identity = inspected()
        if identity is None:
            raise LocalTargetError("MAIN_IMAGE_IDENTITY_FAILED")
        value = {
            "cache_key": immutable_build_cache_key(source.revision, recipe_hash, config_hash),
            "commit": source.revision, "recipe_hash": recipe_hash,
            "configuration_hash": config_hash, "image_tag": image_tag,
            "image_id": identity["image_id"], "repo_digest": identity["repo_digest"],
            "build_base": build_base, "runtime_base": runtime_base,
            "success": True, "built_at": self.now(),
        }
        self.cache.write(value)
        return {**value, "cache_hit": False}

    def retest(self, candidate: dict[str, Any]) -> dict[str, Any]:
        commit = digest = None
        reason = "MAIN_RUNTIME_FAILED"
        try:
            source = self.resolve_source()
            commit = source.revision
            image = self.prepare_image(source)
            digest = image["image_id"]
            # The runtime/bootstrap validator is a separate gate; image success
            # cannot be interpreted as a behavior result.
            reason = "MAIN_RUNTIME_FAILED"
        except LocalTargetError as error:
            reason = error.code
        return {
            "target": "main", "version": None, "commit": commit, "digest": digest,
            "runtime_id": MAIN_RUNTIME_ID, "endpoint": MAIN_ENDPOINT, "isolated": True,
            "result": "RETEST_BLOCKED", "control_passed": False, "evidence_ids": [],
            "blocked_reason": reason, "candidate_id": candidate.get("candidate_id"),
        }

    def _immutable_base(self, reference: str) -> str:
        try:
            self.runner.run(["docker", "pull", reference], cwd=self.runtime_root, timeout=1800)
            result = self.runner.run(
                ["docker", "image", "inspect", reference], cwd=self.runtime_root, timeout=30,
            )
            value = json.loads(result.stdout)
        except (OSError, subprocess.SubprocessError, TypeError, ValueError):
            raise LocalTargetError("MAIN_BUILD_BASE_FAILED") from None
        if not isinstance(value, list) or len(value) != 1 or not isinstance(value[0], dict):
            raise LocalTargetError("MAIN_BUILD_BASE_FAILED")
        for item in value[0].get("RepoDigests") or []:
            if isinstance(item, str) and re.fullmatch(r"[^@]+@sha256:[0-9a-f]{64}", item):
                return item
        raise LocalTargetError("MAIN_BUILD_BASE_FAILED")

    def _inspect_image(self, tag: str, labels: dict[str, str]) -> dict[str, Any] | None:
        try:
            result = self.runner.run(
                ["docker", "image", "inspect", tag], cwd=self.runtime_root, timeout=30,
            )
            value = json.loads(result.stdout)
        except (OSError, subprocess.SubprocessError, TypeError, ValueError):
            return None
        return immutable_image_identity(value, expected_labels=labels)


def _write_exact(path: Path, content: bytes) -> None:
    if path.exists() or path.is_symlink():
        try:
            if path.is_symlink() or path.read_bytes() != content:
                raise LocalTargetError("unsafe_local_runtime")
        except OSError:
            raise LocalTargetError("unsafe_local_runtime") from None
        return
    path.write_bytes(content)
    path.chmod(0o600)
