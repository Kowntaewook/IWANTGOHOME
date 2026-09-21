"""Fixed local-target adapter interface and shared safety primitives."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
import json
import os
from pathlib import Path
import re
import subprocess
from typing import Any, Callable, Sequence
from urllib.parse import urlsplit


TARGET_ID = re.compile(r"[a-z0-9][a-z0-9_-]{0,63}\Z")


class LocalTargetError(Exception):
    """Stable public failure code with no command, response body, or secret."""

    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


@dataclass(frozen=True)
class LocalTargetManifest:
    target_id: str
    repository: str
    revision: str
    host_health_url: str


class FixedCommandRunner:
    """Run code-owned argv arrays without a shell."""

    def run(
        self,
        argv: Sequence[str],
        *,
        cwd: Path,
        timeout: float,
        env: dict[str, str] | None = None,
        capture_output: bool = True,
    ) -> subprocess.CompletedProcess[str]:
        if not argv or not all(isinstance(value, str) and value for value in argv):
            raise LocalTargetError("invalid_fixed_command")
        return subprocess.run(
            list(argv),
            cwd=cwd,
            timeout=timeout,
            check=True,
            capture_output=capture_output,
            text=True,
            env=env,
            shell=False,
        )


class LocalTargetAdapter(ABC):
    target_id: str
    repository: str
    pinned_revision: str
    host_health_url: str
    supported_candidates: frozenset[str]

    @abstractmethod
    def prepare(self) -> dict[str, Any]: ...

    @abstractmethod
    def up(self, progress: Callable[[str], None] = print) -> dict[str, Any]: ...

    @abstractmethod
    def health(self, timeout: float = 2.0) -> dict[str, Any]: ...

    @abstractmethod
    def bootstrap(self) -> dict[str, Any]: ...

    @abstractmethod
    def validate(self, candidate: str | None = None) -> list[dict[str, Any]]: ...

    @abstractmethod
    def stop(self) -> dict[str, Any]: ...

    @abstractmethod
    def reset(self) -> dict[str, Any]: ...

    @abstractmethod
    def status(self) -> dict[str, Any]: ...

    def hunt(self) -> dict[str, Any]:
        raise LocalTargetError("HUNT_UNAVAILABLE")

    def full_hunt(self) -> dict[str, Any]:
        raise LocalTargetError("FULL_HUNT_UNAVAILABLE")


def load_manifest(root: Path, target_id: str) -> LocalTargetManifest:
    if not TARGET_ID.fullmatch(target_id):
        raise LocalTargetError("invalid_local_target")
    path = root / "config" / "local-targets" / (target_id + ".json")
    try:
        if path.is_symlink() or path.stat().st_size > 4096:
            raise LocalTargetError("invalid_local_target_manifest")
        data = json.loads(path.read_text(encoding="utf-8"))
    except LocalTargetError:
        raise
    except (OSError, ValueError, TypeError):
        raise LocalTargetError("invalid_local_target_manifest") from None
    expected = {"target_id", "repository", "revision", "host_health_url"}
    if not isinstance(data, dict) or set(data) != expected or not all(isinstance(data[k], str) for k in expected):
        raise LocalTargetError("invalid_local_target_manifest")
    if data["target_id"] != target_id or not re.fullmatch(r"[0-9a-f]{40}", data["revision"]):
        raise LocalTargetError("invalid_local_target_manifest")
    health = urlsplit(data["host_health_url"])
    if (health.scheme != "http" or health.hostname not in {"127.0.0.1", "localhost", "::1"}
            or health.username is not None or health.password is not None or health.fragment):
        raise LocalTargetError("invalid_local_target_manifest")
    return LocalTargetManifest(**data)


def secure_directory(path: Path, mode: int = 0o700) -> Path:
    """Create a private operator directory and reject symlink ancestors in scope."""
    pending: list[Path] = []
    current = path
    while not current.exists():
        pending.append(current)
        current = current.parent
    if current.is_symlink() or not current.is_dir():
        raise LocalTargetError("unsafe_local_path")
    for item in reversed(pending):
        item.mkdir(mode=mode)
    if path.is_symlink() or not path.is_dir():
        raise LocalTargetError("unsafe_local_path")
    os.chmod(path, mode)
    return path


def atomic_private_json(path: Path, value: dict[str, Any]) -> None:
    secure_directory(path.parent)
    temp = path.parent / (".pending-" + os.urandom(8).hex())
    raw = json.dumps(value, ensure_ascii=True, sort_keys=True).encode("utf-8")
    try:
        with temp.open("xb") as handle:
            os.chmod(temp, 0o600)
            handle.write(raw)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp, path)
        os.chmod(path, 0o600)
    finally:
        temp.unlink(missing_ok=True)


def run_confined_git(
    runner: FixedCommandRunner,
    targets_root: Path,
    argv: Sequence[str],
    *,
    cwd: Path,
    timeout: float = 30,
) -> subprocess.CompletedProcess[str]:
    """Run Git with extensions disabled inside the adapter-owned target root."""
    resolved = cwd.resolve()
    confined_root = targets_root.resolve()
    if resolved != confined_root and confined_root not in resolved.parents:
        raise LocalTargetError("unsafe_git_directory")
    env = dict(os.environ)
    env.update({
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_SYSTEM": os.devnull,
        "GIT_TERMINAL_PROMPT": "0",
    })
    try:
        return runner.run(
            ["git", "-c", "core.hooksPath=/dev/null", "-c", "credential.helper=", *argv],
            cwd=resolved,
            timeout=timeout,
            env=env,
        )
    except (OSError, subprocess.SubprocessError):
        raise LocalTargetError("SOURCE_ACQUIRE_FAILED") from None


def repository_origin_matches(value: str, expected: str) -> bool:
    return value.strip().rstrip("/").removesuffix(".git") == expected


def reject_active_git_extensions(repository: Path) -> None:
    """Reject repository-local hooks, filters, includes, credentials, and SSH commands."""
    config = repository / ".git" / "config"
    try:
        if config.is_symlink() or config.stat().st_size > 128 * 1024:
            raise LocalTargetError("REPOSITORY_MISMATCH")
        text = config.read_text(encoding="utf-8")
    except LocalTargetError:
        raise
    except OSError:
        raise LocalTargetError("REPOSITORY_MISMATCH") from None
    if re.search(
        r"(?im)^\s*\[(?:credential|filter|include|includeif)\b|"
        r"^\s*(?:fsmonitor|hookspath|sshcommand|credential)\s*=",
        text,
    ):
        raise LocalTargetError("REPOSITORY_MISMATCH")


def load_adapter(
    root: Path,
    target_id: str | None,
    *,
    runner: FixedCommandRunner | None = None,
) -> LocalTargetAdapter:
    if target_id not in {"mattermost", "gitea"}:
        raise LocalTargetError("invalid_local_target")
    manifest = load_manifest(root, target_id)
    # The manifest is metadata only. Code pins these values independently so a
    # changed JSON file can never redirect clone or network operations.
    from .gitea import GiteaAdapter
    from .mattermost import MattermostAdapter

    registry: dict[str, type[LocalTargetAdapter]] = {
        "mattermost": MattermostAdapter,
        "gitea": GiteaAdapter,
    }
    adapter_type = registry[target_id]
    if (manifest.target_id != adapter_type.target_id
            or manifest.repository != adapter_type.repository
            or manifest.revision != adapter_type.pinned_revision
            or manifest.host_health_url != adapter_type.host_health_url):
        raise LocalTargetError("invalid_local_target_manifest")
    return adapter_type(root, manifest, runner=runner)
