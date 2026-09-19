"""Mattermost adapter pinned to one reviewed upstream revision."""

from __future__ import annotations

from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import subprocess
import time
from typing import Any, Callable

from ctf_mcp.records import Records

from .base import (
    FixedCommandRunner,
    LocalTargetAdapter,
    LocalTargetError,
    LocalTargetManifest,
    atomic_private_json,
    secure_directory,
)
from .http import LocalMattermostClient, LocalResponse


SYNTHETIC_PREFIX = "finder-local-"
SYNTHETIC_MESSAGE = "PRIVATE_S12_TEST_MESSAGE"
SYNTHETIC_DM_MESSAGE = "PRIVATE_S12_DM_TEST_MESSAGE"
MATTERMOST_ID = re.compile(r"[a-z0-9]{26}\Z")
CANDIDATES = {
    "S12": "0d113880df784ab4b98d13c72d2ec2eb",
    "S13": "baf0a7d684584d45956dc16dc6a93f1c",
    "S15": "67695a713fc9486eafc96d41f8b3e6f6",
}
REQUEST_BUDGETS = {"S12": 8, "S13": 5, "S15": 5}
ENTERPRISE_IMAGE = "mattermostdevelopment/mattermost-enterprise-edition:d283cc6"
ENTERPRISE_IMAGE_DIGEST = "sha256:3c11c93b5f75b4e9bc407711d6ad345c0072cff520e34ffc0e99238a507daeb1"
ENTERPRISE_IMAGE_REFERENCE = ENTERPRISE_IMAGE + "@" + ENTERPRISE_IMAGE_DIGEST
ENTERPRISE_PLATFORM = "linux/amd64"
COMPOSE_PROJECT = "iwantgohome-local-mattermost"
COMPOSE = f"""name: iwantgohome-local-mattermost
services:
  postgres:
    image: postgres:15
    restart: "no"
    environment:
      POSTGRES_USER: mmuser
      POSTGRES_PASSWORD: ${{FINDER_LOCAL_DB_PASSWORD:?local database password required}}
      POSTGRES_DB: mattermost_test
      POSTGRES_INITDB_ARGS: --auth-host=scram-sha-256 --auth-local=scram-sha-256
    ports:
      - 127.0.0.1:55432:5432
    volumes:
      - mattermost-postgres-data:/var/lib/postgresql/data
    healthcheck:
      test: [CMD, pg_isready, -U, mmuser, -d, mattermost_test]
      interval: 2s
      timeout: 5s
      retries: 60
    networks: [local-target-internal]
    security_opt: [no-new-privileges:true]
  mattermost:
    image: {ENTERPRISE_IMAGE_REFERENCE}
    platform: {ENTERPRISE_PLATFORM}
    restart: "no"
    depends_on:
      postgres:
        condition: service_healthy
    environment:
      MM_SQLSETTINGS_DRIVERNAME: postgres
      MM_SQLSETTINGS_DATASOURCE: "postgres://mmuser:${{FINDER_LOCAL_DB_PASSWORD:?local database password required}}@postgres:5432/mattermost_test?sslmode=disable&connect_timeout=10"
      MM_SERVICESETTINGS_SITEURL: http://127.0.0.1:8065
      MM_SERVICESETTINGS_LISTENADDRESS: ":8065"
      MM_SERVICESETTINGS_ENABLELOCALMODE: "true"
      MM_TEAMSETTINGS_ENABLEOPENSERVER: "true"
      MM_PLUGINSETTINGS_ENABLE: "false"
      MM_PLUGINSETTINGS_ENABLEUPLOADS: "false"
      MM_EMAILSETTINGS_SENDEMAILNOTIFICATIONS: "false"
      MM_FILESETTINGS_DIRECTORY: /mattermost/data
      MM_LOGSETTINGS_ENABLECONSOLE: "true"
      MM_LOGSETTINGS_ENABLEFILE: "false"
    ports:
      - 127.0.0.1:8065:8065
    volumes:
      - ./data:/mattermost/data
    networks: [local-target-internal]
    security_opt: [no-new-privileges:true]
volumes:
  mattermost-postgres-data: {{}}
networks:
  local-target-internal:
    driver: bridge
"""


class MattermostAdapter(LocalTargetAdapter):
    target_id = "mattermost"
    repository = "https://github.com/mattermost/mattermost"
    pinned_revision = "d283cc6301368f6e3dc0fa6be0a1537a9677750b"
    host_health_url = "http://127.0.0.1:8065/api/v4/system/ping"

    def __init__(
        self,
        root: Path,
        manifest: LocalTargetManifest,
        *,
        runner: FixedCommandRunner | None = None,
        client_factory: Callable[..., LocalMattermostClient] = LocalMattermostClient,
        sleep: Callable[[float], None] = time.sleep,
    ):
        self.root = root.resolve()
        self.manifest = manifest
        self.runner = runner or FixedCommandRunner()
        self.client_factory = client_factory
        self.sleep = sleep
        self.operator = self.root / ".operator"
        self.targets_root = self.operator / "targets"
        self.target_root = self.targets_root / self.target_id
        self.server_root = self.target_root / "server"
        self.runtime_root = self.operator / "local-runtime" / self.target_id
        self.secret_root = self.operator / "local-secrets" / self.target_id
        self.evidence_root = self.operator / "local-evidence" / self.target_id
        self.compose_file = self.runtime_root / "compose.yaml"
        self.bootstrap_file = self.runtime_root / "bootstrap.json"
        self.secrets_file = self.secret_root / "secrets.json"

    # ----- source acquisition -------------------------------------------------
    def _git(self, argv: list[str], cwd: Path, timeout: float = 30) -> subprocess.CompletedProcess[str]:
        resolved = cwd.resolve()
        targets = self.targets_root.resolve()
        if resolved != targets and targets not in resolved.parents:
            raise LocalTargetError("unsafe_git_directory")
        try:
            env = dict(os.environ)
            env.update({"GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_SYSTEM": os.devnull, "GIT_TERMINAL_PROMPT": "0"})
            return self.runner.run(["git", "-c", "core.hooksPath=/dev/null", "-c", "credential.helper=", *argv],
                                   cwd=resolved, timeout=timeout, env=env)
        except (OSError, subprocess.SubprocessError):
            raise LocalTargetError("SOURCE_ACQUIRE_FAILED") from None

    @staticmethod
    def _origin_matches(value: str) -> bool:
        return value.strip().rstrip("/").removesuffix(".git") == MattermostAdapter.repository

    @staticmethod
    def _reject_active_git_extensions(repository: Path) -> None:
        config = repository / ".git" / "config"
        try:
            if config.is_symlink() or config.stat().st_size > 128 * 1024:
                raise LocalTargetError("REPOSITORY_MISMATCH")
            text = config.read_text(encoding="utf-8")
        except LocalTargetError:
            raise
        except OSError:
            raise LocalTargetError("REPOSITORY_MISMATCH") from None
        if re.search(r"(?im)^\s*\[(?:filter|include|includeif)\b|^\s*(?:fsmonitor|hookspath|sshcommand|credential)\s*=", text):
            raise LocalTargetError("REPOSITORY_MISMATCH")

    def _source_details(self, timeout: float = 0.75) -> dict[str, Any]:
        git_dir = self.target_root / ".git"
        if self.target_root.is_symlink() or not self.target_root.is_dir() or git_dir.is_symlink() or not git_dir.is_dir():
            return {"prepared": False, "actual_commit": None, "origin_ok": False, "source_status": "SOURCE_NOT_PREPARED"}
        try:
            origin = self._git(["remote", "get-url", "origin"], self.target_root, timeout).stdout.strip()
            head = self._git(["rev-parse", "HEAD"], self.target_root, timeout).stdout.strip()
        except LocalTargetError:
            return {"prepared": True, "actual_commit": None, "origin_ok": False, "source_status": "SOURCE_VALIDATION_FAILED"}
        origin_ok = self._origin_matches(origin)
        revision_ok = head == self.pinned_revision
        code = "READY" if origin_ok and revision_ok else ("REVISION_MISMATCH" if origin_ok else "REPOSITORY_MISMATCH")
        return {"prepared": True, "actual_commit": head, "origin_ok": origin_ok, "source_status": code}

    def _require_source(self) -> None:
        state = self._source_details(2)
        if not state["prepared"]:
            raise LocalTargetError("SOURCE_NOT_PREPARED")
        if not state["origin_ok"]:
            raise LocalTargetError("REPOSITORY_MISMATCH")
        if state["actual_commit"] != self.pinned_revision:
            raise LocalTargetError("REVISION_MISMATCH")
        module = self.server_root / "go.mod"
        if self.server_root.is_symlink() or module.is_symlink() or not module.is_file():
            raise LocalTargetError("SOURCE_NOT_PREPARED")
        self._reject_active_git_extensions(self.target_root)
        if self._git(["status", "--porcelain", "--untracked-files=normal"], self.target_root, 10).stdout.strip():
            raise LocalTargetError("SOURCE_DIRTY")

    def prepare(self) -> dict[str, Any]:
        secure_directory(self.targets_root)
        if self.target_root.exists() or self.target_root.is_symlink():
            git_dir = self.target_root / ".git"
            if self.target_root.is_symlink() or not self.target_root.is_dir() or git_dir.is_symlink() or not git_dir.is_dir():
                raise LocalTargetError("REPOSITORY_MISMATCH")
            self._reject_active_git_extensions(self.target_root)
            origin = self._git(["remote", "get-url", "origin"], self.target_root).stdout.strip()
            if not self._origin_matches(origin):
                raise LocalTargetError("REPOSITORY_MISMATCH")
            try:
                self._git(["cat-file", "-e", self.pinned_revision + "^{commit}"], self.target_root)
            except LocalTargetError:
                self._git(["fetch", "--depth", "1", "origin", self.pinned_revision], self.target_root, 600)
            if self._git(["rev-parse", "HEAD"], self.target_root).stdout.strip() != self.pinned_revision:
                self._git(["checkout", "--detach", self.pinned_revision], self.target_root, 120)
        else:
            temporary = self.targets_root / (".mattermost-preparing-" + secrets.token_hex(8))
            try:
                self._git(["clone", "--filter=blob:none", "--no-checkout", self.repository, str(temporary)], self.targets_root, 1800)
                self._reject_active_git_extensions(temporary)
                self._git(["checkout", "--detach", self.pinned_revision], temporary, 120)
                if not self._origin_matches(self._git(["remote", "get-url", "origin"], temporary).stdout):
                    raise LocalTargetError("REPOSITORY_MISMATCH")
                if self._git(["rev-parse", "HEAD"], temporary).stdout.strip() != self.pinned_revision:
                    raise LocalTargetError("REVISION_MISMATCH")
                temporary.rename(self.target_root)
            finally:
                if temporary.exists():
                    shutil.rmtree(temporary)
        self._require_source()
        return {"target": self.target_id, "repository": self.repository, "commit": self.pinned_revision, "status": "prepared"}

    # ----- runtime ------------------------------------------------------------
    def _load_secrets(self, create: bool) -> dict[str, Any]:
        if self.secrets_file.exists():
            try:
                if self.secrets_file.is_symlink() or self.secrets_file.stat().st_mode & 0o077:
                    raise LocalTargetError("unsafe_local_secret_store")
                value = json.loads(self.secrets_file.read_text(encoding="utf-8"))
                required = {"database", "system_admin", "delegated_admin", "victim", "normal_user"}
                if not isinstance(value, dict) or set(value) != required or not all(isinstance(value[k], str) and len(value[k]) >= 20 for k in required):
                    raise LocalTargetError("unsafe_local_secret_store")
                return value
            except LocalTargetError:
                raise
            except (OSError, ValueError):
                raise LocalTargetError("unsafe_local_secret_store") from None
        if not create:
            raise LocalTargetError("BOOTSTRAP_FAILED")
        value = {name: _password() for name in ("database", "system_admin", "delegated_admin", "victim", "normal_user")}
        atomic_private_json(self.secrets_file, value)
        return value

    def _write_runtime_files(self, passwords: dict[str, str]) -> None:
        secure_directory(self.runtime_root)
        secure_directory(self.secret_root)
        if not self.compose_file.exists():
            self.compose_file.write_text(COMPOSE, encoding="utf-8")
            os.chmod(self.compose_file, 0o600)
        elif self.compose_file.is_symlink() or self.compose_file.read_text(encoding="utf-8") != COMPOSE:
            raise LocalTargetError("unsafe_local_runtime")
        # The parent remains 0700 host-only. The mounted leaf must be writable by
        # the image's fixed non-root user on both Docker Desktop and Linux.
        secure_directory(self.runtime_root / "data", mode=0o777)

    def _docker_env(self, passwords: dict[str, str] | None = None) -> dict[str, str]:
        env = dict(os.environ)
        env["FINDER_LOCAL_DB_PASSWORD"] = passwords["database"] if passwords else "status-placeholder-not-a-secret"
        return env

    def _compose(self, tail: list[str], *, timeout: float, passwords: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
        try:
            if self.compose_file.is_symlink() or not self.compose_file.is_file():
                raise LocalTargetError("unsafe_local_runtime")
            if self.compose_file.stat().st_size != len(COMPOSE.encode("utf-8")):
                raise LocalTargetError("unsafe_local_runtime")
            if self.compose_file.read_text(encoding="utf-8") != COMPOSE:
                raise LocalTargetError("unsafe_local_runtime")
        except LocalTargetError:
            raise
        except OSError:
            raise LocalTargetError("unsafe_local_runtime") from None
        try:
            return self.runner.run(
                ["docker", "compose", "-p", COMPOSE_PROJECT, "-f", str(self.compose_file), *tail],
                cwd=self.runtime_root,
                timeout=timeout,
                env=self._docker_env(passwords),
            )
        except (OSError, subprocess.SubprocessError):
            code = "DEPENDENCY_START_FAILED" if tail[:1] == ["up"] else "DOCKER_UNAVAILABLE"
            raise LocalTargetError(code) from None

    def _inspect_enterprise_image(self, *, timeout: float, allow_missing: bool) -> dict[str, str] | None:
        try:
            result = self.runner.run(
                ["docker", "image", "inspect", ENTERPRISE_IMAGE_REFERENCE],
                cwd=self.root,
                timeout=timeout,
                env=self._docker_env(),
            )
            value = json.loads(result.stdout)
            if not isinstance(value, list) or len(value) != 1 or not isinstance(value[0], dict):
                raise LocalTargetError("IMAGE_MISMATCH")
            metadata = value[0]
            digests = metadata.get("RepoDigests")
            if metadata.get("Os") != "linux" or metadata.get("Architecture") != "amd64":
                raise LocalTargetError("IMAGE_MISMATCH")
            if not isinstance(digests, list) or not any(
                isinstance(item, str) and item.endswith("@" + ENTERPRISE_IMAGE_DIGEST) for item in digests
            ):
                raise LocalTargetError("IMAGE_MISMATCH")
            return {"digest": ENTERPRISE_IMAGE_DIGEST, "platform": ENTERPRISE_PLATFORM}
        except LocalTargetError:
            raise
        except (OSError, subprocess.SubprocessError, ValueError, TypeError):
            if allow_missing:
                return None
            raise LocalTargetError("IMAGE_MISMATCH") from None

    @staticmethod
    def _validate_enterprise_version(output: str) -> dict[str, str]:
        fields: dict[str, str] = {}
        for line in output.splitlines():
            if ":" in line:
                key, value = line.split(":", 1)
                fields[key.strip()] = value.strip()
        if fields.get("Build Enterprise Ready", "").lower() != "true":
            raise LocalTargetError("ENTERPRISE_RUNTIME_REQUIRED")
        if fields.get("Build Hash") != MattermostAdapter.pinned_revision:
            raise LocalTargetError("IMAGE_MISMATCH")
        return {
            "version": fields.get("Version", "unknown"),
            "build_number": fields.get("Build Number", "unknown"),
            "build_date": fields.get("Build Date", "unknown"),
            "build_hash": fields["Build Hash"],
            "enterprise_ready": fields["Build Enterprise Ready"].lower(),
        }

    def _probe_enterprise_version(self, *, timeout: float = 30) -> dict[str, str]:
        try:
            result = self.runner.run(
                [
                    "docker", "run", "--rm", "--network", "none", "--read-only",
                    "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
                    "--tmpfs", "/tmp:rw,nosuid,nodev,size=16m", "--platform", ENTERPRISE_PLATFORM,
                    "--entrypoint", "/mattermost/bin/mattermost", ENTERPRISE_IMAGE_REFERENCE, "version",
                ],
                cwd=self.root,
                timeout=timeout,
                env=self._docker_env(),
            )
        except (OSError, subprocess.SubprocessError):
            raise LocalTargetError("ENTERPRISE_RUNTIME_REQUIRED") from None
        return self._validate_enterprise_version(result.stdout + "\n" + result.stderr)

    def _ensure_enterprise_image(self, progress: Callable[[str], None]) -> dict[str, str]:
        metadata = self._inspect_enterprise_image(timeout=10, allow_missing=True)
        if metadata is None:
            progress("Local target: pulling exact Enterprise image")
            try:
                self.runner.run(
                    ["docker", "pull", "--platform", ENTERPRISE_PLATFORM, ENTERPRISE_IMAGE_REFERENCE],
                    cwd=self.root,
                    timeout=1800,
                    env=self._docker_env(),
                )
            except (OSError, subprocess.SubprocessError):
                raise LocalTargetError("TARGET_START_FAILED") from None
            self._inspect_enterprise_image(timeout=10, allow_missing=False)
        progress("Local target: verifying Enterprise build")
        return self._probe_enterprise_version()

    def _running_services(self, *, timeout: float, passwords: dict[str, str] | None = None) -> set[str]:
        result = self._compose(["ps", "--status", "running", "--services"], timeout=timeout, passwords=passwords)
        services = set(result.stdout.split())
        if not services <= {"postgres", "mattermost"}:
            raise LocalTargetError("unsafe_local_runtime")
        return services

    def _verify_owned_mattermost_container(self, passwords: dict[str, str]) -> None:
        container = self._compose(["ps", "-q", "mattermost"], timeout=5, passwords=passwords).stdout.split()
        if len(container) != 1 or not re.fullmatch(r"[0-9a-f]{12,64}", container[0]):
            raise LocalTargetError("TARGET_START_FAILED")
        try:
            result = self.runner.run(
                ["docker", "container", "inspect", container[0]],
                cwd=self.root,
                timeout=5,
                env=self._docker_env(),
            )
            value = json.loads(result.stdout)
            if not isinstance(value, list) or len(value) != 1 or not isinstance(value[0], dict):
                raise LocalTargetError("TARGET_START_FAILED")
            config = value[0].get("Config")
            labels = config.get("Labels") if isinstance(config, dict) else None
            state = value[0].get("State")
            if not isinstance(labels, dict) or labels.get("com.docker.compose.project") != COMPOSE_PROJECT:
                raise LocalTargetError("TARGET_START_FAILED")
            if labels.get("com.docker.compose.service") != "mattermost":
                raise LocalTargetError("TARGET_START_FAILED")
            if config.get("Image") != ENTERPRISE_IMAGE_REFERENCE:
                raise LocalTargetError("IMAGE_MISMATCH")
            if not isinstance(state, dict) or state.get("Running") is not True:
                raise LocalTargetError("TARGET_START_FAILED")
        except LocalTargetError:
            raise
        except (OSError, subprocess.SubprocessError, ValueError, TypeError, AttributeError):
            raise LocalTargetError("TARGET_START_FAILED") from None

    def _stop_services(self) -> None:
        if self.compose_file.is_file() and shutil.which("docker"):
            try:
                self._compose(["stop", "mattermost", "postgres"], timeout=60)
            except LocalTargetError:
                pass

    def _require_active_enterprise_runtime(self, passwords: dict[str, str]) -> None:
        if shutil.which("docker") is None or not self.compose_file.is_file():
            raise LocalTargetError("ENTERPRISE_RUNTIME_REQUIRED")
        self._inspect_enterprise_image(timeout=10, allow_missing=False)
        running = self._running_services(timeout=5, passwords=passwords)
        if not {"mattermost", "postgres"} <= running:
            raise LocalTargetError("ENTERPRISE_RUNTIME_REQUIRED")
        self._verify_owned_mattermost_container(passwords)
        self._probe_enterprise_version()

    def health(self, timeout: float = 2.0) -> dict[str, Any]:
        try:
            response = self.client_factory(timeout=timeout).request("health", "GET", "/api/v4/system/ping", count=False)
            ok = response.status == 200 and isinstance(response.data, dict) and response.data.get("status") == "OK"
            return {"healthy": ok, "status": "healthy" if ok else "unhealthy", "status_code": response.status}
        except LocalTargetError:
            return {"healthy": False, "status": "unreachable", "status_code": None}

    def up(self, progress: Callable[[str], None] = print) -> dict[str, Any]:
        self._require_source()
        if shutil.which("docker") is None:
            raise LocalTargetError("DOCKER_UNAVAILABLE")
        passwords = self._load_secrets(create=True)
        self._write_runtime_files(passwords)
        progress("Local target: validating Docker")
        try:
            self.runner.run(["docker", "version"], cwd=self.runtime_root, timeout=15, env=self._docker_env(passwords))
            self.runner.run(["docker", "compose", "version"], cwd=self.runtime_root, timeout=15, env=self._docker_env(passwords))
        except (OSError, subprocess.SubprocessError):
            raise LocalTargetError("DOCKER_UNAVAILABLE") from None
        version = self._ensure_enterprise_image(progress)
        running = self._running_services(timeout=5, passwords=passwords)
        if self.health(timeout=0.4)["healthy"]:
            if "mattermost" not in running:
                raise LocalTargetError("TARGET_START_FAILED")
            if "postgres" not in running:
                self._compose(["up", "-d", "--wait", "postgres"], timeout=180, passwords=passwords)
            self._verify_owned_mattermost_container(passwords)
            result = self.status()
            result.update({"status": "healthy", "enterprise_ready": True, "image_version": version["version"]})
            return result
        if "mattermost" in running:
            self._stop_services()
        progress("Local target: starting PostgreSQL and Enterprise Mattermost")
        self._compose(["up", "-d", "--wait", "postgres", "mattermost"], timeout=300, passwords=passwords)
        progress("Local target: waiting for health")
        for attempt in range(150):
            if self.health(timeout=2)["healthy"]:
                self._verify_owned_mattermost_container(passwords)
                result = self.status()
                result.update({"status": "healthy", "enterprise_ready": True, "image_version": version["version"]})
                return result
            if attempt % 5 == 4 and "mattermost" not in self._running_services(timeout=5, passwords=passwords):
                self._stop_services()
                raise LocalTargetError("TARGET_START_FAILED")
            self.sleep(2)
        self._stop_services()
        raise LocalTargetError("HEALTH_TIMEOUT")

    def stop(self) -> dict[str, Any]:
        if self.compose_file.is_file():
            if not shutil.which("docker"):
                raise LocalTargetError("DOCKER_UNAVAILABLE")
            self._compose(["stop", "mattermost", "postgres"], timeout=60)
        return {"target": self.target_id, "status": "stopped", "data_preserved": True}

    def reset(self) -> dict[str, Any]:
        if self.compose_file.is_file():
            if not shutil.which("docker"):
                raise LocalTargetError("DOCKER_UNAVAILABLE")
            self._compose(["down", "--volumes", "--remove-orphans"], timeout=120)
        legacy_files = (self.runtime_root / "process.json", self.runtime_root / "go.work", self.secret_root / "config.json")
        for path in (self.bootstrap_file, self.secrets_file, *legacy_files):
            if path.is_file() and not path.is_symlink():
                path.unlink()
        for data_root in (self.runtime_root / "data", self.runtime_root / "go-cache", self.runtime_root / "go-path"):
            if data_root.is_dir() and not data_root.is_symlink():
                shutil.rmtree(data_root)
        return {"target": self.target_id, "status": "reset", "synthetic_data_removed": True, "evidence_preserved": True, "source_preserved": True}

    def status(self) -> dict[str, Any]:
        source = self._source_details(0.4)
        health = self.health(timeout=0.4)
        bootstrap = _read_json(self.bootstrap_file)
        image = None
        mattermost_state = postgres_state = "not_configured"
        if shutil.which("docker"):
            try:
                image = self._inspect_enterprise_image(timeout=0.4, allow_missing=True)
            except LocalTargetError:
                image = None
        if self.compose_file.is_file() and shutil.which("docker"):
            try:
                running = self._running_services(timeout=0.4)
                mattermost_state = "running" if "mattermost" in running else "stopped"
                postgres_state = "running" if "postgres" in running else "stopped"
            except LocalTargetError:
                mattermost_state = postgres_state = "unavailable"
        return {
            "target": self.target_id,
            "repository": self.repository,
            "expected_commit": self.pinned_revision,
            "actual_commit": source["actual_commit"],
            "source_status": source["source_status"],
            "enterprise_image": ENTERPRISE_IMAGE,
            "expected_image_digest": ENTERPRISE_IMAGE_DIGEST,
            "image_digest": image["digest"] if image else None,
            "image_platform": ENTERPRISE_PLATFORM,
            "mattermost_container": mattermost_state,
            "postgres_container": postgres_state,
            "health": health["status"],
            "host_endpoint": "http://127.0.0.1:8065",
            "observer_endpoint": "http://host.docker.internal:8065",
            "observer_linux_mapping": "host-gateway",
            "synthetic_bootstrap_status": "ready" if _valid_bootstrap_state(bootstrap) else "not_ready",
        }

    # ----- synthetic bootstrap ------------------------------------------------
    def _login(self, identity: str, passwords: dict[str, str]) -> LocalMattermostClient:
        client = self.client_factory(timeout=5)
        response = client.request("session", "POST", "/api/v4/users/login", {
            "login_id": _username(identity), "password": passwords[identity],
        }, count=False)
        if response.status != 200 or not client.session_fingerprint:
            raise LocalTargetError("BOOTSTRAP_FAILED")
        return client

    def _get_or_create_user(self, admin: LocalMattermostClient | None, identity: str, passwords: dict[str, str]) -> dict[str, Any]:
        username = _username(identity)
        client = admin or self.client_factory(timeout=5)
        if admin:
            found = admin.request("bootstrap", "GET", "/api/v4/users/username/" + username, count=False)
            if found.status == 200 and isinstance(found.data, dict) and found.data.get("username") == username:
                return found.data
        created = client.request("bootstrap", "POST", "/api/v4/users", {
            "email": username + "@localhost.invalid",
            "username": username,
            "password": passwords[identity],
            "first_name": "FINDER_LOCAL_" + identity.upper(),
        }, count=False)
        if created.status not in {200, 201} or not isinstance(created.data, dict):
            raise LocalTargetError("BOOTSTRAP_FAILED")
        return created.data

    def _get_or_create_team(self, admin: LocalMattermostClient) -> dict[str, Any]:
        name = "finder-local-team-a"
        found = admin.request("bootstrap", "GET", "/api/v4/teams/name/" + name, count=False)
        if found.status == 200 and isinstance(found.data, dict):
            return found.data
        created = admin.request("bootstrap", "POST", "/api/v4/teams", {
            "name": name, "display_name": "FINDER_LOCAL_TEAM_A", "type": "O",
        }, count=False)
        if created.status != 201 or not isinstance(created.data, dict):
            raise LocalTargetError("BOOTSTRAP_FAILED")
        return created.data

    def _ensure_team_member(self, admin: LocalMattermostClient, team_id: str, user_id: str) -> None:
        response = admin.request("bootstrap", "POST", f"/api/v4/teams/{team_id}/members", {
            "team_id": team_id, "user_id": user_id,
        }, count=False)
        if response.status not in {200, 201, 400}:
            raise LocalTargetError("BOOTSTRAP_FAILED")

    def _get_or_create_channel(self, admin: LocalMattermostClient, team_id: str, suffix: str) -> dict[str, Any]:
        name = "finder-local-" + suffix.replace("_", "-")
        found = admin.request("bootstrap", "GET", f"/api/v4/teams/name/finder-local-team-a/channels/name/{name}", count=False)
        if found.status == 200 and isinstance(found.data, dict):
            return found.data
        created = admin.request("bootstrap", "POST", "/api/v4/channels", {
            "team_id": team_id, "name": name, "display_name": "FINDER_LOCAL_" + suffix.upper(), "type": "P",
        }, count=False)
        if created.status != 201 or not isinstance(created.data, dict):
            raise LocalTargetError("BOOTSTRAP_FAILED")
        return created.data

    def _ensure_channel_member(self, admin: LocalMattermostClient, channel_id: str, user_id: str) -> None:
        response = admin.request("bootstrap", "POST", f"/api/v4/channels/{channel_id}/members", {
            "user_id": user_id,
        }, count=False)
        if response.status not in {200, 201, 400}:
            raise LocalTargetError("BOOTSTRAP_FAILED")

    def _configure_delegated_role(self, admin: LocalMattermostClient, user_id: str) -> dict[str, bool]:
        role_response = admin.request("bootstrap", "GET", "/api/v4/roles/name/system_user_manager", count=False)
        if role_response.status != 200 or not isinstance(role_response.data, dict):
            raise LocalTargetError("ROLE_UNAVAILABLE")
        role = role_response.data
        role_id = _id(role.get("id"))
        permissions = set(value for value in role.get("permissions", []) if isinstance(value, str))
        permissions.update({"edit_other_users", "view_team", "sysconsole_read_user_management_users", "sysconsole_write_user_management_users"})
        if "manage_system" in permissions:
            raise LocalTargetError("ROLE_UNAVAILABLE")
        patched = admin.request("bootstrap", "PUT", f"/api/v4/roles/{role_id}/patch", {
            "permissions": sorted(permissions),
        }, count=False)
        if patched.status != 200 or not isinstance(patched.data, dict):
            raise LocalTargetError("ROLE_UNAVAILABLE")
        actual = set(patched.data.get("permissions", []))
        assigned = admin.request("bootstrap", "PUT", f"/api/v4/users/{user_id}/roles", {
            "roles": "system_user system_user_manager",
        }, count=False)
        if assigned.status != 200:
            raise LocalTargetError("ROLE_UNAVAILABLE")
        summary = {
            "system_admin": False,
            "edit_other_users": "edit_other_users" in actual,
            "view_team": "view_team" in actual,
            "manage_system": "manage_system" in actual,
            "read_channel_content": "read_channel_content" in actual,
            "target_channel_member": False,
        }
        if not summary["edit_other_users"] or not summary["view_team"] or summary["manage_system"] or summary["read_channel_content"]:
            raise LocalTargetError("ROLE_UNAVAILABLE")
        return summary

    def bootstrap(self) -> dict[str, Any]:
        self._require_source()
        if not self.health()["healthy"]:
            raise LocalTargetError("BOOTSTRAP_FAILED")
        passwords = self._load_secrets(create=True)
        self._require_active_enterprise_runtime(passwords)
        try:
            admin = self._login("system_admin", passwords)
            admin_user_response = admin.request("bootstrap", "GET", "/api/v4/users/username/" + _username("system_admin"), count=False)
            admin_user = admin_user_response.data
        except LocalTargetError:
            admin_user = self._get_or_create_user(None, "system_admin", passwords)
            admin = self._login("system_admin", passwords)
        if not isinstance(admin_user, dict) or "system_admin" not in str(admin_user.get("roles", "")).split():
            raise LocalTargetError("BOOTSTRAP_FAILED")
        users = {"system_admin": admin_user}
        for identity in ("delegated_admin", "victim", "normal_user"):
            users[identity] = self._get_or_create_user(admin, identity, passwords)
        user_ids = {name: _id(value.get("id")) for name, value in users.items()}
        try:
            role_summary = self._configure_delegated_role(admin, user_ids["delegated_admin"])
        except LocalTargetError as error:
            if error.code == "ROLE_UNAVAILABLE":
                self._record_blocked_setup()
            raise
        team = self._get_or_create_team(admin)
        team_id = _id(team.get("id"))
        for user_id in user_ids.values():
            self._ensure_team_member(admin, team_id, user_id)
        channel_a = self._get_or_create_channel(admin, team_id, "private-channel-a")
        channel_b = self._get_or_create_channel(admin, team_id, "private-channel-b")
        channel_a_id, channel_b_id = _id(channel_a.get("id")), _id(channel_b.get("id"))
        self._ensure_channel_member(admin, channel_a_id, user_ids["victim"])
        self._ensure_channel_member(admin, channel_a_id, user_ids["normal_user"])
        self._ensure_channel_member(admin, channel_b_id, user_ids["normal_user"])
        removed = admin.request("bootstrap", "DELETE", f"/api/v4/channels/{channel_a_id}/members/{user_ids['delegated_admin']}", count=False)
        if removed.status not in {200, 404}:
            raise LocalTargetError("BOOTSTRAP_FAILED")
        victim = self._login("victim", passwords)
        prior = _read_json(self.bootstrap_file)
        if _valid_bootstrap_state(prior) and prior.get("private_channel_a") == channel_a_id:
            thread_id = _id(prior.get("thread_id"))
        else:
            post = victim.request("bootstrap", "POST", "/api/v4/posts", {
                "channel_id": channel_a_id, "message": SYNTHETIC_MESSAGE,
            }, count=False)
            if post.status not in {200, 201} or not isinstance(post.data, dict):
                raise LocalTargetError("BOOTSTRAP_FAILED")
            thread_id = _id(post.data.get("id"))
        direct = admin.request("bootstrap", "POST", "/api/v4/channels/direct", [user_ids["victim"], user_ids["normal_user"]], count=False)
        if direct.status not in {200, 201} or not isinstance(direct.data, dict):
            raise LocalTargetError("BOOTSTRAP_FAILED")
        direct_id = _id(direct.data.get("id"))
        if _valid_bootstrap_state(prior) and prior.get("dm_victim_normal_user") == direct_id:
            dm_thread_id = _id(prior.get("dm_thread_id"))
        else:
            dm_post = victim.request("bootstrap", "POST", "/api/v4/posts", {
                "channel_id": direct_id, "message": SYNTHETIC_DM_MESSAGE,
            }, count=False)
            if dm_post.status not in {200, 201} or not isinstance(dm_post.data, dict):
                raise LocalTargetError("BOOTSTRAP_FAILED")
            dm_thread_id = _id(dm_post.data.get("id"))
        state = {
            "marker": "FINDER_LOCAL_BOOTSTRAP_V1",
            "target_commit": self.pinned_revision,
            "users": user_ids,
            "team_a": team_id,
            "private_channel_a": channel_a_id,
            "private_channel_b": channel_b_id,
            "dm_victim_normal_user": direct_id,
            "dm_thread_id": dm_thread_id,
            "thread_id": thread_id,
            "role_summary": role_summary,
            "updated_at": _now(),
        }
        atomic_private_json(self.bootstrap_file, state)
        return {
            "target": self.target_id,
            "status": "ready",
            "identities": ["system_admin", "delegated_admin", "victim", "normal_user"],
            "resources": ["team_a", "private_channel_a", "private_channel_b", "dm_victim_normal_user"],
            "role_summary": role_summary,
        }

    def _record_blocked_setup(self) -> None:
        secure_directory(self.evidence_root)
        records = Records(self.evidence_root)
        for candidate, source_record in CANDIDATES.items():
            evidence = records.save("local_validation", {
                "target": self.target_id,
                "target_commit": self.pinned_revision,
                "candidate_id": candidate,
                "source_candidate_record": source_record,
                "identity": "delegated_admin",
                "authenticated": False,
                "role_summary": {"system_admin": False},
                "requests": [],
                "synthetic_marker_present": False,
                "request_count": 0,
                "assessment": "BLOCKED_BY_LOCAL_SETUP",
                "details": {"reason": "required_supported_role_not_constructible"},
            })
            records.save("candidate_reassessment", {
                "target": self.target_id,
                "target_commit": self.pinned_revision,
                "candidate_id": candidate,
                "source_candidate_record": source_record,
                "local_validation_evidence_id": evidence["id"],
                "review_status": "BLOCKED_BY_LOCAL_SETUP",
                "automatic_confirmation": False,
            })

    # ----- candidate validators ----------------------------------------------
    def _validation_context(self) -> tuple[dict[str, Any], dict[str, str], LocalMattermostClient]:
        state = _read_json(self.bootstrap_file)
        if not _valid_bootstrap_state(state):
            raise LocalTargetError("VALIDATION_BLOCKED")
        passwords = self._load_secrets(create=False)
        client = self._login("delegated_admin", passwords)
        role = state["role_summary"]
        if role.get("system_admin") or not role.get("edit_other_users") or not role.get("view_team") or role.get("manage_system") or role.get("read_channel_content") or role.get("target_channel_member"):
            raise LocalTargetError("ROLE_UNAVAILABLE")
        return state, passwords, client

    @staticmethod
    def _request_summary(method: str, path: str, expected: str, response: LocalResponse) -> dict[str, Any]:
        return {"method": method, "path": path, "expected": expected, "status_code": response.status, "response_shape": response.shape}

    def _save_validation(self, candidate: str, status: str, requests: list[dict[str, Any]], marker: bool, count: int, details: dict[str, Any]) -> dict[str, Any]:
        if count > REQUEST_BUDGETS[candidate]:
            raise LocalTargetError("local_request_budget_exceeded")
        secure_directory(self.evidence_root)
        records = Records(self.evidence_root)
        evidence = records.save("local_validation", {
            "target": self.target_id,
            "target_commit": self.pinned_revision,
            "candidate_id": candidate,
            "source_candidate_record": CANDIDATES[candidate],
            "identity": "delegated_admin",
            "authenticated": True,
            "session_fingerprint": details.pop("session_fingerprint"),
            "role_summary": details.pop("role_summary"),
            "requests": requests,
            "synthetic_marker_present": marker,
            "request_count": count,
            "assessment": status,
            "details": details,
        })
        reassessment = records.save("candidate_reassessment", {
            "target": self.target_id,
            "target_commit": self.pinned_revision,
            "candidate_id": candidate,
            "source_candidate_record": CANDIDATES[candidate],
            "local_validation_evidence_id": evidence["id"],
            "review_status": status,
            "automatic_confirmation": False,
        })
        return {
            "target": self.target_id,
            "candidate": candidate,
            "status": status,
            "evidence": evidence["id"],
            "reassessment": reassessment["id"],
            "request_count": count,
            **details,
        }

    def _validate_s12(self) -> dict[str, Any]:
        state, _, client = self._validation_context()
        victim, team, thread = state["users"]["victim"], state["team_a"], state["thread_id"]
        single_path = f"/api/v4/users/{victim}/teams/{team}/threads/{thread}"
        bulk_path = f"/api/v4/users/{victim}/teams/{team}/threads?per_page=100&extended=true"
        single = client.request("S12", "GET", single_path)
        bulk = client.request("S12", "GET", bulk_path)
        marker = _contains_message(bulk.data, SYNTHETIC_MESSAGE)
        role = dict(state["role_summary"])
        private_verified = single.status in {401, 403, 404} and bulk.status == 200 and marker
        dm_control = None
        dm_marker = False
        if private_verified:
            dm_path = f"/api/v4/users/{victim}/teams/{team}/threads/{state['dm_thread_id']}"
            dm_control = client.request("S12", "GET", dm_path)
            dm_marker = _contains_message(bulk.data, SYNTHETIC_DM_MESSAGE)
        status = "VERIFIED_CANDIDATE" if private_verified else "NEEDS_MORE_EVIDENCE"
        requests = [
            self._request_summary("GET", single_path, "deny", single),
            self._request_summary("GET", bulk_path, "success_with_synthetic_marker", bulk),
        ]
        if dm_control is not None:
            requests.append(self._request_summary("GET", dm_path, "deny_dm_variant", dm_control))
        return self._save_validation("S12", status, requests, marker, client.request_count, {
            "role_summary": role,
            "session_fingerprint": client.session_fingerprint,
            "control": "DENIED" if single.status in {401, 403, 404} else str(single.status),
            "bulk": bulk.status,
            "synthetic_marker_returned": marker,
            "dm_variant_control_denied": dm_control is not None and dm_control.status in {401, 403, 404},
            "dm_variant_marker_returned": dm_marker,
        })

    def _validate_s13(self) -> dict[str, Any]:
        state, _, client = self._validation_context()
        victim, team = state["users"]["victim"], state["team_a"]
        control_path = f"/api/v4/users/{victim}/teams/{team}/channels/members?page=0&per_page=100"
        candidate_path = f"/api/v4/users/{victim}/channel_members?page=0&per_page=100"
        control = client.request("S13", "GET", control_path)
        candidate = client.request("S13", "GET", candidate_path)
        comparison = _membership_comparison(control.data, candidate.data)
        marker = state["private_channel_a"] in comparison["candidate_channel_ids"]
        # The pinned handler explicitly authorizes this endpoint with edit_other_users
        # and sanitizes each member for the requester, so success is documented
        # delegated behavior rather than an automatic vulnerability confirmation.
        status = "INTENDED_BEHAVIOR" if candidate.status == 200 else "NEEDS_MORE_EVIDENCE"
        requests = [
            self._request_summary("GET", control_path, "comparison_control", control),
            self._request_summary("GET", candidate_path, "documented_edit_other_users_behavior", candidate),
        ]
        return self._save_validation("S13", status, requests, marker, client.request_count, {
            "role_summary": dict(state["role_summary"]),
            "session_fingerprint": client.session_fingerprint,
            "control": control.status,
            "candidate_result": candidate.status,
            "comparison": comparison,
        })

    def _validate_s15(self) -> dict[str, Any]:
        state, passwords, client = self._validation_context()
        victim, team, thread = state["users"]["victim"], state["team_a"], state["thread_id"]
        normal = self._login("normal_user", passwords)
        # This reply is deterministic setup and is excluded from the A/B budget.
        setup = normal.request("bootstrap", "POST", "/api/v4/posts", {
            "channel_id": state["private_channel_a"], "root_id": thread,
            "message": "FINDER_LOCAL_S15_UNREAD_" + secrets.token_hex(4),
        }, count=False)
        if setup.status not in {200, 201}:
            # Retry with the victim only if the synthetic membership drifted.
            victim_setup = self._login("victim", passwords)
            setup = victim_setup.request("bootstrap", "POST", "/api/v4/posts", {
                "channel_id": state["private_channel_a"], "root_id": thread,
                "message": "FINDER_LOCAL_S15_UNREAD_" + secrets.token_hex(4),
            }, count=False)
            if setup.status not in {200, 201}:
                raise LocalTargetError("VALIDATION_BLOCKED")
        victim_client = self._login("victim", passwords)
        list_path = f"/api/v4/users/{victim}/teams/{team}/threads?per_page=100&extended=true"
        before = victim_client.request("S15", "GET", list_path)
        timestamp = str(int(time.time() * 1000))
        single_path = f"/api/v4/users/{victim}/teams/{team}/threads/{thread}/read/{timestamp}"
        bulk_path = f"/api/v4/users/{victim}/teams/{team}/threads/read"
        single = client.request("S15", "PUT", single_path)
        bulk = client.request("S15", "PUT", bulk_path)
        after = victim_client.request("S15", "GET", list_path)
        before_state, after_state = _thread_state(before.data, thread), _thread_state(after.data, thread)
        changed = before_state != after_state and after_state is not None
        count = client.request_count + victim_client.request_count
        marker = before_state is not None
        status = "VERIFIED_CANDIDATE" if single.status in {401, 403, 404} and bulk.status == 200 and changed else "NEEDS_MORE_EVIDENCE"
        requests = [
            self._request_summary("GET", list_path, "before_state", before),
            self._request_summary("PUT", single_path, "deny", single),
            self._request_summary("PUT", bulk_path, "accept", bulk),
            self._request_summary("GET", list_path, "after_state", after),
        ]
        return self._save_validation("S15", status, requests, marker, count, {
            "role_summary": dict(state["role_summary"]),
            "session_fingerprint": client.session_fingerprint,
            "control": "DENIED" if single.status in {401, 403, 404} else str(single.status),
            "bulk": bulk.status,
            "victim_state_changed": changed,
            "before_state": before_state,
            "after_state": after_state,
        })

    def validate(self, candidate: str | None = None) -> list[dict[str, Any]]:
        if candidate is not None and candidate not in CANDIDATES:
            raise LocalTargetError("unknown_local_candidate")
        if not self.health()["healthy"]:
            raise LocalTargetError("VALIDATION_BLOCKED")
        self._require_active_enterprise_runtime(self._load_secrets(create=False))
        selected = [candidate] if candidate else list(CANDIDATES)
        methods = {"S12": self._validate_s12, "S13": self._validate_s13, "S15": self._validate_s15}
        return [methods[value]() for value in selected]


def _password() -> str:
    # Mattermost's mixed-character password checks are satisfied without ever
    # exposing the generated value through argv, stdout, evidence, or logs.
    return "Lh9!" + secrets.token_urlsafe(28)


def _username(identity: str) -> str:
    return SYNTHETIC_PREFIX + identity.replace("_", "-")


def _id(value: Any) -> str:
    if not isinstance(value, str) or not MATTERMOST_ID.fullmatch(value):
        raise LocalTargetError("BOOTSTRAP_FAILED")
    return value


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _read_json(path: Path) -> dict[str, Any] | None:
    try:
        if path.is_symlink() or path.stat().st_size > 128 * 1024:
            return None
        value = json.loads(path.read_text(encoding="utf-8"))
        return value if isinstance(value, dict) else None
    except (OSError, ValueError):
        return None


def _valid_bootstrap_state(value: dict[str, Any] | None) -> bool:
    try:
        return bool(
            value
            and value.get("marker") == "FINDER_LOCAL_BOOTSTRAP_V1"
            and value.get("target_commit") == MattermostAdapter.pinned_revision
            and set(value.get("users", {})) == {"system_admin", "delegated_admin", "victim", "normal_user"}
            and all(MATTERMOST_ID.fullmatch(item) for item in value["users"].values())
            and all(MATTERMOST_ID.fullmatch(value[key]) for key in
                    ("team_a", "private_channel_a", "private_channel_b", "dm_victim_normal_user", "thread_id", "dm_thread_id"))
        )
    except (TypeError, KeyError):
        return False


def _contains_message(value: Any, marker: str) -> bool:
    if isinstance(value, dict):
        return any(key == "message" and item == marker or _contains_message(item, marker) for key, item in value.items())
    if isinstance(value, list):
        return any(_contains_message(item, marker) for item in value)
    return False


def _membership_rows(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    return [row for row in value if isinstance(row, dict)]


def _membership_comparison(control: Any, candidate: Any) -> dict[str, Any]:
    left, right = _membership_rows(control), _membership_rows(candidate)
    fields = ("channel_id", "roles", "msg_count", "mention_count", "notify_props", "team_display_name", "team_name")
    return {
        "control_count": len(left),
        "candidate_count": len(right),
        "control_channel_ids": sorted({str(row.get("channel_id")) for row in left if row.get("channel_id")}),
        "candidate_channel_ids": sorted({str(row.get("channel_id")) for row in right if row.get("channel_id")}),
        "compared_fields": list(fields),
        "candidate_fields_present": sorted({field for row in right for field in fields if field in row}),
    }


def _thread_state(value: Any, thread_id: str) -> dict[str, Any] | None:
    if not isinstance(value, dict) or not isinstance(value.get("threads"), list):
        return None
    for thread in value["threads"]:
        if not isinstance(thread, dict):
            continue
        post = thread.get("post") if isinstance(thread.get("post"), dict) else {}
        if post.get("id") == thread_id:
            return {key: thread.get(key) for key in ("last_viewed_at", "unread_replies", "unread_mentions", "is_following")}
    return None
