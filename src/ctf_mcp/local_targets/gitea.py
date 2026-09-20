"""Gitea adapter pinned to one reviewed upstream revision and image digest."""

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
    reject_active_git_extensions,
    repository_origin_matches,
    run_confined_git,
    secure_directory,
)
from .gitea_http import (
    COLLABORATOR,
    CONTROL_TOKEN_DELETE_PATH,
    CONTROL_TOKEN_NAME,
    LIMITED_ORGANIZATION,
    LIMITED_ORG_PATH,
    LIMITED_ORG_PUBLIC_REPOSITORY,
    LIMITED_ORG_PUBLIC_REPO_PATH,
    ORGANIZATION,
    ORG_PATH,
    ORG_PRIVATE_REPOSITORY,
    ORG_PRIVATE_REPO_PATH,
    ORG_PUBLIC_REPOSITORY,
    ORG_PUBLIC_REPO_PATH,
    ORG_REPOS_PATH,
    ORG_TEAMS_PATH,
    OUTSIDER,
    OWNER,
    PUBLIC_ONLY_TOKEN_NAME,
    PUBLIC_ONLY_TOKEN_DELETE_PATH,
    PUBLIC_REPOSITORY,
    PUBLIC_REPO_PATH,
    REPOSITORY,
    REPO_PATH,
    TEAM,
    TOKEN_PATH,
    USER_FEEDS_PATH,
    USER_HEATMAP_PATH,
    USER_REPOS_PATH,
    LocalGiteaClient,
    team_repository_path,
)
from .gitea_hunt import VERIFICATION_ASSERTIONS, adjudicate, create_hunt_reports
from .http import LocalResponse


GITEA_VERSION = "1.27.3"
GITEA_IMAGE = "docker.gitea.com/gitea:1.27.3-rootless"
GITEA_IMAGE_DIGEST = "sha256:1c17ecaead42eb3b5391553d8708103a4beb0e86edf5b9ebc1eb269c318845f2"
GITEA_IMAGE_REFERENCE = GITEA_IMAGE + "@" + GITEA_IMAGE_DIGEST
COMPOSE_PROJECT = "iwantgohome-local-gitea"
SYNTHETIC_DESCRIPTION = "finder-local synthetic authorization control repository"
PUBLIC_DESCRIPTION = "finder-local synthetic public control repository"
ORGANIZATION_DESCRIPTION = "finder-local synthetic public organization"
ORG_PUBLIC_DESCRIPTION = "finder-local synthetic public organization repository"
ORG_PRIVATE_DESCRIPTION = "finder-local synthetic private organization repository"
LIMITED_ORGANIZATION_DESCRIPTION = "finder-local synthetic limited organization"
LIMITED_ORG_PUBLIC_DESCRIPTION = "finder-local synthetic limited organization public repository"
TEAM_DESCRIPTION = "finder-local synthetic public repository control team"
IDENTITIES = ("system_admin", "repo_owner", "collaborator", "outsider")
CANDIDATES = {
    "G01": "finder-local-gitea-control-G01",
    "G02": "finder-local-gitea-control-G02",
    "G03": "finder-local-gitea-control-G03",
    "G04": "finder-local-gitea-control-G04",
    "G05": "finder-local-gitea-control-G05",
    "G06": "finder-local-gitea-control-G06",
    "G07": "finder-local-gitea-control-G07",
    "G08": "finder-local-gitea-control-G08",
}
REQUEST_BUDGETS = {
    "G01": 1,
    "G02": 1,
    "G03": 1,
    "G04": 3,
    "G05": 3,
    "G06": 2,
    "G07": 2,
    "G08": 2,
}
COMPOSE = f"""name: {COMPOSE_PROJECT}
services:
  gitea:
    image: {GITEA_IMAGE_REFERENCE}
    restart: "no"
    environment:
      GITEA__database__DB_TYPE: sqlite3
      GITEA__database__PATH: /var/lib/gitea/data/gitea.db
      GITEA__server__ROOT_URL: http://127.0.0.1:13000/
      GITEA__server__HTTP_PORT: "3000"
      GITEA__server__DISABLE_SSH: "true"
      GITEA__security__INSTALL_LOCK: "true"
      GITEA__service__DISABLE_REGISTRATION: "true"
    ports:
      - 127.0.0.1:13000:3000
    volumes:
      - gitea-data:/var/lib/gitea
      - gitea-config:/etc/gitea
    networks: [local-target]
    security_opt: [no-new-privileges:true]
volumes:
  gitea-data: {{}}
  gitea-config: {{}}
networks:
  local-target: {{}}
"""


class GiteaAdapter(LocalTargetAdapter):
    target_id = "gitea"
    repository = "https://github.com/go-gitea/gitea"
    pinned_revision = "146cc3eec57174711eac0e0a0c7b38670c6e3922"
    host_health_url = "http://127.0.0.1:13000/api/healthz"
    supported_candidates = frozenset(CANDIDATES)

    def __init__(
        self,
        root: Path,
        manifest: LocalTargetManifest,
        *,
        runner: FixedCommandRunner | None = None,
        client_factory: Callable[..., LocalGiteaClient] = LocalGiteaClient,
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
        self.runtime_root = self.operator / "local-runtime" / self.target_id
        self.secret_root = self.operator / "local-secrets" / self.target_id
        self.evidence_root = self.operator / "local-evidence" / self.target_id
        self.compose_file = self.runtime_root / "compose.yaml"
        self.bootstrap_file = self.runtime_root / "bootstrap.json"
        self.secrets_file = self.secret_root / "secrets.json"

    # ----- source acquisition -------------------------------------------------
    def _git(self, argv: list[str], cwd: Path, timeout: float = 30) -> subprocess.CompletedProcess[str]:
        return run_confined_git(self.runner, self.targets_root, argv, cwd=cwd, timeout=timeout)

    @staticmethod
    def _origin_matches(value: str) -> bool:
        return repository_origin_matches(value, GiteaAdapter.repository)

    def _source_details(self, timeout: float = 0.75) -> dict[str, Any]:
        git_dir = self.target_root / ".git"
        if (self.target_root.is_symlink() or not self.target_root.is_dir()
                or git_dir.is_symlink() or not git_dir.is_dir()):
            return {
                "prepared": False,
                "actual_commit": None,
                "origin_ok": False,
                "source_status": "SOURCE_NOT_PREPARED",
            }
        try:
            origin = self._git(["remote", "get-url", "origin"], self.target_root, timeout).stdout.strip()
            head = self._git(["rev-parse", "HEAD"], self.target_root, timeout).stdout.strip()
        except LocalTargetError:
            return {
                "prepared": True,
                "actual_commit": None,
                "origin_ok": False,
                "source_status": "SOURCE_VALIDATION_FAILED",
            }
        origin_ok = self._origin_matches(origin)
        code = "READY" if origin_ok and head == self.pinned_revision else (
            "REVISION_MISMATCH" if origin_ok else "REPOSITORY_MISMATCH"
        )
        return {
            "prepared": True,
            "actual_commit": head,
            "origin_ok": origin_ok,
            "source_status": code,
        }

    def _require_source(self) -> None:
        state = self._source_details(2)
        if not state["prepared"]:
            raise LocalTargetError("SOURCE_NOT_PREPARED")
        if not state["origin_ok"]:
            raise LocalTargetError("REPOSITORY_MISMATCH")
        if state["actual_commit"] != self.pinned_revision:
            raise LocalTargetError("REVISION_MISMATCH")
        module = self.target_root / "go.mod"
        if module.is_symlink() or not module.is_file():
            raise LocalTargetError("SOURCE_NOT_PREPARED")
        reject_active_git_extensions(self.target_root)
        if self._git(["status", "--porcelain", "--untracked-files=normal"], self.target_root, 10).stdout.strip():
            raise LocalTargetError("SOURCE_DIRTY")

    def prepare(self) -> dict[str, Any]:
        secure_directory(self.targets_root)
        if self.target_root.exists() or self.target_root.is_symlink():
            git_dir = self.target_root / ".git"
            if (self.target_root.is_symlink() or not self.target_root.is_dir()
                    or git_dir.is_symlink() or not git_dir.is_dir()):
                raise LocalTargetError("REPOSITORY_MISMATCH")
            reject_active_git_extensions(self.target_root)
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
            temporary = self.targets_root / (".gitea-preparing-" + secrets.token_hex(8))
            try:
                self._git(
                    ["clone", "--filter=blob:none", "--no-checkout", self.repository, str(temporary)],
                    self.targets_root,
                    1800,
                )
                reject_active_git_extensions(temporary)
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
        return {
            "target": self.target_id,
            "repository": self.repository,
            "commit": self.pinned_revision,
            "status": "prepared",
        }

    # ----- runtime ------------------------------------------------------------
    def _write_runtime_files(self) -> None:
        secure_directory(self.runtime_root)
        if not self.compose_file.exists():
            self.compose_file.write_text(COMPOSE, encoding="utf-8")
            os.chmod(self.compose_file, 0o600)
        elif self.compose_file.is_symlink() or self.compose_file.read_text(encoding="utf-8") != COMPOSE:
            raise LocalTargetError("unsafe_local_runtime")

    def _docker_env(self) -> dict[str, str]:
        return dict(os.environ)

    def _compose(self, tail: list[str], *, timeout: float) -> subprocess.CompletedProcess[str]:
        try:
            if (self.runtime_root.is_symlink() or self.compose_file.is_symlink()
                    or not self.compose_file.is_file()):
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
                env=self._docker_env(),
            )
        except (OSError, subprocess.SubprocessError):
            code = "TARGET_START_FAILED" if tail[:1] == ["up"] else "DOCKER_UNAVAILABLE"
            raise LocalTargetError(code) from None

    def _inspect_image(self, *, timeout: float, allow_missing: bool) -> dict[str, str] | None:
        try:
            result = self.runner.run(
                ["docker", "image", "inspect", GITEA_IMAGE_REFERENCE],
                cwd=self.root,
                timeout=timeout,
                env=self._docker_env(),
            )
            value = json.loads(result.stdout)
            if not isinstance(value, list) or len(value) != 1 or not isinstance(value[0], dict):
                raise LocalTargetError("IMAGE_MISMATCH")
            metadata = value[0]
            digests = metadata.get("RepoDigests")
            image_id = metadata.get("Id")
            if (not isinstance(digests, list)
                    or not any(isinstance(item, str) and item.endswith("@" + GITEA_IMAGE_DIGEST) for item in digests)
                    or not isinstance(image_id, str)
                    or not re.fullmatch(r"sha256:[0-9a-f]{64}", image_id)):
                raise LocalTargetError("IMAGE_MISMATCH")
            return {"digest": GITEA_IMAGE_DIGEST, "id": image_id}
        except LocalTargetError:
            raise
        except (OSError, subprocess.SubprocessError, ValueError, TypeError):
            if allow_missing:
                return None
            raise LocalTargetError("IMAGE_MISMATCH") from None

    def _ensure_image(self, progress: Callable[[str], None]) -> dict[str, str]:
        metadata = self._inspect_image(timeout=10, allow_missing=True)
        if metadata is None:
            progress("Local target: pulling exact Gitea image")
            try:
                self.runner.run(
                    ["docker", "pull", GITEA_IMAGE_REFERENCE],
                    cwd=self.root,
                    timeout=1800,
                    env=self._docker_env(),
                )
            except (OSError, subprocess.SubprocessError):
                raise LocalTargetError("TARGET_START_FAILED") from None
            metadata = self._inspect_image(timeout=10, allow_missing=False)
        assert metadata is not None
        return metadata

    def _running_services(self, *, timeout: float) -> set[str]:
        result = self._compose(["ps", "--status", "running", "--services"], timeout=timeout)
        services = set(result.stdout.split())
        if not services <= {"gitea"}:
            raise LocalTargetError("unsafe_local_runtime")
        return services

    def _owned_container_id(self) -> str:
        container = self._compose(["ps", "-q", "gitea"], timeout=5).stdout.split()
        if len(container) != 1 or not re.fullmatch(r"[0-9a-f]{12,64}", container[0]):
            raise LocalTargetError("TARGET_START_FAILED")
        image = self._inspect_image(timeout=5, allow_missing=False)
        assert image is not None
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
            if labels.get("com.docker.compose.service") != "gitea":
                raise LocalTargetError("TARGET_START_FAILED")
            if config.get("Image") != GITEA_IMAGE_REFERENCE or value[0].get("Image") != image["id"]:
                raise LocalTargetError("IMAGE_MISMATCH")
            if not isinstance(state, dict) or state.get("Running") is not True:
                raise LocalTargetError("TARGET_START_FAILED")
            return container[0]
        except LocalTargetError:
            raise
        except (OSError, subprocess.SubprocessError, ValueError, TypeError, AttributeError):
            raise LocalTargetError("TARGET_START_FAILED") from None

    @staticmethod
    def _validate_version(output: str) -> str:
        match = re.search(r"\bgitea version ([0-9]+\.[0-9]+\.[0-9]+)\b", output, re.IGNORECASE)
        if match is None or match.group(1) != GITEA_VERSION:
            raise LocalTargetError("IMAGE_MISMATCH")
        return match.group(1)

    def _probe_container_version(self, container_id: str) -> str:
        try:
            result = self.runner.run(
                ["docker", "exec", container_id, "gitea", "--version"],
                cwd=self.root,
                timeout=15,
                env=self._docker_env(),
            )
        except (OSError, subprocess.SubprocessError):
            raise LocalTargetError("IMAGE_MISMATCH") from None
        return self._validate_version(result.stdout + "\n" + result.stderr)

    def _verify_owned_gitea_container(self, *, probe_version: bool = True) -> str | None:
        container_id = self._owned_container_id()
        return self._probe_container_version(container_id) if probe_version else None

    def _stop_services(self) -> None:
        if self.compose_file.is_file() and shutil.which("docker"):
            try:
                self._compose(["stop", "gitea"], timeout=60)
            except LocalTargetError:
                pass

    def _require_active_runtime(self) -> str:
        if shutil.which("docker") is None or not self.compose_file.is_file():
            raise LocalTargetError("TARGET_START_FAILED")
        self._inspect_image(timeout=10, allow_missing=False)
        if "gitea" not in self._running_services(timeout=5):
            raise LocalTargetError("TARGET_START_FAILED")
        version = self._verify_owned_gitea_container(probe_version=True)
        assert version is not None
        return version

    def _raw_health(self, timeout: float) -> dict[str, Any]:
        try:
            response = self.client_factory(timeout=timeout).request(
                "health", "GET", "/api/healthz", count=False
            )
            valid = (
                response.status == 200
                and isinstance(response.data, dict)
                and response.data.get("status") == "pass"
                and isinstance(response.data.get("description"), str)
                and isinstance(response.data.get("checks"), dict)
            )
            return {
                "healthy": valid,
                "status": "healthy" if valid else "unhealthy",
                "status_code": response.status,
            }
        except LocalTargetError:
            return {"healthy": False, "status": "unreachable", "status_code": None}

    def health(self, timeout: float = 2.0) -> dict[str, Any]:
        result = self._raw_health(timeout)
        if not result["healthy"]:
            return result
        if shutil.which("docker") is None or not self.compose_file.is_file():
            return {"healthy": False, "status": "unowned_listener", "status_code": result["status_code"]}
        try:
            if "gitea" not in self._running_services(timeout=timeout):
                raise LocalTargetError("TARGET_START_FAILED")
            self._verify_owned_gitea_container(probe_version=False)
        except LocalTargetError:
            return {"healthy": False, "status": "unowned_listener", "status_code": result["status_code"]}
        return result

    def up(self, progress: Callable[[str], None] = print) -> dict[str, Any]:
        self._require_source()
        if shutil.which("docker") is None:
            raise LocalTargetError("DOCKER_UNAVAILABLE")
        self._write_runtime_files()
        progress("Local target: validating Docker")
        try:
            self.runner.run(["docker", "version"], cwd=self.runtime_root, timeout=15, env=self._docker_env())
            self.runner.run(
                ["docker", "compose", "version"], cwd=self.runtime_root, timeout=15, env=self._docker_env()
            )
        except (OSError, subprocess.SubprocessError):
            raise LocalTargetError("DOCKER_UNAVAILABLE") from None
        self._ensure_image(progress)
        running = self._running_services(timeout=5)
        if self.health(timeout=0.4)["healthy"]:
            version = self._verify_owned_gitea_container(probe_version=True)
            result = self.status()
            result.update({"status": "healthy", "image_version": version})
            return result
        if "gitea" in running:
            self._stop_services()
        progress("Local target: starting Gitea")
        self._compose(["up", "-d", "gitea"], timeout=300)
        progress("Local target: waiting for health")
        for attempt in range(150):
            if self.health(timeout=2)["healthy"]:
                version = self._verify_owned_gitea_container(probe_version=True)
                result = self.status()
                result.update({"status": "healthy", "image_version": version})
                return result
            if attempt % 5 == 4 and "gitea" not in self._running_services(timeout=5):
                self._stop_services()
                raise LocalTargetError("TARGET_START_FAILED")
            self.sleep(2)
        self._stop_services()
        raise LocalTargetError("HEALTH_TIMEOUT")

    def stop(self) -> dict[str, Any]:
        if self.compose_file.is_file():
            if shutil.which("docker") is None:
                raise LocalTargetError("DOCKER_UNAVAILABLE")
            self._compose(["stop", "gitea"], timeout=60)
        return {"target": self.target_id, "status": "stopped", "data_preserved": True}

    def reset(self) -> dict[str, Any]:
        if self.runtime_root.is_symlink() or self.secret_root.is_symlink():
            raise LocalTargetError("unsafe_local_path")
        if self.compose_file.is_file():
            if shutil.which("docker") is None:
                raise LocalTargetError("DOCKER_UNAVAILABLE")
            self._compose(["down", "--volumes", "--remove-orphans"], timeout=120)
        for path in (self.bootstrap_file, self.secrets_file):
            if path.is_file() and not path.is_symlink():
                path.unlink()
        return {
            "target": self.target_id,
            "status": "reset",
            "synthetic_data_removed": True,
            "evidence_preserved": True,
            "source_preserved": True,
        }

    def status(self) -> dict[str, Any]:
        source = self._source_details(0.4)
        health = self.health(timeout=0.4)
        bootstrap = _read_json(self.bootstrap_file)
        image = None
        container_state = "not_configured"
        version = None
        if shutil.which("docker"):
            try:
                image = self._inspect_image(timeout=0.4, allow_missing=True)
            except LocalTargetError:
                image = None
        if self.compose_file.is_file() and shutil.which("docker"):
            try:
                running = self._running_services(timeout=0.4)
                container_state = "running" if "gitea" in running else "stopped"
                if container_state == "running":
                    version = self._verify_owned_gitea_container(probe_version=True)
            except LocalTargetError:
                container_state = "unavailable"
        return {
            "target": self.target_id,
            "repository": self.repository,
            "expected_commit": self.pinned_revision,
            "actual_commit": source["actual_commit"],
            "source_status": source["source_status"],
            "gitea_image": GITEA_IMAGE,
            "expected_image_digest": GITEA_IMAGE_DIGEST,
            "image_digest": image["digest"] if image else None,
            "image_version": version,
            "gitea_container": container_state,
            "health": health["status"],
            "host_endpoint": "http://127.0.0.1:13000",
            "synthetic_bootstrap_status": "ready" if _valid_bootstrap_state(bootstrap) else "not_ready",
        }

    # ----- synthetic bootstrap ------------------------------------------------
    def _load_secrets(self, create: bool) -> dict[str, str]:
        if self.secrets_file.exists():
            try:
                if (self.secret_root.is_symlink() or self.secrets_file.is_symlink()
                        or self.secret_root.stat().st_mode & 0o077
                        or self.secrets_file.stat().st_mode & 0o077):
                    raise LocalTargetError("unsafe_local_secret_store")
                value = json.loads(self.secrets_file.read_text(encoding="utf-8"))
                required = set(IDENTITIES)
                optional = {"control_token", "public_only_token"}
                if (not isinstance(value, dict) or not required <= set(value)
                        or set(value) - required - optional
                        or not all(isinstance(value[name], str) and len(value[name]) >= 20 for name in IDENTITIES)):
                    raise LocalTargetError("unsafe_local_secret_store")
                if any(
                    name in value
                    and (not isinstance(value[name], str) or len(value[name]) < 20)
                    for name in optional
                ):
                    raise LocalTargetError("unsafe_local_secret_store")
                return value
            except LocalTargetError:
                raise
            except (OSError, ValueError, TypeError):
                raise LocalTargetError("unsafe_local_secret_store") from None
        if not create:
            raise LocalTargetError("BOOTSTRAP_FAILED")
        value = {identity: _password() for identity in IDENTITIES}
        atomic_private_json(self.secrets_file, value)
        return value

    def _identity_client(self, identity: str, passwords: dict[str, str]) -> LocalGiteaClient:
        return self.client_factory(_username(identity), passwords[identity], timeout=5)

    def _token_client(
        self, passwords: dict[str, str], secret_name: str, identity_label: str
    ) -> LocalGiteaClient:
        token = passwords.get(secret_name)
        if not isinstance(token, str) or len(token) < 20:
            raise LocalTargetError("BOOTSTRAP_FAILED")
        return self.client_factory(timeout=5, token=token, identity_label=identity_label)

    def _control_token_client(self, passwords: dict[str, str]) -> LocalGiteaClient:
        return self._token_client(passwords, "control_token", "finder-local-control-token")

    def _public_only_client(self, passwords: dict[str, str]) -> LocalGiteaClient:
        return self._token_client(
            passwords, "public_only_token", "finder-local-public-only-token"
        )

    @staticmethod
    def _token_is_expected(
        client: LocalGiteaClient, token_name: str, expected_scopes: set[str]
    ) -> bool:
        identity = client.request("identity", "GET", "/api/v1/user", count=False)
        metadata = client.request("token_identity", "GET", "/api/v1/token", count=False)
        user = metadata.data.get("user") if isinstance(metadata.data, dict) else None
        return bool(
            identity.status == 200
            and isinstance(identity.data, dict)
            and identity.data.get("login") == OWNER
            and metadata.status == 200
            and isinstance(metadata.data, dict)
            and metadata.data.get("name") == token_name
            and set(metadata.data.get("scopes", [])) == expected_scopes
            and isinstance(user, dict)
            and user.get("login") == OWNER
        )

    def _ensure_token(
        self,
        passwords: dict[str, str],
        *,
        secret_name: str,
        token_name: str,
        delete_path: str,
        scopes: set[str],
        identity_label: str,
    ) -> dict[str, str]:
        if secret_name in passwords:
            try:
                existing = self._token_client(passwords, secret_name, identity_label)
                if self._token_is_expected(existing, token_name, scopes):
                    return passwords
            except LocalTargetError:
                pass
        owner = self._identity_client("repo_owner", passwords)
        removed = owner.request("bootstrap", "DELETE", delete_path, count=False)
        if removed.status not in {204, 404}:
            raise LocalTargetError("BOOTSTRAP_FAILED")
        created = owner.request("bootstrap", "POST", TOKEN_PATH, {
            "name": token_name,
            "scopes": sorted(scopes),
        }, count=False)
        if (created.status != 201 or not isinstance(created.data, dict)
                or created.data.get("name") != token_name
                or set(created.data.get("scopes", [])) != scopes):
            raise LocalTargetError("BOOTSTRAP_FAILED")
        token = created.data.get("sha1")
        if not isinstance(token, str) or len(token) < 20:
            raise LocalTargetError("BOOTSTRAP_FAILED")
        updated = dict(passwords)
        updated[secret_name] = token
        atomic_private_json(self.secrets_file, updated)
        client = self._token_client(updated, secret_name, identity_label)
        if not self._token_is_expected(client, token_name, scopes):
            raise LocalTargetError("BOOTSTRAP_FAILED")
        return updated

    def _ensure_control_token(self, passwords: dict[str, str]) -> dict[str, str]:
        return self._ensure_token(
            passwords,
            secret_name="control_token",
            token_name=CONTROL_TOKEN_NAME,
            delete_path=CONTROL_TOKEN_DELETE_PATH,
            scopes={"read:user", "read:repository", "read:organization"},
            identity_label="finder-local-control-token",
        )

    def _ensure_public_only_token(self, passwords: dict[str, str]) -> dict[str, str]:
        return self._ensure_token(
            passwords,
            secret_name="public_only_token",
            token_name=PUBLIC_ONLY_TOKEN_NAME,
            delete_path=PUBLIC_ONLY_TOKEN_DELETE_PATH,
            scopes={"public-only", "read:user", "read:repository", "read:organization"},
            identity_label="finder-local-public-only-token",
        )

    def _create_user(self, container_id: str, identity: str, passwords: dict[str, str]) -> dict[str, Any]:
        username = _username(identity)
        argv = [
            "docker", "exec", container_id, "gitea", "admin", "user", "create",
            "--username", username,
            "--password", passwords[identity],
            "--email", username + "@localhost.invalid",
            "--must-change-password=false",
        ]
        if identity == "system_admin":
            argv.append("--admin")
        try:
            self.runner.run(argv, cwd=self.root, timeout=60, env=self._docker_env())
        except (OSError, subprocess.SubprocessError):
            # An existing synthetic user is the expected idempotent path. The
            # authenticated identity check below distinguishes it from failure.
            pass
        response = self._identity_client(identity, passwords).request(
            "identity", "GET", "/api/v1/user", count=False
        )
        expected_admin = identity == "system_admin"
        if (response.status != 200 or not isinstance(response.data, dict)
                or response.data.get("login") != username
                or response.data.get("is_admin") is not expected_admin
                or not isinstance(response.data.get("id"), int)):
            raise LocalTargetError("BOOTSTRAP_FAILED")
        return response.data

    @staticmethod
    def _synthetic_repository_matches(
        value: Any,
        *,
        owner_name: str,
        repository_name: str,
        private: bool,
        description: str,
    ) -> bool:
        if not isinstance(value, dict):
            return False
        owner = value.get("owner")
        return bool(
            value.get("name") == repository_name
            and value.get("full_name") == owner_name + "/" + repository_name
            and value.get("private") is private
            and value.get("description") == description
            and isinstance(value.get("id"), int)
            and isinstance(owner, dict)
            and owner.get("login") == owner_name
        )

    @classmethod
    def _repository_matches(cls, value: Any) -> bool:
        return cls._synthetic_repository_matches(
            value,
            owner_name=OWNER,
            repository_name=REPOSITORY,
            private=True,
            description=SYNTHETIC_DESCRIPTION,
        )

    def _get_or_create_repository(
        self,
        client: LocalGiteaClient,
        *,
        get_path: str,
        create_path: str,
        owner_name: str,
        repository_name: str,
        private: bool,
        description: str,
    ) -> dict[str, Any]:
        response = client.request("bootstrap", "GET", get_path, count=False)
        if response.status == 404:
            response = client.request("bootstrap", "POST", create_path, {
                "name": repository_name,
                "description": description,
                "private": private,
                "auto_init": True,
                "default_branch": "main",
            }, count=False)
            if response.status != 201:
                raise LocalTargetError("BOOTSTRAP_FAILED")
        if response.status not in {200, 201} or not self._synthetic_repository_matches(
            response.data,
            owner_name=owner_name,
            repository_name=repository_name,
            private=private,
            description=description,
        ):
            raise LocalTargetError("BOOTSTRAP_FAILED")
        return response.data

    def _get_or_create_organization(
        self,
        owner: LocalGiteaClient,
        *,
        get_path: str,
        organization_name: str,
        description: str,
        visibility: str,
    ) -> dict[str, Any]:
        response = owner.request("bootstrap", "GET", get_path, count=False)
        if response.status == 404:
            response = owner.request("bootstrap", "POST", "/api/v1/orgs", {
                "username": organization_name,
                "full_name": organization_name.upper().replace("-", "_"),
                "description": description,
                "visibility": visibility,
                "repo_admin_change_team_access": False,
            }, count=False)
            if response.status != 201:
                raise LocalTargetError("BOOTSTRAP_FAILED")
        if (response.status not in {200, 201} or not isinstance(response.data, dict)
                or response.data.get("username") != organization_name
                or response.data.get("description") != description
                or response.data.get("visibility") != visibility
                or not isinstance(response.data.get("id"), int)):
            raise LocalTargetError("BOOTSTRAP_FAILED")
        return response.data

    def _get_or_create_team(self, owner: LocalGiteaClient) -> dict[str, Any]:
        listed = owner.request("bootstrap", "GET", ORG_TEAMS_PATH, count=False)
        if listed.status != 200 or not isinstance(listed.data, list):
            raise LocalTargetError("BOOTSTRAP_FAILED")
        matches = [item for item in listed.data if isinstance(item, dict) and item.get("name") == TEAM]
        if len(matches) > 1:
            raise LocalTargetError("BOOTSTRAP_FAILED")
        if matches:
            team = matches[0]
        else:
            created = owner.request(
                "bootstrap", "POST", f"/api/v1/orgs/{ORGANIZATION}/teams", {
                    "name": TEAM,
                    "description": TEAM_DESCRIPTION,
                    "includes_all_repositories": False,
                    "permission": "read",
                    "units": ["repo.code"],
                    "can_create_org_repo": False,
                    "visibility": "public",
                }, count=False,
            )
            if created.status != 201 or not isinstance(created.data, dict):
                raise LocalTargetError("BOOTSTRAP_FAILED")
            team = created.data
        units_map = team.get("units_map")
        units = team.get("units")
        if (team.get("name") != TEAM or team.get("description") != TEAM_DESCRIPTION
                or team.get("visibility") != "public"
                or team.get("includes_all_repositories") is not False
                or team.get("can_create_org_repo") is not False
                or not isinstance(units_map, dict)
                or units_map.get("repo.code") != "read"
                or not isinstance(units, list)
                or "repo.code" not in units
                or not isinstance(team.get("id"), int)
                or team["id"] <= 0):
            raise LocalTargetError("BOOTSTRAP_FAILED")
        return team

    @staticmethod
    def _attach_team_repositories(owner: LocalGiteaClient, team_id: int) -> None:
        for repository_name in (ORG_PUBLIC_REPOSITORY, ORG_PRIVATE_REPOSITORY):
            response = owner.request(
                "bootstrap",
                "PUT",
                team_repository_path(team_id, repository_name),
                count=False,
            )
            if response.status != 204:
                raise LocalTargetError("BOOTSTRAP_FAILED")

    def bootstrap(self) -> dict[str, Any]:
        self._require_source()
        if not self.health()["healthy"]:
            raise LocalTargetError("BOOTSTRAP_FAILED")
        self._require_active_runtime()
        passwords = self._load_secrets(create=True)
        container_id = self._owned_container_id()
        users = {identity: self._create_user(container_id, identity, passwords) for identity in IDENTITIES}
        owner = self._identity_client("repo_owner", passwords)
        repository = self._get_or_create_repository(
            owner,
            get_path=REPO_PATH,
            create_path="/api/v1/user/repos",
            owner_name=OWNER,
            repository_name=REPOSITORY,
            private=True,
            description=SYNTHETIC_DESCRIPTION,
        )
        public_repository = self._get_or_create_repository(
            owner,
            get_path=PUBLIC_REPO_PATH,
            create_path="/api/v1/user/repos",
            owner_name=OWNER,
            repository_name=PUBLIC_REPOSITORY,
            private=False,
            description=PUBLIC_DESCRIPTION,
        )
        organization = self._get_or_create_organization(
            owner,
            get_path=ORG_PATH,
            organization_name=ORGANIZATION,
            description=ORGANIZATION_DESCRIPTION,
            visibility="public",
        )
        org_public_repository = self._get_or_create_repository(
            owner,
            get_path=ORG_PUBLIC_REPO_PATH,
            create_path=f"/api/v1/orgs/{ORGANIZATION}/repos",
            owner_name=ORGANIZATION,
            repository_name=ORG_PUBLIC_REPOSITORY,
            private=False,
            description=ORG_PUBLIC_DESCRIPTION,
        )
        org_private_repository = self._get_or_create_repository(
            owner,
            get_path=ORG_PRIVATE_REPO_PATH,
            create_path=f"/api/v1/orgs/{ORGANIZATION}/repos",
            owner_name=ORGANIZATION,
            repository_name=ORG_PRIVATE_REPOSITORY,
            private=True,
            description=ORG_PRIVATE_DESCRIPTION,
        )
        limited_organization = self._get_or_create_organization(
            owner,
            get_path=LIMITED_ORG_PATH,
            organization_name=LIMITED_ORGANIZATION,
            description=LIMITED_ORGANIZATION_DESCRIPTION,
            visibility="limited",
        )
        limited_org_public_repository = self._get_or_create_repository(
            owner,
            get_path=LIMITED_ORG_PUBLIC_REPO_PATH,
            create_path=f"/api/v1/orgs/{LIMITED_ORGANIZATION}/repos",
            owner_name=LIMITED_ORGANIZATION,
            repository_name=LIMITED_ORG_PUBLIC_REPOSITORY,
            private=False,
            description=LIMITED_ORG_PUBLIC_DESCRIPTION,
        )
        team = self._get_or_create_team(owner)
        self._attach_team_repositories(owner, team["id"])
        added_to_team = owner.request(
            "bootstrap", "PUT", f"/api/v1/teams/{team['id']}/members/{COLLABORATOR}",
            count=False,
        )
        # Gitea returns 422 when this idempotent bootstrap step finds that the
        # user is already a member of the team.
        if added_to_team.status not in {204, 422}:
            raise LocalTargetError("BOOTSTRAP_FAILED")
        team_non_member = owner.request(
            "bootstrap", "DELETE", f"/api/v1/teams/{team['id']}/members/{OUTSIDER}",
            count=False,
        )
        if team_non_member.status not in {204, 404}:
            raise LocalTargetError("BOOTSTRAP_FAILED")
        org_non_member = owner.request(
            "bootstrap", "DELETE", f"/api/v1/orgs/{ORGANIZATION}/members/{OUTSIDER}",
            count=False,
        )
        if org_non_member.status not in {204, 404}:
            raise LocalTargetError("BOOTSTRAP_FAILED")
        added = owner.request(
            "bootstrap", "PUT", REPO_PATH + "/collaborators/" + COLLABORATOR,
            {"permission": "read"}, count=False,
        )
        if added.status != 204:
            raise LocalTargetError("BOOTSTRAP_FAILED")
        permission = owner.request(
            "bootstrap", "GET", REPO_PATH + "/collaborators/" + COLLABORATOR + "/permission",
            count=False,
        )
        if (permission.status != 200 or not isinstance(permission.data, dict)
                or permission.data.get("permission") != "read"):
            raise LocalTargetError("BOOTSTRAP_FAILED")
        removed = owner.request(
            "bootstrap", "DELETE", REPO_PATH + "/collaborators/" + OUTSIDER, count=False
        )
        if removed.status not in {204, 404}:
            raise LocalTargetError("BOOTSTRAP_FAILED")
        passwords = self._ensure_control_token(passwords)
        passwords = self._ensure_public_only_token(passwords)
        activity = self._control_token_client(passwords).request(
            "bootstrap", "GET", USER_FEEDS_PATH, count=False
        )
        private_activity_bucket = _activity_bucket(activity.data, OWNER + "/" + REPOSITORY)
        limited_activity_bucket = _activity_bucket(
            activity.data,
            LIMITED_ORGANIZATION + "/" + LIMITED_ORG_PUBLIC_REPOSITORY,
        )
        if activity.status != 200 or private_activity_bucket is None or limited_activity_bucket is None:
            raise LocalTargetError("BOOTSTRAP_FAILED")
        state = {
            "marker": "FINDER_LOCAL_GITEA_BOOTSTRAP_V1",
            "target_commit": self.pinned_revision,
            "users": {identity: users[identity]["id"] for identity in IDENTITIES},
            "usernames": {identity: _username(identity) for identity in IDENTITIES},
            "repository_id": repository["id"],
            "repository": OWNER + "/" + REPOSITORY,
            "private": True,
            "repositories": {
                "user_private": repository["id"],
                "user_public": public_repository["id"],
                "org_private": org_private_repository["id"],
                "org_public": org_public_repository["id"],
                "limited_org_public": limited_org_public_repository["id"],
            },
            "organization_id": organization["id"],
            "organization": ORGANIZATION,
            "limited_organization_id": limited_organization["id"],
            "limited_organization": LIMITED_ORGANIZATION,
            "team_id": team["id"],
            "team": TEAM,
            "control_scopes": ["read:organization", "read:repository", "read:user"],
            "public_only_scopes": ["public-only", "read:organization", "read:repository", "read:user"],
            "private_activity_bucket": private_activity_bucket,
            "limited_activity_bucket": limited_activity_bucket,
            "collaborator_permission": "read",
            "roles": {
                "target_owner": "repo_owner",
                "org_owner": "repo_owner",
                "team_member": "collaborator",
                "unrelated_viewer": "outsider",
                "org_non_member": "outsider",
                "team_metadata_non_member": "outsider",
            },
            "team_visibility": "public",
            "updated_at": _now(),
        }
        atomic_private_json(self.bootstrap_file, state)
        return {
            "target": self.target_id,
            "status": "ready",
            "identities": list(IDENTITIES),
            "repository": state["repository"],
            "private": True,
            "organization": ORGANIZATION,
            "limited_organization": LIMITED_ORGANIZATION,
            "team": TEAM,
            "collaborator_permission": "read",
        }

    # ----- candidate validators ----------------------------------------------
    def _validation_context(
        self, identity: str
    ) -> tuple[dict[str, Any], dict[str, str], LocalGiteaClient, LocalGiteaClient]:
        state = _read_json(self.bootstrap_file)
        if not _valid_bootstrap_state(state):
            raise LocalTargetError("VALIDATION_BLOCKED")
        passwords = self._load_secrets(create=False)
        return (
            state,
            passwords,
            self._identity_client(identity, passwords),
            self._identity_client("repo_owner", passwords),
        )

    def _token_validation_context(
        self,
    ) -> tuple[
        dict[str, Any],
        LocalGiteaClient,
        LocalGiteaClient,
    ]:
        state = _read_json(self.bootstrap_file)
        if not _valid_bootstrap_state(state):
            raise LocalTargetError("VALIDATION_BLOCKED")
        passwords = self._load_secrets(create=False)
        return (
            state,
            self._control_token_client(passwords),
            self._public_only_client(passwords),
        )

    def _role_validation_context(
        self, control_identity: str, viewer_identity: str
    ) -> tuple[dict[str, Any], LocalGiteaClient, LocalGiteaClient]:
        state = _read_json(self.bootstrap_file)
        if not _valid_bootstrap_state(state):
            raise LocalTargetError("VALIDATION_BLOCKED")
        passwords = self._load_secrets(create=False)
        return (
            state,
            self._identity_client(control_identity, passwords),
            self._identity_client(viewer_identity, passwords),
        )

    @staticmethod
    def _request_summary(method: str, path: str, expected: str, response: LocalResponse) -> dict[str, Any]:
        result = {
            "method": method,
            "path": path,
            "expected": expected,
            "status_code": response.status,
            "response_shape": response.shape,
        }
        total_count = getattr(response, "total_count", None)
        if total_count is not None:
            result["x_total_count"] = total_count
        return result

    def _save_validation(
        self,
        candidate: str,
        identity: str,
        status: str,
        requests: list[dict[str, Any]],
        count: int,
        details: dict[str, Any],
    ) -> dict[str, Any]:
        if count > REQUEST_BUDGETS[candidate]:
            raise LocalTargetError("local_request_budget_exceeded")
        assertions = details.get("assertions")
        if (not isinstance(assertions, dict) or not assertions
                or not all(isinstance(key, str) and isinstance(value, bool)
                           for key, value in assertions.items())):
            raise LocalTargetError("invalid_local_assertions")
        verified_local = status == "VERIFIED_LOCAL"
        secure_directory(self.evidence_root)
        records = Records(self.evidence_root)
        evidence = records.save("local_validation", {
            "target": self.target_id,
            "target_commit": self.pinned_revision,
            "candidate_id": candidate,
            "source_candidate_record": CANDIDATES[candidate],
            "identity": identity,
            "authenticated": True,
            "session_fingerprint": details.pop("session_fingerprint"),
            "repository": OWNER + "/" + REPOSITORY,
            "requests": requests,
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
            "automatic_confirmation": verified_local,
            "verification_scope": "pinned_local_target" if verified_local else None,
            "external_confirmation": False,
        })
        return {
            "target": self.target_id,
            "candidate": candidate,
            "status": status,
            "evidence": evidence["id"],
            "reassessment": reassessment["id"],
            "request_count": count,
            "requests": requests,
            "assertions": assertions,
            **details,
        }

    def _validate_g01(self) -> dict[str, Any]:
        _, _, outsider, owner = self._validation_context("outsider")
        membership = owner.request(
            "bootstrap", "GET", REPO_PATH + "/collaborators/" + OUTSIDER, count=False
        )
        if membership.status != 404:
            raise LocalTargetError("VALIDATION_BLOCKED")
        response = outsider.request("G01", "GET", REPO_PATH)
        returned = self._repository_matches(response.data)
        denied = response.status in {401, 403, 404}
        status = "INTENDED_BEHAVIOR" if denied else "NEEDS_MORE_EVIDENCE"
        assertions = {
            "fixture_ready": True,
            "control_passed": True,
            "security_boundary_passed": denied,
            "candidate_behavior_observed": returned,
            "reproducible": denied or returned,
            "intended_behavior_observed": denied,
        }
        return self._save_validation("G01", "outsider", status, [
            self._request_summary("GET", REPO_PATH, "deny_private_repository_metadata", response)
        ], outsider.request_count, {
            "session_fingerprint": outsider.session_fingerprint,
            "control": "DENIED" if denied else response.status,
            "synthetic_repository_returned": returned,
            "outsider_member": False,
            "assertions": assertions,
        })

    def _require_read_collaborator(self, owner: LocalGiteaClient) -> None:
        permission = owner.request(
            "bootstrap", "GET", REPO_PATH + "/collaborators/" + COLLABORATOR + "/permission",
            count=False,
        )
        if (permission.status != 200 or not isinstance(permission.data, dict)
                or permission.data.get("permission") != "read"):
            raise LocalTargetError("VALIDATION_BLOCKED")

    def _validate_g02(self) -> dict[str, Any]:
        _, _, collaborator, owner = self._validation_context("collaborator")
        self._require_read_collaborator(owner)
        response = collaborator.request("G02", "GET", REPO_PATH)
        returned = response.status == 200 and self._repository_matches(response.data)
        status = "INTENDED_BEHAVIOR" if returned else "NEEDS_MORE_EVIDENCE"
        assertions = {
            "fixture_ready": True,
            "control_passed": True,
            "security_boundary_passed": returned,
            "candidate_behavior_observed": False,
            "reproducible": returned,
            "intended_behavior_observed": returned,
        }
        return self._save_validation("G02", "collaborator", status, [
            self._request_summary("GET", REPO_PATH, "allow_read_collaborator_metadata", response)
        ], collaborator.request_count, {
            "session_fingerprint": collaborator.session_fingerprint,
            "candidate_result": response.status,
            "synthetic_repository_returned": returned,
            "collaborator_permission": "read",
            "assertions": assertions,
        })

    def _validate_g03(self) -> dict[str, Any]:
        _, _, collaborator, owner = self._validation_context("collaborator")
        self._require_read_collaborator(owner)
        response = collaborator.request("G03", "PATCH", REPO_PATH, {})
        returned = response.status == 200 and self._repository_matches(response.data)
        denied = response.status in {401, 403, 404}
        status = "INTENDED_BEHAVIOR" if denied else "NEEDS_MORE_EVIDENCE"
        assertions = {
            "fixture_ready": True,
            "control_passed": True,
            "security_boundary_passed": denied,
            "candidate_behavior_observed": returned,
            "reproducible": denied or returned,
            "intended_behavior_observed": denied,
        }
        return self._save_validation("G03", "collaborator", status, [
            self._request_summary("PATCH", REPO_PATH, "deny_read_collaborator_empty_admin_edit", response)
        ], collaborator.request_count, {
            "session_fingerprint": collaborator.session_fingerprint,
            "control": "DENIED" if denied else response.status,
            "synthetic_repository_returned": returned,
            "collaborator_permission": "read",
            "request_payload": {},
            "assertions": assertions,
        })

    def _validate_g04(self) -> dict[str, Any]:
        state, control, public_only = self._token_validation_context()
        control_repo = control.request("G04", "GET", LIMITED_ORG_PUBLIC_REPO_PATH)
        public_only_repo = public_only.request("G04", "GET", LIMITED_ORG_PUBLIC_REPO_PATH)
        candidate = public_only.request("G04", "GET", USER_FEEDS_PATH)
        marker = LIMITED_ORGANIZATION + "/" + LIMITED_ORG_PUBLIC_REPOSITORY
        candidate_has_marker = _contains_marker(candidate.data, marker)
        control_passed = bool(
            control_repo.status == 200
            and self._synthetic_repository_matches(
                control_repo.data,
                owner_name=LIMITED_ORGANIZATION,
                repository_name=LIMITED_ORG_PUBLIC_REPOSITORY,
                private=False,
                description=LIMITED_ORG_PUBLIC_DESCRIPTION,
            )
        )
        boundary_passed = public_only_repo.status in {403, 404}
        fixture_ready = bool(
            control_passed
            and boundary_passed
            and isinstance(state.get("limited_activity_bucket"), int)
            and state["limited_activity_bucket"] > 0
        )
        feed_valid = candidate.status == 200 and isinstance(candidate.data, list)
        assertions = {
            "fixture_ready": fixture_ready,
            "control_passed": control_passed,
            "security_boundary_passed": boundary_passed,
            "candidate_behavior_observed": feed_valid and candidate_has_marker,
            "reproducible": feed_valid,
            "normal_repo_access_200": control_passed,
            "public_only_repo_denied": boundary_passed,
            "public_only_feed_200": feed_valid,
            "limited_repo_marker_found": candidate_has_marker,
            "intended_behavior_observed": feed_valid and not candidate_has_marker,
        }
        status = adjudicate("G04", assertions)
        requests = [
            self._request_summary(
                "GET", LIMITED_ORG_PUBLIC_REPO_PATH,
                "normal_token_can_access_public_repo_under_limited_org", control_repo,
            ),
            self._request_summary(
                "GET", LIMITED_ORG_PUBLIC_REPO_PATH,
                "public_only_token_cannot_access_limited_org_repo", public_only_repo,
            ),
            self._request_summary(
                "GET", USER_FEEDS_PATH,
                "public_only_feed_excludes_limited_org_repo_activity", candidate,
            ),
        ]
        count = control.request_count + public_only.request_count
        return self._save_validation("G04", "public_only_repo_owner", status, requests, count, {
            "session_fingerprint": public_only.session_fingerprint,
            "fixture_ready": fixture_ready,
            "limited_activity_bucket": state["limited_activity_bucket"],
            "control_repo_access": control_repo.status,
            "public_only_repo_access": public_only_repo.status,
            "candidate_has_limited_repo_marker": candidate_has_marker,
            "assertions": assertions,
        })

    def _validate_g05(self) -> dict[str, Any]:
        state, control, public_only = self._token_validation_context()
        bucket = state["private_activity_bucket"]
        full = control.request("G05", "GET", USER_HEATMAP_PATH)
        private_repo = public_only.request("G05", "GET", REPO_PATH)
        candidate = public_only.request("G05", "GET", USER_HEATMAP_PATH)
        full_contributions = _heatmap_bucket(full.data, bucket)
        candidate_contributions = _heatmap_bucket(candidate.data, bucket)
        control_passed = bool(
            full.status == 200
            and full_contributions is not None
            and full_contributions > 0
        )
        boundary_passed = private_repo.status in {403, 404}
        fixture_ready = control_passed and boundary_passed
        candidate_valid = candidate.status == 200 and candidate_contributions is not None
        candidate_positive = bool(candidate_valid and candidate_contributions > 0)
        contributions_equal = bool(
            candidate_positive and candidate_contributions == full_contributions
        )
        assertions = {
            "fixture_ready": fixture_ready,
            "control_passed": control_passed,
            "security_boundary_passed": boundary_passed,
            "candidate_behavior_observed": contributions_equal,
            "reproducible": candidate_valid,
            "control_bucket_positive": control_passed,
            "public_only_bucket_positive": candidate_positive,
            "bucket_contributions_equal": contributions_equal,
            "public_only_private_repo_denied": boundary_passed,
            "intended_behavior_observed": bool(
                candidate_valid and candidate_contributions < full_contributions
            ),
        }
        status = adjudicate("G05", assertions)
        requests = [
            self._request_summary(
                "GET", USER_HEATMAP_PATH, "normal_token_private_activity_bucket_control", full
            ),
            self._request_summary(
                "GET", REPO_PATH, "public_only_token_cannot_access_private_repository", private_repo
            ),
            self._request_summary(
                "GET", USER_HEATMAP_PATH, "public_only_private_activity_bucket", candidate
            ),
        ]
        count = control.request_count + public_only.request_count
        return self._save_validation("G05", "public_only_repo_owner", status, requests, count, {
            "session_fingerprint": public_only.session_fingerprint,
            "fixture_ready": fixture_ready,
            "private_activity_bucket": bucket,
            "control_bucket_contributions": full_contributions,
            "candidate_bucket_contributions": candidate_contributions,
            "public_only_private_repo_access": private_repo.status,
            "assertions": assertions,
        })

    def _validate_repo_count(
        self,
        candidate_id: str,
        path: str,
        expected_public: str,
        expected_private: str,
        control_identity: str,
        viewer_identity: str,
        viewer_role: str,
    ) -> dict[str, Any]:
        _, control_client, viewer = self._role_validation_context(
            control_identity, viewer_identity
        )
        control = control_client.request(candidate_id, "GET", path)
        candidate = viewer.request(candidate_id, "GET", path)
        control_names = _repository_names(control.data)
        candidate_names = _repository_names(candidate.data)
        expected_full = {expected_public, expected_private}
        control_passed = bool(
            control.status == 200
            and isinstance(control.data, list)
            and len(control.data) == 2
            and control_names == expected_full
            and getattr(control, "total_count", None) == 2
        )
        fixture_ready = control_passed
        candidate_body_valid = bool(
            candidate.status == 200
            and isinstance(candidate.data, list)
            and len(candidate.data) == len(candidate_names)
        )
        private_exposed = expected_private in candidate_names
        security_boundary_passed = bool(
            candidate_body_valid
            and candidate_names == {expected_public}
            and not private_exposed
        )
        candidate_total = getattr(candidate, "total_count", None)
        control_total = getattr(control, "total_count", None)
        total_exceeds_body = bool(
            isinstance(candidate_total, int) and candidate_total > len(candidate_names)
        )
        total_matches_control = candidate_total == control_total
        count_exposed = bool(
            security_boundary_passed
            and total_exceeds_body
            and total_matches_control
        )
        assertions = {
            "fixture_ready": fixture_ready,
            "control_passed": control_passed,
            "security_boundary_passed": security_boundary_passed,
            "candidate_behavior_observed": count_exposed,
            "reproducible": candidate_body_valid and isinstance(candidate_total, int),
            "control_has_public_marker": expected_public in control_names,
            "control_has_private_marker": expected_private in control_names,
            "viewer_has_public_marker": expected_public in candidate_names,
            "viewer_private_marker_absent": not private_exposed,
            "total_exceeds_filtered_body": total_exceeds_body,
            "total_matches_control": total_matches_control,
            "count_includes_filtered_private_repository": count_exposed,
            "intended_behavior_observed": bool(
                security_boundary_passed and candidate_total == len(candidate_names) == 1
            ),
        }
        status = adjudicate(candidate_id, assertions)
        requests = [
            self._request_summary("GET", path, control_identity + "_repository_count_control", control),
            self._request_summary("GET", path, viewer_role + "_filtered_repository_count", candidate),
        ]
        count = control_client.request_count + viewer.request_count
        return self._save_validation(candidate_id, viewer_role, status, requests, count, {
            "session_fingerprint": viewer.session_fingerprint,
            "fixture_ready": fixture_ready,
            "control_identity": control_identity,
            "viewer_identity": viewer_identity,
            "control_repository_count": getattr(control, "total_count", None),
            "candidate_repository_count": getattr(candidate, "total_count", None),
            "candidate_body_count": len(candidate_names) if candidate_body_valid else None,
            "count_includes_filtered_private_repository": count_exposed,
            "control_public_marker": expected_public in control_names,
            "control_private_marker": expected_private in control_names,
            "candidate_public_marker": expected_public in candidate_names,
            "candidate_private_marker": private_exposed,
            "assertions": assertions,
        })

    def _validate_g06(self) -> dict[str, Any]:
        return self._validate_repo_count(
            "G06",
            USER_REPOS_PATH,
            OWNER + "/" + PUBLIC_REPOSITORY,
            OWNER + "/" + REPOSITORY,
            "repo_owner",
            "outsider",
            "unrelated_logged_in_viewer",
        )

    def _validate_g07(self) -> dict[str, Any]:
        return self._validate_repo_count(
            "G07",
            ORG_REPOS_PATH,
            ORGANIZATION + "/" + ORG_PUBLIC_REPOSITORY,
            ORGANIZATION + "/" + ORG_PRIVATE_REPOSITORY,
            "repo_owner",
            "outsider",
            "org_non_member_viewer",
        )

    def _validate_g08(self) -> dict[str, Any]:
        state = _read_json(self.bootstrap_file)
        if not _valid_bootstrap_state(state):
            raise LocalTargetError("VALIDATION_BLOCKED")
        return self._validate_repo_count(
            "G08",
            f"/api/v1/teams/{state['team_id']}/repos?limit=50",
            ORGANIZATION + "/" + ORG_PUBLIC_REPOSITORY,
            ORGANIZATION + "/" + ORG_PRIVATE_REPOSITORY,
            "collaborator",
            "outsider",
            "team_metadata_non_member_viewer",
        )

    def validate(self, candidate: str | None = None) -> list[dict[str, Any]]:
        if candidate is not None and candidate not in self.supported_candidates:
            raise LocalTargetError("unknown_local_candidate")
        if not self.health()["healthy"]:
            raise LocalTargetError("VALIDATION_BLOCKED")
        self._require_active_runtime()
        selected = [candidate] if candidate else list(CANDIDATES)
        methods = {
            "G01": self._validate_g01,
            "G02": self._validate_g02,
            "G03": self._validate_g03,
            "G04": self._validate_g04,
            "G05": self._validate_g05,
            "G06": self._validate_g06,
            "G07": self._validate_g07,
            "G08": self._validate_g08,
        }
        return [methods[value]() for value in selected]

    def hunt(self) -> dict[str, Any]:
        current = self.status()
        if current.get("health") != "healthy":
            raise LocalTargetError("VALIDATION_BLOCKED")
        bootstrapped = current.get("synthetic_bootstrap_status") != "ready"
        if bootstrapped:
            self.bootstrap()
        results = []
        for candidate in CANDIDATES:
            try:
                results.extend(self.validate(candidate))
            except LocalTargetError as error:
                if error.code not in {"VALIDATION_BLOCKED", "BOOTSTRAP_FAILED", "local_http_failed"}:
                    raise
                required = VERIFICATION_ASSERTIONS.get(candidate)
                assertions = (
                    {**{key: False for key in required}, "intended_behavior_observed": False}
                    if required is not None else {
                        "fixture_ready": False,
                        "control_passed": False,
                        "security_boundary_passed": False,
                        "candidate_behavior_observed": False,
                        "reproducible": False,
                        "intended_behavior_observed": False,
                    }
                )
                results.append(self._save_validation(
                    candidate,
                    "hunt_orchestrator",
                    "BLOCKED_BY_LOCAL_SETUP",
                    [],
                    0,
                    {
                        "session_fingerprint": "unavailable",
                        "fixture_ready": False,
                        "blocked_reason": error.code,
                        "assertions": assertions,
                    },
                ))
        artifacts = create_hunt_reports(
            self.root,
            target=self.target_id,
            version=GITEA_VERSION,
            commit=self.pinned_revision,
            results=results,
        )
        summary = artifacts["summary"]
        return {
            "target": self.target_id,
            "version": GITEA_VERSION,
            "commit": self.pinned_revision,
            "bootstrap_performed": bootstrapped,
            **summary,
            "root_cause_clusters": [
                {"id": item["id"], "candidates": item["candidate_ids"]}
                for item in artifacts["clusters"]
            ],
            "reports": artifacts["report_directory"],
            "json_report": artifacts["json_report"],
            "markdown_report": artifacts["markdown_report"],
            "poc_scripts": artifacts["poc_scripts"],
            "human_action_required": "Review report before any external disclosure/submission.",
            "external_submission_performed": False,
            "results": results,
        }


def _password() -> str:
    return "Gh9!" + secrets.token_urlsafe(28)


def _username(identity: str) -> str:
    return "finder-local-" + identity.replace("_", "-")


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
            and value.get("marker") == "FINDER_LOCAL_GITEA_BOOTSTRAP_V1"
            and value.get("target_commit") == GiteaAdapter.pinned_revision
            and set(value.get("users", {})) == set(IDENTITIES)
            and all(isinstance(value["users"][identity], int) and value["users"][identity] > 0 for identity in IDENTITIES)
            and value.get("usernames") == {identity: _username(identity) for identity in IDENTITIES}
            and isinstance(value.get("repository_id"), int)
            and value.get("repository") == OWNER + "/" + REPOSITORY
            and value.get("private") is True
            and set(value.get("repositories", {})) == {
                "user_private", "user_public", "org_private", "org_public",
                "limited_org_public",
            }
            and all(isinstance(item, int) and item > 0 for item in value["repositories"].values())
            and value.get("organization") == ORGANIZATION
            and isinstance(value.get("organization_id"), int)
            and value["organization_id"] > 0
            and value.get("limited_organization") == LIMITED_ORGANIZATION
            and isinstance(value.get("limited_organization_id"), int)
            and value["limited_organization_id"] > 0
            and value.get("team") == TEAM
            and isinstance(value.get("team_id"), int)
            and value["team_id"] > 0
            and value.get("control_scopes") == [
                "read:organization", "read:repository", "read:user",
            ]
            and value.get("public_only_scopes") == [
                "public-only", "read:organization", "read:repository", "read:user",
            ]
            and isinstance(value.get("private_activity_bucket"), int)
            and not isinstance(value["private_activity_bucket"], bool)
            and value["private_activity_bucket"] > 0
            and isinstance(value.get("limited_activity_bucket"), int)
            and not isinstance(value["limited_activity_bucket"], bool)
            and value["limited_activity_bucket"] > 0
            and value.get("collaborator_permission") == "read"
            and value.get("roles") == {
                "target_owner": "repo_owner",
                "org_owner": "repo_owner",
                "team_member": "collaborator",
                "unrelated_viewer": "outsider",
                "org_non_member": "outsider",
                "team_metadata_non_member": "outsider",
            }
            and value.get("team_visibility") == "public"
        )
    except (TypeError, KeyError):
        return False


def _contains_marker(value: Any, marker: str) -> bool:
    if isinstance(value, str):
        return marker in value
    if isinstance(value, dict):
        return any(_contains_marker(item, marker) for item in value.values())
    if isinstance(value, list):
        return any(_contains_marker(item, marker) for item in value)
    return False


def _activity_bucket(value: Any, repository: str) -> int | None:
    if not isinstance(value, list):
        return None
    for item in value:
        if (not isinstance(item, dict) or item.get("op_type") != "create_repo"
                or not _contains_marker(item.get("repo"), repository)):
            continue
        created = item.get("created")
        if not isinstance(created, str):
            return None
        try:
            timestamp = int(datetime.fromisoformat(created.replace("Z", "+00:00")).timestamp())
        except (ValueError, OverflowError):
            return None
        return timestamp // 900 * 900
    return None


def _heatmap_bucket(value: Any, bucket: int) -> int | None:
    if not isinstance(value, list) or isinstance(bucket, bool) or not isinstance(bucket, int):
        return None
    contribution = 0
    matched = False
    for item in value:
        if not isinstance(item, dict):
            return None
        timestamp = item.get("timestamp")
        count = item.get("contributions")
        if (isinstance(timestamp, bool) or not isinstance(timestamp, int)
                or isinstance(count, bool) or not isinstance(count, int) or count < 0):
            return None
        if timestamp == bucket:
            if matched:
                return None
            contribution = count
            matched = True
    return contribution


def _repository_names(value: Any) -> set[str]:
    if not isinstance(value, list):
        return set()
    return {
        item["full_name"]
        for item in value
        if isinstance(item, dict) and isinstance(item.get("full_name"), str)
    }
