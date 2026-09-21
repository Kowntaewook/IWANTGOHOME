import importlib.util
import json
from pathlib import Path
import stat
import subprocess

import pytest
import yaml

from ctf_mcp.local_targets.base import LocalTargetError, LocalTargetManifest, load_adapter
from ctf_mcp.local_targets.gitea import (
    CANDIDATES,
    COMPOSE,
    COMPOSE_PROJECT,
    GITEA_IMAGE,
    GITEA_IMAGE_DIGEST,
    GITEA_IMAGE_REFERENCE,
    GITEA_VERSION,
    LIMITED_ORGANIZATION_DESCRIPTION,
    LIMITED_ORG_PUBLIC_DESCRIPTION,
    ORGANIZATION_DESCRIPTION,
    ORG_PRIVATE_DESCRIPTION,
    ORG_PUBLIC_DESCRIPTION,
    PUBLIC_DESCRIPTION,
    REQUEST_BUDGETS,
    SYNTHETIC_DESCRIPTION,
    TEAM_DESCRIPTION,
    GiteaAdapter,
    _activity_bucket,
    _heatmap_bucket,
    _valid_bootstrap_state,
)
from ctf_mcp.local_targets.gitea_http import (
    COLLABORATOR,
    GITEA_ALLOWED,
    GiteaResponse,
    LIMITED_ORGANIZATION,
    LIMITED_ORG_PUBLIC_REPOSITORY,
    LIMITED_ORG_PUBLIC_REPO_PATH,
    ORGANIZATION,
    ORG_PRIVATE_REPOSITORY,
    ORG_PUBLIC_REPOSITORY,
    ORG_REPOS_PATH,
    OUTSIDER,
    OWNER,
    PUBLIC_REPOSITORY,
    REPOSITORY,
    REPO_PATH,
    TEAM,
    USER_FEEDS_PATH,
    USER_HEATMAP_PATH,
    USER_REPOS_PATH,
    LocalGiteaClient,
    _total_count,
    team_repository_path,
)
from ctf_mcp.local_targets.gitea_hunt import (
    VERIFICATION_ASSERTIONS,
    adjudicate,
    cluster_verified,
    create_hunt_reports,
)
from ctf_mcp.local_targets.http import LocalResponse, response_shape
from ctf_mcp.local_targets.mattermost import MattermostAdapter


REVISION = GiteaAdapter.pinned_revision


def manifest():
    return LocalTargetManifest(
        "gitea",
        GiteaAdapter.repository,
        REVISION,
        "http://127.0.0.1:13000/api/healthz",
    )


def adapter(tmp_path, **kwargs):
    return GiteaAdapter(tmp_path, manifest(), **kwargs)


def write_manifest(root, target, repository, revision, health):
    config = root / "config/local-targets"
    config.mkdir(parents=True, exist_ok=True)
    (config / f"{target}.json").write_text(json.dumps({
        "target_id": target,
        "repository": repository,
        "revision": revision,
        "host_health_url": health,
    }))


class GitRunner:
    def __init__(self, origin=GiteaAdapter.repository, head=REVISION):
        self.origin, self.head, self.calls = origin, head, []

    def run(self, argv, **kwargs):
        self.calls.append((list(argv), kwargs))
        if argv[-3:] == ["remote", "get-url", "origin"]:
            output = self.origin + "\n"
        elif argv[-2:] == ["rev-parse", "HEAD"]:
            output = self.head + "\n"
        else:
            output = ""
        return subprocess.CompletedProcess(argv, 0, output, "")


def make_source(value):
    (value.target_root / ".git").mkdir(parents=True)
    (value.target_root / ".git/config").write_text("[core]\n\trepositoryformatversion = 0\n")
    (value.target_root / "go.mod").write_text("module code.gitea.io/gitea\n")


def repository_data(repository_id=42):
    return {
        "id": repository_id,
        "name": REPOSITORY,
        "full_name": OWNER + "/" + REPOSITORY,
        "private": True,
        "description": SYNTHETIC_DESCRIPTION,
        "owner": {"login": OWNER},
    }


def bootstrap_state():
    return {
        "marker": "FINDER_LOCAL_GITEA_BOOTSTRAP_V1",
        "target_commit": REVISION,
        "users": {name: number for number, name in enumerate(
            ("system_admin", "repo_owner", "collaborator", "outsider"), 1)},
        "usernames": {
            "system_admin": "finder-local-system-admin",
            "repo_owner": OWNER,
            "collaborator": COLLABORATOR,
            "outsider": OUTSIDER,
        },
        "repository_id": 42,
        "repository": OWNER + "/" + REPOSITORY,
        "private": True,
        "repositories": {
            "user_private": 42,
            "user_public": 43,
            "org_private": 44,
            "org_public": 45,
            "limited_org_public": 46,
        },
        "organization_id": 5,
        "organization": ORGANIZATION,
        "limited_organization_id": 7,
        "limited_organization": LIMITED_ORGANIZATION,
        "team_id": 6,
        "team": TEAM,
        "control_scopes": ["read:organization", "read:repository", "read:user"],
        "public_only_scopes": [
            "public-only", "read:organization", "read:repository", "read:user",
        ],
        "private_activity_bucket": 1789849800,
        "limited_activity_bucket": 1789849800,
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
        "updated_at": "2026-01-01T00:00:00+00:00",
    }


def test_target_registry_selects_mattermost_and_gitea(tmp_path):
    write_manifest(
        tmp_path, "mattermost", MattermostAdapter.repository, MattermostAdapter.pinned_revision,
        MattermostAdapter.host_health_url,
    )
    write_manifest(
        tmp_path, "gitea", GiteaAdapter.repository, GiteaAdapter.pinned_revision,
        GiteaAdapter.host_health_url,
    )
    assert isinstance(load_adapter(tmp_path, "mattermost"), MattermostAdapter)
    assert isinstance(load_adapter(tmp_path, "gitea"), GiteaAdapter)
    with pytest.raises(LocalTargetError, match="invalid_local_target"):
        load_adapter(tmp_path, "unknown")


def test_gitea_manifest_is_metadata_only_and_must_match_adapter(tmp_path):
    write_manifest(
        tmp_path, "gitea", "https://invalid.example/gitea", REVISION,
        GiteaAdapter.host_health_url,
    )
    with pytest.raises(LocalTargetError, match="invalid_local_target_manifest"):
        load_adapter(tmp_path, "gitea")
    write_manifest(
        tmp_path, "gitea", GiteaAdapter.repository, "0" * 40,
        GiteaAdapter.host_health_url,
    )
    with pytest.raises(LocalTargetError, match="invalid_local_target_manifest"):
        load_adapter(tmp_path, "gitea")


def test_registry_is_explicit_and_does_not_import_target_names_dynamically():
    code = (Path(__file__).resolve().parents[1] / "src/ctf_mcp/local_targets/base.py").read_text()
    assert 'target_id not in {"mattermost", "gitea"}' in code
    assert "import_module" not in code
    assert "__import__" not in code


def test_gitea_repository_revision_and_health_are_independently_pinned():
    assert GiteaAdapter.repository == "https://github.com/go-gitea/gitea"
    assert REVISION == "146cc3eec57174711eac0e0a0c7b38670c6e3922"
    assert GiteaAdapter.host_health_url == "http://127.0.0.1:13000/api/healthz"
    assert GiteaAdapter.supported_candidates == {
        "G01", "G02", "G03", "G04", "G05", "G06", "G07", "G08",
    }
    assert MattermostAdapter.supported_candidates == {"S12", "S13", "S15"}


def test_gitea_compose_is_single_service_digest_pinned_and_localhost_only():
    local = yaml.safe_load(COMPOSE)
    assert local["name"] == COMPOSE_PROJECT
    assert set(local["services"]) == {"gitea"}
    service = local["services"]["gitea"]
    assert GITEA_IMAGE == "docker.gitea.com/gitea:1.27.3-rootless"
    assert GITEA_IMAGE_DIGEST == "sha256:1c17ecaead42eb3b5391553d8708103a4beb0e86edf5b9ebc1eb269c318845f2"
    assert service["image"] == GITEA_IMAGE_REFERENCE
    assert service["ports"] == ["127.0.0.1:13000:3000"]
    assert service["environment"]["GITEA__database__DB_TYPE"] == "sqlite3"
    assert service["environment"]["GITEA__server__DISABLE_SSH"] == "true"
    assert set(service["volumes"]) == {
        "gitea-data:/var/lib/gitea", "gitea-config:/etc/gitea",
    }
    assert "local-target" in local["networks"]
    assert local["networks"]["local-target"] == {}
    text = COMPOSE.lower()
    assert "internal: true" not in text
    assert "0.0.0.0" not in text
    assert "/var/run/docker.sock" not in text
    assert "privileged" not in text
    assert "network_mode" not in text and "host network" not in text


def test_all_local_target_subprocesses_keep_shell_disabled():
    root = Path(__file__).resolve().parents[1]
    code = "\n".join(path.read_text() for path in (root / "src/ctf_mcp/local_targets").glob("*.py"))
    assert "shell=True" not in code and "shell = True" not in code
    assert "/var/run/docker.sock" not in code


def test_gitea_health_client_and_routes_are_fixed_to_localhost():
    assert LocalGiteaClient.host == "127.0.0.1"
    assert LocalGiteaClient.port == 13000
    assert any(method == "GET" and pattern.fullmatch("/api/healthz")
               for method, pattern in GITEA_ALLOWED["health"])
    client = LocalGiteaClient("finder-local-outsider", "synthetic-password")
    with pytest.raises(LocalTargetError, match="local_route_not_allowed"):
        client.request("G01", "GET", REPO_PATH + "/unreviewed")
    token_client = LocalGiteaClient(
        token="finder-local-synthetic-token-value",
        identity_label="finder-local-public-only-token",
    )
    assert token_client.session_fingerprint is not None
    assert _total_count("2") == 2
    assert _total_count("invalid") is None


def test_health_requires_valid_shape_and_owned_container(tmp_path, monkeypatch):
    class Client:
        def __init__(self, timeout=5):
            pass

        def request(self, *args, **kwargs):
            return LocalResponse(200, {"status": "pass", "description": "Gitea", "checks": {}}, {})

    value = adapter(tmp_path, client_factory=Client)
    value._write_runtime_files()
    monkeypatch.setattr("ctf_mcp.local_targets.gitea.shutil.which", lambda _: "/fixed/docker")
    monkeypatch.setattr(value, "_running_services", lambda timeout: {"gitea"})
    monkeypatch.setattr(value, "_verify_owned_gitea_container", lambda probe_version=False: None)
    assert value.health()["healthy"] is True

    class InvalidClient(Client):
        def request(self, *args, **kwargs):
            return LocalResponse(200, {"status": "pass"}, {})

    value.client_factory = InvalidClient
    assert value.health()["healthy"] is False


def test_runtime_file_tamper_and_symlink_are_rejected(tmp_path):
    value = adapter(tmp_path)
    value.runtime_root.mkdir(parents=True)
    value.compose_file.write_text(COMPOSE + "\nservices: {}\n")
    with pytest.raises(LocalTargetError, match="unsafe_local_runtime"):
        value._compose(["stop", "gitea"], timeout=1)
    value.compose_file.unlink()
    external = tmp_path / "outside.yaml"
    external.write_text(COMPOSE)
    value.compose_file.symlink_to(external)
    with pytest.raises(LocalTargetError, match="unsafe_local_runtime"):
        value._compose(["stop", "gitea"], timeout=1)


def test_source_origin_revision_dirty_and_symlink_mismatch(tmp_path):
    wrong_origin = adapter(tmp_path / "origin", runner=GitRunner(origin="https://invalid.example/gitea"))
    make_source(wrong_origin)
    with pytest.raises(LocalTargetError, match="REPOSITORY_MISMATCH"):
        wrong_origin.prepare()

    wrong_revision = adapter(tmp_path / "revision", runner=GitRunner(head="0" * 40))
    make_source(wrong_revision)
    with pytest.raises(LocalTargetError, match="REVISION_MISMATCH"):
        wrong_revision.prepare()

    dirty_runner = GitRunner()
    dirty = adapter(tmp_path / "dirty", runner=dirty_runner)
    make_source(dirty)
    original = dirty_runner.run

    def dirty_run(argv, **kwargs):
        if argv[-3:] == ["status", "--porcelain", "--untracked-files=normal"]:
            return subprocess.CompletedProcess(argv, 0, "modified\n", "")
        return original(argv, **kwargs)

    dirty_runner.run = dirty_run
    with pytest.raises(LocalTargetError, match="SOURCE_DIRTY"):
        dirty._require_source()

    linked = adapter(tmp_path / "linked", runner=GitRunner())
    outside = tmp_path / "outside-source"
    outside.mkdir()
    linked.targets_root.mkdir(parents=True)
    linked.target_root.symlink_to(outside, target_is_directory=True)
    with pytest.raises(LocalTargetError, match="REPOSITORY_MISMATCH"):
        linked.prepare()


def test_source_rejects_active_git_extensions(tmp_path):
    value = adapter(tmp_path, runner=GitRunner())
    make_source(value)
    (value.target_root / ".git/config").write_text(
        "[core]\n\trepositoryformatversion = 0\n[includeIf \"gitdir:/**\"]\n\tpath=/tmp/unsafe\n"
    )
    with pytest.raises(LocalTargetError, match="REPOSITORY_MISMATCH"):
        value.prepare()
    (value.target_root / ".git/config").write_text(
        "[core]\n\trepositoryformatversion = 0\n[credential]\n\thelper = /tmp/unsafe\n"
    )
    with pytest.raises(LocalTargetError, match="REPOSITORY_MISMATCH"):
        value.prepare()


def test_image_digest_and_running_container_identity_are_exact(tmp_path):
    image_id = "sha256:" + "1" * 64

    class Runner:
        def run(self, argv, **kwargs):
            if argv[:3] == ["docker", "image", "inspect"]:
                data = [{"RepoDigests": ["docker.gitea.com/gitea@" + GITEA_IMAGE_DIGEST], "Id": image_id}]
            elif argv[:4] == ["docker", "compose", "-p", COMPOSE_PROJECT] and argv[-3:] == ["ps", "-q", "gitea"]:
                return subprocess.CompletedProcess(argv, 0, "a" * 64 + "\n", "")
            elif argv[:3] == ["docker", "container", "inspect"]:
                data = [{
                    "Config": {
                        "Image": GITEA_IMAGE_REFERENCE,
                        "Labels": {
                            "com.docker.compose.project": COMPOSE_PROJECT,
                            "com.docker.compose.service": "gitea",
                        },
                    },
                    "State": {"Running": True},
                    "Image": image_id,
                }]
            else:
                return subprocess.CompletedProcess(argv, 0, "", "")
            return subprocess.CompletedProcess(argv, 0, json.dumps(data), "")

    value = adapter(tmp_path, runner=Runner())
    value._write_runtime_files()
    assert value._inspect_image(timeout=1, allow_missing=False)["digest"] == GITEA_IMAGE_DIGEST
    assert value._owned_container_id() == "a" * 64


def test_image_and_container_mismatch_fail_with_stable_codes(tmp_path):
    class BadImageRunner:
        def run(self, argv, **kwargs):
            data = [{"RepoDigests": ["docker.gitea.com/gitea@sha256:" + "0" * 64],
                     "Id": "sha256:" + "1" * 64}]
            return subprocess.CompletedProcess(argv, 0, json.dumps(data), "")

    with pytest.raises(LocalTargetError, match="IMAGE_MISMATCH"):
        adapter(tmp_path / "image", runner=BadImageRunner())._inspect_image(timeout=1, allow_missing=False)

    image_id = "sha256:" + "1" * 64

    class BadContainerRunner:
        def run(self, argv, **kwargs):
            if argv[:3] == ["docker", "image", "inspect"]:
                data = [{"RepoDigests": ["docker.gitea.com/gitea@" + GITEA_IMAGE_DIGEST], "Id": image_id}]
                return subprocess.CompletedProcess(argv, 0, json.dumps(data), "")
            if argv[:3] == ["docker", "container", "inspect"]:
                data = [{"Config": {"Image": "wrong", "Labels": {
                    "com.docker.compose.project": COMPOSE_PROJECT,
                    "com.docker.compose.service": "gitea",
                }}, "State": {"Running": True}, "Image": image_id}]
                return subprocess.CompletedProcess(argv, 0, json.dumps(data), "")
            return subprocess.CompletedProcess(argv, 0, "a" * 64 + "\n", "")

    value = adapter(tmp_path / "container", runner=BadContainerRunner())
    value._write_runtime_files()
    with pytest.raises(LocalTargetError, match="IMAGE_MISMATCH"):
        value._owned_container_id()


def test_gitea_version_probe_requires_exact_1273():
    assert GiteaAdapter._validate_version("Gitea version 1.27.3 built with GNU Make") == GITEA_VERSION
    with pytest.raises(LocalTargetError, match="IMAGE_MISMATCH"):
        GiteaAdapter._validate_version("Gitea version 1.27.2 built with GNU Make")


def test_secret_store_permissions_and_evidence_redaction(tmp_path):
    value = adapter(tmp_path)
    passwords = value._load_secrets(create=True)
    passwords["control_token"] = "finder-local-control-token-secret"
    passwords["public_only_token"] = "finder-local-public-only-token-secret"
    assert stat.S_IMODE(value.secret_root.stat().st_mode) == 0o700
    assert stat.S_IMODE(value.secrets_file.stat().st_mode) == 0o600
    result = value._save_validation("G01", "outsider", "INTENDED_BEHAVIOR", [], 0, {
        "session_fingerprint": "0123456789abcdef",
        "control": "DENIED",
        "assertions": {"fixture_ready": True},
    })
    raw = "\n".join(path.read_text() for path in value.evidence_root.glob("*.json"))
    assert result["status"] == "INTENDED_BEHAVIOR"
    assert not any(secret in raw for secret in passwords.values())
    assert str(value.secret_root) not in raw
    assert "Authorization" not in raw and "Basic " not in raw


def test_public_only_token_is_private_and_never_printed(tmp_path, monkeypatch, capsys):
    value = adapter(tmp_path)
    passwords = value._load_secrets(create=True)
    token = "finder-local-public-only-token-secret-value"

    class OwnerClient:
        def request(self, scope, method, path, payload=None, *, count=True):
            if method == "DELETE":
                return LocalResponse(404, None, "null")
            if method == "POST":
                return LocalResponse(201, {
                    "name": "finder-local-public-only",
                    "sha1": token,
                    "scopes": ["public-only", "read:organization", "read:repository", "read:user"],
                }, {})
            raise AssertionError((scope, method, path, payload))

    class TokenClient:
        def request(self, scope, method, path, payload=None, *, count=True):
            if scope == "identity":
                return LocalResponse(200, {"login": OWNER}, {"login": "str"})
            if scope == "token_identity":
                return LocalResponse(200, {
                    "name": "finder-local-public-only",
                    "scopes": ["public-only", "read:organization", "read:repository", "read:user"],
                    "user": {"login": OWNER},
                }, {})
            raise AssertionError((scope, method, path))

    monkeypatch.setattr(value, "_identity_client", lambda identity, secrets: OwnerClient())
    monkeypatch.setattr(
        value, "_token_client", lambda secrets, secret_name, identity_label: TokenClient()
    )
    updated = value._ensure_public_only_token(passwords)
    assert updated["public_only_token"] == token
    assert stat.S_IMODE(value.secrets_file.stat().st_mode) == 0o600
    assert json.loads(value.secrets_file.read_text())["public_only_token"] == token
    assert capsys.readouterr().out == ""


def test_repository_bootstrap_is_idempotent_and_keeps_private_repository(tmp_path):
    value = adapter(tmp_path)
    existing = {"repository": None, "post_count": 0}

    class OwnerClient:
        session_fingerprint = "owner-fingerprint"
        request_count = 0

        def request(self, scope, method, path, payload=None, *, count=True):
            if method == "GET" and path == REPO_PATH:
                return LocalResponse(404 if existing["repository"] is None else 200,
                                     existing["repository"], response_shape(existing["repository"]))
            if method == "POST" and path == "/api/v1/user/repos":
                existing["post_count"] += 1
                existing["repository"] = repository_data()
                return LocalResponse(201, existing["repository"], response_shape(existing["repository"]))
            raise AssertionError((scope, method, path, payload))

    client = OwnerClient()
    first = value._get_or_create_repository(
        client,
        get_path=REPO_PATH,
        create_path="/api/v1/user/repos",
        owner_name=OWNER,
        repository_name=REPOSITORY,
        private=True,
        description=SYNTHETIC_DESCRIPTION,
    )
    second = value._get_or_create_repository(
        client,
        get_path=REPO_PATH,
        create_path="/api/v1/user/repos",
        owner_name=OWNER,
        repository_name=REPOSITORY,
        private=True,
        description=SYNTHETIC_DESCRIPTION,
    )
    assert first == second == repository_data()
    assert existing["post_count"] == 1


def test_bootstrap_rerun_records_fixtures_roles_tokens_and_activity_buckets(tmp_path, monkeypatch):
    value = adapter(tmp_path)
    events = []

    class OwnerClient:
        session_fingerprint = "owner-fingerprint"

        def __init__(self):
            self.request_count = 0
            self.calls = []
            self.team = None
            self.team_member_additions = 0

        def request(self, scope, method, path, payload=None, *, count=True):
            self.calls.append((scope, method, path, payload, count))
            events.append(method + " " + path)
            if method == "GET" and path == "/api/v1/orgs/finder-local-org/teams?limit=50":
                return LocalResponse(200, [] if self.team is None else [self.team], "list[dict]")
            if method == "POST" and path == "/api/v1/orgs/finder-local-org/teams":
                self.team = {
                    "id": 6,
                    "name": TEAM,
                    "description": TEAM_DESCRIPTION,
                    "visibility": "public",
                    "permission": "read",
                    "includes_all_repositories": False,
                    "can_create_org_repo": False,
                    "units_map": {"repo.code": "read"},
                    "units": ["repo.code"],
                }
                return LocalResponse(201, self.team, response_shape(self.team))
            if method == "PUT" and path.endswith("/members/" + COLLABORATOR):
                self.team_member_additions += 1
                return LocalResponse(
                    204 if self.team_member_additions == 1 else 422,
                    None,
                    "null",
                )
            if method == "PUT":
                return LocalResponse(204, None, "null")
            if method == "GET" and path.endswith("/permission"):
                return LocalResponse(200, {"permission": "read"}, {"permission": "str"})
            if method == "DELETE":
                return LocalResponse(204, None, "null")
            raise AssertionError((scope, method, path, payload))

    class FeedClient:
        session_fingerprint = "control-token-fingerprint"
        request_count = 0

        def request(self, scope, method, path, payload=None, *, count=True):
            assert (scope, method, path, count) == ("bootstrap", "GET", USER_FEEDS_PATH, False)
            return LocalResponse(200, [
                {
                    "op_type": "create_repo",
                    "repo": {"full_name": OWNER + "/" + REPOSITORY},
                    "created": "2026-09-20T12:03:00Z",
                },
                {
                    "op_type": "create_repo",
                    "repo": {
                        "full_name": LIMITED_ORGANIZATION + "/" + LIMITED_ORG_PUBLIC_REPOSITORY,
                    },
                    "created": "2026-09-20T12:04:00Z",
                },
            ], "list[dict]")

    ids = {
        REPOSITORY: 42,
        PUBLIC_REPOSITORY: 43,
        ORG_PRIVATE_REPOSITORY: 44,
        ORG_PUBLIC_REPOSITORY: 45,
        LIMITED_ORG_PUBLIC_REPOSITORY: 46,
    }

    def fake_repository(client, **values):
        return {
            "id": ids[values["repository_name"]],
            "name": values["repository_name"],
            "full_name": values["owner_name"] + "/" + values["repository_name"],
            "private": values["private"],
            "description": values["description"],
            "owner": {"login": values["owner_name"]},
        }

    monkeypatch.setattr(value, "_require_source", lambda: None)
    monkeypatch.setattr(value, "health", lambda timeout=2: {"healthy": True})
    monkeypatch.setattr(value, "_require_active_runtime", lambda: GITEA_VERSION)
    monkeypatch.setattr(value, "_owned_container_id", lambda: "a" * 64)
    monkeypatch.setattr(value, "_create_user", lambda container, identity, passwords: {
        "id": list(("system_admin", "repo_owner", "collaborator", "outsider")).index(identity) + 1
    })
    owner_client = OwnerClient()
    monkeypatch.setattr(value, "_identity_client", lambda identity, passwords: owner_client)
    monkeypatch.setattr(value, "_get_or_create_repository", fake_repository)
    monkeypatch.setattr(value, "_get_or_create_organization", lambda owner, **values: {
        "id": 5 if values["organization_name"] == ORGANIZATION else 7,
        "username": values["organization_name"],
        "description": values["description"],
        "visibility": values["visibility"],
    })
    def ensure_control(passwords):
        events.append("TOKEN control")
        return {**passwords, "control_token": "finder-local-control-token-secret"}

    def ensure_public_only(passwords):
        events.append("TOKEN public-only")
        return {**passwords, "public_only_token": "finder-local-public-only-token-secret"}

    monkeypatch.setattr(value, "_ensure_control_token", ensure_control)
    monkeypatch.setattr(value, "_ensure_public_only_token", ensure_public_only)
    monkeypatch.setattr(value, "_control_token_client", lambda passwords: FeedClient())
    first = value.bootstrap()
    second = value.bootstrap()
    assert first == second
    assert first["organization"] == ORGANIZATION and first["team"] == TEAM
    assert first["limited_organization"] == LIMITED_ORGANIZATION
    assert owner_client.team_member_additions == 2
    assert _valid_bootstrap_state(json.loads(value.bootstrap_file.read_text()))
    team_repo_puts = [
        call for call in owner_client.calls
        if call[1] == "PUT" and "/repos/" in call[2] and "/teams/" in call[2]
    ]
    assert len(team_repo_puts) == 4
    created_team = events.index("POST /api/v1/orgs/finder-local-org/teams")
    first_team_repo = "PUT " + team_repository_path(6, ORG_PUBLIC_REPOSITORY)
    assert events[created_team + 1] == first_team_repo
    control_token_steps = [index for index, event in enumerate(events) if event == "TOKEN control"]
    public_token_steps = [index for index, event in enumerate(events) if event == "TOKEN public-only"]
    private_team_repo = "PUT " + team_repository_path(6, ORG_PRIVATE_REPOSITORY)
    assert len(control_token_steps) == len(public_token_steps) == 2
    for run_number, (control_index, public_index) in enumerate(
        zip(control_token_steps, public_token_steps, strict=True), 1
    ):
        assert control_index < public_index
        assert events[:control_index].count(first_team_repo) == run_number
        assert events[:control_index].count(private_team_repo) == run_number


def test_team_repository_bootstrap_route_reaches_transport_and_is_idempotent(
    tmp_path, monkeypatch,
):
    value = adapter(tmp_path)
    requests = []

    class Response:
        status = 204

        @staticmethod
        def read(size):
            return b""

        @staticmethod
        def getheader(name):
            return None

    class Connection:
        def __init__(self, host, port, timeout):
            assert (host, port) == ("127.0.0.1", 13000)

        def request(self, method, path, body=None, headers=None):
            requests.append((method, path))

        @staticmethod
        def getresponse():
            return Response()

        @staticmethod
        def close():
            pass

    monkeypatch.setattr(
        "ctf_mcp.local_targets.gitea_http.http.client.HTTPConnection", Connection
    )
    owner = LocalGiteaClient(OWNER, "finder-local-owner-password")
    value._attach_team_repositories(owner, 6)
    value._attach_team_repositories(owner, 6)
    expected = [
        ("PUT", team_repository_path(6, ORG_PUBLIC_REPOSITORY)),
        ("PUT", team_repository_path(6, ORG_PRIVATE_REPOSITORY)),
    ]
    assert requests == expected * 2

    with pytest.raises(LocalTargetError, match="local_route_not_allowed"):
        owner.request(
            "bootstrap", "PUT", "/api/v1/teams/6/repos/finder-local-org/unreviewed",
            count=False,
        )
    with pytest.raises(LocalTargetError, match="local_route_not_allowed"):
        team_repository_path(6, "unreviewed")
    assert requests == expected * 2


def test_team_repository_bootstrap_rejects_non_idempotent_422(tmp_path):
    value = adapter(tmp_path)

    rejected = SequenceClient([(204, None), (422, {"message": "unexpected"})])
    with pytest.raises(LocalTargetError, match="BOOTSTRAP_FAILED"):
        value._attach_team_repositories(rejected, 6)


class SequenceClient:
    def __init__(self, responses, fingerprint="0123456789abcdef"):
        self.responses = list(responses)
        self.request_count = 0
        self.session_fingerprint = fingerprint
        self.calls = []

    def request(self, scope, method, path, payload=None, *, count=True):
        self.calls.append((scope, method, path, payload, count))
        if count:
            self.request_count += 1
        response = self.responses.pop(0)
        status, data = response[:2]
        total_count = response[2] if len(response) == 3 else None
        return GiteaResponse(status, data, response_shape(data), total_count)


def test_g01_g02_g03_authorization_controls_and_budgets(tmp_path, monkeypatch):
    assert {candidate: REQUEST_BUDGETS[candidate] for candidate in ("G01", "G02", "G03")} == {
        "G01": 1, "G02": 1, "G03": 1,
    }
    value = adapter(tmp_path)

    outsider = SequenceClient([(404, {"message": "not found"})])
    owner = SequenceClient([(404, None)])
    monkeypatch.setattr(value, "_validation_context", lambda identity: (bootstrap_state(), {}, outsider, owner))
    g01 = value._validate_g01()
    assert g01["status"] == "INTENDED_BEHAVIOR" and g01["request_count"] == 1

    collaborator = SequenceClient([(200, repository_data())])
    owner = SequenceClient([(200, {"permission": "read"})])
    monkeypatch.setattr(value, "_validation_context", lambda identity: (bootstrap_state(), {}, collaborator, owner))
    g02 = value._validate_g02()
    assert g02["status"] == "INTENDED_BEHAVIOR" and g02["request_count"] == 1

    collaborator = SequenceClient([(403, {"message": "forbidden"})])
    owner = SequenceClient([(200, {"permission": "read"})])
    monkeypatch.setattr(value, "_validation_context", lambda identity: (bootstrap_state(), {}, collaborator, owner))
    g03 = value._validate_g03()
    assert g03["status"] == "INTENDED_BEHAVIOR" and g03["request_count"] == 1
    assert collaborator.calls[0][3] == {}

    with pytest.raises(LocalTargetError, match="local_request_budget_exceeded"):
        value._save_validation("G01", "outsider", "NEEDS_MORE_EVIDENCE", [], 2, {
            "session_fingerprint": "0123456789abcdef",
            "assertions": {"fixture_ready": True},
        })


def activity(full_name, created="2026-09-20T12:03:00Z"):
    return {"op_type": "create_repo", "repo": {"full_name": full_name}, "created": created}


def heatmap(contributions, other_contributions=0):
    return [
        {"timestamp": 1789848900, "contributions": other_contributions},
        {"timestamp": 1789849800, "contributions": contributions},
    ]


def limited_repository_data():
    return {
        "id": 46,
        "name": LIMITED_ORG_PUBLIC_REPOSITORY,
        "full_name": LIMITED_ORGANIZATION + "/" + LIMITED_ORG_PUBLIC_REPOSITORY,
        "private": False,
        "description": LIMITED_ORG_PUBLIC_DESCRIPTION,
        "owner": {"login": LIMITED_ORGANIZATION},
    }


def repo_rows(*full_names):
    return [{"full_name": name} for name in full_names]


def verified_assertions(candidate):
    return {
        **{key: True for key in VERIFICATION_ASSERTIONS[candidate]},
        "intended_behavior_observed": False,
    }


@pytest.mark.parametrize("candidate", ["G04", "G05", "G06", "G07", "G08"])
def test_deterministic_adjudication_requires_every_assertion(candidate):
    assertions = verified_assertions(candidate)
    assert adjudicate(candidate, assertions) == "VERIFIED_LOCAL"

    incomplete = dict(assertions)
    incomplete["candidate_behavior_observed"] = False
    assert adjudicate(candidate, incomplete) == "NEEDS_MORE_EVIDENCE"

    intended = dict(incomplete)
    intended["intended_behavior_observed"] = True
    assert adjudicate(candidate, intended) == "INTENDED_BEHAVIOR"

    blocked = dict(assertions)
    blocked["fixture_ready"] = False
    assert adjudicate(candidate, blocked) == "BLOCKED_BY_LOCAL_SETUP"


def test_deterministic_adjudication_rejects_missing_or_non_boolean_assertions():
    assertions = verified_assertions("G04")
    assertions.pop("public_only_feed_200")
    with pytest.raises(LocalTargetError, match="invalid_local_assertions"):
        adjudicate("G04", assertions)
    assertions["public_only_feed_200"] = "yes"
    with pytest.raises(LocalTargetError, match="invalid_local_assertions"):
        adjudicate("G04", assertions)


def test_g04_public_only_activity_feed_status_mapping(tmp_path, monkeypatch):
    value = adapter(tmp_path)
    marker = LIMITED_ORGANIZATION + "/" + LIMITED_ORG_PUBLIC_REPOSITORY
    control = SequenceClient([(200, limited_repository_data())])
    public_only = SequenceClient([(403, {"message": "forbidden"}), (200, [])])
    monkeypatch.setattr(value, "_token_validation_context", lambda: (
        bootstrap_state(), control, public_only,
    ))
    intended = value._validate_g04()
    assert intended["status"] == "INTENDED_BEHAVIOR"
    assert intended["request_count"] == REQUEST_BUDGETS["G04"] == 3
    assert control.calls[0][2] == LIMITED_ORG_PUBLIC_REPO_PATH
    assert [call[2] for call in public_only.calls] == [LIMITED_ORG_PUBLIC_REPO_PATH, USER_FEEDS_PATH]

    control = SequenceClient([(200, limited_repository_data())])
    public_only = SequenceClient([(404, None), (200, [activity(marker)])])
    monkeypatch.setattr(value, "_token_validation_context", lambda: (
        bootstrap_state(), control, public_only,
    ))
    suspicious = value._validate_g04()
    assert suspicious["status"] == "VERIFIED_LOCAL"
    assert suspicious["candidate_has_limited_repo_marker"] is True
    assert all(suspicious["assertions"][key] for key in VERIFICATION_ASSERTIONS["G04"])

    control = SequenceClient([(200, limited_repository_data())])
    public_only = SequenceClient([(200, limited_repository_data()), (200, [])])
    monkeypatch.setattr(value, "_token_validation_context", lambda: (
        bootstrap_state(), control, public_only,
    ))
    blocked = value._validate_g04()
    assert blocked["status"] == "BLOCKED_BY_LOCAL_SETUP"


def test_g05_public_only_heatmap_status_mapping(tmp_path, monkeypatch):
    bucket = bootstrap_state()["private_activity_bucket"]
    assert _activity_bucket(
        [activity(OWNER + "/" + REPOSITORY, "2026-09-20T12:03:00Z")],
        OWNER + "/" + REPOSITORY,
    ) == 1789905600
    assert _heatmap_bucket(heatmap(2, 999), bucket) == 2
    value = adapter(tmp_path)
    control = SequenceClient([(200, heatmap(4, 999))])
    public_only = SequenceClient([(403, None), (200, heatmap(2, 999))])
    monkeypatch.setattr(value, "_token_validation_context", lambda: (
        bootstrap_state(), control, public_only,
    ))
    intended = value._validate_g05()
    assert intended["status"] == "INTENDED_BEHAVIOR"
    assert intended["request_count"] == REQUEST_BUDGETS["G05"] == 3
    assert intended["control_bucket_contributions"] == 4
    assert intended["candidate_bucket_contributions"] == 2
    assert [call[2] for call in public_only.calls] == [REPO_PATH, USER_HEATMAP_PATH]

    control = SequenceClient([(200, heatmap(4, 1))])
    public_only = SequenceClient([(404, None), (200, heatmap(4, 0))])
    monkeypatch.setattr(value, "_token_validation_context", lambda: (
        bootstrap_state(), control, public_only,
    ))
    suspicious = value._validate_g05()
    assert suspicious["status"] == "VERIFIED_LOCAL"
    assert suspicious["candidate_bucket_contributions"] == 4
    assert suspicious["public_only_private_repo_access"] == 404
    assert all(suspicious["assertions"][key] for key in VERIFICATION_ASSERTIONS["G05"])

    control = SequenceClient([(200, heatmap(0))])
    public_only = SequenceClient([(403, None), (200, heatmap(0))])
    monkeypatch.setattr(value, "_token_validation_context", lambda: (
        bootstrap_state(), control, public_only,
    ))
    blocked = value._validate_g05()
    assert blocked["status"] == "BLOCKED_BY_LOCAL_SETUP"

    control = SequenceClient([(200, heatmap(4))])
    public_only = SequenceClient([(200, repository_data()), (200, heatmap(4))])
    monkeypatch.setattr(value, "_token_validation_context", lambda: (
        bootstrap_state(), control, public_only,
    ))
    boundary_failed = value._validate_g05()
    assert boundary_failed["status"] == "BLOCKED_BY_LOCAL_SETUP"
    assert boundary_failed["assertions"]["public_only_private_repo_denied"] is False


def test_g04_g05_incomplete_probe_uses_needs_more_evidence(tmp_path, monkeypatch):
    value = adapter(tmp_path / "g04")
    control = SequenceClient([(200, limited_repository_data())])
    public_only = SequenceClient([(403, None), (500, None)])
    monkeypatch.setattr(value, "_token_validation_context", lambda: (
        bootstrap_state(), control, public_only,
    ))
    g04 = value._validate_g04()
    assert g04["status"] == "NEEDS_MORE_EVIDENCE"
    assert g04["assertions"]["fixture_ready"] is True
    assert g04["assertions"]["reproducible"] is False

    value = adapter(tmp_path / "g05")
    control = SequenceClient([(200, heatmap(4))])
    public_only = SequenceClient([(403, None), (500, None)])
    monkeypatch.setattr(value, "_token_validation_context", lambda: (
        bootstrap_state(), control, public_only,
    ))
    g05 = value._validate_g05()
    assert g05["status"] == "NEEDS_MORE_EVIDENCE"
    assert g05["assertions"]["fixture_ready"] is True
    assert g05["assertions"]["reproducible"] is False


@pytest.mark.parametrize("candidate,path,public_name,private_name,control_identity,viewer_role", [
    ("G06", USER_REPOS_PATH, OWNER + "/" + PUBLIC_REPOSITORY, OWNER + "/" + REPOSITORY,
     "repo_owner", "unrelated_logged_in_viewer"),
    ("G07", ORG_REPOS_PATH, ORGANIZATION + "/" + ORG_PUBLIC_REPOSITORY,
     ORGANIZATION + "/" + ORG_PRIVATE_REPOSITORY, "repo_owner", "org_non_member_viewer"),
    ("G08", "/api/v1/teams/6/repos?limit=50", ORGANIZATION + "/" + ORG_PUBLIC_REPOSITORY,
     ORGANIZATION + "/" + ORG_PRIVATE_REPOSITORY, "collaborator",
     "team_metadata_non_member_viewer"),
])
def test_g06_g07_g08_role_specific_total_count_intended(
    tmp_path, monkeypatch, candidate, path, public_name, private_name, control_identity, viewer_role,
):
    value = adapter(tmp_path)
    value.runtime_root.mkdir(parents=True)
    value.bootstrap_file.write_text(json.dumps(bootstrap_state()))
    control = SequenceClient([(200, repo_rows(public_name, private_name), 2)])
    viewer = SequenceClient([(200, repo_rows(public_name), 1)])
    roles = []

    def role_context(actual_control, actual_viewer):
        roles.append((actual_control, actual_viewer))
        return bootstrap_state(), control, viewer

    monkeypatch.setattr(value, "_role_validation_context", role_context)
    result = getattr(value, "_validate_" + candidate.lower())()
    assert result["status"] == "INTENDED_BEHAVIOR"
    assert result["request_count"] == REQUEST_BUDGETS[candidate] == 2
    assert result["candidate_repository_count"] == 1
    assert result["count_includes_filtered_private_repository"] is False
    assert roles == [(control_identity, "outsider")]
    evidence = [json.loads(item.read_text()) for item in value.evidence_root.glob("*.json")]
    assert any(item.get("payload", {}).get("identity") == viewer_role for item in evidence)


@pytest.mark.parametrize("candidate,public_name,private_name", [
    ("G06", OWNER + "/" + PUBLIC_REPOSITORY, OWNER + "/" + REPOSITORY),
    ("G07", ORGANIZATION + "/" + ORG_PUBLIC_REPOSITORY,
     ORGANIZATION + "/" + ORG_PRIVATE_REPOSITORY),
    ("G08", ORGANIZATION + "/" + ORG_PUBLIC_REPOSITORY,
     ORGANIZATION + "/" + ORG_PRIVATE_REPOSITORY),
])
def test_g06_g07_g08_verified_local_positive_cases(
    tmp_path, monkeypatch, candidate, public_name, private_name,
):
    value = adapter(tmp_path)
    value.runtime_root.mkdir(parents=True)
    value.bootstrap_file.write_text(json.dumps(bootstrap_state()))
    control = SequenceClient([(200, repo_rows(public_name, private_name), 2)])
    viewer = SequenceClient([(200, repo_rows(public_name), 2)])
    monkeypatch.setattr(value, "_role_validation_context", lambda control_identity, viewer_identity: (
        bootstrap_state(), control, viewer,
    ))
    result = getattr(value, "_validate_" + candidate.lower())()
    assert result["status"] == "VERIFIED_LOCAL"
    assert result["candidate_body_count"] == 1
    assert result["candidate_repository_count"] == 2
    assert all(result["assertions"][key] for key in VERIFICATION_ASSERTIONS[candidate])
    reassessment = json.loads(
        (value.evidence_root / (result["reassessment"] + ".json")).read_text()
    )["payload"]
    assert reassessment["automatic_confirmation"] is True
    assert reassessment["verification_scope"] == "pinned_local_target"
    assert reassessment["external_confirmation"] is False


@pytest.mark.parametrize("candidate,public_name,private_name", [
    ("G06", OWNER + "/" + PUBLIC_REPOSITORY, OWNER + "/" + REPOSITORY),
    ("G07", ORGANIZATION + "/" + ORG_PUBLIC_REPOSITORY,
     ORGANIZATION + "/" + ORG_PRIVATE_REPOSITORY),
    ("G08", ORGANIZATION + "/" + ORG_PUBLIC_REPOSITORY,
     ORGANIZATION + "/" + ORG_PRIVATE_REPOSITORY),
])
def test_g06_g07_g08_control_failure_blocks(
    tmp_path, monkeypatch, candidate, public_name, private_name,
):
    value = adapter(tmp_path)
    value.runtime_root.mkdir(parents=True)
    value.bootstrap_file.write_text(json.dumps(bootstrap_state()))
    control = SequenceClient([(200, repo_rows(public_name, private_name), 1)])
    viewer = SequenceClient([(200, repo_rows(public_name), 1)])
    monkeypatch.setattr(value, "_role_validation_context", lambda control_identity, viewer_identity: (
        bootstrap_state(), control, viewer,
    ))
    result = getattr(value, "_validate_" + candidate.lower())()
    assert result["status"] == "BLOCKED_BY_LOCAL_SETUP"
    assert result["assertions"]["control_passed"] is False


def test_total_count_leak_needs_evidence_and_bad_fixture_blocks(tmp_path, monkeypatch):
    value = adapter(tmp_path)
    public_name = OWNER + "/" + PUBLIC_REPOSITORY
    private_name = OWNER + "/" + REPOSITORY
    control = SequenceClient([(200, repo_rows(public_name, private_name), 2)])
    viewer = SequenceClient([(200, repo_rows(public_name), 2)])
    monkeypatch.setattr(value, "_role_validation_context", lambda control_identity, viewer_identity: (
        bootstrap_state(), control, viewer,
    ))
    suspicious = value._validate_g06()
    assert suspicious["status"] == "VERIFIED_LOCAL"
    assert suspicious["candidate_private_marker"] is False
    assert suspicious["candidate_repository_count"] == 2
    assert suspicious["count_includes_filtered_private_repository"] is True
    assert all(suspicious["assertions"][key] for key in VERIFICATION_ASSERTIONS["G06"])

    control = SequenceClient([(200, repo_rows(public_name, private_name), 1)])
    viewer = SequenceClient([(200, repo_rows(public_name), 1)])
    monkeypatch.setattr(value, "_role_validation_context", lambda control_identity, viewer_identity: (
        bootstrap_state(), control, viewer,
    ))
    blocked = value._validate_g06()
    assert blocked["status"] == "BLOCKED_BY_LOCAL_SETUP"


def test_gitea_never_auto_marks_unexpected_behavior_verified(tmp_path, monkeypatch):
    value = adapter(tmp_path)
    outsider = SequenceClient([(200, repository_data())])
    owner = SequenceClient([(404, None)])
    monkeypatch.setattr(value, "_validation_context", lambda identity: (
        bootstrap_state(), {}, outsider, owner,
    ))
    assert value._validate_g01()["status"] == "NEEDS_MORE_EVIDENCE"


def test_private_body_exposure_is_not_misclassified_as_count_leak(tmp_path, monkeypatch):
    value = adapter(tmp_path)
    public_name = OWNER + "/" + PUBLIC_REPOSITORY
    private_name = OWNER + "/" + REPOSITORY
    control = SequenceClient([(200, repo_rows(public_name, private_name), 2)])
    viewer = SequenceClient([(200, repo_rows(public_name, private_name), 2)])
    monkeypatch.setattr(value, "_role_validation_context", lambda control_identity, viewer_identity: (
        bootstrap_state(), control, viewer,
    ))
    result = value._validate_g06()
    assert result["status"] == "NEEDS_MORE_EVIDENCE"
    assert result["assertions"]["security_boundary_passed"] is False
    assert result["assertions"]["count_includes_filtered_private_repository"] is False


def sample_hunt_results():
    results = []
    for number, candidate in enumerate(("G04", "G05", "G06", "G07", "G08"), 1):
        observations = {
            "G04": {
                "control_repo_access": 200,
                "public_only_repo_access": 403,
                "candidate_has_limited_repo_marker": True,
            },
            "G05": {
                "control_bucket_contributions": 4,
                "candidate_bucket_contributions": 4,
                "public_only_private_repo_access": 403,
            },
            "G06": {"control_repository_count": 2, "candidate_repository_count": 2,
                    "candidate_body_count": 1, "candidate_private_marker": False},
            "G07": {"control_repository_count": 2, "candidate_repository_count": 2,
                    "candidate_body_count": 1, "candidate_private_marker": False},
            "G08": {"control_repository_count": 2, "candidate_repository_count": 2,
                    "candidate_body_count": 1, "candidate_private_marker": False},
        }[candidate]
        results.append({
            "target": "gitea",
            "candidate": candidate,
            "status": "VERIFIED_LOCAL",
            "evidence": f"{number:032x}",
            "reassessment": f"{number + 100:032x}",
            "request_count": REQUEST_BUDGETS[candidate],
            "assertions": verified_assertions(candidate),
            "requests": [{
                "method": "GET",
                "path": USER_FEEDS_PATH if candidate == "G04" else USER_HEATMAP_PATH,
                "expected": "sanitized",
                "status_code": 200,
                "response_shape": {"secret": "omitted"},
                "x_total_count": 2,
            }],
            **observations,
        })
    for number, candidate in enumerate(("G01", "G02", "G03"), 20):
        results.append({
            "target": "gitea",
            "candidate": candidate,
            "status": "INTENDED_BEHAVIOR",
            "evidence": f"{number:032x}",
            "reassessment": f"{number + 100:032x}",
            "request_count": 1,
            "assertions": {"fixture_ready": True},
            "requests": [],
        })
    return results


def test_root_cause_clustering_groups_only_verified_candidates():
    clusters = cluster_verified(sample_hunt_results())
    assert [(item["id"], item["candidate_ids"]) for item in clusters] == [
        ("RC01", ["G04"]),
        ("RC02", ["G05"]),
        ("RC03", ["G06", "G07"]),
        ("RC04", ["G08"]),
    ]
    assert all(item["kind"] == "root_cause_cluster" for item in clusters)
    assert all(item["status"] == "VERIFIED_LOCAL" for item in clusters)
    assert clusters[2]["shared_source_function"].startswith("listUserRepos")


def test_hunt_report_and_get_only_pocs_are_sanitized_and_append_only(tmp_path):
    secret_root = tmp_path / ".operator/local-secrets/gitea"
    secret_root.mkdir(parents=True)
    secrets_value = {
        "control_token": "control-token-must-not-appear",
        "public_only_token": "public-token-must-not-appear",
        "repo_owner": "owner-password-must-not-appear",
        "collaborator": "collaborator-password-must-not-appear",
        "outsider": "outsider-password-must-not-appear",
    }
    (secret_root / "secrets.json").write_text(json.dumps(secrets_value))

    first = create_hunt_reports(
        tmp_path,
        target="gitea",
        version=GITEA_VERSION,
        commit=REVISION,
        results=sample_hunt_results(),
        run_id="run-one",
    )
    report = json.loads((tmp_path / first["json_report"]).read_text())
    markdown = (tmp_path / first["markdown_report"]).read_text()
    assert report["status"] == "VERIFIED_LOCAL"
    assert report["summary"] == {
        "candidates_analyzed": 8,
        "verified_locally": 5,
        "intended_behavior": 3,
        "blocked": 0,
        "needs_more_evidence": 0,
    }
    assert [item["id"] for item in report["root_cause_clusters"]] == [
        "RC01", "RC02", "RC03", "RC04",
    ]
    assert {item["candidate_id"]: item["status"] for item in report["candidate_outcomes"]} == {
        "G01": "INTENDED_BEHAVIOR",
        "G02": "INTENDED_BEHAVIOR",
        "G03": "INTENDED_BEHAVIOR",
        "G04": "VERIFIED_LOCAL",
        "G05": "VERIFIED_LOCAL",
        "G06": "VERIFIED_LOCAL",
        "G07": "VERIFIED_LOCAL",
        "G08": "VERIFIED_LOCAL",
    }
    assert "Security Invariant" in markdown
    assert "Sanitized HTTP Evidence" in markdown
    assert "Human review is required" in markdown
    assert "response_shape" not in json.dumps(report)
    g05_report = next(item for item in report["candidates"] if item["candidate_id"] == "G05")
    assert g05_report["control_probe_comparison"]["observations"] == {
        "control_bucket_contributions": 4,
        "candidate_bucket_contributions": 4,
        "public_only_private_repo_access": 403,
    }

    report_root = tmp_path / first["report_directory"]
    raw = "\n".join(path.read_text() for path in report_root.iterdir())
    assert not any(secret in raw for secret in secrets_value.values())
    assert "Cookie" not in raw and "Authorization" not in raw
    assert len(first["poc_scripts"]) == 4
    for relative in first["poc_scripts"]:
        script = (tmp_path / relative).read_text()
        assert 'HOST = "127.0.0.1"' in script and "PORT = 13000" in script
        assert 'connection.request("GET"' in script
        assert 'connection.request("POST"' not in script
        assert 'connection.request("PUT"' not in script
        assert 'connection.request("PATCH"' not in script
        compile(script, relative, "exec")

    second = create_hunt_reports(
        tmp_path,
        target="gitea",
        version=GITEA_VERSION,
        commit=REVISION,
        results=sample_hunt_results(),
        run_id="run-two",
    )
    assert first["report_directory"] != second["report_directory"]
    assert (tmp_path / first["json_report"]).is_file()
    with pytest.raises(LocalTargetError, match="hunt_run_exists"):
        create_hunt_reports(
            tmp_path,
            target="gitea",
            version=GITEA_VERSION,
            commit=REVISION,
            results=sample_hunt_results(),
            run_id="run-one",
        )


def test_hunt_orchestrates_status_bootstrap_validation_and_new_runs(tmp_path, monkeypatch):
    value = adapter(tmp_path)
    states = iter([
        {"health": "healthy", "synthetic_bootstrap_status": "not_ready"},
        {"health": "healthy", "synthetic_bootstrap_status": "ready"},
    ])
    bootstraps = []
    validations = []
    report_runs = []
    results = sample_hunt_results()
    monkeypatch.setattr(value, "status", lambda: next(states))
    monkeypatch.setattr(value, "bootstrap", lambda: bootstraps.append(True) or {"status": "ready"})
    monkeypatch.setattr(value, "validate", lambda candidate: validations.append(candidate) or [
        next(item for item in results if item["candidate"] == candidate)
    ])

    def reports(root, **values):
        report_runs.append(values["results"])
        number = len(report_runs)
        return {
            "summary": {
                "candidates_analyzed": 8,
                "verified_locally": 5,
                "intended_behavior": 3,
                "blocked": 0,
                "needs_more_evidence": 0,
            },
            "clusters": cluster_verified(results),
            "report_directory": f".operator/reports/gitea/run-{number}",
            "json_report": f".operator/reports/gitea/run-{number}/report.json",
            "markdown_report": f".operator/reports/gitea/run-{number}/report.md",
            "poc_scripts": [],
        }

    monkeypatch.setattr("ctf_mcp.local_targets.gitea.create_hunt_reports", reports)
    first = value.hunt()
    second = value.hunt()
    assert bootstraps == [True]
    assert validations == list(CANDIDATES) * 2
    assert first["bootstrap_performed"] is True
    assert second["bootstrap_performed"] is False
    assert first["verified_locally"] == second["verified_locally"] == 5
    assert first["reports"] != second["reports"]
    assert first["external_submission_performed"] is False


def test_hunt_stops_when_local_target_is_not_healthy(tmp_path, monkeypatch):
    value = adapter(tmp_path)
    monkeypatch.setattr(value, "status", lambda: {
        "health": "unreachable", "synthetic_bootstrap_status": "not_ready",
    })
    with pytest.raises(LocalTargetError, match="VALIDATION_BLOCKED"):
        value.hunt()


def test_hunt_classifies_one_candidate_blocked_and_continues(tmp_path, monkeypatch):
    value = adapter(tmp_path)
    monkeypatch.setattr(value, "status", lambda: {
        "health": "healthy", "synthetic_bootstrap_status": "ready",
    })
    by_candidate = {item["candidate"]: item for item in sample_hunt_results()}

    def validate(candidate):
        if candidate == "G04":
            raise LocalTargetError("VALIDATION_BLOCKED")
        return [by_candidate[candidate]]

    monkeypatch.setattr(value, "validate", validate)
    result = value.hunt()
    assert result["candidates_analyzed"] == 8
    assert result["verified_locally"] == 4
    assert result["blocked"] == 1
    blocked = next(item for item in result["results"] if item["candidate"] == "G04")
    assert blocked["status"] == "BLOCKED_BY_LOCAL_SETUP"
    assert blocked["blocked_reason"] == "VALIDATION_BLOCKED"
    assert blocked["assertions"]["fixture_ready"] is False


def test_candidate_route_allowlists_are_adapter_owned_and_fixed():
    fixed_paths = {
        "G01": ("GET", REPO_PATH),
        "G02": ("GET", REPO_PATH),
        "G03": ("PATCH", REPO_PATH),
        "G04": ("GET", USER_FEEDS_PATH),
        "G05": ("GET", USER_HEATMAP_PATH),
        "G06": ("GET", USER_REPOS_PATH),
        "G07": ("GET", ORG_REPOS_PATH),
        "G08": ("GET", "/api/v1/teams/6/repos?limit=50"),
    }
    for candidate, (method, path) in fixed_paths.items():
        assert any(allowed == method and pattern.fullmatch(path)
                   for allowed, pattern in GITEA_ALLOWED[candidate])
    assert any(method == "GET" and pattern.fullmatch(REPO_PATH)
               for method, pattern in GITEA_ALLOWED["G05"])
    assert all(method == "GET" for candidate in ("G04", "G05", "G06", "G07", "G08")
               for method, _ in GITEA_ALLOWED[candidate])
    assert REQUEST_BUDGETS == {
        "G01": 1, "G02": 1, "G03": 1,
        "G04": 3, "G05": 3, "G06": 2, "G07": 2, "G08": 2,
    }
    assert set(CANDIDATES) == GiteaAdapter.supported_candidates


def test_host_cli_validates_candidate_and_runs_hunt(tmp_path, monkeypatch, capsys):
    root = Path(__file__).resolve().parents[1]
    spec = importlib.util.spec_from_file_location("local_target_gitea_test", root / "scripts/local_target.py")
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)

    class FakeAdapter:
        def __init__(self, candidates):
            self.supported_candidates = frozenset(candidates)

        def validate(self, candidate):
            return []

        def hunt(self):
            return {
                "target": "gitea",
                "version": GITEA_VERSION,
                "candidates_analyzed": 8,
                "verified_locally": 5,
                "intended_behavior": 3,
                "blocked": 0,
                "needs_more_evidence": 0,
                "root_cause_clusters": [
                    {"id": "RC03", "candidates": ["G06", "G07"]},
                ],
                "reports": ".operator/reports/gitea/run-one",
                "human_action_required": "Review report before any external disclosure/submission.",
            }

    selected = {
        "mattermost": FakeAdapter({"S12", "S13", "S15"}),
        "gitea": FakeAdapter({"G01", "G02", "G03", "G04", "G05", "G06", "G07", "G08"}),
    }
    monkeypatch.setattr(module, "load_adapter", lambda root, target: selected[target])
    assert module.run_local(tmp_path, ["validate", "S12"], {"FINDER_TARGET": "mattermost"}) == 0
    assert module.run_local(tmp_path, ["validate", "G01"], {"FINDER_TARGET": "gitea"}) == 0
    assert module.run_local(tmp_path, ["validate", "G08"], {"FINDER_TARGET": "gitea"}) == 0
    assert module.run_local(tmp_path, ["hunt"], {"FINDER_TARGET": "gitea"}) == 0
    output = capsys.readouterr().out
    assert "Verified locally: 5" in output
    assert "- RC03: G06, G07" in output
    assert "Reports: .operator/reports/gitea/run-one" in output
    with pytest.raises(LocalTargetError, match="unknown_local_candidate"):
        module.run_local(tmp_path, ["validate", "G01"], {"FINDER_TARGET": "mattermost"})
    with pytest.raises(LocalTargetError, match="unknown_local_candidate"):
        module.run_local(tmp_path, ["validate", "S12"], {"FINDER_TARGET": "gitea"})


def test_stop_preserves_runtime_source_secrets_and_evidence(tmp_path, monkeypatch):
    runner = GitRunner()
    value = adapter(tmp_path, runner=runner)
    value._write_runtime_files()
    for path in (value.target_root, value.secret_root, value.evidence_root):
        path.mkdir(parents=True, exist_ok=True)
        (path / "preserve").write_text("synthetic")
    (value.runtime_root / "preserve").write_text("synthetic")
    monkeypatch.setattr("ctf_mcp.local_targets.gitea.shutil.which", lambda _: "/fixed/docker")
    result = value.stop()
    assert result["data_preserved"] is True
    assert all((path / "preserve").is_file() for path in (
        value.target_root, value.runtime_root, value.secret_root, value.evidence_root,
    ))
    assert any(call[0][-2:] == ["stop", "gitea"] for call in runner.calls)


def test_reset_removes_only_gitea_volumes_bootstrap_and_secrets(tmp_path, monkeypatch):
    runner = GitRunner()
    value = adapter(tmp_path, runner=runner)
    value._write_runtime_files()
    value.target_root.mkdir(parents=True)
    value.evidence_root.mkdir(parents=True)
    (value.target_root / "source-preserve").write_text("synthetic")
    (value.evidence_root / "evidence-preserve").write_text("synthetic")
    (value.runtime_root / "runtime-preserve").write_text("synthetic")
    value.bootstrap_file.write_text(json.dumps(bootstrap_state()))
    value._load_secrets(create=True)
    monkeypatch.setattr("ctf_mcp.local_targets.gitea.shutil.which", lambda _: "/fixed/docker")
    result = value.reset()
    assert result["synthetic_data_removed"] is True
    assert not value.bootstrap_file.exists() and not value.secrets_file.exists()
    assert (value.target_root / "source-preserve").is_file()
    assert (value.evidence_root / "evidence-preserve").is_file()
    assert (value.runtime_root / "runtime-preserve").is_file()
    down = next(call[0] for call in runner.calls if "down" in call[0])
    assert down[-3:] == ["down", "--volumes", "--remove-orphans"]
    assert COMPOSE_PROJECT in down


def test_status_exposes_required_gitea_fields_without_secrets(tmp_path, monkeypatch):
    value = adapter(tmp_path)
    monkeypatch.setattr(value, "_source_details", lambda timeout=0.4: {
        "actual_commit": REVISION, "source_status": "READY",
    })
    monkeypatch.setattr(value, "health", lambda timeout=0.4: {"status": "unreachable", "healthy": False})
    monkeypatch.setattr("ctf_mcp.local_targets.gitea.shutil.which", lambda _: None)
    status = value.status()
    assert status == {
        "target": "gitea",
        "repository": GiteaAdapter.repository,
        "expected_commit": REVISION,
        "actual_commit": REVISION,
        "source_status": "READY",
        "gitea_image": GITEA_IMAGE,
        "expected_image_digest": GITEA_IMAGE_DIGEST,
        "image_digest": None,
        "image_version": None,
        "gitea_container": "not_configured",
        "health": "unreachable",
        "host_endpoint": "http://127.0.0.1:13000",
        "synthetic_bootstrap_status": "not_ready",
    }
