import importlib.util
import hashlib
import json
from pathlib import Path
import stat
import subprocess

import pytest
import yaml

from ctf_mcp.local_targets.base import LocalTargetError, LocalTargetManifest, load_adapter
from ctf_mcp.local_targets.http import ALLOWED, LocalMattermostClient, LocalResponse, response_shape
from ctf_mcp.local_targets.mattermost import (
    COMPOSE,
    COMPOSE_PROJECT,
    ENTERPRISE_IMAGE,
    ENTERPRISE_IMAGE_DIGEST,
    ENTERPRISE_IMAGE_REFERENCE,
    ENTERPRISE_PLATFORM,
    INTERNAL_NETWORK,
    PROXY_CONFIG,
    PROXY_IMAGE,
    PROXY_IMAGE_DIGEST,
    PROXY_IMAGE_REFERENCE,
    PROXY_PLATFORM,
    PUBLISHED_NETWORK,
    REQUIRED_DELEGATED_PERMISSIONS,
    REQUEST_BUDGETS,
    SYNTHETIC_MESSAGE,
    MattermostAdapter,
    _bootstrap_state_status,
    _contains_message,
    _valid_bootstrap_state,
)


REVISION = MattermostAdapter.pinned_revision


def manifest():
    return LocalTargetManifest(
        "mattermost",
        MattermostAdapter.repository,
        REVISION,
        "http://127.0.0.1:13100/api/v4/system/ping",
    )


def adapter(tmp_path, **kwargs):
    return MattermostAdapter(tmp_path, manifest(), **kwargs)


def delegated_capability(status="ready", reason=None, permissions=None):
    actual = set(REQUIRED_DELEGATED_PERMISSIONS if permissions is None else permissions)
    return {
        "status": status,
        "reason": reason,
        "required_permissions": sorted(REQUIRED_DELEGATED_PERMISSIONS),
        "role_summary": {
            "system_admin": False,
            "edit_other_users": "edit_other_users" in actual,
            "view_team": "view_team" in actual,
            "manage_system": "manage_system" in actual,
            "read_channel_content": "read_channel_content" in actual,
            "target_channel_member": False,
        },
        "assignment_verified": status == "ready",
        "effective_control_verified": status == "ready",
    }


class GitRunner:
    def __init__(self, origin=MattermostAdapter.repository, head=REVISION):
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
    value.server_root.mkdir()
    (value.server_root / "go.mod").write_text("module synthetic\n")


def test_unknown_and_invalid_targets_are_rejected(tmp_path):
    with pytest.raises(LocalTargetError, match="invalid_local_target"):
        load_adapter(tmp_path, None)
    with pytest.raises(LocalTargetError, match="invalid_local_target"):
        load_adapter(tmp_path, "../../mattermost")
    with pytest.raises(LocalTargetError, match="invalid_local_target"):
        load_adapter(tmp_path, "nextcloud")


def test_manifest_cannot_override_pinned_repository(tmp_path):
    config = tmp_path / "config/local-targets"
    config.mkdir(parents=True)
    (config / "mattermost.json").write_text(json.dumps({
        "target_id": "mattermost",
        "repository": "https://invalid.example/redirect",
        "revision": REVISION,
        "host_health_url": "http://127.0.0.1:13100/api/v4/system/ping",
    }))
    with pytest.raises(LocalTargetError, match="invalid_local_target_manifest"):
        load_adapter(tmp_path, "mattermost")


def test_generic_base_contains_no_mattermost_runtime_policy():
    root = Path(__file__).resolve().parents[1]
    code = "\n".join((root / path).read_text() for path in (
        "src/ctf_mcp/local_targets/base.py",
        "src/ctf_mcp/local_targets/__init__.py",
        "scripts/control.py",
        "scripts/local_target.py",
    ))
    for target_specific in (ENTERPRISE_IMAGE, "postgres:15", "8065", "linux/amd64",
                            "postgres", "BuildEnterpriseReady", "Build Enterprise Ready",
                            "/mattermost/data", ENTERPRISE_IMAGE_DIGEST):
        assert target_specific not in code


def test_repository_origin_mismatch_is_rejected(tmp_path):
    value = adapter(tmp_path, runner=GitRunner(origin="https://invalid.example/repo"))
    make_source(value)
    with pytest.raises(LocalTargetError, match="REPOSITORY_MISMATCH"):
        value.prepare()


def test_revision_mismatch_is_rejected(tmp_path):
    value = adapter(tmp_path, runner=GitRunner(head="0" * 40))
    make_source(value)
    with pytest.raises(LocalTargetError, match="REVISION_MISMATCH"):
        value.prepare()


def test_git_runner_is_confined_to_operator_target_directory(tmp_path):
    value = adapter(tmp_path, runner=GitRunner())
    with pytest.raises(LocalTargetError, match="unsafe_git_directory"):
        value._git(["rev-parse", "HEAD"], tmp_path)


def test_active_local_git_extensions_are_rejected(tmp_path):
    value = adapter(tmp_path, runner=GitRunner())
    make_source(value)
    (value.target_root / ".git/config").write_text(
        "[core]\n\trepositoryformatversion = 0\n[include]\n\tpath = /tmp/untrusted\n"
    )
    with pytest.raises(LocalTargetError, match="REPOSITORY_MISMATCH"):
        value.prepare()


def test_require_source_rechecks_git_extensions(tmp_path):
    value = adapter(tmp_path, runner=GitRunner())
    make_source(value)
    (value.target_root / ".git/config").write_text(
        "[filter \"unsafe\"]\n\tprocess = /tmp/untrusted\n"
    )
    with pytest.raises(LocalTargetError, match="REPOSITORY_MISMATCH"):
        value._require_source()


def test_compose_actions_reject_modified_or_linked_runtime_file(tmp_path):
    value = adapter(tmp_path, runner=GitRunner())
    value.runtime_root.mkdir(parents=True)
    value.compose_file.write_text(COMPOSE + "\nservices: {}\n")
    with pytest.raises(LocalTargetError, match="unsafe_local_runtime"):
        value._compose(["stop"], timeout=1)
    value.compose_file.unlink()
    value._write_runtime_files({"database": "x" * 24})
    value.proxy_config_file.write_text(PROXY_CONFIG.replace("mattermost:8065", "attacker.invalid:8065"))
    with pytest.raises(LocalTargetError, match="unsafe_local_runtime"):
        value._compose(["stop"], timeout=1)
    value.compose_file.unlink()
    value.proxy_config_file.write_text(PROXY_CONFIG)
    external = tmp_path / "untrusted-compose.yaml"
    external.write_text(COMPOSE)
    value.compose_file.symlink_to(external)
    with pytest.raises(LocalTargetError, match="unsafe_local_runtime"):
        value._compose(["stop"], timeout=1)


def test_exact_legacy_direct_publish_compose_is_migrated_to_proxy(tmp_path, monkeypatch):
    value = adapter(tmp_path)
    value.runtime_root.mkdir(parents=True)
    legacy = "adapter-owned-legacy-compose\n"
    monkeypatch.setattr(
        "ctf_mcp.local_targets.mattermost.LEGACY_DIRECT_COMPOSE_SHA256",
        hashlib.sha256(legacy.encode()).hexdigest(),
    )
    value.compose_file.write_text(legacy)
    value._write_runtime_files({"database": "x" * 24})
    assert value.compose_file.read_text() == COMPOSE
    assert value.proxy_config_file.read_text() == PROXY_CONFIG
    parsed = yaml.safe_load(value.compose_file.read_text())
    assert "ports" not in parsed["services"]["mattermost"]
    assert parsed["services"]["proxy"]["ports"] == ["127.0.0.1:13100:13100"]


def test_subprocesses_never_enable_shell_and_compose_never_mounts_docker_socket():
    root = Path(__file__).resolve().parents[1]
    code = "\n".join(path.read_text() for path in (root / "src/ctf_mcp/local_targets").glob("*.py"))
    assert "shell=True" not in code and "shell = True" not in code
    assert "/var/run/docker.sock" not in code
    assert "0.0.0.0:13100" not in code
    assert "127.0.0.1:13100" in code
    assert '"go", "run"' not in code
    assert "-tags enterprise" not in code
    assert "postgres:15" in COMPOSE
    local = yaml.safe_load(COMPOSE)
    assert set(local["services"]) == {"postgres", "mattermost", "proxy"}
    postgres = local["services"]["postgres"]
    mattermost = local["services"]["mattermost"]
    proxy = local["services"]["proxy"]
    assert ENTERPRISE_IMAGE == "mattermostdevelopment/mattermost-enterprise-edition:d283cc6"
    assert ENTERPRISE_IMAGE_DIGEST == "sha256:3c11c93b5f75b4e9bc407711d6ad345c0072cff520e34ffc0e99238a507daeb1"
    assert mattermost["image"] == ENTERPRISE_IMAGE_REFERENCE
    assert mattermost["platform"] == ENTERPRISE_PLATFORM == "linux/amd64"
    assert "user" not in mattermost
    assert "ports" not in mattermost
    assert "ports" not in postgres
    assert mattermost["networks"] == ["local-target-internal"]
    assert postgres["networks"] == ["local-target-internal"]
    assert mattermost["environment"]["MM_SERVICESETTINGS_LISTENADDRESS"] == ":8065"
    assert mattermost["environment"]["MM_SERVICESETTINGS_LISTENADDRESS"] != "127.0.0.1:8065"
    assert "@postgres:5432/mattermost_test" in mattermost["environment"]["MM_SQLSETTINGS_DATASOURCE"]
    assert mattermost["volumes"] == ["./data:/mattermost/data"]
    assert proxy["image"] == PROXY_IMAGE_REFERENCE
    assert PROXY_IMAGE == "haproxy:3.2.23-alpine3.24"
    assert PROXY_IMAGE_DIGEST == "sha256:37372c5ade6fc5cfb3a0c1a3dc0f77da472fce80ee8aa1294ed78af67179a3f2"
    assert proxy["platform"] == PROXY_PLATFORM == "linux/amd64"
    assert proxy["ports"] == ["127.0.0.1:13100:13100"]
    assert proxy["networks"] == ["local-target-internal", "local-target-published"]
    assert proxy["read_only"] is True and proxy["cap_drop"] == ["ALL"]
    assert proxy["volumes"] == ["./haproxy.cfg:/usr/local/etc/haproxy/haproxy.cfg:ro"]
    assert local["networks"]["local-target-internal"]["internal"] is True
    assert local["networks"]["local-target-published"] == {"driver": "bridge"}
    assert "mode tcp" in PROXY_CONFIG
    assert "server mattermost mattermost:8065 check" in PROXY_CONFIG
    assert "http-request" not in PROXY_CONFIG and "http-response" not in PROXY_CONFIG
    assert "0.0.0.0" not in COMPOSE + PROXY_CONFIG
    compose = yaml.safe_load((root / "docker-compose.yml").read_text())
    assert compose["services"]["observer"]["extra_hosts"] == ["host.docker.internal:host-gateway"]
    assert "host-adapter-egress" in compose["services"]["observer"]["networks"]
    assert not any(".operator/targets" in str(service.get("volumes", [])) for service in compose["services"].values())


def test_stop_preserves_source_data_secrets_and_evidence(tmp_path, monkeypatch):
    runner = GitRunner()
    value = adapter(tmp_path, runner=runner)
    for path in (value.target_root, value.runtime_root, value.secret_root, value.evidence_root):
        path.mkdir(parents=True, exist_ok=True)
        (path / "preserve").write_text("synthetic")
    value._write_runtime_files({"database": "x" * 24})
    monkeypatch.setattr("ctf_mcp.local_targets.mattermost.shutil.which", lambda _: "/fixed/docker")
    result = value.stop()
    assert result["data_preserved"] is True
    assert all((path / "preserve").is_file() for path in
               (value.target_root, value.runtime_root, value.secret_root, value.evidence_root))
    assert any(call[0][-4:] == ["stop", "proxy", "mattermost", "postgres"] for call in runner.calls)


def test_reset_removes_only_synthetic_runtime_and_preserves_source_evidence(tmp_path, monkeypatch):
    value = adapter(tmp_path, runner=GitRunner())
    value._write_runtime_files({"database": "x" * 24})
    assert stat.S_IMODE((value.runtime_root / "data").stat().st_mode) == 0o777
    assert stat.S_IMODE(value.runtime_root.stat().st_mode) == 0o700
    value.target_root.mkdir(parents=True)
    value.evidence_root.mkdir(parents=True)
    (value.target_root / "source-preserve").write_text("synthetic")
    (value.evidence_root / "evidence-preserve").write_text("synthetic")
    (value.runtime_root / "runtime-preserve").write_text("synthetic")
    value.bootstrap_file.write_text("{}")
    value._load_secrets(create=True)
    monkeypatch.setattr("ctf_mcp.local_targets.mattermost.shutil.which", lambda _: "/fixed/docker")
    result = value.reset()
    assert result["synthetic_data_removed"] is True
    assert not (value.runtime_root / "data").exists()
    assert not value.bootstrap_file.exists()
    assert not value.secrets_file.exists()
    assert (value.runtime_root / "runtime-preserve").is_file()
    assert (value.target_root / "source-preserve").is_file()
    assert (value.evidence_root / "evidence-preserve").is_file()


def test_secret_store_is_private_and_secrets_never_enter_evidence(tmp_path, capsys):
    value = adapter(tmp_path)
    passwords = value._load_secrets(create=True)
    assert stat.S_IMODE(value.secret_root.stat().st_mode) == 0o700
    assert stat.S_IMODE(value.secrets_file.stat().st_mode) == 0o600
    details = {
        "role_summary": {"system_admin": False, "edit_other_users": True, "view_team": True,
                         "manage_system": False, "read_channel_content": False},
        "session_fingerprint": "0123456789abcdef",
        "control": "DENIED",
    }
    result = value._save_validation("S12", "NEEDS_MORE_EVIDENCE", [], False, 0, details)
    raw = "\n".join(path.read_text() for path in value.evidence_root.glob("*.json"))
    assert not any(secret in raw for secret in passwords.values())
    assert str(value.secret_root) not in raw
    assert result["status"] == "NEEDS_MORE_EVIDENCE"
    assert capsys.readouterr().out == ""


def test_health_retry_is_bounded_to_five_minutes(tmp_path, monkeypatch):
    value = adapter(tmp_path, sleep=lambda seconds: sleeps.append(seconds))
    sleeps = []
    value.runtime_root.mkdir(parents=True)
    monkeypatch.setattr(value, "_require_source", lambda: None)
    monkeypatch.setattr(value, "_load_secrets", lambda create: {name: "x" * 24 for name in
                        ("database", "system_admin", "delegated_admin", "victim", "normal_user")})
    monkeypatch.setattr(value, "_write_runtime_files", lambda passwords: None)
    monkeypatch.setattr(value, "_compose", lambda *args, **kwargs: None)
    monkeypatch.setattr(value.runner, "run", lambda *args, **kwargs: subprocess.CompletedProcess([], 0, "", ""))
    monkeypatch.setattr(value, "_ensure_enterprise_image", lambda progress: {"version": "12.0.0"})
    monkeypatch.setattr(value, "_ensure_proxy_image", lambda progress: {"digest": PROXY_IMAGE_DIGEST})
    service_checks = [0]

    def running_services(**kwargs):
        service_checks[0] += 1
        return set() if service_checks[0] == 1 else {"mattermost", "postgres", "proxy"}

    monkeypatch.setattr(value, "_running_services", running_services)
    monkeypatch.setattr(value, "health", lambda timeout=2: {"healthy": False})
    stopped = []
    monkeypatch.setattr(value, "_stop_services", lambda: stopped.append(True))
    monkeypatch.setattr("ctf_mcp.local_targets.mattermost.shutil.which", lambda _: "/fixed")
    with pytest.raises(LocalTargetError, match="HEALTH_TIMEOUT"):
        value.up(progress=lambda _: None)
    assert sleeps == [2] * 150
    assert sum(sleeps) == 300
    assert stopped == [True]


def test_up_never_adopts_an_unowned_healthy_listener(tmp_path, monkeypatch):
    value = adapter(tmp_path)
    monkeypatch.setattr(value, "_require_source", lambda: None)
    monkeypatch.setattr(value, "_load_secrets", lambda create: {name: "x" * 24 for name in
                        ("database", "system_admin", "delegated_admin", "victim", "normal_user")})
    monkeypatch.setattr(value, "_write_runtime_files", lambda passwords: None)
    monkeypatch.setattr(value.runner, "run", lambda *args, **kwargs: subprocess.CompletedProcess([], 0, "", ""))
    monkeypatch.setattr(value, "_ensure_enterprise_image", lambda progress: {"version": "12.0.0"})
    monkeypatch.setattr(value, "_ensure_proxy_image", lambda progress: {"digest": PROXY_IMAGE_DIGEST})
    monkeypatch.setattr(value, "_running_services", lambda **kwargs: set())
    monkeypatch.setattr(value, "health", lambda timeout=2: {"healthy": True})
    monkeypatch.setattr("ctf_mcp.local_targets.mattermost.shutil.which", lambda _: "/fixed")
    with pytest.raises(LocalTargetError, match="TARGET_START_FAILED"):
        value.up(progress=lambda _: None)


def test_up_starts_proxy_before_strict_host_health_gate(tmp_path, monkeypatch):
    value = adapter(tmp_path)
    monkeypatch.setattr(value, "_require_source", lambda: None)
    monkeypatch.setattr(value, "_load_secrets", lambda create: {name: "x" * 24 for name in
                        ("database", "system_admin", "delegated_admin", "victim", "normal_user")})
    monkeypatch.setattr(value, "_write_runtime_files", lambda passwords: None)
    monkeypatch.setattr(value.runner, "run", lambda *args, **kwargs:
                        subprocess.CompletedProcess([], 0, "", ""))
    monkeypatch.setattr(value, "_ensure_enterprise_image", lambda progress: {"version": "12.0.0"})
    monkeypatch.setattr(value, "_ensure_proxy_image", lambda progress: {"digest": PROXY_IMAGE_DIGEST})
    monkeypatch.setattr(value, "_running_services", lambda **kwargs: set())
    health = iter(({"healthy": False}, {"healthy": True}))
    monkeypatch.setattr(value, "health", lambda timeout=2: next(health))
    compose_calls = []
    monkeypatch.setattr(value, "_compose", lambda tail, **kwargs:
                        compose_calls.append(tail) or subprocess.CompletedProcess([], 0, "", ""))
    verified = []
    monkeypatch.setattr(value, "_verify_owned_runtime_containers", lambda passwords:
                        verified.append(True))
    monkeypatch.setattr(value, "status", lambda: {"health": "healthy"})
    monkeypatch.setattr("ctf_mcp.local_targets.mattermost.shutil.which", lambda _: "/fixed")

    result = value.up(progress=lambda _: None)

    assert compose_calls == [[
        "up", "-d", "--wait", "postgres", "mattermost", "proxy",
    ]]
    assert verified == [True]
    assert result["status"] == "healthy"


def test_enterprise_version_probe_accepts_exact_prevalidated_build():
    result = MattermostAdapter._validate_enterprise_version("""Version: 12.0.0
Build Number: master-35359240453
Build Date: Fri Sep 18 14:59:51 UTC 2026
Build Hash: d283cc6301368f6e3dc0fa6be0a1537a9677750b
Build Enterprise Ready: true
""")
    assert result == {
        "version": "12.0.0",
        "build_number": "master-35359240453",
        "build_date": "Fri Sep 18 14:59:51 UTC 2026",
        "build_hash": REVISION,
        "enterprise_ready": "true",
    }


def test_enterprise_ready_false_is_rejected():
    with pytest.raises(LocalTargetError, match="ENTERPRISE_RUNTIME_REQUIRED"):
        MattermostAdapter._validate_enterprise_version(
            "Build Hash: " + REVISION + "\nBuild Enterprise Ready: false\n"
        )


def test_enterprise_build_hash_mismatch_is_rejected():
    with pytest.raises(LocalTargetError, match="IMAGE_MISMATCH"):
        MattermostAdapter._validate_enterprise_version(
            "Build Hash: " + "0" * 40 + "\nBuild Enterprise Ready: true\n"
        )


def test_local_image_digest_or_platform_mismatch_is_rejected(tmp_path):
    class ImageRunner:
        def run(self, argv, **kwargs):
            value = [{"RepoDigests": ["mattermostdevelopment/mattermost-enterprise-edition@sha256:" + "0" * 64],
                      "Os": "linux", "Architecture": "amd64"}]
            return subprocess.CompletedProcess(argv, 0, json.dumps(value), "")

    value = adapter(tmp_path, runner=ImageRunner())
    with pytest.raises(LocalTargetError, match="IMAGE_MISMATCH"):
        value._inspect_enterprise_image(timeout=1, allow_missing=False)


def test_proxy_image_digest_and_platform_are_immutable(tmp_path):
    class ImageRunner:
        def __init__(self, digest=PROXY_IMAGE_DIGEST, architecture="amd64"):
            self.digest, self.architecture = digest, architecture

        def run(self, argv, **kwargs):
            value = [{
                "RepoDigests": ["haproxy@" + self.digest],
                "Os": "linux", "Architecture": self.architecture,
            }]
            return subprocess.CompletedProcess(argv, 0, json.dumps(value), "")

    assert adapter(tmp_path / "valid", runner=ImageRunner())._inspect_proxy_image(
        timeout=1, allow_missing=False,
    ) == {"digest": PROXY_IMAGE_DIGEST, "platform": PROXY_PLATFORM}
    for index, runner in enumerate((
        ImageRunner("sha256:" + "0" * 64), ImageRunner(architecture="arm64"),
    )):
        with pytest.raises(LocalTargetError, match="PROXY_IMAGE_MISMATCH"):
            adapter(tmp_path / f"invalid-{index}", runner=runner)._inspect_proxy_image(
                timeout=1, allow_missing=False,
            )


def test_running_services_rejects_unowned_compose_service(tmp_path, monkeypatch):
    value = adapter(tmp_path)
    monkeypatch.setattr(value, "_compose", lambda *args, **kwargs:
                        subprocess.CompletedProcess([], 0, "postgres\nmattermost\nproxy\n", ""))
    assert value._running_services(timeout=1) == {"postgres", "mattermost", "proxy"}
    monkeypatch.setattr(value, "_compose", lambda *args, **kwargs:
                        subprocess.CompletedProcess([], 0, "postgres\nmattermost\nproxy\nrogue\n", ""))
    with pytest.raises(LocalTargetError, match="unsafe_local_runtime"):
        value._running_services(timeout=1)


def test_running_container_image_mismatch_is_rejected(tmp_path, monkeypatch):
    class ContainerRunner:
        def run(self, argv, **kwargs):
            value = [{
                "Config": {
                    "Image": "mattermostdevelopment/mattermost-enterprise-edition:wrong",
                    "Labels": {
                        "com.docker.compose.project": "iwantgohome-local-mattermost",
                        "com.docker.compose.service": "mattermost",
                    },
                },
                "State": {"Running": True},
            }]
            return subprocess.CompletedProcess(argv, 0, json.dumps(value), "")

    value = adapter(tmp_path, runner=ContainerRunner())
    monkeypatch.setattr(value, "_compose", lambda *args, **kwargs:
                        subprocess.CompletedProcess([], 0, "a" * 64 + "\n", ""))
    with pytest.raises(LocalTargetError, match="IMAGE_MISMATCH"):
        value._verify_owned_mattermost_container({"database": "x" * 24})


def test_mattermost_container_requires_internal_only_network_and_no_published_port(tmp_path, monkeypatch):
    class ContainerRunner:
        def __init__(self, *, project=COMPOSE_PROJECT, bindings=None, networks=None):
            self.project = project
            self.bindings = bindings
            self.networks = networks or {INTERNAL_NETWORK: {}}

        def run(self, argv, **kwargs):
            value = [{
                "Config": {
                    "Image": ENTERPRISE_IMAGE_REFERENCE,
                    "Labels": {
                        "com.docker.compose.project": self.project,
                        "com.docker.compose.service": "mattermost",
                    },
                },
                "HostConfig": {"PortBindings": self.bindings},
                "NetworkSettings": {"Networks": self.networks},
                "State": {"Running": True},
            }]
            return subprocess.CompletedProcess(argv, 0, json.dumps(value), "")

    good = ContainerRunner()
    value = adapter(tmp_path / "good", runner=good)
    monkeypatch.setattr(value, "_compose", lambda *args, **kwargs:
                        subprocess.CompletedProcess([], 0, "a" * 64 + "\n", ""))
    value._verify_owned_mattermost_container({"database": "x" * 24})

    for index, runner in enumerate((
        ContainerRunner(project="unowned"),
        ContainerRunner(bindings={"8065/tcp": [{"HostIp": "127.0.0.1", "HostPort": "13100"}]}),
        ContainerRunner(networks={INTERNAL_NETWORK: {}, PUBLISHED_NETWORK: {}}),
    )):
        value = adapter(tmp_path / f"bad-{index}", runner=runner)
        monkeypatch.setattr(value, "_compose", lambda *args, **kwargs:
                            subprocess.CompletedProcess([], 0, "a" * 64 + "\n", ""))
        with pytest.raises(LocalTargetError, match="TARGET_START_FAILED"):
            value._verify_owned_mattermost_container({"database": "x" * 24})


def test_proxy_container_requires_owned_image_networks_loopback_port_and_hardening(tmp_path, monkeypatch):
    expected_binding = {"13100/tcp": [{"HostIp": "127.0.0.1", "HostPort": "13100"}]}

    class ProxyRunner:
        def __init__(self, *, image=PROXY_IMAGE_REFERENCE, bindings=expected_binding,
                     networks=None, privileged=False, read_only=True, cap_drop=None):
            self.image, self.bindings = image, bindings
            self.networks = networks or {INTERNAL_NETWORK: {}, PUBLISHED_NETWORK: {}}
            self.privileged, self.read_only = privileged, read_only
            self.cap_drop = ["ALL"] if cap_drop is None else cap_drop

        def run(self, argv, **kwargs):
            value = [{
                "Config": {
                    "Image": self.image,
                    "Labels": {
                        "com.docker.compose.project": COMPOSE_PROJECT,
                        "com.docker.compose.service": "proxy",
                    },
                },
                "HostConfig": {
                    "PortBindings": self.bindings, "Privileged": self.privileged,
                    "ReadonlyRootfs": self.read_only, "NetworkMode": INTERNAL_NETWORK,
                    "CapDrop": self.cap_drop,
                },
                "NetworkSettings": {"Networks": self.networks},
                "State": {"Running": True},
            }]
            return subprocess.CompletedProcess(argv, 0, json.dumps(value), "")

    def inspect(runner, suffix):
        value = adapter(tmp_path / suffix, runner=runner)
        monkeypatch.setattr(value, "_compose", lambda *args, **kwargs:
                            subprocess.CompletedProcess([], 0, "b" * 64 + "\n", ""))
        value._inspect_owned_container(
            "proxy", PROXY_IMAGE_REFERENCE, {INTERNAL_NETWORK, PUBLISHED_NETWORK},
            expected_binding, {"database": "x" * 24}, hardened_proxy=True,
        )

    inspect(ProxyRunner(), "good-proxy")
    with pytest.raises(LocalTargetError, match="PROXY_IMAGE_MISMATCH"):
        inspect(ProxyRunner(image="haproxy:wrong"), "wrong-image")
    for index, runner in enumerate((
        ProxyRunner(bindings={"13100/tcp": [{"HostIp": "0.0.0.0", "HostPort": "13100"}]}),
        ProxyRunner(networks={PUBLISHED_NETWORK: {}}),
        ProxyRunner(privileged=True),
        ProxyRunner(read_only=False),
        ProxyRunner(cap_drop=[]),
    )):
        with pytest.raises(LocalTargetError, match="TARGET_START_FAILED"):
            inspect(runner, f"unsafe-proxy-{index}")


def test_runtime_ownership_checks_postgres_mattermost_and_proxy(tmp_path, monkeypatch):
    value = adapter(tmp_path)
    observed = []
    monkeypatch.setattr(value, "_inspect_owned_container", lambda *args, **kwargs:
                        observed.append((args, kwargs)))
    value._verify_owned_runtime_containers({"database": "x" * 24})
    assert [item[0][0] for item in observed] == ["postgres", "mattermost", "proxy"]
    assert observed[0][0][1:4] == ("postgres:15", {INTERNAL_NETWORK}, None)
    assert observed[1][0][1:4] == (ENTERPRISE_IMAGE_REFERENCE, {INTERNAL_NETWORK}, None)
    assert observed[2][0][1] == PROXY_IMAGE_REFERENCE
    assert observed[2][0][2] == {INTERNAL_NETWORK, PUBLISHED_NETWORK}
    assert observed[2][1]["hardened_proxy"] is True


def test_health_client_is_fixed_to_localhost_only():
    assert LocalMattermostClient.host == "127.0.0.1"
    assert LocalMattermostClient.port == 13100


def test_tcp_proxy_path_preserves_auth_token_status_content_type_and_body(monkeypatch):
    captured = {}

    class Response:
        status = 207

        @staticmethod
        def read(size):
            return b'{"status":"FORWARDED","value":7}'

        @staticmethod
        def getheader(name):
            return {
                "Token": "finder-local-response-token",
                "Content-Type": "application/json; charset=utf-8",
            }.get(name)

    class Connection:
        def __init__(self, host, port, timeout):
            assert (host, port) == ("127.0.0.1", 13100)

        def request(self, method, path, body=None, headers=None):
            captured.update({"method": method, "path": path, "body": body, "headers": headers})

        @staticmethod
        def getresponse():
            return Response()

        @staticmethod
        def close():
            pass

    monkeypatch.setattr("ctf_mcp.local_targets.http.http.client.HTTPConnection", Connection)
    client = LocalMattermostClient(token="finder-local-request-token")
    response = client.request("health", "GET", "/api/v4/system/ping")
    assert captured == {
        "method": "GET", "path": "/api/v4/system/ping", "body": None,
        "headers": {
            "Accept": "application/json",
            "Authorization": "Bearer finder-local-request-token",
        },
    }
    assert response.status == 207
    assert response.data == {"status": "FORWARDED", "value": 7}
    assert client.session_fingerprint == hashlib.sha256(
        b"finder-local-response-token"
    ).hexdigest()[:16]


def test_health_via_proxy_keeps_exact_200_and_ok_body_gate(tmp_path):
    class Client:
        def __init__(self, response):
            self.response = response

        def request(self, scope, method, path, count=False):
            assert (scope, method, path, count) == (
                "health", "GET", "/api/v4/system/ping", False,
            )
            return self.response

    responses = iter((
        LocalResponse(200, {"status": "OK"}, {"status": "str"}),
        LocalResponse(200, {"status": "STARTING"}, {"status": "str"}),
        LocalResponse(503, {"status": "OK"}, {"status": "str"}),
    ))
    value = adapter(tmp_path, client_factory=lambda timeout: Client(next(responses)))
    assert value.health() == {"healthy": True, "status": "healthy", "status_code": 200}
    assert value.health() == {"healthy": False, "status": "unhealthy", "status_code": 200}
    assert value.health() == {"healthy": False, "status": "unhealthy", "status_code": 503}


def test_bootstrap_rejects_missing_active_enterprise_runtime(tmp_path, monkeypatch):
    value = adapter(tmp_path)
    monkeypatch.setattr(value, "_require_source", lambda: None)
    monkeypatch.setattr(value, "health", lambda timeout=2: {"healthy": True})
    monkeypatch.setattr(value, "_load_secrets", lambda create: {"database": "x" * 24})
    monkeypatch.setattr(value, "_require_active_enterprise_runtime",
                        lambda passwords: (_ for _ in ()).throw(LocalTargetError("ENTERPRISE_RUNTIME_REQUIRED")))
    with pytest.raises(LocalTargetError, match="ENTERPRISE_RUNTIME_REQUIRED"):
        value.bootstrap()


class RecordingClient:
    def __init__(self, responses, fingerprint="0123456789abcdef"):
        self.responses = list(responses)
        self.calls = []
        self.session_fingerprint = fingerprint

    def request(self, scope, method, path, payload=None, *, count=True):
        self.calls.append((scope, method, path, payload, count))
        status, data = self.responses.pop(0)
        return LocalResponse(status, data, response_shape(data))


def built_in_manager_role(permissions=None):
    return {
        "id": "r" * 26,
        "name": "system_user_manager",
        "permissions": sorted(
            REQUIRED_DELEGATED_PERMISSIONS
            if permissions is None else permissions
        ),
    }


def test_delegated_role_uses_builtin_permissions_without_patching(tmp_path, monkeypatch):
    delegated_id, control_id = "b" * 26, "c" * 26
    role = built_in_manager_role(set(REQUIRED_DELEGATED_PERMISSIONS) | {"manage_team"})
    admin = RecordingClient([
        (200, role),
        (200, {"status": "OK"}),
        (200, {"id": delegated_id, "roles": "system_user system_user_manager"}),
    ])
    delegated = RecordingClient([(200, {"id": control_id})])
    value = adapter(tmp_path)
    monkeypatch.setattr(value, "_login", lambda identity, passwords: delegated)

    capability = value._configure_delegated_role(
        admin, delegated_id, control_id, {"delegated_admin": "unused"},
    )

    assert capability["status"] == "ready"
    assert capability["assignment_verified"] is True
    assert capability["effective_control_verified"] is True
    assert [call[1:4] for call in admin.calls] == [
        ("GET", "/api/v4/roles/name/system_user_manager", None),
        ("PUT", f"/api/v4/users/{delegated_id}/roles", {
            "roles": "system_user system_user_manager",
        }),
        ("GET", f"/api/v4/users/{delegated_id}", None),
    ]
    assert delegated.calls[0][1:4] == (
        "GET", f"/api/v4/users/{control_id}", None,
    )
    assert not any("/roles/" in call[2] and call[1] != "GET" for call in admin.calls)


@pytest.mark.parametrize(("status", "role", "reason"), [
    (404, {}, "ROLE_LOOKUP_FAILED"),
    (200, {**built_in_manager_role(), "name": "system_admin"}, "ROLE_LOOKUP_FAILED"),
    (200, {**built_in_manager_role(), "id": "invalid"}, "ROLE_LOOKUP_FAILED"),
    (200, {**built_in_manager_role(), "permissions": "view_team"}, "ROLE_LOOKUP_FAILED"),
    (200, built_in_manager_role(
        set(REQUIRED_DELEGATED_PERMISSIONS) | {"manage_system"},
    ), "ROLE_TOO_PRIVILEGED"),
    (200, built_in_manager_role({"view_team"}), "REQUIRED_ROLE_PERMISSIONS_MISSING"),
])
def test_delegated_role_lookup_rejects_unsafe_or_incomplete_role(
    tmp_path, status, role, reason,
):
    admin = RecordingClient([(status, role)])
    result = adapter(tmp_path)._configure_delegated_role(
        admin, "b" * 26, "c" * 26, {"delegated_admin": "unused"},
    )
    assert result["status"] == "unavailable"
    assert result["reason"] == reason
    assert len(admin.calls) == 1


def test_delegated_role_reports_assignment_failure(tmp_path):
    admin = RecordingClient([(200, built_in_manager_role()), (403, {})])
    result = adapter(tmp_path)._configure_delegated_role(
        admin, "b" * 26, "c" * 26, {"delegated_admin": "unused"},
    )
    assert result["reason"] == "ROLE_ASSIGNMENT_FAILED"


@pytest.mark.parametrize(("completed", "reason"), [
    ([], "ROLE_LOOKUP_FAILED"),
    ([(200, built_in_manager_role())], "ROLE_ASSIGNMENT_FAILED"),
    ([(200, built_in_manager_role()), (200, {})], "ROLE_ASSIGNMENT_NOT_EFFECTIVE"),
])
def test_delegated_role_normalizes_client_failures(tmp_path, completed, reason):
    class FailingClient(RecordingClient):
        def request(self, scope, method, path, payload=None, *, count=True):
            if not self.responses:
                raise LocalTargetError("BOOTSTRAP_FAILED")
            return super().request(scope, method, path, payload, count=count)

    result = adapter(tmp_path)._configure_delegated_role(
        FailingClient(completed), "b" * 26, "c" * 26,
        {"delegated_admin": "unused"},
    )
    assert result["reason"] == reason


@pytest.mark.parametrize("verified_user", [
    {"id": "b" * 26, "roles": "system_user"},
    {"id": "b" * 26, "roles": "system_user system_user_manager system_admin"},
    {"id": "z" * 26, "roles": "system_user system_user_manager"},
])
def test_delegated_role_requires_exact_effective_assignment(tmp_path, verified_user):
    admin = RecordingClient([
        (200, built_in_manager_role()), (200, {}), (200, verified_user),
    ])
    result = adapter(tmp_path)._configure_delegated_role(
        admin, "b" * 26, "c" * 26, {"delegated_admin": "unused"},
    )
    assert result["reason"] == "ROLE_ASSIGNMENT_NOT_EFFECTIVE"


def test_delegated_role_requires_effective_read_only_control(tmp_path, monkeypatch):
    admin = RecordingClient([
        (200, built_in_manager_role()),
        (200, {}),
        (200, {"id": "b" * 26, "roles": "system_user system_user_manager"}),
    ])
    delegated = RecordingClient([(403, {"id": "permission_denied"})])
    value = adapter(tmp_path)
    monkeypatch.setattr(value, "_login", lambda identity, passwords: delegated)
    result = value._configure_delegated_role(
        admin, "b" * 26, "c" * 26, {"delegated_admin": "unused"},
    )
    assert result["reason"] == "ROLE_ASSIGNMENT_NOT_EFFECTIVE"


@pytest.mark.parametrize(("capability", "status", "bootstrap_status"), [
    (delegated_capability(), "ready", "READY"),
    (delegated_capability(
        "unavailable", "REQUIRED_ROLE_PERMISSIONS_MISSING", {"view_team"},
    ), "partial", "PARTIAL"),
])
def test_bootstrap_rerun_reuses_existing_fixture_posts(
    tmp_path, monkeypatch, capability, status, bootstrap_status,
):
    value = adapter(tmp_path)
    ids = {name: char * 26 for name, char in {
        "system_admin": "a", "delegated_admin": "b", "victim": "c", "normal_user": "d",
        "team": "e", "channel_a": "f", "channel_b": "g", "direct": "h",
        "thread": "i", "dm_thread": "j",
    }.items()}

    class BootstrapClient:
        session_fingerprint = "0123456789abcdef"
        request_count = 0

        def __init__(self, identity):
            self.identity = identity
            self.post_ids = [ids["thread"], ids["dm_thread"]]
            self.created_posts = 0

        def request(self, scope, method, path, payload=None, *, count=True):
            if method == "GET" and "/users/username/" in path:
                data = {"id": ids["system_admin"], "roles": "system_user system_admin"}
                return LocalResponse(200, data, response_shape(data))
            if method == "DELETE":
                return LocalResponse(200, {}, {})
            if method == "POST" and path == "/api/v4/channels/direct":
                data = {"id": ids["direct"]}
                return LocalResponse(201, data, response_shape(data))
            if method == "POST" and path == "/api/v4/posts":
                data = {"id": self.post_ids[self.created_posts]}
                self.created_posts += 1
                return LocalResponse(201, data, response_shape(data))
            raise AssertionError((scope, method, path))

    admin, victim = BootstrapClient("system_admin"), BootstrapClient("victim")
    monkeypatch.setattr(value, "_require_source", lambda: None)
    monkeypatch.setattr(value, "health", lambda timeout=2: {"healthy": True})
    monkeypatch.setattr(value, "_load_secrets", lambda create: {
        name: "x" * 24 for name in ("database", "system_admin", "delegated_admin", "victim", "normal_user")
    })
    monkeypatch.setattr(value, "_require_active_enterprise_runtime", lambda passwords: None)
    monkeypatch.setattr(value, "_login", lambda identity, passwords: admin if identity == "system_admin" else victim)
    monkeypatch.setattr(value, "_get_or_create_user", lambda admin_client, identity, passwords: {
        "id": ids[identity], "roles": "system_user",
    })
    monkeypatch.setattr(
        value,
        "_configure_delegated_role",
        lambda admin_client, user_id, control_user_id, passwords: capability,
    )
    monkeypatch.setattr(value, "_get_or_create_team", lambda admin_client: {"id": ids["team"]})
    monkeypatch.setattr(value, "_ensure_team_member", lambda *args: None)
    monkeypatch.setattr(value, "_get_or_create_channel", lambda admin_client, team_id, suffix: {
        "id": ids["channel_a" if suffix == "private-channel-a" else "channel_b"]
    })
    monkeypatch.setattr(value, "_ensure_channel_member", lambda *args: None)

    first = value.bootstrap()
    first_state = json.loads(value.bootstrap_file.read_text())
    second = value.bootstrap()
    second_state = json.loads(value.bootstrap_file.read_text())

    assert first["status"] == second["status"] == status
    assert first["bootstrap_status"] == second["bootstrap_status"] == bootstrap_status
    assert second_state["capabilities"]["delegated_user_manager"] == capability
    assert _valid_bootstrap_state(second_state)
    assert _bootstrap_state_status(second_state) == status
    assert victim.created_posts == 2
    for key in ("thread_id", "dm_thread_id", "private_channel_a", "dm_victim_normal_user"):
        assert second_state[key] == first_state[key]


def test_validate_rechecks_active_enterprise_runtime(tmp_path, monkeypatch):
    value = adapter(tmp_path)
    checked = []
    monkeypatch.setattr(value, "_require_source", lambda: None)
    monkeypatch.setattr(value, "health", lambda timeout=2: {"healthy": True})
    monkeypatch.setattr(value, "_load_secrets", lambda create: {"database": "x" * 24})
    monkeypatch.setattr(value, "_require_active_enterprise_runtime", lambda passwords: checked.append(True))
    monkeypatch.setattr(value, "_validate_s12", lambda: {"candidate": "S12"})
    assert value.validate("S12") == [{"candidate": "S12"}]
    assert checked == [True]


def test_candidate_request_budgets_and_unknown_candidate(tmp_path, monkeypatch):
    assert REQUEST_BUDGETS == {"S12": 8, "S13": 5, "S15": 5}
    value = adapter(tmp_path)
    with pytest.raises(LocalTargetError, match="local_request_budget_exceeded"):
        value._save_validation("S12", "NEEDS_MORE_EVIDENCE", [], False, 9,
                               {"role_summary": {}, "session_fingerprint": "0123456789abcdef", "control": "DENIED"})
    monkeypatch.setattr(value, "health", lambda timeout=2: {"healthy": True})
    with pytest.raises(LocalTargetError, match="unknown_local_candidate"):
        value.validate("S99")


@pytest.mark.parametrize("candidate,method,path", [
    ("S12", "GET", "/api/v4/users/" + "a" * 26 + "/teams/" + "b" * 26 + "/threads/" + "c" * 26),
    ("S13", "GET", "/api/v4/users/" + "a" * 26 + "/channel_members?page=0&per_page=100"),
    ("S15", "PUT", "/api/v4/users/" + "a" * 26 + "/teams/" + "b" * 26 + "/threads/read"),
])
def test_candidate_route_allowlists(candidate, method, path):
    assert any(allowed_method == method and pattern.fullmatch(path)
               for allowed_method, pattern in ALLOWED[candidate])
    client = LocalMattermostClient()
    with pytest.raises(LocalTargetError, match="local_route_not_allowed"):
        client.request(candidate, method, path + "/unreviewed")


def test_bootstrap_allowlist_rejects_global_role_patch():
    client = LocalMattermostClient()
    with pytest.raises(LocalTargetError, match="local_route_not_allowed"):
        client.request("bootstrap", "PUT", "/api/v4/roles/" + "r" * 26 + "/patch", {})


def test_synthetic_resource_marker_and_status_mapping(tmp_path, monkeypatch):
    assert _contains_message({"threads": [{"post": {"message": SYNTHETIC_MESSAGE}}]}, SYNTHETIC_MESSAGE)
    value = adapter(tmp_path)
    monkeypatch.setattr(value, "_source_details", lambda timeout=0.75: {
        "actual_commit": REVISION, "source_status": "READY",
    })
    monkeypatch.setattr(value, "health", lambda timeout=0.75: {"status": "healthy", "healthy": True})
    monkeypatch.setattr("ctf_mcp.local_targets.mattermost.shutil.which", lambda _: None)
    status = value.status()
    assert status["source_status"] == "READY"
    assert status["health"] == "healthy"
    assert status["enterprise_image"] == ENTERPRISE_IMAGE
    assert status["expected_image_digest"] == ENTERPRISE_IMAGE_DIGEST
    assert status["image_digest"] is None
    assert status["proxy_image"] == PROXY_IMAGE
    assert status["expected_proxy_image_digest"] == PROXY_IMAGE_DIGEST
    assert status["proxy_image_digest"] is None
    assert status["mattermost_container"] == "not_configured"
    assert status["postgres_container"] == "not_configured"
    assert status["local_proxy_container"] == "not_configured"
    assert status["host_endpoint"] == "http://127.0.0.1:13100"
    assert status["observer_linux_mapping"] == "host-gateway"


def synthetic_state():
    capability = delegated_capability()
    return {
        "marker": "FINDER_LOCAL_BOOTSTRAP_V1",
        "target_commit": REVISION,
        "users": {"system_admin": "a" * 26, "delegated_admin": "b" * 26,
                  "victim": "c" * 26, "normal_user": "d" * 26},
        "team_a": "e" * 26,
        "private_channel_a": "f" * 26,
        "private_channel_b": "g" * 26,
        "dm_victim_normal_user": "h" * 26,
        "thread_id": "i" * 26,
        "dm_thread_id": "j" * 26,
        "role_summary": capability["role_summary"],
        "bootstrap_status": "READY",
        "capabilities": {"delegated_user_manager": capability},
    }


def test_bootstrap_state_requires_matching_capability_status():
    state = synthetic_state()
    assert _valid_bootstrap_state(state)
    state["bootstrap_status"] = "PARTIAL"
    assert not _valid_bootstrap_state(state)
    capability = delegated_capability(
        "unavailable", "REQUIRED_ROLE_PERMISSIONS_MISSING", {"view_team"},
    )
    state["capabilities"]["delegated_user_manager"] = capability
    state["role_summary"] = capability["role_summary"]
    assert _valid_bootstrap_state(state)
    assert _bootstrap_state_status(state) == "partial"


@pytest.mark.parametrize("candidate", ["S12", "S13"])
def test_partial_bootstrap_blocks_only_selected_candidate_with_precise_reason(
    tmp_path, monkeypatch, candidate,
):
    value = adapter(tmp_path)
    state = synthetic_state()
    state["bootstrap_status"] = "PARTIAL"
    capability = delegated_capability(
        "unavailable", "REQUIRED_ROLE_PERMISSIONS_MISSING", {"view_team"},
    )
    state["capabilities"]["delegated_user_manager"] = capability
    state["role_summary"] = capability["role_summary"]
    value.bootstrap_file.parent.mkdir(parents=True)
    value.bootstrap_file.write_text(json.dumps(state))
    monkeypatch.setattr(value, "_require_source", lambda: None)
    monkeypatch.setattr(value, "health", lambda timeout=2: {"healthy": True})
    monkeypatch.setattr(value, "_load_secrets", lambda create: {"database": "x" * 24})
    monkeypatch.setattr(value, "_require_active_enterprise_runtime", lambda passwords: None)

    results = value.validate(candidate)

    assert len(results) == 1
    assert results[0]["candidate"] == candidate
    assert results[0]["status"] == "BLOCKED_BY_LOCAL_SETUP"
    assert results[0]["blocked_reason"] == "REQUIRED_ROLE_PERMISSIONS_MISSING"
    assert results[0]["request_count"] == 0


class SequenceClient:
    def __init__(self, responses, fingerprint="0123456789abcdef"):
        self.responses = list(responses)
        self.request_count = 0
        self.session_fingerprint = fingerprint

    def request(self, scope, method, path, payload=None, *, count=True):
        if count:
            self.request_count += 1
        status, data = self.responses.pop(0)
        return LocalResponse(status, data, response_shape(data))


def test_s12_validator_requires_denied_single_and_returned_marker(tmp_path, monkeypatch):
    value = adapter(tmp_path)
    state = synthetic_state()
    permitted = SequenceClient([
        (200, {"post": {"id": state["thread_id"], "message": SYNTHETIC_MESSAGE}}),
        (200, {"threads": [{"post": {"id": state["thread_id"], "message": SYNTHETIC_MESSAGE}}]}),
    ], fingerprint="fedcba9876543210")
    delegated = SequenceClient([
        (403, {"id": "permission_denied"}),
        (200, {"threads": [{"post": {"id": state["thread_id"], "message": SYNTHETIC_MESSAGE}},
                            {"post": {"id": state["dm_thread_id"], "message": "PRIVATE_S12_DM_TEST_MESSAGE"}}]}),
        (403, {"id": "permission_denied"}),
    ])
    monkeypatch.setattr(value, "_validation_context", lambda candidate: (state, {"victim": "unused"}, delegated))
    monkeypatch.setattr(value, "_login", lambda identity, passwords: permitted)
    result = value._validate_s12()
    assert result["status"] == "VERIFIED_CANDIDATE"
    assert result["request_count"] == 5
    assert result["control_fixture_verified"] is True
    assert result["synthetic_marker_returned"] is True
    assert result["dm_variant_control_denied"] is True


def test_s13_validator_maps_supported_delegated_behavior(tmp_path, monkeypatch):
    value = adapter(tmp_path)
    state = synthetic_state()
    row = {"channel_id": state["private_channel_a"], "roles": "channel_user",
           "msg_count": 1, "mention_count": 0, "notify_props": {}, "team_name": "finder-local-team-a"}
    permitted = SequenceClient([(200, [row])], fingerprint="fedcba9876543210")
    delegated = SequenceClient([(200, [row])])
    monkeypatch.setattr(value, "_validation_context", lambda candidate: (state, {"victim": "unused"}, delegated))
    monkeypatch.setattr(value, "_login", lambda identity, passwords: permitted)
    result = value._validate_s13()
    assert result["status"] == "INTENDED_BEHAVIOR"
    assert result["control_fixture_verified"] is True
    assert result["candidate_result"] == 200
    assert result["comparison"]["candidate_channel_ids"] == [state["private_channel_a"]]
    assert result["request_count"] == 2


def test_s15_validator_requires_victim_state_change(tmp_path, monkeypatch):
    value = adapter(tmp_path)
    state = synthetic_state()
    delegated = SequenceClient([(403, {"id": "permission_denied"}), (200, {"status": "OK"})])
    setup = SequenceClient([(201, {"id": "k" * 26})])
    victim = SequenceClient([
        (200, {"threads": [{"post": {"id": state["thread_id"]}, "last_viewed_at": 1,
                              "unread_replies": 1, "unread_mentions": 0, "is_following": True}]}),
        (200, {"threads": [{"post": {"id": state["thread_id"]}, "last_viewed_at": 2,
                              "unread_replies": 0, "unread_mentions": 0, "is_following": True}]}),
    ])
    monkeypatch.setattr(value, "_validation_context", lambda candidate: (state, {"normal_user": "unused", "victim": "unused"}, delegated))
    monkeypatch.setattr(value, "_login", lambda identity, passwords: setup if identity == "normal_user" else victim)
    result = value._validate_s15()
    assert result["status"] == "VERIFIED_CANDIDATE"
    assert result["victim_state_changed"] is True
    assert result["request_count"] == 4


def test_host_cli_imports_without_optional_yaml_dependency():
    root = Path(__file__).resolve().parents[1]
    spec = importlib.util.spec_from_file_location("local_control", root / "scripts/control.py")
    assert spec is not None
