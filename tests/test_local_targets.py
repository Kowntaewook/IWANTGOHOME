import importlib.util
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
    REQUEST_BUDGETS,
    SYNTHETIC_MESSAGE,
    MattermostAdapter,
    _contains_message,
)


REVISION = MattermostAdapter.pinned_revision


def manifest():
    return LocalTargetManifest(
        "mattermost",
        MattermostAdapter.repository,
        REVISION,
        "http://127.0.0.1:8065/api/v4/system/ping",
    )


def adapter(tmp_path, **kwargs):
    return MattermostAdapter(tmp_path, manifest(), **kwargs)


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
        "host_health_url": "http://127.0.0.1:8065/api/v4/system/ping",
    }))
    with pytest.raises(LocalTargetError, match="invalid_local_target_manifest"):
        load_adapter(tmp_path, "mattermost")


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
    external = tmp_path / "untrusted-compose.yaml"
    external.write_text(COMPOSE)
    value.compose_file.symlink_to(external)
    with pytest.raises(LocalTargetError, match="unsafe_local_runtime"):
        value._compose(["stop"], timeout=1)


def test_subprocesses_never_enable_shell_and_compose_never_mounts_docker_socket():
    root = Path(__file__).resolve().parents[1]
    code = "\n".join(path.read_text() for path in (root / "src/ctf_mcp/local_targets").glob("*.py"))
    assert "shell=True" not in code and "shell = True" not in code
    assert "/var/run/docker.sock" not in code
    assert "0.0.0.0:8065" not in code
    assert "127.0.0.1:8065" in code
    assert "postgres:15" in COMPOSE
    compose = yaml.safe_load((root / "docker-compose.yml").read_text())
    assert compose["services"]["observer"]["extra_hosts"] == ["host.docker.internal:host-gateway"]
    assert "host-adapter-egress" in compose["services"]["observer"]["networks"]
    assert not any(".operator/targets" in str(service.get("volumes", [])) for service in compose["services"].values())


def test_stop_preserves_source_data_secrets_and_evidence(tmp_path, monkeypatch):
    value = adapter(tmp_path)
    for path in (value.target_root, value.runtime_root, value.secret_root, value.evidence_root):
        path.mkdir(parents=True, exist_ok=True)
        (path / "preserve").write_text("synthetic")
    monkeypatch.setattr(value, "_stop_server", lambda: None)
    monkeypatch.setattr("ctf_mcp.local_targets.mattermost.shutil.which", lambda _: None)
    result = value.stop()
    assert result["data_preserved"] is True
    assert all((path / "preserve").is_file() for path in
               (value.target_root, value.runtime_root, value.secret_root, value.evidence_root))


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
    monkeypatch.setattr(value, "_read_process", lambda: None)
    monkeypatch.setattr(value, "_load_secrets", lambda create: {name: "x" * 24 for name in
                        ("database", "system_admin", "delegated_admin", "victim", "normal_user")})
    monkeypatch.setattr(value, "_write_runtime_files", lambda passwords: None)
    monkeypatch.setattr(value, "_compose", lambda *args, **kwargs: None)
    monkeypatch.setattr(value.runner, "run", lambda *args, **kwargs: subprocess.CompletedProcess([], 0, "", ""))
    monkeypatch.setattr(value, "health", lambda timeout=2: {"healthy": False})
    stopped = []
    monkeypatch.setattr(value, "_stop_server", lambda: stopped.append(True))
    monkeypatch.setattr("ctf_mcp.local_targets.mattermost.shutil.which", lambda _: "/fixed")

    class Process:
        pid = 424242

        def poll(self):
            return None

    monkeypatch.setattr("ctf_mcp.local_targets.mattermost.subprocess.Popen", lambda *a, **k: Process())
    monkeypatch.setattr(value, "_process_marker", lambda pid: "synthetic-start")
    with pytest.raises(LocalTargetError, match="HEALTH_TIMEOUT"):
        value.up(progress=lambda _: None)
    assert sleeps == [2] * 150
    assert sum(sleeps) == 300
    assert stopped == [True]


def test_up_never_adopts_an_unowned_healthy_listener(tmp_path, monkeypatch):
    value = adapter(tmp_path)
    monkeypatch.setattr(value, "_require_source", lambda: None)
    monkeypatch.setattr(value, "_read_process", lambda: None)
    monkeypatch.setattr(value, "health", lambda timeout=2: {"healthy": True})
    with pytest.raises(LocalTargetError, match="TARGET_START_FAILED"):
        value.up(progress=lambda _: None)


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


def test_synthetic_resource_marker_and_status_mapping(tmp_path, monkeypatch):
    assert _contains_message({"threads": [{"post": {"message": SYNTHETIC_MESSAGE}}]}, SYNTHETIC_MESSAGE)
    value = adapter(tmp_path)
    monkeypatch.setattr(value, "_source_details", lambda timeout=0.75: {
        "actual_commit": REVISION, "source_status": "READY",
    })
    monkeypatch.setattr(value, "health", lambda timeout=0.75: {"status": "healthy", "healthy": True})
    monkeypatch.setattr(value, "_read_process", lambda: None)
    monkeypatch.setattr("ctf_mcp.local_targets.mattermost.shutil.which", lambda _: None)
    status = value.status()
    assert status["source_status"] == "READY"
    assert status["health"] == "healthy"
    assert status["host_endpoint"] == "http://127.0.0.1:8065"
    assert status["observer_linux_mapping"] == "host-gateway"


def synthetic_state():
    return {
        "users": {"system_admin": "a" * 26, "delegated_admin": "b" * 26,
                  "victim": "c" * 26, "normal_user": "d" * 26},
        "team_a": "e" * 26,
        "private_channel_a": "f" * 26,
        "private_channel_b": "g" * 26,
        "dm_victim_normal_user": "h" * 26,
        "thread_id": "i" * 26,
        "dm_thread_id": "j" * 26,
        "role_summary": {"system_admin": False, "edit_other_users": True, "view_team": True,
                         "manage_system": False, "read_channel_content": False,
                         "target_channel_member": False},
    }


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
    client = SequenceClient([
        (403, {"id": "permission_denied"}),
        (200, {"threads": [{"post": {"id": state["thread_id"], "message": SYNTHETIC_MESSAGE}},
                            {"post": {"id": state["dm_thread_id"], "message": "PRIVATE_S12_DM_TEST_MESSAGE"}}]}),
        (403, {"id": "permission_denied"}),
    ])
    monkeypatch.setattr(value, "_validation_context", lambda: (state, {}, client))
    result = value._validate_s12()
    assert result["status"] == "VERIFIED_CANDIDATE"
    assert result["request_count"] == 3
    assert result["synthetic_marker_returned"] is True
    assert result["dm_variant_control_denied"] is True


def test_s13_validator_maps_supported_delegated_behavior(tmp_path, monkeypatch):
    value = adapter(tmp_path)
    state = synthetic_state()
    row = {"channel_id": state["private_channel_a"], "roles": "channel_user",
           "msg_count": 1, "mention_count": 0, "notify_props": {}, "team_name": "finder-local-team-a"}
    client = SequenceClient([(403, {"id": "permission_denied"}), (200, [row])])
    monkeypatch.setattr(value, "_validation_context", lambda: (state, {}, client))
    result = value._validate_s13()
    assert result["status"] == "INTENDED_BEHAVIOR"
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
    monkeypatch.setattr(value, "_validation_context", lambda: (state, {"normal_user": "unused", "victim": "unused"}, delegated))
    monkeypatch.setattr(value, "_login", lambda identity, passwords: setup if identity == "normal_user" else victim)
    result = value._validate_s15()
    assert result["status"] == "VERIFIED_CANDIDATE"
    assert result["victim_state_changed"] is True
    assert result["request_count"] == 4


def test_host_cli_imports_without_optional_yaml_dependency():
    root = Path(__file__).resolve().parents[1]
    spec = importlib.util.spec_from_file_location("local_control", root / "scripts/control.py")
    assert spec is not None
