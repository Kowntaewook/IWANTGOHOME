import json
from pathlib import Path
import subprocess

import pytest

from ctf_mcp.local_targets.base import LocalTargetError, LocalTargetManifest
from ctf_mcp.local_targets.gitea import GiteaAdapter
from ctf_mcp.local_targets.gitea_main_retest import (
    MAIN_COMPOSE_PROJECT,
    MAIN_ENDPOINT,
    MAIN_PORT,
    MAIN_REPOSITORY,
    GiteaMainRetest,
)


COMMIT = "a" * 40
IMAGE_ID = "sha256:" + "b" * 64


def manifest():
    return LocalTargetManifest(
        "gitea",
        MAIN_REPOSITORY,
        GiteaAdapter.pinned_revision,
        "http://127.0.0.1:13000/api/healthz",
    )


class MainRunner:
    def __init__(self, *, remote_output=None, fail_build=False, invalid_identity=False):
        self.remote_output = (
            f"{COMMIT}\trefs/heads/main\n" if remote_output is None else remote_output
        )
        self.fail_build = fail_build
        self.invalid_identity = invalid_identity
        self.calls = []
        self.image = False
        self.labels = {}

    def run(self, argv, **kwargs):
        argv = list(argv)
        self.calls.append((argv, kwargs))
        if argv[0] == "git":
            if "ls-remote" in argv:
                output = self.remote_output
            elif argv[-3:] == ["remote", "get-url", "origin"]:
                output = MAIN_REPOSITORY + "\n"
            elif argv[-2:] == ["rev-parse", "HEAD"]:
                output = COMMIT + "\n"
            elif "status" in argv:
                output = ""
            else:
                output = ""
            return subprocess.CompletedProcess(argv, 0, output, "")
        if argv[:3] == ["docker", "image", "inspect"]:
            if not self.image:
                raise subprocess.CalledProcessError(1, argv)
            labels = dict(self.labels)
            image_id = IMAGE_ID
            if self.invalid_identity:
                labels["iwantgohome.gitea.main.commit"] = "c" * 40
            output = json.dumps([{
                "Id": image_id,
                "RepoDigests": [],
                "Config": {"Labels": labels},
            }])
            return subprocess.CompletedProcess(argv, 0, output, "")
        if argv[:2] == ["docker", "build"]:
            if self.fail_build:
                raise subprocess.CalledProcessError(
                    1, argv, output="Authorization: synthetic-secret\n", stderr="failed\n"
                )
            self.labels = {
                value.split("=", 1)[0]: value.split("=", 1)[1]
                for index, value in enumerate(argv)
                if index and argv[index - 1] == "--label"
            }
            self.image = True
            return subprocess.CompletedProcess(
                argv, 0, "build complete\nAuthorization: synthetic-secret\n", ""
            )
        raise AssertionError(argv)


def manager(tmp_path, runner=None, **kwargs):
    kwargs.setdefault("port_in_use", lambda: False)
    return GiteaMainRetest(
        tmp_path,
        manifest(),
        runner=runner or MainRunner(),
        now=lambda: "2026-09-21T01:02:03+00:00",
        monotonic=iter((10.0, 12.5, 20.0, 23.0, 30.0, 34.0)).__next__,
        **kwargs,
    )


def source_fixture(value, dockerfile=b"FROM scratch\n"):
    source = value.source_root / COMMIT
    (source / ".git").mkdir(parents=True)
    (source / ".git/config").write_text(
        "[remote \"origin\"]\n\turl = https://github.com/go-gitea/gitea\n"
    )
    (source / "Dockerfile.rootless").write_bytes(dockerfile)
    (source / "go.mod").write_text("module code.gitea.io/gitea\n")
    return source


def resolved_source(value):
    source = source_fixture(value)
    return {
        "branch": "main",
        "commit": COMMIT,
        "fetched_at": "2026-09-21T01:02:03+00:00",
        "repository": MAIN_REPOSITORY,
        "source_directory": str(source.relative_to(value.root)),
    }


def build_identity():
    return {
        "commit": COMMIT,
        "image_tag": "iwantgohome/gitea-main:" + COMMIT[:12],
        "image_id": IMAGE_ID,
        "repo_digest": None,
        "build_timestamp": "2026-09-21T01:03:00+00:00",
        "build_log_path": ".operator/local-runtime/gitea-main/build.log",
        "build_elapsed_seconds": 2.5,
        "cache_hit": False,
        "success": True,
    }


def candidate(candidate_id="SD-G04", baseline="G04"):
    return {"candidate_id": candidate_id, "baseline_candidate": baseline}


def local_result(status, control=True):
    return {
        "candidate": "G04",
        "status": status,
        "assertions": {"control_passed": control},
        "evidence": "1" * 32,
        "reassessment": "2" * 32,
    }


def test_main_head_resolution_records_immutable_identity(tmp_path):
    value = manager(tmp_path)
    source_fixture(value)
    result = value.resolve_source()
    assert result == {
        "branch": "main",
        "commit": COMMIT,
        "fetched_at": "2026-09-21T01:02:03+00:00",
        "repository": MAIN_REPOSITORY,
        "source_directory": f".operator/targets/gitea-main/{COMMIT}",
    }
    assert json.loads(value.source_record.read_text()) == result
    call = value.runner.calls[0][0]
    assert "ls-remote" in call and call[-2:] == [MAIN_REPOSITORY, "refs/heads/main"]


@pytest.mark.parametrize("output", ["main\trefs/heads/main\n", "", "a" * 39 + "\trefs/heads/main\n"])
def test_main_head_rejects_missing_or_non_sha_identity(tmp_path, output):
    value = manager(tmp_path, MainRunner(remote_output=output))
    with pytest.raises(LocalTargetError, match="MAIN_COMMIT_UNRESOLVED"):
        value.resolve_source()


def test_main_build_command_is_fixed_and_local_source_only(tmp_path, monkeypatch):
    runner = MainRunner()
    value = manager(tmp_path, runner)
    source = resolved_source(value)
    monkeypatch.setattr("ctf_mcp.local_targets.gitea_main_retest.shutil.which", lambda name: "/usr/bin/docker")
    result = value.ensure_image(source)
    build = next(call for call, _ in runner.calls if call[:2] == ["docker", "build"])
    assert build[0:2] == ["docker", "build"]
    assert build[-1] == str(tmp_path / source["source_directory"])
    assert "Dockerfile.rootless" in build[3]
    assert not any(value in build for value in ("--network=host", "--ssh", "--secret"))
    assert result["image_id"] == IMAGE_ID and result["repo_digest"] is None
    log = (tmp_path / result["build_log_path"]).read_text()
    assert "synthetic-secret" not in log
    assert "[REDACTED SECRET-LIKE LINE]" in log


def test_main_build_cache_hit_reuses_matching_image_identity(tmp_path, monkeypatch):
    runner = MainRunner()
    first = manager(tmp_path, runner)
    source = resolved_source(first)
    monkeypatch.setattr("ctf_mcp.local_targets.gitea_main_retest.shutil.which", lambda name: "/usr/bin/docker")
    built = first.ensure_image(source)
    second = manager(tmp_path, runner)
    second._source = source
    cached = second.ensure_image(source)
    assert built["image_id"] == cached["image_id"] == IMAGE_ID
    assert cached["cache_hit"] is True
    assert sum(call[:2] == ["docker", "build"] for call, _ in runner.calls) == 1


def test_main_build_cache_invalidates_when_recipe_changes(tmp_path, monkeypatch):
    runner = MainRunner()
    first = manager(tmp_path, runner)
    source = resolved_source(first)
    monkeypatch.setattr("ctf_mcp.local_targets.gitea_main_retest.shutil.which", lambda name: "/usr/bin/docker")
    first.ensure_image(source)
    (tmp_path / source["source_directory"] / "Dockerfile.rootless").write_text("FROM scratch\n# changed\n")
    second = manager(tmp_path, runner)
    second._source = source
    rebuilt = second.ensure_image(source)
    assert rebuilt["cache_hit"] is False
    assert sum(call[:2] == ["docker", "build"] for call, _ in runner.calls) == 2


def test_main_image_identity_requires_commit_recipe_and_config_labels(tmp_path, monkeypatch):
    runner = MainRunner(invalid_identity=True)
    value = manager(tmp_path, runner)
    source = resolved_source(value)
    monkeypatch.setattr("ctf_mcp.local_targets.gitea_main_retest.shutil.which", lambda name: "/usr/bin/docker")
    with pytest.raises(LocalTargetError, match="MAIN_IMAGE_IDENTITY_FAILED"):
        value.ensure_image(source)


def test_main_build_failure_serializes_reason_metadata_and_redacted_log(tmp_path, monkeypatch):
    runner = MainRunner(fail_build=True)
    value = manager(tmp_path, runner)
    source = resolved_source(value)
    value._source = source
    monkeypatch.setattr("ctf_mcp.local_targets.gitea_main_retest.shutil.which", lambda name: "/usr/bin/docker")
    with pytest.raises(LocalTargetError, match="MAIN_BUILD_FAILED"):
        value.ensure_image(source)
    cache = json.loads(value.cache_file.read_text())
    assert cache["success"] is False and cache["build_log_path"]
    value._failure = "MAIN_BUILD_FAILED"
    record = value.retest(candidate())
    assert record["blocked_reason"] == "MAIN_BUILD_FAILED"
    assert record["result"] == "RETEST_BLOCKED"
    assert "synthetic-secret" not in (tmp_path / cache["build_log_path"]).read_text()


def test_main_runtime_profile_isolated_from_pinned_and_latest(tmp_path):
    source = tmp_path / ".operator/targets/gitea-main" / COMMIT
    source.mkdir(parents=True)
    value = GiteaAdapter(
        tmp_path,
        manifest(),
        runtime_variant="main",
        runtime_port=13002,
        runtime_version="main",
        runtime_image_reference="iwantgohome/gitea-main:" + COMMIT[:12],
        runtime_image_digest=IMAGE_ID,
        runtime_image_id=IMAGE_ID,
        runtime_source_root=source,
        runtime_source_commit=COMMIT,
        compose_project=MAIN_COMPOSE_PROJECT,
    )
    assert value.runtime_root == tmp_path / ".operator/local-runtime/gitea-main"
    assert value.secret_root == tmp_path / ".operator/local-secrets/gitea-main"
    assert value.evidence_root == tmp_path / ".operator/local-evidence/gitea-main"
    assert "127.0.0.1:13002:3000" in value.compose_text
    assert "13000" not in value.compose_text and "13001" not in value.compose_text
    assert "2222:" not in value.compose_text and "22:" not in value.compose_text
    assert "sqlite3" in value.compose_text
    assert value.client_factory(timeout=1).host == "127.0.0.1"
    assert value.client_factory(timeout=1).port == MAIN_PORT


class ResultAdapter:
    def __init__(self, result):
        self.result = result

    def validate(self, baseline):
        return [{**self.result, "candidate": baseline}]

    def stop(self):
        return None


@pytest.mark.parametrize(
    ("local_status", "expected"),
    [("VERIFIED_LOCAL", "AFFECTED"), ("INTENDED_BEHAVIOR", "INTENDED_BEHAVIOR")],
)
def test_main_retest_deterministically_maps_affected_and_fixed(tmp_path, local_status, expected):
    value = manager(tmp_path)
    value._source = resolved_source(value)
    value._build = build_identity()
    value._bootstrap_status = "ready"
    value._adapter = ResultAdapter(local_result(local_status))
    record = value.retest(candidate())
    assert record["result"] == expected
    assert record["commit"] == COMMIT and record["image_id"] == IMAGE_ID
    assert record["control_passed"] is True


def test_main_control_failure_cannot_be_classified_fixed(tmp_path):
    value = manager(tmp_path)
    value._source = resolved_source(value)
    value._build = build_identity()
    value._bootstrap_status = "ready"
    value._adapter = ResultAdapter(local_result("INTENDED_BEHAVIOR", control=False))
    record = value.retest(candidate())
    assert record["result"] == "RETEST_BLOCKED"
    assert record["blocked_reason"] == "MAIN_CONTROL_FAILED"


def test_main_port_conflict_is_machine_readable(tmp_path, monkeypatch):
    class Adapter:
        def health(self, timeout):
            return {"healthy": False}

    value = manager(tmp_path, port_in_use=lambda: True, adapter_factory=lambda *a, **k: Adapter())
    value._source = resolved_source(value)
    value._build = build_identity()
    record = value.retest(candidate())
    assert record["blocked_reason"] == "MAIN_PORT_CONFLICT"
    assert record["runtime_host"] == "http://127.0.0.1:13002"


def test_main_candidate_filter_only_selects_verified_value_targets():
    assert GiteaMainRetest.supports(candidate("SD-G04", "G04")) is True
    assert GiteaMainRetest.supports(candidate("SD-G08", "G08")) is True
    assert GiteaMainRetest.supports(candidate("SD-G05", "G05")) is False
    assert GiteaMainRetest.supports(candidate("SD-G07", "G07")) is False
