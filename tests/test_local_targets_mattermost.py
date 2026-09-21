from ctf_mcp.full_hunt.engine import FullHuntEngine
from ctf_mcp.local_targets.base import LocalTargetManifest
from ctf_mcp.local_targets.mattermost import MattermostAdapter
from ctf_mcp.local_targets.mattermost_hunt_adapter import MattermostFullHuntTargetAdapter


def manifest():
    return LocalTargetManifest(
        "mattermost", MattermostAdapter.repository, MattermostAdapter.pinned_revision,
        MattermostAdapter.host_health_url,
    )


def test_mattermost_runtime_namespaces_do_not_overlap_gitea(tmp_path):
    value = MattermostAdapter(tmp_path, manifest())
    assert value.runtime_root == tmp_path / ".operator/local-runtime/mattermost"
    assert value.secret_root == tmp_path / ".operator/local-secrets/mattermost"
    assert value.evidence_root == tmp_path / ".operator/local-evidence/mattermost"
    for path in (value.runtime_root, value.secret_root, value.evidence_root):
        assert "gitea" not in str(path)


def test_full_hunt_entrypoint_uses_generic_engine(tmp_path, monkeypatch):
    value = MattermostAdapter(tmp_path, manifest())
    observed = {}

    def fake_run(self, *, root, run_id=None):
        observed["adapter"] = self.adapter
        observed["root"] = root
        return {"target": self.adapter.target_id}

    monkeypatch.setattr(FullHuntEngine, "run", fake_run)
    result = value.full_hunt()
    assert result == {"target": "mattermost"}
    assert isinstance(observed["adapter"], MattermostFullHuntTargetAdapter)
    assert observed["root"] == tmp_path


def test_pinned_source_configuration_uses_official_repository_and_lock():
    assert MattermostAdapter.repository == "https://github.com/mattermost/mattermost"
    assert len(MattermostAdapter.pinned_revision) == 40
    assert set(MattermostAdapter.pinned_revision) <= set("0123456789abcdef")
