from pathlib import Path

import pytest

from ctf_mcp.targets import (
    TARGET_API_VERSION,
    TARGET_ENTRY_POINT_GROUP,
    TargetPluginError,
    TargetRegistry,
)
from ctf_mcp.local_targets.base import load_adapter
from ctf_mcp.target_cli import run_target


class FakeDistribution:
    name = "example-target-package"
    version = "1.2.3"


class FakeEntryPoint:
    group = TARGET_ENTRY_POINT_GROUP
    dist = FakeDistribution()

    def __init__(self, name, factory, value=None):
        self.name = name
        self.value = value or f"example_{name}.adapter:create_adapter"
        self.factory = factory
        self.loads = 0

    def load(self):
        self.loads += 1
        if isinstance(self.factory, Exception):
            raise self.factory
        return self.factory


class FakeAdapter:
    target_api_version = TARGET_API_VERSION
    supported_candidates = frozenset({"CAND-001"})

    def __init__(self, target_id, root):
        self.target_id = target_id
        self.root = root

    def prepare(self): return {"status": "prepared"}
    def up(self, progress=print): return {"status": "ready"}
    def status(self): return {"status": "ready"}
    def bootstrap(self): return {"status": "ready"}
    def validate(self, candidate=None): return []
    def stop(self): return {"status": "stopped"}
    def reset(self): return {"status": "reset"}


def factory_for(target_id, *, version=TARGET_API_VERSION, adapter_type=FakeAdapter):
    def create_adapter(*, root, runner=None):
        del runner
        adapter = adapter_type(target_id, root)
        adapter.target_api_version = version
        return adapter
    return create_adapter


def registry(*entries):
    return TargetRegistry(entry_points_provider=lambda: entries)


def test_valid_plugin_metadata_discovery_and_load(tmp_path):
    entry = FakeEntryPoint("sample", factory_for("sample"))
    value = registry(entry)

    metadata = value.list()
    assert [item.to_dict() for item in metadata] == [{
        "target_id": "sample",
        "entry_point": "example_sample.adapter:create_adapter",
        "distribution": "example-target-package",
        "distribution_version": "1.2.3",
        "built_in": False,
    }]
    assert entry.loads == 0

    adapter = value.load("sample", root=tmp_path)
    assert adapter.target_id == "sample"
    assert adapter.root == tmp_path
    assert entry.loads == 1


def test_target_list_is_lazy_and_explicit_selection_imports_only_one(tmp_path):
    first = FakeEntryPoint("first", factory_for("first"))
    second = FakeEntryPoint("second", factory_for("second"))
    value = registry(first, second)

    assert [item.target_id for item in value.list()] == ["first", "second"]
    assert (first.loads, second.loads) == (0, 0)
    assert value.load("second", root=tmp_path).target_id == "second"
    assert (first.loads, second.loads) == (0, 1)


def test_duplicate_target_id_is_rejected_before_import(tmp_path):
    first = FakeEntryPoint("same", factory_for("same"), "one:create")
    second = FakeEntryPoint("same", factory_for("same"), "two:create")
    value = registry(first, second)
    with pytest.raises(TargetPluginError, match="DUPLICATE_TARGET_ID"):
        value.load("same", root=tmp_path)
    assert (first.loads, second.loads) == (0, 0)


@pytest.mark.parametrize("entry", [
    FakeEntryPoint("invalid name", factory_for("invalid-name")),
    FakeEntryPoint("broken", RuntimeError("import failed")),
])
def test_invalid_plugin_is_rejected(tmp_path, entry):
    with pytest.raises(TargetPluginError, match="INVALID_TARGET_PLUGIN"):
        registry(entry).load(entry.name, root=tmp_path)


def test_wrong_api_version_is_incompatible(tmp_path):
    entry = FakeEntryPoint("old", factory_for("old", version=0))
    with pytest.raises(TargetPluginError, match="INCOMPATIBLE_TARGET_PLUGIN"):
        registry(entry).load("old", root=tmp_path)


def test_malformed_adapter_is_incompatible(tmp_path):
    class Incomplete:
        target_api_version = TARGET_API_VERSION
        target_id = "incomplete"
        supported_candidates = frozenset()

    def create_adapter(*, root, runner=None):
        del root, runner
        return Incomplete()

    entry = FakeEntryPoint("incomplete", create_adapter)
    with pytest.raises(TargetPluginError, match="INCOMPATIBLE_TARGET_PLUGIN"):
        registry(entry).doctor("incomplete", root=tmp_path)


def test_registry_instances_are_isolated(tmp_path):
    one = registry(FakeEntryPoint("one", factory_for("one")))
    two = registry(FakeEntryPoint("two", factory_for("two")))
    assert [item.target_id for item in one.list()] == ["one"]
    assert [item.target_id for item in two.list()] == ["two"]
    with pytest.raises(TargetPluginError, match="TARGET_NOT_FOUND"):
        one.load("two", root=tmp_path)


def test_registry_has_no_arbitrary_path_loading():
    source = Path(__file__).parents[1].joinpath("src/ctf_mcp/targets.py").read_text()
    for forbidden in ("PYTHONPATH", "os.listdir", ".rglob(", "sys.path"):
        assert forbidden not in source


def test_local_adapter_lookup_accepts_installed_plugin_without_core_manifest(
    tmp_path, monkeypatch,
):
    value = registry(FakeEntryPoint("external", factory_for("external")))
    monkeypatch.setattr(
        "ctf_mcp.local_targets.plugin_registry.get_target_registry",
        lambda: value,
    )
    loaded = load_adapter(tmp_path, "external")
    assert loaded.target_id == "external"
    assert not (tmp_path / "config/local-targets/external.json").exists()


def test_target_cli_list_is_lazy_and_doctor_only_loads_selected(
    tmp_path, monkeypatch,
):
    first = FakeEntryPoint("first", factory_for("first"))
    second = FakeEntryPoint("second", factory_for("second"))
    value = registry(first, second)
    monkeypatch.setattr("ctf_mcp.target_cli.get_target_registry", lambda: value)
    output = []
    assert run_target(tmp_path, ["list"], output=output.append) == 0
    assert (first.loads, second.loads) == (0, 0)
    assert '"imports_performed": false' in output[0]
    output.clear()
    assert run_target(tmp_path, ["doctor", "second"], output=output.append) == 0
    assert (first.loads, second.loads) == (0, 1)
    assert '"status": "compatible"' in output[0]
