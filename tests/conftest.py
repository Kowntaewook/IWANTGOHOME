import importlib.util
from pathlib import Path
import pytest
from ctf_mcp.config import Settings, Limits

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('fixture_factory',ROOT/'examples/make_fixtures.py')
factory=importlib.util.module_from_spec(spec);spec.loader.exec_module(factory)


@pytest.fixture
def settings(tmp_path):
    roots=[tmp_path/x for x in ('inputs','results','grants')]
    for root in roots:root.mkdir()
    factory.generate(roots[0])
    return Settings(*roots, Limits())


INTEGRATION_MODULES = {
    "test_analysis.py", "test_burp_adapter.py", "test_device_adapter.py", "test_mcp.py",
    "test_optional_native.py", "test_persistent_sessions.py", "test_program_integration.py",
    "test_upgrade_offline.py", "test_web.py",
    "test_local_targets_integration.py",
}
INTEGRATION_TEST_NAMES = {"test_actual_codex_discovery_when_available"}


def pytest_collection_modifyitems(items):
    """Classify every existing test without changing full-suite behavior or skips."""
    for item in items:
        marker = pytest.mark.integration if Path(str(item.fspath)).name in INTEGRATION_MODULES or \
            item.name in INTEGRATION_TEST_NAMES \
            else pytest.mark.fast
        item.add_marker(marker)
