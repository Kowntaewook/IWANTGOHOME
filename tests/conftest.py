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
