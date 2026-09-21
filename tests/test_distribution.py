from pathlib import Path


def test_release_file_list_contains_generic_hunt_core():
    root = Path(__file__).resolve().parents[1]
    release = root / "release-files.txt"

    names = {
        line.strip()
        for line in release.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    }

    assert {
        "src/ctf_mcp/full_hunt/engine.py",
        "src/ctf_mcp/full_hunt/schema.py",
        "src/ctf_mcp/full_hunt/scenario.py",
    } <= names
