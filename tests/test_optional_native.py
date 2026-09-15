"""Real optional parsers on our own inert fixtures; never execute an input app."""
from dataclasses import replace
import os
from pathlib import Path
import subprocess
import zipfile
import pytest
from ctf_mcp.config import Rejected
from ctf_mcp.engine import Engine


@pytest.mark.parametrize("analyzer,path", [("android_decompile_summary", "sample.apk"), ("ghidra_analyze", "sample.elf")])
def test_native_missing_tool_and_input_boundaries(settings, tmp_path, monkeypatch, analyzer, path):
    monkeypatch.setenv("FINDER_TOOL_ROOT", str(tmp_path / "absent-tools"))
    record = Engine(settings).analyze(analyzer, path)
    assert record["payload"]["result"]["status"] == "OPTIONAL_TOOL_REQUIRED"
    with pytest.raises(Rejected):Engine(settings).analyze(analyzer, "../escape")
    (settings.input_root / "bad").write_bytes(b"malformed")
    with pytest.raises(Rejected):Engine(settings).analyze(analyzer, "bad")
    small = replace(settings, limits=replace(settings.limits, file_bytes=64))
    with pytest.raises(Rejected, match="file_too_large"):Engine(small).analyze(analyzer, path)


def installed(name):
    root = Path(os.environ.get("FINDER_TOOL_ROOT", "/opt/finder-tools"))
    if not (root / name).is_file():pytest.skip("Reviewed optional native tool is not installed; no execution claim")
    return root


def test_real_jadx_decompiles_own_java_fixture(settings, tmp_path):
    root = installed("jadx/bin/jadx")
    installed("java/bin/javac")
    # Compile only this fixed test string, never code from a submitted project.
    source = tmp_path / "FinderFixture.java"
    source.write_text('public final class FinderFixture { public String label() { return "synthetic"; } }')
    classes = tmp_path / "classes";classes.mkdir()
    dex = tmp_path / "dex";dex.mkdir()
    subprocess.run([str(root / "java/bin/javac"), "--release", "8", "-d", str(classes), str(source)],
        check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30)
    jars = list((root / "jadx/lib").glob("jadx-*-all.jar"))
    assert len(jars) == 1
    subprocess.run([str(root / "java/bin/java"), "-cp", str(jars[0]), "com.android.tools.r8.D8",
        "--min-api", "21", "--output", str(dex), str(classes / "FinderFixture.class")],
        check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30)
    target = settings.input_root / "own-fixture.apk"
    with zipfile.ZipFile(settings.input_root / "sample.apk") as original:
        manifest = original.read("AndroidManifest.xml")
    with zipfile.ZipFile(target, "w") as archive:
        archive.writestr("AndroidManifest.xml", manifest)
        archive.writestr("classes.dex", (dex / "classes.dex").read_bytes())
    record = Engine(replace(settings, limits=replace(settings.limits, seconds=90))).analyze("android_decompile_summary", target.name)
    result = record["payload"]["result"]
    assert result["status"] == "analyzed" and result["files_inspected"] > 0, result
    assert any("FinderFixture" in review["input"]["path"] for review in result["reviews"])
    assert record["provenance"]["input_sha256"]


def test_real_ghidra_fixed_headless_script(settings):
    installed("ghidra/support/analyzeHeadless")
    engine = Engine(replace(settings, limits=replace(settings.limits, seconds=90)))
    record = engine.analyze("ghidra_analyze", "sample.elf")
    result = record["payload"]["result"]
    assert result["status"] == "analyzed", result
    assert result["observations"]["format"] == "Executable and Linking Format (ELF)"
    assert result["observations"]["analysis_timed_out"] is False
    assert isinstance(result["observations"]["functions"], list)
    assert result["observations"]["symbols"]
