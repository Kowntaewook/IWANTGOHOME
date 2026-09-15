"""Fixed optional JADX/Ghidra invocations on private snapshots; never execute targets."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time
from .config import Rejected
from .platforms import android, binary
from .records import digest
from .safety import SafeRoot
from .source_analysis import source_view


def tool_root():return Path(os.environ.get("FINDER_TOOL_ROOT", "/opt/finder-tools"))


def run_fixed(argv, cwd, limits, generated):
    root = tool_root()
    env = {"HOME": str(cwd), "PATH": str(root / "java/bin") + ":/usr/bin:/bin", "JAVA_HOME": str(root / "java"),
        "LANG": "C.UTF-8", "JAVA_TOOL_OPTIONS": "-Xms32m -Xmx768m -XX:ReservedCodeCacheSize=64m -XX:CompressedClassSpaceSize=64m",
        "XDG_CONFIG_HOME": str(cwd / "config"), "XDG_CACHE_HOME": str(cwd / "cache")}
    env["GHIDRA_HEADLESS_MAXMEM"] = "768M"
    deadline = time.monotonic() + limits.seconds
    with tempfile.TemporaryFile() as output:
        proc = subprocess.Popen(argv, cwd=cwd, env=env, stdin=subprocess.DEVNULL,
            stdout=output, stderr=subprocess.STDOUT, shell=False)
        try:
            while proc.poll() is None:
                if time.monotonic() >= deadline:raise Rejected("native_tool_time_limit")
                total = count = 0
                for base, dirs, files in os.walk(generated, followlinks=False):
                    for name in files:
                        path = Path(base) / name
                        if path.is_symlink():raise Rejected("native_tool_generated_symlink")
                        total += path.stat().st_size;count += 1
                        if total > limits.archive_bytes or count > limits.archive_entries:raise Rejected("native_tool_output_limit")
                if output.tell() > limits.output_bytes:raise Rejected("native_tool_log_limit")
                time.sleep(.05)
            return proc.returncode
        finally:
            if proc.poll() is None:proc.kill()
            proc.wait()


def jadx_review(reader, path, view="android_decompile_summary", query=None):
    data = reader.read(path);parsed = android(data, reader.limits)
    executable = tool_root() / "jadx/bin/jadx"
    if not executable.is_file():
        return {"analyzer": view, "input": {"path": path, "sha256": digest(data)},
            "result": {"status": "OPTIONAL_TOOL_REQUIRED", "profile": "android", "tool": "JADX"}}
    with tempfile.TemporaryDirectory(prefix="finder-jadx-") as temp:
        temp = Path(temp);output = temp / "output";output.mkdir()
        target = temp / ("input.aab" if parsed["observations"]["format"] == "AAB" else "input.apk")
        target.write_bytes(data)
        code = run_fixed([str(executable), "--config", "none", "--no-res", "--no-imports", "--log-level", "quiet",
            "-j", "1", "-d", str(output), str(target)], temp, reader.limits, output)
        generated = SafeRoot(output, reader.limits)
        if view == "android_decompile_summary":
            review = source_view(generated, ".", "source_security_scan")
        else:review = source_view(generated, ".", view, query)
        review.update(analyzer=view, input={"path": path, "sha256": digest(data)})
        review["result"].update(tool="jadx", tool_version="1.5.6", exit_code=code,
            status="analyzed" if code == 0 else "partial_decompilation")
        review["result"]["limitations"].append("Generated source is temporary and may be incomplete/incorrect; line numbers refer to derived files. No APK install or execution.")
        return review


def ghidra_review(reader, path):
    data = reader.read(path);metadata = binary(data, reader.limits)
    executable = tool_root() / "ghidra/support/analyzeHeadless"
    if not executable.is_file():
        return {"analyzer": "ghidra_analyze", "input": {"path": path, "sha256": digest(data)},
            "result": {"status": "OPTIONAL_TOOL_REQUIRED", "profile": "binary", "tool": "Ghidra"}}
    scripts = Path(__file__).resolve().parent / "ghidra_scripts"
    with tempfile.TemporaryDirectory(prefix="finder-ghidra-") as temp:
        temp = Path(temp);projects = temp / "projects";projects.mkdir()
        target = temp / "input.bin";target.write_bytes(data)
        result_file = temp / "metadata.json"
        code = run_fixed([str(executable), str(projects), "review", "-import", str(target), "-max-cpu", "1",
            "-analysisTimeoutPerFile", str(max(1, reader.limits.seconds - 5)), "-scriptPath", str(scripts),
            "-postScript", "FinderMetadata.java", str(result_file)], temp, reader.limits, temp)
        if code != 0 or not result_file.is_file():raise Rejected("ghidra_analysis_failed_or_incomplete")
        result = json.loads(SafeRoot(temp, reader.limits).read("metadata.json", reader.limits.output_bytes))
        return {"analyzer": "ghidra_analyze", "input": {"path": path, "sha256": digest(data)},
                "result": {"status": "partial_analysis" if result.get("analysis_timed_out") else "analyzed", "tool_version": "12.1.3", "metadata": metadata,
                "observations": result, "limitations": ["Fresh private Ghidra project and checked-in postScript only; target never executed.",
                "Automatic analysis and symbol/function discovery can be incomplete; inferred function boundaries are not runtime evidence.",
                "No user scripts, extensions, project reuse, remote symbol downloads or decompiler code execution requested."]}}


def register(mcp, engine, role, annotations):
    from typing import Any
    if role in {"platform", "android"}:
        @mcp.tool(annotations=annotations)
        def android_decompile_summary(path: str) -> dict[str, Any]:
            """Run fixed JADX on an authorized APK/AAB snapshot and summarize derived source; never install or execute the app."""
            return engine.analyze("android_decompile_summary", path)
    if role in {"platform", "binary"}:
        @mcp.tool(annotations=annotations)
        def ghidra_analyze(path: str) -> dict[str, Any]:
            """Run bounded Ghidra headless in a fresh temporary project with the bundled metadata script; never execute the input."""
            return engine.analyze("ghidra_analyze", path)
        def view(record_id, key):
            record = engine.records.read(record_id)
            if record["kind"] != "analysis" or record["payload"].get("analyzer") != "ghidra_analyze":raise Rejected("ghidra_analysis_record_required")
            result = record["payload"]["result"]
            if result.get("status") not in {"analyzed", "partial_analysis"}:return {"status": result.get("status"), "evidence_id": record_id}
            return {"evidence_id": record_id, key: result["observations"][key], "limitations": result["limitations"]}
        @mcp.tool(annotations=annotations)
        def ghidra_functions(record_id: str) -> dict[str, Any]:
            """Read function metadata from an existing bounded Ghidra analysis record."""
            return view(record_id, "functions")
        @mcp.tool(annotations=annotations)
        def ghidra_symbols(record_id: str) -> dict[str, Any]:
            """Read symbol metadata from an existing bounded Ghidra analysis record."""
            return view(record_id, "symbols")
