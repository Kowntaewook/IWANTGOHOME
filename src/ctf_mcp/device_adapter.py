"""Read-only host/device metadata. No installation, launch, attachment or Frida scripts."""
from importlib.metadata import version
import os
import re
import shutil
import subprocess
import tempfile
from urllib.parse import urlsplit
from .config import Rejected
from .records import digest
from .redaction import PATTERNS


def endpoint(value):
    if not isinstance(value, str) or not value or re.search(r"[\s/\\@?#]", value):raise Rejected("invalid_host_adapter_endpoint")
    try:
        parsed = urlsplit("tcp://" + value)
        if not parsed.hostname or not parsed.port or not 1 <= parsed.port <= 65535:raise ValueError()
        return parsed.hostname, parsed.port
    except ValueError:raise Rejected("invalid_host_adapter_endpoint") from None


def missing(reason):return {"status": "HOST_ADAPTER_REQUIRED", "reason": reason, "actual_device_validated": False}


def adb_output(args, env):
    executable = shutil.which("adb")
    if not executable:raise Rejected("adb_client_not_installed")
    host, port = endpoint(env["FINDER_ADB_ENDPOINT"])
    # -H/-P always address the operator's already running server. No connect,
    # pairing, daemon reset, network discovery, install, launch or arbitrary shell.
    with tempfile.TemporaryFile() as output:
        proc = subprocess.run([executable, "-H", host, "-P", str(port), *args], stdin=subprocess.DEVNULL,
            stdout=output, stderr=subprocess.DEVNULL, timeout=8, shell=False,
            env={"PATH": "/usr/bin:/bin", "HOME": "/tmp", "ADB_MDNS_AUTO_CONNECT": "0", "ADB_TRACE": ""})
        if proc.returncode:raise Rejected("adb_host_unavailable")
        if output.tell() > 1024 * 1024:raise Rejected("adb_output_limit")
        output.seek(0);return output.read().decode("utf-8", errors="replace")


def adb_devices(env):
    if not env.get("FINDER_ADB_ENDPOINT"):return [], missing("configure_host_adb_server_endpoint")
    raw = adb_output(["devices", "-l"], env)
    devices = []
    for line in raw.splitlines()[1:]:
        fields = line.split()
        if len(fields) < 2:continue
        serial, state = fields[:2]
        if not re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.:-]{0,127}", serial):continue
        devices.append({"serial": serial, "device_id": digest(serial.encode())[:16], "state": state if state in {"device", "offline", "unauthorized"} else "unknown"})
    return devices, None if any(d["state"] == "device" for d in devices) else missing("no_authorized_test_device_connected")


def analyze(request, env=None):
    env = os.environ if env is None else env
    kind = request["analyzer"]
    try:
        if kind.startswith("adb_"):
            devices, error = adb_devices(env)
            if error:return error
            if kind == "adb_devices":return {"status": "available", "devices": [{k: v for k, v in d.items() if k != "serial"} for d in devices]}
            device = next((d for d in devices if d["device_id"] == request.get("device_id") and d["state"] == "device"), None)
            if device is None:raise Rejected("device_not_in_configured_host_inventory")
            package = request.get("package", "")
            if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)+", package):raise Rejected("invalid_android_package_name")
            if kind == "adb_package_info":
                raw = adb_output(["-s", device["serial"], "shell", "dumpsys", "package", package], env)
                fields = []
                for line in raw.splitlines():
                    for key, value in re.findall(r"\b(versionCode|versionName|minSdk|targetSdk|firstInstallTime|lastUpdateTime)=([^\s]+)", line):
                        fields.append({"field": key, "value": value})
                return {"status": "available", "package": package, "metadata": fields,
                    "input_sha256": digest(raw.encode()), "limitations": ["Selected dumpsys declarations only; runtime behavior is not tested."]}
            if kind == "adb_logcat_snapshot":
                count = request.get("lines", 100)
                if type(count) is not int or not 1 <= count <= 200:raise Rejected("invalid_logcat_limit")
                pid_text = adb_output(["-s", device["serial"], "shell", "pidof", package], env).strip()
                pids = pid_text.split()
                if len(pids) != 1 or not pids[0].isdigit():return {"status": "PACKAGE_PID_UNAVAILABLE", "package": package}
                raw = adb_output(["-s", device["serial"], "logcat", "-d", "--pid=" + pids[0], "-t", str(count), "-v", "brief"], env)
                entries = []
                for line in raw.splitlines()[-count:]:
                    match = re.match(r"([VDIWEF])/([^(:]{1,64})", line)
                    if match:entries.append({"level": match[1], "tag": match[2].strip(),
                        "secret_indicator": any(p.search(line) for p in PATTERNS), "message_withheld": True})
                return {"status": "available", "package": package, "entries": entries, "input_sha256": digest(raw.encode())}
        elif kind in {"frida_devices", "frida_process_list"}:
            value = env.get("FINDER_FRIDA_ENDPOINT")
            if not value:return missing("configure_host_frida_endpoint")
            endpoint(value)
            try:import frida
            except ImportError:return missing("frida_client_not_installed")
            manager = frida.get_device_manager()
            device = manager.add_remote_device(value)
            try:
                processes = device.enumerate_processes(scope="minimal")
                if kind == "frida_devices":return {"status": "available", "devices": [{"device_id": digest(value.encode())[:16], "type": "configured_remote"}], "frida_version": version("frida")}
                if len(processes) > 2000:raise Rejected("frida_process_limit")
                return {"status": "available", "processes": [{"pid": p.pid, "name": p.name} for p in processes],
                    "frida_version": version("frida"), "limitations": ["Process metadata only; no attachment, instrumentation, hooks or target execution."]}
            finally:manager.remove_remote_device(value)
        raise Rejected("unknown_device_tool")
    except Rejected as exc:
        if str(exc) in {"adb_client_not_installed", "adb_host_unavailable"}:return missing(str(exc))
        raise
    except Exception:return missing("host_or_device_connection_unavailable")


def register(mcp, engine, annotations):
    from typing import Any
    @mcp.tool(annotations=annotations)
    def adb_devices() -> dict[str, Any]:
        """List devices already connected to the operator-configured host ADB server; no pairing or discovery."""
        return engine.device("adb_devices")
    @mcp.tool(annotations=annotations)
    def adb_package_info(device_id: str, package: str) -> dict[str, Any]:
        """Read selected package metadata on a listed test device; never install or start it."""
        return engine.device("adb_package_info", device_id=device_id, package=package)
    @mcp.tool(annotations=annotations)
    def adb_logcat_snapshot(device_id: str, package: str, lines: int = 100) -> dict[str, Any]:
        """Read a bounded package-PID log snapshot; return levels/tags and indicators, withholding all message text."""
        return engine.device("adb_logcat_snapshot", device_id=device_id, package=package, lines=lines)
    @mcp.tool(annotations=annotations)
    def frida_devices() -> dict[str, Any]:
        """Check the configured remote Frida endpoint and return an opaque device label; no scripts or process attachment."""
        return engine.device("frida_devices")
    @mcp.tool(annotations=annotations)
    def frida_process_list() -> dict[str, Any]:
        """List minimal process metadata from the configured Frida endpoint; no attachment or JS execution."""
        return engine.device("frida_process_list")
