"""Host adapter contracts using local mocks, without claiming physical-device validation."""
import asyncio
import json
import os
import sys
import types
import pytest
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from ctf_mcp import device_adapter as adapter
from ctf_mcp.config import Rejected
from ctf_mcp.records import digest
from test_mcp import environment


def test_missing_endpoints_and_invalid_endpoints():
    for name in ("adb_devices", "adb_package_info", "adb_logcat_snapshot", "frida_devices", "frida_process_list"):
        assert adapter.analyze({"analyzer": name}, {})["status"] == "HOST_ADAPTER_REQUIRED"
    for value in ("localhost", "http://host:1234", "host:99999", "user@host:1234", "host:1234/path", "host:1234\n"):
        with pytest.raises(Rejected):adapter.endpoint(value)


def test_adb_fixed_commands_opaque_identity_and_messages_withheld(monkeypatch):
    calls = []
    serial = "SYNTHETIC-SERIAL"
    def output(args, env):
        calls.append(args)
        if args == ["devices", "-l"]:return "List of devices attached\n" + serial + " device product:test\n"
        if args[-3:] == ["dumpsys", "package", "org.example.fixture"]:return "versionCode=1 targetSdk=35\nsecret=NEVER_RETURN"
        if args[-2:] == ["pidof", "org.example.fixture"]:return "123\n"
        if "logcat" in args:return "I/Fixture(123): password=NEVER_RETURN\nD/Fixture(123): harmless but withheld\n"
        raise AssertionError(args)
    monkeypatch.setattr(adapter, "adb_output", output)
    env = {"FINDER_ADB_ENDPOINT": "host.docker.internal:5037"}
    inventory = adapter.analyze({"analyzer": "adb_devices"}, env)
    device = inventory["devices"][0]["device_id"]
    assert device == digest(serial.encode())[:16] and serial not in json.dumps(inventory)
    package = adapter.analyze({"analyzer": "adb_package_info", "device_id": device, "package": "org.example.fixture"}, env)
    logs = adapter.analyze({"analyzer": "adb_logcat_snapshot", "device_id": device, "package": "org.example.fixture", "lines": 2}, env)
    assert package["metadata"] and len(logs["entries"]) == 2
    assert all(entry["message_withheld"] for entry in logs["entries"])
    assert "NEVER_RETURN" not in json.dumps([package, logs])
    with pytest.raises(Rejected):adapter.analyze({"analyzer": "adb_package_info", "device_id": device, "package": "org.test;id"}, env)
    with pytest.raises(Rejected):adapter.analyze({"analyzer": "adb_package_info", "device_id": "unknown", "package": "org.example.fixture"}, env)
    with pytest.raises(Rejected):adapter.analyze({"analyzer": "adb_logcat_snapshot", "device_id": device, "package": "org.example.fixture", "lines": 201}, env)
    assert not any(set(call) & {"install", "am", "connect", "pair", "start-server", "kill-server"} for call in calls)


def test_frida_metadata_only_and_cleanup(monkeypatch):
    calls = []
    class Device:
        def enumerate_processes(self, **kwargs):
            calls.append(kwargs);return [types.SimpleNamespace(pid=7, name="synthetic")]
    class Manager:
        def add_remote_device(self, value):calls.append(("add", value));return Device()
        def remove_remote_device(self, value):calls.append(("remove", value))
    monkeypatch.setitem(sys.modules, "frida", types.SimpleNamespace(get_device_manager=lambda: Manager()))
    monkeypatch.setattr(adapter, "version", lambda name: "synthetic-test-version")
    result = adapter.analyze({"analyzer": "frida_process_list"}, {"FINDER_FRIDA_ENDPOINT": "host.docker.internal:27042"})
    assert result["processes"] == [{"pid": 7, "name": "synthetic"}]
    assert calls[1] == {"scope": "minimal"} and calls[-1][0] == "remove"


@pytest.mark.parametrize("role,tool,args", [("android", "android_manifest", {"path": "sample.apk"}),
    ("binary", "binary_identify", {"path": "sample.macho"}), ("android-dynamic", "adb_devices", {}),
    ("burp", "burp_capabilities", {})])
def test_new_roles_real_mcp_initialize_list_call(settings, tmp_path, role, tool, args):
    async def run():
        async with asyncio.timeout(25):
            params = StdioServerParameters(command=sys.executable, args=["-m", "ctf_mcp.server", "--role", role], env=environment(settings, tmp_path))
            with open(os.devnull, "w") as errors:
                async with stdio_client(params, errlog=errors) as (read, write):
                    async with ClientSession(read, write) as client:
                        init = await client.initialize()
                        assert init.serverInfo.name == "something-finder-" + role
                        names = {t.name for t in (await client.list_tools()).tools}
                        assert tool in names and not {"run_tool", "frida_js", "adb_shell", "request_replay"} & names
                        result = await client.call_tool(tool, args)
                        assert not result.isError, result
                        if role == "android-dynamic":assert result.structuredContent["payload"]["result"]["status"] == "HOST_ADAPTER_REQUIRED"
    asyncio.run(run())
