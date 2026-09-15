import asyncio
import json
from pathlib import Path
import socket
import subprocess
import sys
import time
import pytest
from ctf_mcp.burp_adapter import BurpAdapter, metadata
from ctf_mcp.config import Rejected
from ctf_mcp.records import Records


@pytest.fixture(params=["streamable-http", "sse"])
def burp_mock(tmp_path, request):
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0));port = sock.getsockname()[1]
    source = tmp_path / "host_mock.py"
    source.write_text('''import json
from mcp.server.fastmcp import FastMCP
server=FastMCP("synthetic-host",host="127.0.0.1",port=''' + str(port) + ''',stateless_http=True,json_response=True)
@server.tool()
def get_proxy_http_history(count:int,offset:int)->str:
    return json.dumps({"request":"GET /api?name=PRIVATE_QUERY HTTP/1.1\\r\\nHost: fixture.invalid\\r\\nAuthorization: Bearer PRIVATE_AUTH\\r\\nCookie: sid=PRIVATE_COOKIE\\r\\n\\r\\n", "response":"HTTP/1.1 200 OK\\r\\nSet-Cookie: sid=PRIVATE_RESPONSE_COOKIE\\r\\nX-Content-Type-Options: nosniff\\r\\n\\r\\n{\\"name\\":\\"PRIVATE_NAME\\"}", "notes":"PRIVATE_NOTES"})
@server.tool()
def send_http1_request(target:str)->str:
    raise AssertionError("Active tool must never be called")
server.run(transport=''' + repr(request.param) + ''')
''')
    proc = subprocess.Popen([sys.executable, str(source)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            if proc.poll() is not None:raise AssertionError("Mock MCP server exited")
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=.1):break
            except OSError:time.sleep(.05)
        else:raise AssertionError("Mock MCP server not ready")
        yield {"BURP_MCP_URL": "http://127.0.0.1:" + str(port) + ("/sse" if request.param == "sse" else "/mcp"), "BURP_MCP_TRANSPORT": request.param, "BURP_MCP_TOKEN": "SYNTHETIC_CONNECTOR_TOKEN"}
    finally:proc.terminate();proc.wait(timeout=5)


def test_optional_absence_is_not_system_failure(settings):
    adapter = BurpAdapter(Records(settings.results_root), {})
    result = asyncio.run(adapter.capabilities())
    assert result["status"] == "NOT_CONFIGURED" and result["system_usable_without_burp"]
    assert asyncio.run(adapter.read("proxy_history"))["status"] == "HOST_ADAPTER_REQUIRED"


def test_real_mcp_discovery_history_and_minimization(settings, burp_mock):
    adapter = BurpAdapter(Records(settings.results_root), burp_mock)
    async def run():
        caps = await adapter.capabilities()
        assert caps["status"] == "connected", caps
        assert caps["reviewed_capabilities"]["proxy_history"]
        assert not caps["reviewed_capabilities"]["saved_requests"]
        assert "send_http1_request" not in caps["remote_tool_names"]
        saved = await adapter.read("proxy_history", 1, 0)
        text = json.dumps(saved)
        for sentinel in ("PRIVATE_QUERY", "PRIVATE_AUTH", "PRIVATE_COOKIE", "PRIVATE_RESPONSE_COOKIE", "PRIVATE_NAME", "PRIVATE_NOTES", "SYNTHETIC_CONNECTOR_TOKEN"):
            assert sentinel not in text
        observation = saved["payload"]["result"]["observations"][0]
        assert observation["method"] == "GET" and observation["status"] == 200
        assert observation["response_structure"]["shape"]["name"] == "string"
        assert (await adapter.read("saved_requests"))["status"] == "UNSUPPORTED_BY_HOST"
        with pytest.raises(Rejected):await adapter.read("send_http1_request")
    asyncio.run(run())


def test_endpoint_and_pagination_controls(settings):
    adapter = BurpAdapter(Records(settings.results_root), {"BURP_MCP_URL": "http://user:password@127.0.0.1/mcp"})
    assert asyncio.run(adapter.capabilities())["status"] == "HOST_ADAPTER_REQUIRED"
    with pytest.raises(Rejected):asyncio.run(adapter.read("proxy_history", 1000))
    assert "UNRECOGNIZED_RAW_SECRET" not in json.dumps(metadata({"request": "UNRECOGNIZED_RAW_SECRET"}))
