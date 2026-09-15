"""Optional host Burp MCP reader. Exposes only reviewed fixed history operations."""
import asyncio
from contextlib import asynccontextmanager
import json
import os
import re
from urllib.parse import urlsplit
import httpx
from mcp import ClientSession
from mcp.client.sse import sse_client
from mcp.client.streamable_http import streamable_http_client
from .artifacts import header_metadata
from .browser_sessions import structure
from .config import Rejected
from .records import digest
from .redaction import public_url
from .research_policy import origin

REVIEWED = {"proxy_history": "get_proxy_http_history", "saved_requests": "get_organizer_items",
            "websocket_history": "get_proxy_websocket_history"}


class CappedStream(httpx.AsyncByteStream):
    def __init__(self, stream, transport):self.stream, self.transport = stream, transport
    async def __aiter__(self):
        async for chunk in self.stream:
            self.transport.received += len(chunk)
            if self.transport.received > 2 * 1024 * 1024:raise Rejected("burp_response_byte_limit")
            yield chunk
    async def aclose(self):await self.stream.aclose()


class HostTransport(httpx.AsyncBaseTransport):
    def __init__(self, url):
        self.origin = origin(url);self.received = 0
        self.inner = httpx.AsyncHTTPTransport(retries=0)
    async def handle_async_request(self, request):
        if origin(str(request.url)) != self.origin:raise Rejected("burp_cross_origin_endpoint_blocked")
        response = await self.inner.handle_async_request(request)
        response.stream = CappedStream(response.stream, self)
        return response
    async def aclose(self):await self.inner.aclose()


def metadata(item):
    if not isinstance(item, dict):return {"status": "unrecognized_item_values_withheld"}
    if "payload" in item:
        return {"direction": item.get("direction") if item.get("direction") in {"CLIENT_TO_SERVER", "SERVER_TO_CLIENT"} else "unknown",
                "payload_structure": structure(str(item["payload"]).encode()), "raw_values_withheld": True}
    request, response = item.get("request"), item.get("response")
    if not isinstance(request, str):return {"status": "request_not_available"}
    parts = request.replace("\r\n", "\n").split("\n\n", 1)
    lines = parts[0].splitlines();first = lines[0].split() if lines else []
    if len(first) < 2 or first[0] not in {"GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE", "CONNECT"}:
        return {"status": "unrecognized_request_values_withheld"}
    header_names = sorted({line.split(":", 1)[0].lower() for line in lines[1:] if ":" in line})
    result = {"method": first[0], "path": public_url(first[1]), "request_header_names": header_names,
        "request_structure": structure(parts[1].encode() if len(parts) == 2 else b""), "raw_values_withheld": True}
    if isinstance(response, str):
        chunks = response.replace("\r\n", "\n").split("\n\n", 1);rows = chunks[0].splitlines()
        status = re.match(r"HTTP/\S+\s+(\d{3})", rows[0] if rows else "")
        headers = dict(line.split(":", 1) for line in rows[1:] if ":" in line)
        result.update(status=int(status[1]) if status else None, response_security=header_metadata(headers),
                      response_structure=structure(chunks[1].encode() if len(chunks) == 2 else b""))
    return result


class BurpAdapter:
    def __init__(self, records, environ=None):
        self.records = records
        self.env = os.environ if environ is None else environ

    @asynccontextmanager
    async def connect(self):
        url = self.env.get("BURP_MCP_URL", "")
        parsed = urlsplit(url)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.password or parsed.fragment or parsed.query:
            raise Rejected("invalid_burp_endpoint")
        token = self.env.get("BURP_MCP_TOKEN", "")
        if "\r" in token or "\n" in token:raise Rejected("invalid_burp_token")
        headers = {"Authorization": "Bearer " + token} if token else {}
        transport = HostTransport(url)
        def factory(**kwargs):
            return httpx.AsyncClient(headers=headers, timeout=5, follow_redirects=False, trust_env=False, transport=transport)
        async with asyncio.timeout(12):
            if self.env.get("BURP_MCP_TRANSPORT", "sse") == "sse":
                async with sse_client(url, headers=headers, timeout=5, sse_read_timeout=8, httpx_client_factory=factory) as streams:
                    async with ClientSession(*streams) as session:
                        await session.initialize();yield session
            elif self.env.get("BURP_MCP_TRANSPORT") == "streamable-http":
                async with factory() as client:
                    async with streamable_http_client(url, http_client=client) as streams:
                        async with ClientSession(streams[0], streams[1]) as session:
                            await session.initialize();yield session
            else:raise Rejected("invalid_burp_transport")

    async def tools(self, session):
        found, cursor = {}, None
        for _ in range(5):
            page = await session.list_tools(cursor=cursor)
            for tool in page.tools:
                if tool.name in REVIEWED.values():found[tool.name] = tool.inputSchema
            cursor = page.nextCursor
            if not cursor:return found
        raise Rejected("burp_tool_list_limit")

    async def capabilities(self):
        if not self.env.get("BURP_MCP_URL"):return {"status": "NOT_CONFIGURED", "system_usable_without_burp": True}
        try:
            async with self.connect() as session:found = await self.tools(session)
            return {"status": "connected", "reviewed_capabilities": {k: v in found for k, v in REVIEWED.items()},
                "remote_tool_names": sorted(found), "comparison": "local_compare_records", "openapi_graphql": "local_file_analysis_tools",
                "note": "Only discovered, reviewed history tools are admitted. No active request/scanner/configuration tools are exposed."}
        except Exception:return {"status": "HOST_ADAPTER_REQUIRED", "reason": "burp_connection_or_protocol_unavailable", "system_usable_without_burp": True}

    async def read(self, capability, count=10, offset=0):
        if capability not in REVIEWED:raise Rejected("unreviewed_burp_capability")
        if type(count) is not int or not 1 <= count <= 20 or type(offset) is not int or not 0 <= offset <= 10000:
            raise Rejected("invalid_burp_pagination")
        if not self.env.get("BURP_MCP_URL"):return {"status": "HOST_ADAPTER_REQUIRED", "reason": "burp_not_configured"}
        try:
            async with self.connect() as session:
                found = await self.tools(session);name = REVIEWED[capability]
                if name not in found:return {"status": "UNSUPPORTED_BY_HOST", "capability": capability}
                schema = found[name]
                if set(schema.get("required", [])) - {"count", "offset"} or not {"count", "offset"} <= schema.get("properties", {}).keys():
                    return {"status": "UNSUPPORTED_HOST_SCHEMA", "capability": capability}
                result = await session.call_tool(name, {"count": count, "offset": offset})
            if result.isError:raise Rejected("burp_host_tool_error")
            raw = result.model_dump_json().encode()
            items, unparsed = [], 0
            for block in result.content:
                if block.type != "text":continue
                remaining = block.text.strip()
                while remaining:
                    try:item, end = json.JSONDecoder().raw_decode(remaining)
                    except ValueError:unparsed += 1;break
                    remaining = remaining[end:].lstrip()
                    for entry in item if isinstance(item, list) else [item]:
                        if len(items) >= count:raise Rejected("burp_history_item_limit")
                        items.append(metadata(entry))
            return self.records.save("analysis", {"analyzer": "burp_" + capability, "identity_label": "host_burp_unknown",
                "input": {"sha256": digest(raw), "source": "configured_host_mcp"},
                "result": {"observations": items, "unparsed_blocks_withheld": unparsed,
                    "limitations": ["Previously captured host history only; no replay, scanning, remote introspection or request mutation.",
                                    "Burp may truncate saved messages; structures are partial and raw notes/body/credentials are withheld."]}})
        except Rejected:raise
        except Exception:raise Rejected("burp_connection_or_protocol_failure") from None


def register(mcp, engine, annotations):
    from typing import Any
    adapter = BurpAdapter(engine.records)
    @mcp.tool(annotations=annotations)
    async def burp_capabilities() -> dict[str, Any]:
        """Discover reviewed host capabilities using actual MCP tools/list. Unconfigured Burp is optional."""
        return await adapter.capabilities()
    def add(capability):
        async def tool(count: int = 10, offset: int = 0) -> dict[str, Any]:return await adapter.read(capability, count, offset)
        tool.__name__ = "burp_" + capability
        tool.__doc__ = "Read bounded existing " + capability + " from configured Burp; never send or replay target requests."
        mcp.tool(annotations=annotations)(tool)
    for capability in REVIEWED:add(capability)
