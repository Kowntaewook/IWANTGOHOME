"""Container readiness check through the real loopback MCP transport."""
import asyncio
import logging
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client


async def check(url="http://127.0.0.1:8000/mcp"):
    logging.disable(logging.CRITICAL)
    async with asyncio.timeout(8):
        async with streamable_http_client(url) as (read, write, _):
            async with ClientSession(read, write) as session:
                await session.initialize()
                result = await session.call_tool("health", {})
                if result.isError or result.structuredContent.get("status") != "ok":
                    raise RuntimeError("unhealthy_mcp")


if __name__ == "__main__":
    try:asyncio.run(check())
    except Exception:raise SystemExit(1)
