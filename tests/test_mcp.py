import asyncio
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import time
import pytest
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from mcp.client.streamable_http import streamable_http_client
from ctf_mcp.server import create_server


def environment(settings,tmp_path):
    cfg=tmp_path/'mcp.json'
    cfg.write_text(json.dumps({k:str(getattr(settings,k)) for k in ('input_root','results_root','grants_root')}))
    return {'PATH':os.environ['PATH'],'PYTHONPATH':str(Path(__file__).resolve().parents[1]/'src'),
            'FINDER_CONFIG':str(cfg),'HOME':str(tmp_path)}


def test_official_stdio_initialize_list_call_and_safe_errors(settings,tmp_path):
    async def run():
        async with asyncio.timeout(20):
            params=StdioServerParameters(command=sys.executable,args=['-m','ctf_mcp.server'],env=environment(settings,tmp_path))
            with open(os.devnull,'w') as errors:
                async with stdio_client(params,errlog=errors) as (read,write):
                    async with ClientSession(read,write) as client:
                        init=await client.initialize();assert init.serverInfo.name=='something-finder-analysis'
                        tools=await client.list_tools();names={x.name for x in tools.tools}
                        assert {'health','analyze_har','review_ios','record_candidate','write_report'}<=names
                        assert not {'curl','run_tool','radare2','ghidra_headless'}&names
                        for tool in tools.tools:
                            assert tool.inputSchema['type']=='object'
                            assert tool.outputSchema
                        result=await client.call_tool('analyze_har',{'path':'sample.har'})
                        assert not result.isError and result.structuredContent['kind']=='analysis'
                        error=await client.call_tool('analyze_har',{'path':'../private'})
                        assert error.isError
                        sentinel='SYNTHETIC_TOKEN_NO_ECHO'
                        error=await client.call_tool('analyze_har',{'path':{'access_token':sentinel}})
                        assert error.isError and sentinel not in str(error)
                        missing=await client.call_tool('missing_tool',{})
                        assert missing.isError
    asyncio.run(run())


def test_official_http_transport(settings,tmp_path):
    with socket.socket() as s:s.bind(('127.0.0.1',0));port=s.getsockname()[1]
    env=environment(settings,tmp_path)
    process=subprocess.Popen([sys.executable,'-m','ctf_mcp.server','--transport','streamable-http','--port',str(port)],env=env,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    try:
        for _ in range(100):
            if process.poll() is not None:raise AssertionError('HTTP MCP terminated')
            try:
                with socket.create_connection(('127.0.0.1',port),timeout=.1):break
            except OSError:time.sleep(.05)
        async def run():
            async with asyncio.timeout(15):
                async with streamable_http_client('http://127.0.0.1:'+str(port)+'/mcp') as (read,write,_):
                    async with ClientSession(read,write) as client:
                        await client.initialize()
                        result=await client.call_tool('health',{})
                        assert not result.isError and result.structuredContent['role']=='analysis'
        asyncio.run(run())
        from ctf_mcp.healthcheck import check
        asyncio.run(check('http://127.0.0.1:'+str(port)+'/mcp'))
        import httpx
        wrong=httpx.post('http://127.0.0.1:'+str(port)+'/mcp',headers={'Host':'untrusted.invalid','Origin':'http://untrusted.invalid'},json={})
        assert wrong.status_code in {403,421}
        huge=httpx.post('http://127.0.0.1:'+str(port)+'/mcp',content=b'x'*70000)
        assert huge.status_code==413
    finally:
        process.terminate();process.wait(timeout=5)


def test_role_surfaces_and_schemas(settings):
    async def run():
        alltools={}
        for role in ['analysis','platform','observer']:
            server=create_server(settings,role)
            ts=await server.list_tools()
            alltools[role]={x.name for x in ts}
        assert {'binary_metadata','review_android'}<=alltools['platform']
        assert {'observe_web','stop_web','web_status'}<=alltools['observer']
        assert not any('approve' in name for tools in alltools.values() for name in tools)
    asyncio.run(run())
