import asyncio
import importlib.util
import io
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys
from uuid import UUID
import pytest
import yaml
from ctf_mcp.cli import approve
from ctf_mcp.config import Rejected
from ctf_mcp.server import create_server
from conftest import ROOT


def test_skill_frontmatter_and_actual_tools(settings):
    async def registered():
        result=set()
        for role in ['analysis','platform','observer','android','android-dynamic','binary','burp']:
            result|={t.name for t in await create_server(settings,role).list_tools()}
        return result
    tools=asyncio.run(registered());skills=list((ROOT/'.agents/skills').glob('*/SKILL.md'))
    assert {p.parent.name for p in skills} == {'scope-gate', 'attack-surface-map', 'web-observation',
        'authenticated-session-review', 'authz-comparison', 'api-review', 'android-static-review',
        'android-dynamic-review', 'ios-static-review', 'binary-review', 'source-review', 'dependency-review',
        'business-logic-review', 'evidence-capture', 'skeptical-retest', 'privacy-review',
        'prompt-injection-defense', 'report-writing'}
    for path in skills:
        text=path.read_text();front=yaml.safe_load(text.split('---',2)[1])
        assert front['name']==path.parent.name and front['description']
        for tool in re.findall(r'tool: `([^`]+)`',text):assert tool in tools,(path,tool)
        assert all(x in text for x in ['## Trigger','## Prerequisites','## Inputs','## Procedure','## Evidence','## Common false positives','## Stop conditions','## Output','## Sources'])
        schema = re.search(r'```json\n(.*?)\n```', text, re.S)
        assert schema and isinstance(json.loads(schema.group(1)), dict)


def test_human_approval_cannot_be_script_flag(settings,tmp_path,monkeypatch):
    plan=tmp_path/'plan.json';plan.write_text((ROOT/'examples/web-plan.json').read_text())
    with pytest.raises(Rejected,match='human_tty'):
        approve(plan,settings.grants_root,input_stream=io.StringIO('APPROVE\n'))
    import ctf_mcp.cli as cli
    key=UUID('a'*32);monkeypatch.setattr(cli,'uuid4',lambda:key)
    class TTY(io.StringIO):
        def isatty(self):return True
    out=io.StringIO()
    assert approve(plan,settings.grants_root,input_stream=TTY('APPROVE '+key.hex[-8:]+'\n'),output_stream=out)==key.hex
    assert '127.0.0.1' in out.getvalue()
    saved=json.loads((settings.grants_root/(key.hex+'.json')).read_text())
    assert saved['approval_method']=='host_tty_review'
    assert saved['plan']['private_cidrs']==['127.0.0.1/32']
    with pytest.raises(FileExistsError):
        approve(plan,settings.grants_root,input_stream=TTY('APPROVE '+key.hex[-8:]+'\n'),output_stream=io.StringIO())


def control():
    spec=importlib.util.spec_from_file_location('control',ROOT/'scripts/control.py')
    mod=importlib.util.module_from_spec(spec);spec.loader.exec_module(mod);return mod


def test_lifecycle_preserves_legacy_state_and_volumes():
    ctl=control()
    for action in ['build','login','logout','switch','run','resume','status','doctor','test','stop']:
        commands=ctl.commands(action,[],{'FINDER_WEB':'1','FINDER_PLATFORM':'1'})
        for cmd in commands:
            assert not {'down','prune','volume','--volumes','ctf-claude','claude-home'}&set(cmd)
            assert 'something-finder-codex' in cmd
    assert ctl.commands('stop',[],{})[-1][-1]=='stop'
    compose=yaml.safe_load((ROOT/'docker-compose.yml').read_text())
    assert {'codex-state-v1','evidence-v1'} <= set(compose['volumes'])
    assert 'browser-sessions-v1' in compose['volumes']
    for name,svc in compose['services'].items():
        assert not svc.get('privileged') and not svc.get('ports')
        assert 'docker.sock' not in str(svc.get('volumes',[]))
    assert compose['services']['codex']['volumes']==['codex-state-v1:/home/node/.codex']
    assert compose['networks']['analysis-internal']['internal']


def test_actual_codex_discovery_when_available():
    if not shutil.which('codex'):pytest.skip('Codex CLI absent; model/account evaluations are separate')
    p=subprocess.run([sys.executable,str(ROOT/'scripts/check_codex.py')],capture_output=True,text=True,timeout=50)
    assert p.returncode==0,p.stderr
    info=json.loads(p.stdout)
    assert len(info['discovered_project_skills'])==18
    assert info['strict_config_accepted'] and not info['chatgpt_login_executed']


def test_stop_covers_oneoff_containers_in_only_new_project():
    ctl=control();calls=[]
    def fake(cmd,**kwargs):
        calls.append(cmd)
        return subprocess.CompletedProcess(cmd,0,stdout='012345abcdef\n' if 'ps' in cmd else '')
    ctl.stop_oneoffs(fake)
    assert calls[0]==['docker','ps','--filter','label=com.docker.compose.project=something-finder-codex','--format','{{.ID}}']
    assert calls[1]==['docker','stop','012345abcdef']
