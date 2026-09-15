"""Actual Codex CLI config parsing + skill discovery, without login or a model call."""
import json
import os
from pathlib import Path
import selectors
import shutil
import subprocess
import tempfile
import time

ROOT=Path(__file__).resolve().parents[1]


def verify():
    if not shutil.which('codex'):raise RuntimeError('Codex CLI not installed; discovery unverified')
    with tempfile.TemporaryDirectory(prefix='finder-codex-check-') as tmp:
        env={'PATH':os.environ['PATH'],'HOME':tmp,'CODEX_HOME':tmp,'RUST_LOG':'off'}
        shutil.copyfile(ROOT/'config/codex.toml',Path(tmp)/'config.toml')
        cli=subprocess.run(['codex','--version'],env=env,capture_output=True,text=True,timeout=15,check=True).stdout.strip()
        check=subprocess.run(['codex','mcp','list','--json'],env=env,capture_output=True,text=True,timeout=15)
        if check.returncode:raise RuntimeError('Codex rejected config (diagnostic text suppressed)')
        configured=json.loads(check.stdout)
        proc=subprocess.Popen(['codex','app-server','--stdio','--strict-config'],env=env,cwd=ROOT,
            stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,bufsize=0)
        selector=selectors.DefaultSelector();selector.register(proc.stdout,selectors.EVENT_READ)
        buffered=b''
        def rpc(message, expected):
            nonlocal buffered
            proc.stdin.write(json.dumps(message).encode()+b'\n');proc.stdin.flush()
            deadline=time.monotonic()+20
            while time.monotonic()<deadline:
                if b'\n' not in buffered:
                    if not selector.select(timeout=.2):continue
                    chunk=os.read(proc.stdout.fileno(),65536)
                    if not chunk:raise RuntimeError('Codex app server exited')
                    buffered+=chunk
                while b'\n' in buffered:
                    line,buffered=buffered.split(b'\n',1)
                    obj=json.loads(line)
                    if obj.get('id')==expected:
                        if 'error' in obj:raise RuntimeError('Codex RPC rejected request')
                        return obj['result']
            raise RuntimeError('Codex RPC observation timeout')
        try:
            rpc({'id':1,'method':'initialize','params':{'clientInfo':{'name':'finder-validation','version':'0.3.0'},'capabilities':{'experimentalApi':True}}},1)
            proc.stdin.write(b'{"method":"initialized"}\n');proc.stdin.flush()
            result=rpc({'id':2,'method':'skills/list','params':{'cwds':[str(ROOT)],'forceReload':True}},2)
            names={skill['name'] for row in result.get('data',[]) for skill in row.get('skills',[])}
            expected={p.parent.name for p in (ROOT/'.agents/skills').glob('*/SKILL.md')}
            if not expected<=names:raise RuntimeError('Codex did not discover all project skills: '+','.join(sorted(expected-names)))
            errors=[e for row in result.get('data',[]) for e in row.get('errors',[])]
            if errors:raise RuntimeError('Codex reported skill load errors')
            return {'cli_version':cli,'strict_config_accepted':True,'mcp_configured':[x['name'] for x in configured],
                'discovered_project_skills':sorted(expected),'discovery_rpc':'skills/list','model_selection_evaluated':False,'chatgpt_login_executed':False}
        finally:
            selector.close();proc.terminate();proc.wait(timeout=5)


if __name__=='__main__':print(json.dumps(verify(),indent=2))
