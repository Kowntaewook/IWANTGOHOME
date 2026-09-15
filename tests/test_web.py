from datetime import datetime,timedelta,timezone
import io
import json
import socket
import threading
import time
from http.server import ThreadingHTTPServer,BaseHTTPRequestHandler
from uuid import uuid4
import pytest
from ctf_mcp.config import Rejected
from ctf_mcp.web import Observer, Grant, Fetcher, canonical_url
from ctf_mcp.engine import Engine


@pytest.fixture
def local_server():
    seen=[]
    class Handler(BaseHTTPRequestHandler):
        def log_message(self,*args):pass
        def do_GET(self):
            seen.append((self.path,dict(self.headers)))
            if self.path=='/redirect':
                self.send_response(302);self.send_header('Location','/ok');self.end_headers();return
            if self.path=='/badredirect':
                self.send_response(302);self.send_header('Location','/outside');self.end_headers();return
            if self.path=='/slow':time.sleep(3)
            body=b'ok'
            if self.path=='/page':
                body=b'<html><link rel="stylesheet" href="/style.css"><img src="/image"><img src="/blocked"><script src="/never.js"></script></html>'
            elif self.path=='/style.css':body=b'body { color: black; }'
            elif self.path in {'/large','/stream'}:body=b'x'*512
            self.send_response(200)
            if self.path!='/stream':self.send_header('Content-Length',str(len(body)))
            self.send_header('Content-Type','text/html' if self.path=='/page' else 'text/css' if self.path=='/style.css' else 'text/plain')
            self.send_header('X-Content-Type-Options','nosniff')
            self.send_header('Set-Cookie','sid=SYNTHETIC_COOKIE; HttpOnly; Secure')
            self.end_headers()
            try:self.wfile.write(body)
            except (BrokenPipeError,ConnectionResetError):pass
    server=ThreadingHTTPServer(('127.0.0.1',0),Handler)
    thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
    yield 'http://127.0.0.1:'+str(server.server_port),seen
    server.shutdown();server.server_close();thread.join(timeout=2)


def grant(settings,base,start='/ok',allowed=None,excluded=None,private=True,**overrides):
    plan={'start_url':base+start,'allowed_urls':[base+p for p in (allowed or [start])],
        'excluded_urls':[base+p for p in (excluded or [])],'private_cidrs':['127.0.0.1/32'] if private else [],
        'max_requests':10,'max_bytes':10000,'max_response_bytes':5000,'seconds':15}
    plan.update(overrides)
    key=uuid4().hex
    obj={'id':key,'plan':plan,'expires_at':(datetime.now(timezone.utc)+timedelta(minutes=2)).isoformat(),
         'approved_at':datetime.now(timezone.utc).isoformat(),'approval_method':'host_tty_review'}
    (settings.grants_root/(key+'.json')).write_text(json.dumps(obj))
    return key


def finished(observer,job_id):
    until=time.monotonic()+20
    while time.monotonic()<until:
        value=observer.status(job_id)
        if value['state']!='running':return value
        time.sleep(.05)
    raise AssertionError('local observation did not stop')


def observe(settings,key,mode='read'):
    observer=Observer(settings)
    return finished(observer,observer.start(key,mode)['job_id'])


def test_no_approval_no_request(settings,local_server):
    base,seen=local_server
    with pytest.raises(Rejected):Observer(settings).start(uuid4().hex,'read')
    assert seen==[]


def test_read_redirect_and_one_use(settings,local_server):
    base,seen=local_server
    key=grant(settings,base,'/redirect',['/redirect','/ok'])
    result=observe(settings,key)
    assert result['state']=='complete',result
    assert [p for p,h in seen]==['/redirect','/ok']
    assert result['record']['payload']['requests']==2
    assert all('Cookie' not in h and 'Authorization' not in h for p,h in seen)
    assert 'SYNTHETIC_COOKIE' not in json.dumps(result)
    with pytest.raises(Rejected,match='grant_already_used'):Observer(settings).start(key,'read')


def test_forbidden_redirect_never_sent(settings,local_server):
    base,seen=local_server
    result=observe(settings,grant(settings,base,'/badredirect'))
    assert result['state']=='failed'
    assert result['record']['payload']['result']['error']=='url_not_approved'
    assert [p for p,h in seen]==['/badredirect']


def test_private_and_exclusion_precedence(settings,local_server):
    base,seen=local_server
    a=observe(settings,grant(settings,base,private=False))
    assert a['record']['payload']['result']['error']=='private_destination_not_approved'
    b=observe(settings,grant(settings,base,excluded=['/ok']))
    assert b['record']['payload']['result']['error']=='url_excluded'
    assert seen==[]


@pytest.mark.parametrize('path,expected', [('/large','response_size_limit'),('/stream','response_read_limit')])
def test_real_read_byte_limits(settings,local_server,path,expected):
    base,seen=local_server
    result=observe(settings,grant(settings,base,path,max_bytes=64,max_response_bytes=64))
    payload=result['record']['payload']
    assert payload['result']['error']==expected
    assert payload['bytes_read']<=64
    assert [p for p,h in seen]==[path]


def test_count_stop_and_concurrency(settings,local_server):
    base,seen=local_server
    result=observe(settings,grant(settings,base,'/redirect',['/redirect','/ok'],max_requests=1))
    assert result['record']['payload']['result']['error']=='request_limit'
    assert [p for p,h in seen]==['/redirect']
    observer=Observer(settings)
    job=observer.start(grant(settings,base,'/slow'),'read')['job_id']
    with pytest.raises(Rejected,match='observer_busy'):observer.start(grant(settings,base),'read')
    observer.stop(job)
    result=finished(observer,job)
    assert result['state']=='stopped'
    assert result['record']['payload']['result']['error']=='observation_stopped'


def test_process_deadline(settings,local_server):
    base,seen=local_server
    t=time.monotonic()
    result=observe(settings,grant(settings,base,'/slow',seconds=1))
    assert time.monotonic()-t<3
    assert result['state']=='failed'
    assert result['record']['payload']['result']['error'] in {'worker_time_limit','observation_network_or_browser_failure','observation_time_limit'}


def test_browser_subrequests_blocked_before_network(settings,local_server):
    pytest.importorskip('playwright')
    base,seen=local_server
    result=observe(settings,grant(settings,base,'/page',['/page','/style.css','/image']),'browser')
    assert result['state']=='complete',result
    assert result['record']['payload']['result']['final_status']==200,result
    paths=[p for p,h in seen]
    assert '/page' in paths and '/style.css' in paths and '/image' in paths
    assert '/blocked' not in paths and '/never.js' not in paths
    assert 'url_not_approved' in result['record']['payload']['result']['blocked_or_incomplete']
    assert any(json.loads(p.read_text())['kind']=='web_audit' for p in settings.results_root.glob('*.json'))


def test_pinned_connection_and_revocation(settings,local_server,monkeypatch):
    base,seen=local_server
    alias=base.replace('127.0.0.1','fixture.invalid')
    key=grant(settings,alias)
    actual=socket.getaddrinfo;names=[]
    def resolve(host,*args,**kwargs):
        names.append(host)
        if host=='fixture.invalid':host='127.0.0.1'
        return actual(host,*args,**kwargs)
    monkeypatch.setattr(socket,'getaddrinfo',resolve)
    g=Grant(settings,key);f=Fetcher(g,threading.Event(),lambda *_:None)
    assert f.read()['final_status']==200
    assert names.count('fixture.invalid')==1
    (settings.grants_root/(key+'.json')).unlink()
    with pytest.raises(Rejected):f.get(alias+'/ok')
    assert len(seen)==1


def test_saved_observation_regression_test_runs(settings,local_server,tmp_path):
    base,_=local_server
    response=observe(settings,grant(settings,base))['record']
    record=Engine(settings).regression(response['id'],['x-content-type-options'])
    test_path=tmp_path/'test_observation.py';test_path.write_text(record['payload']['python'])
    (tmp_path/(response['id']+'.json')).write_text(json.dumps(response))
    import subprocess,sys
    p=subprocess.run([sys.executable,'-m','pytest','-q',str(test_path)],cwd=tmp_path,capture_output=True,timeout=20)
    assert p.returncode==0,p.stdout.decode()


@pytest.mark.parametrize('url',['file:///etc/passwd','http://u:p@host/a','http://host/a#b','http://host/a/../b','http://host/%252e%252e/b','http://host/logout','http://host/a?token=x','http://host:0/a','http://host/a\\b'])
def test_url_rejection(url):
    with pytest.raises(Rejected):canonical_url(url)
