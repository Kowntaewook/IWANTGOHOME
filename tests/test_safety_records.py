from dataclasses import replace
import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import time
import zipfile
import pytest
from ctf_mcp.config import Settings,Limits,Rejected
from ctf_mcp.engine import Engine,run_worker
from ctf_mcp.records import Records
from ctf_mcp.safety import SafeRoot,SafeZip,structured
from conftest import ROOT,factory


def test_settings_missing_invalid_and_disjoint(settings,tmp_path,monkeypatch):
    monkeypatch.delenv('FINDER_CONFIG',raising=False)
    with pytest.raises(Rejected,match='missing_config'):Settings.load()
    config=tmp_path/'settings.json';monkeypatch.setenv('FINDER_CONFIG',str(config))
    with pytest.raises(Rejected):Settings.load()
    obj={k:str(getattr(settings,k)) for k in ['input_root','results_root','grants_root']}
    config.write_text(json.dumps(obj));assert Settings.load()==settings
    obj['results_root']=obj['input_root'];config.write_text(json.dumps(obj))
    with pytest.raises(Rejected,match='disjoint'):Settings.load()
    with pytest.raises(Rejected):Limits(seconds=-1)
    with pytest.raises(Rejected):Limits(files=True)


def test_paths_symlinks_and_special_files(settings,tmp_path):
    reader=SafeRoot(settings.input_root,settings.limits)
    (settings.input_root/'link').symlink_to(settings.results_root,target_is_directory=True)
    (settings.results_root/'outside').write_text('not input')
    (settings.input_root/'leaf').symlink_to(settings.results_root/'outside')
    os.mkfifo(settings.input_root/'pipe')
    for path in ['../results/outside','/etc/passwd','link/outside','leaf','pipe','a\\b']:
        with pytest.raises(Rejected):reader.read(path)
    assert any(e['kind']=='symlink_skipped' for e in reader.walk())


def test_archives_no_traversal_duplicate_link_bomb(settings):
    for entries in [{'../escape':b'a'},{'/absolute':b'b'},{'x':b'x'*500}]:
        limits=replace(settings.limits,file_bytes=128) if 'x' in entries else settings.limits
        with pytest.raises(Rejected):SafeZip(factory.archive(entries),limits)
    buf=io.BytesIO()
    with zipfile.ZipFile(buf,'w',compression=zipfile.ZIP_DEFLATED) as z:z.writestr('bomb',b'a'*100000)
    with pytest.raises(Rejected,match='ratio'):SafeZip(buf.getvalue(),settings.limits)
    buf=io.BytesIO()
    with zipfile.ZipFile(buf,'w') as z:
        info=zipfile.ZipInfo('link');info.external_attr=(stat.S_IFLNK|0o777)<<16;z.writestr(info,'/etc/passwd')
    with pytest.raises(Rejected):SafeZip(buf.getvalue(),settings.limits)
    with pytest.raises(Rejected):SafeZip(factory.archive({'a':b'a','b':b'b'}),replace(settings.limits,archive_entries=1))
    # Nested content remains inert and is not recursively extracted.
    nested=SafeZip(factory.archive({'inner.zip':factory.archive({'../escape':b'no'})}),settings.limits)
    assert nested.names==['inner.zip']


def test_structured_limits_and_entities(settings):
    with pytest.raises(Rejected):structured(b'a: &a [1]\nb: *a')
    with pytest.raises(Rejected):structured(('['*60+'1'+']'*60).encode())
    (settings.input_root/'xxe.plist').write_text('<?xml version="1.0"?><!DOCTYPE plist [<!ENTITY secret SYSTEM "file:///etc/passwd">]><plist><dict><key>x</key><string>&secret;</string></dict></plist>')
    with pytest.raises(Rejected):Engine(settings).analyze('entitlement','xxe.plist')


def test_research_resume_report_and_confirmation_rejected(settings):
    e=Engine(settings);evidence=e.analyze('source','review.js')
    c={'project':'demo','title':'HTML rendering review','facts':'Assignment observed','concerns':'Input provenance unknown',
       'assumptions':'External data may reach it','counterarguments':'May be static markup','missing_evidence':'Caller review',
       'review_status':'needs_review','remediation':'Prefer text rendering','evidence_ids':[evidence['id']]}
    first=e.records.candidate(c)
    assert Records(settings.results_root).resume('demo')==[first]
    c['facts']='Updated observations';second=e.records.candidate(c)
    assert first['id']!=second['id']
    assert e.records.read(first['id'])['payload']['facts']=='Assignment observed'
    report=e.records.report('demo');assert report['payload']['candidate_count']==2
    c['review_status']='CONFIRMED'
    with pytest.raises(Rejected):e.records.candidate(c)
    assert all(p.name.endswith('.json') for p in settings.results_root.iterdir())


def load_runtime():
    spec=importlib.util.spec_from_file_location('runtime',ROOT/'docker/runtime.py')
    m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m


def test_auth_and_config_preserved_and_status_masked(tmp_path,capsys):
    runtime=load_runtime();home=tmp_path/'codex';home.mkdir()
    auth=home/'auth.json';auth.write_bytes(b'SYNTHETIC_AUTH_SECRET_DO_NOT_PRINT')
    session=home/'session.jsonl';session.write_bytes(b'existing history')
    runtime.initialize(home,ROOT/'config/codex.toml')
    original=(home/'config.toml').read_bytes()
    runtime.initialize(home,ROOT/'config/codex.toml')
    assert auth.read_bytes()==b'SYNTHETIC_AUTH_SECRET_DO_NOT_PRINT' and session.read_bytes()==b'existing history'
    assert (home/'config.toml').read_bytes()==original
    def fake(argv,**kwargs):
        assert kwargs['stdout']==subprocess.DEVNULL and kwargs['stderr']==subprocess.DEVNULL
        return subprocess.CompletedProcess(argv,0)
    assert runtime.status(['codex'],fake)
    assert 'SYNTHETIC_AUTH' not in capsys.readouterr().out


def test_worker_deadline(settings,monkeypatch):
    # Native analysis timeout is exercised with a real subprocess. A tiny parent
    # deadline expires during interpreter startup; no target code executes.
    before=time.monotonic()
    with pytest.raises(Rejected,match='worker_time_limit'):
        run_worker(settings,{'operation':'analyze','analyzer':'source','path':'source.py'},seconds=.001)
    assert time.monotonic()-before<2


def test_archive_duplicate_and_directory_limits(settings):
    buffer=io.BytesIO()
    with zipfile.ZipFile(buffer,'w') as z:
        z.writestr('same',b'a')
        with pytest.warns(UserWarning):z.writestr('same',b'b')
    with pytest.raises(Rejected,match='duplicate'):SafeZip(buffer.getvalue(),settings.limits)
    (settings.input_root/'deep/a/b').mkdir(parents=True)
    with pytest.raises(Rejected,match='depth'):SafeRoot(settings.input_root,replace(settings.limits,depth=1)).walk('deep')
    with pytest.raises(Rejected,match='entry_limit'):SafeRoot(settings.input_root,replace(settings.limits,files=1)).walk('.')


def test_concurrent_records_do_not_overwrite(settings):
    from concurrent.futures import ThreadPoolExecutor
    store=Records(settings.results_root)
    with ThreadPoolExecutor(max_workers=8) as pool:
        records=list(pool.map(lambda n:store.save('test',{'sequence':n}),range(24)))
    assert len({r['id'] for r in records})==24
    assert sorted(store.read(r['id'])['payload']['sequence'] for r in records)==list(range(24))


def test_quoted_secrets_with_spaces_are_suppressed():
    from ctf_mcp.redaction import clean
    for text in ['password = "SYNTHETIC MULTI WORD SECRET"', "'access_token': 'SYNTHETIC MULTI WORD SECRET'",'token=SYNTHETIC_TOKEN']:
        assert 'SYNTHETIC' not in clean({'facts':text})['facts']


def test_fixture_generation_is_repeatable(tmp_path):
    first=factory.generate(tmp_path/'fixtures')
    second=factory.generate(tmp_path/'fixtures')
    assert first==second
