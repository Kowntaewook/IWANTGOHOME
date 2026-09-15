from dataclasses import replace
import json
from pathlib import Path
import pytest
from ctf_mcp.engine import Engine
from ctf_mcp.config import Limits, Rejected
from ctf_mcp.records import digest
from conftest import factory

CASES=[('har','sample.har'),('http_log','http.jsonl'),('openapi','api.json'),('source','source.py'),
       ('source_map','bundle.js.map'),('diff','change.diff'),('dependencies','package-lock.json'),
       ('infrastructure','sample.Dockerfile'),('ios','sample.ipa'),('entitlement','entitlements.plist'),
       ('android','sample.apk'),('android','sample.aab'),('binary','sample.elf'),('binary','sample.exe'),
       ('binary','sample.macho'),('crash','crash.txt'),('packet','sample.pcap'),('archive','sample.zip')]


@pytest.mark.parametrize('kind,path',CASES)
def test_real_parser_and_immutable_evidence(settings,kind,path):
    if kind in {'android','binary'}:
        pytest.importorskip('androguard' if kind=='android' else 'lief')
    original=(settings.input_root/path).read_bytes()
    rec=Engine(settings).analyze(kind,path)
    assert rec['payload']['input']['sha256']==digest(original)
    assert rec['payload']['analyzer']==kind
    assert rec['payload']['result']
    assert rec['created_at'] and rec['analyzer_version']=='0.3.0'
    assert (settings.input_root/path).read_bytes()==original
    assert Engine(settings).records.read(rec['id'])==rec


@pytest.mark.parametrize('kind,path',CASES)
def test_damaged_input(settings,kind,path):
    (settings.input_root/path).write_bytes(b'\xff\x00broken')
    with pytest.raises(Rejected):Engine(settings).analyze(kind,path)
    assert not list(settings.results_root.glob('*.json'))


@pytest.mark.parametrize('kind,path',CASES)
def test_oversize_input(settings,kind,path):
    (settings.input_root/path).write_bytes(b'x'*65)
    cfg=replace(settings,limits=replace(settings.limits,file_bytes=64))
    with pytest.raises(Rejected,match='file_too_large'):Engine(cfg).analyze(kind,path)


def test_platform_semantics(settings):
    pytest.importorskip('androguard');pytest.importorskip('lief');pytest.importorskip('google.protobuf')
    engine=Engine(settings)
    a=engine.analyze('android','sample.apk')['payload']['result']['observations']
    assert a['manifests'][0]['package']=='org.example.fixture'
    assert a['manifests'][0]['application_flags']['debuggable']=='true'
    b=engine.analyze('android','sample.aab')['payload']['result']['observations']
    assert b['format']=='AAB' and b['manifests'][0]['package']=='org.example.bundle'
    for name,fmt in [('sample.elf','ELF'),('sample.exe','PE'),('sample.macho','Mach-O')]:
        data=engine.analyze('binary',name)['payload']['result']['observations'][0]
        assert data['format']==fmt
        assert data['architecture']
        if fmt=='Mach-O':assert '/usr/lib/libSystem.B.dylib' in data['libraries']
    ios=engine.analyze('ios','sample.ipa')['payload']['result']['observations']
    assert ios['bundles'][0]['identifier']=='org.example.fixture'
    assert ios['bundles'][0]['url_schemes']==['sample']


def test_rules_and_fix_regression(settings):
    engine=Engine(settings)
    before=engine.analyze('source','review.js')
    assert before['payload']['result']['concerns'][0]['rule']=='source.html-sink'
    (settings.input_root/'fixed.js').write_text('function render(value) { element.textContent = value; }\n')
    after=engine.analyze('source','fixed.js')
    assert not after['payload']['result']['concerns']
    assert engine.compare(before['id'],after['id'])['payload']['changes']
    tree=engine.analyze('source_tree','.')['payload']['result']
    assert tree['files_reviewed']>=3


def test_secret_values_absent(settings):
    secret='SYNTHETIC_CREDENTIAL_DO_NOT_ECHO'
    data={'log':{'entries':[{'request':{'method':'GET','url':'https://example.invalid/a?session='+secret,
        'headers':[{'name':'Authorization','value':'Bearer '+secret}], 'postData':{'text':secret}},
        'response':{'status':200,'content':{'text':secret},'headers':[{'name':'Set-Cookie','value':'sid='+secret+'; HttpOnly; Secure'}]}}]}}
    (settings.input_root/'secret.har').write_text(json.dumps(data))
    rec=Engine(settings).analyze('har','secret.har')
    assert secret not in json.dumps(rec)
    assert rec['payload']['result']['observations'][0]['credentials_observed']
    (settings.input_root/'secret.py').write_text('password = "'+secret+'"\n')
    rec=Engine(settings).analyze('source','secret.py')
    assert secret not in json.dumps(rec)
    assert rec['payload']['result']['concerns']


def test_no_external_refs_or_project_execution(settings):
    marker=settings.results_root/'should-not-exist'
    (settings.input_root/'script.py').write_text('from pathlib import Path\nPath('+repr(str(marker))+').touch()\n')
    (settings.input_root/'reference.json').write_text(json.dumps({'openapi':'3.0.0','paths':{},'components':{'schemas':{'x':{'$ref':'http://127.0.0.1:1/private'}}}}))
    assert Engine(settings).analyze('openapi','reference.json')['payload']['result']['external_references_not_fetched']==1
    Engine(settings).analyze('source_tree','.')
    assert not marker.exists()


def test_source_context_minimizes_secret_lines(settings):
    (settings.input_root/'context.py').write_text('def sample():\n    password = "SYNTHETIC_SECRET_WITH SPACES"\n    return 1\n')
    e=Engine(settings);rec=e.context('context.py',1,3)
    value=json.dumps(rec)
    assert 'def sample()' in value and 'return 1' in value
    assert 'SYNTHETIC_SECRET' not in value and 'LINE WITHHELD' in value
    with pytest.raises(Rejected):e.context('context.py',1,81)
    with pytest.raises(Rejected):e.context('../escape',1,2)


def test_certificate_metadata_and_bad_inputs(settings):
    pytest.importorskip('cryptography')
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes,serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from datetime import datetime,timedelta,timezone
    key=ec.generate_private_key(ec.SECP256R1())
    name=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'synthetic.invalid')])
    now=datetime.now(timezone.utc)
    cert=x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key()).serial_number(1).not_valid_before(now).not_valid_after(now+timedelta(days=1)).sign(key,hashes.SHA256())
    (settings.input_root/'cert.pem').write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    e=Engine(settings);r=e.analyze('certificate','cert.pem')['payload']['result']['observations'][0]
    assert r['sha256']==cert.fingerprint(hashes.SHA256()).hex()
    assert r['not_after'] and r['key_type']
    from cryptography.hazmat.primitives.serialization import pkcs7
    block=pkcs7.serialize_certificates([cert],serialization.Encoding.DER)
    (settings.input_root/'signed-metadata.apk').write_bytes(factory.archive({
        'AndroidManifest.xml':b'<manifest package="org.example.certificate"><application/></manifest>',
        'META-INF/SAMPLE.RSA':block}))
    apk=e.analyze('android','signed-metadata.apk')['payload']['result']['observations']
    assert apk['certificates'][0]['certificates'][0]['sha256']==r['sha256']
    (settings.input_root/'bad.pem').write_text('broken')
    with pytest.raises(Rejected):e.analyze('certificate','bad.pem')
    cfg=replace(settings,limits=replace(settings.limits,file_bytes=64))
    with pytest.raises(Rejected,match='file_too_large'):Engine(cfg).analyze('certificate','cert.pem')


def test_android_xml_details_and_plist_formats(settings):
    pytest.importorskip('androguard')
    manifest=b'<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="org.example.source"><uses-sdk android:targetSdkVersion="35"/><uses-permission android:name="android.permission.INTERNET"/><application android:networkSecurityConfig="@xml/network"><activity android:name=".Public" android:exported="true" android:permission="org.example.permission"/></application></manifest>'
    network=b'<network-security-config><base-config cleartextTrafficPermitted="false"><trust-anchors><certificates src="system"/></trust-anchors></base-config></network-security-config>'
    (settings.input_root/'details.apk').write_bytes(factory.archive({'AndroidManifest.xml':manifest,'res/xml/network.xml':network,'lib/arm64-v8a/libsample.so':b'inert'}))
    obs=Engine(settings).analyze('android','details.apk')['payload']['result']['observations']
    assert obs['manifests'][0]['permissions']==['android.permission.INTERNET']
    assert obs['manifests'][0]['components'][0]['exported']=='true'
    assert obs['network_security_configs'][0]['configs'][0]['trust_anchor_sources']==['system']
    assert obs['native_libraries']==['lib/arm64-v8a/libsample.so']
    import plistlib
    (settings.input_root/'binary.plist').write_bytes(plistlib.dumps({'get-task-allow':True},fmt=plistlib.FMT_BINARY))
    assert Engine(settings).analyze('entitlement','binary.plist')['payload']['result']['debugging_entitlement'] is True


@pytest.mark.parametrize('filename,contents,fmt',[
    ('Cargo.lock','version = 3\n[[package]]\nname = "sample"\nversion = "1.0.0"\n','toml-lock'),
    ('sbom.json','{"bomFormat":"CycloneDX","components":[{"name":"sample","version":"1.0"}]}','cyclonedx'),
    ('spdx.json','{"spdxVersion":"SPDX-2.3","packages":[{"name":"sample","versionInfo":"1.0"}]}','spdx'),
    ('requirements.txt','sample==1.0.0\n','requirements-pinned'),
    ('pnpm.yaml','lockfileVersion: 9\nsnapshots:\n  sample@1.0.0: {}\n','pnpm-lock')])
def test_dependency_formats(settings,filename,contents,fmt):
    (settings.input_root/filename).write_text(contents)
    o=Engine(settings).analyze('dependencies',filename)['payload']['result']
    assert o['observations']['format']==fmt and o['observations']['packages']
    assert o['external_queries']==0 and o['vulnerability_database'] is None


def test_infrastructure_privilege_and_exposure_rules(settings):
    config='services:\n  demo:\n    privileged: true\n    network_mode: host\n    volumes: ["/var/run/docker.sock:/var/run/docker.sock"]\n'
    (settings.input_root/'compose.yml').write_text(config)
    result=Engine(settings).analyze('infrastructure','compose.yml')['payload']['result']
    assert {'infra.privileged','infra.host-network','infra.docker-socket'}<={f['rule'] for f in result['concerns']}
    assert result['observations']['compose_services'][0]['privileged'] is True
    (settings.input_root/'public.tf').write_text('cidr_blocks = ["0.0.0.0/0"]\n')
    assert Engine(settings).analyze('infrastructure','public.tf')['payload']['result']['concerns'][0]['rule']=='infra.public-range'


def test_common_http_log_and_openapi2(settings):
    (settings.input_root/'access.log').write_text('127.0.0.1 - - [15/Sep/2026:00:00:00 +0000] "GET /status HTTP/1.1" 200 2\n')
    o=Engine(settings).analyze('http_log','access.log')['payload']['result']['observations'][0]
    assert o['method']=='GET' and o['status']==200 and '127.0.0.1' not in json.dumps(o)
    (settings.input_root/'v2.json').write_text(json.dumps({'swagger':'2.0','security':[{'session':[]}],'securityDefinitions':{'session':{'type':'apiKey'}},'paths':{'/status':{'get':{'parameters':[],'responses':{'200':{}}}}}}))
    o=Engine(settings).analyze('openapi','v2.json')['payload']['result']
    assert o['observations'][0]['security_declaration']=='declared' and o['scheme_types']=={'session':'apiKey'}
