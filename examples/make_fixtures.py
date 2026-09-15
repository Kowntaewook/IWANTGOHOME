"""Generate synthetic, non-executed sample artifacts; no user data or downloads."""
import json
from pathlib import Path
import plistlib
import struct
import zipfile
import io


def archive(entries):
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, 'w', compression=zipfile.ZIP_STORED) as z:
        for name, body in entries.items():
            info=zipfile.ZipInfo(name,date_time=(2020,1,1,0,0,0))
            z.writestr(info, body)
    return stream.getvalue()


def axml():
    strings = ['android', 'http://schemas.android.com/apk/res/android', 'manifest', 'package', 'org.example.fixture', 'application', 'debuggable', 'true']
    raw, offsets = bytearray(), []
    for s in strings:
        b=s.encode(); offsets.append(len(raw));raw.extend(bytes([len(s),len(b)])+b+b'\x00')
    raw += b'\x00' * ((-len(raw)) % 4)
    start=28+4*len(strings)
    pool=struct.pack('<HHIIIIII',1,28,start+len(raw),len(strings),0,0x100,start,0)+struct.pack('<'+'I'*len(offsets),*offsets)+raw
    def node(typ, ext):return struct.pack('<HHIII',typ,16,16+len(ext),1,0xffffffff)+ext
    def tag(name,attrs):
        ext=struct.pack('<IIHHHHHH',0xffffffff,name,20,20,len(attrs),0,0,0)
        return node(0x102,ext+b''.join(struct.pack('<IIIHBBI',ns,key,value,8,0,3,value) for ns,key,value in attrs))
    content=pool+node(0x100,struct.pack('<II',0,1))+tag(2,[(0xffffffff,3,4)])+tag(5,[(1,6,7)])+node(0x103,struct.pack('<II',0xffffffff,5))+node(0x103,struct.pack('<II',0xffffffff,2))+node(0x101,struct.pack('<II',0,1))
    return struct.pack('<HHI',3,8,len(content)+8)+content


def aab_manifest():
    # Independent minimal protobuf wire encoder for the public AAPT2 XML schema.
    def varint(n):
        b=bytearray()
        while n>127:b.append((n&127)|128);n>>=7
        b.append(n);return bytes(b)
    def field(n,b):
        if isinstance(b,str):b=b.encode()
        return varint(n*8+2)+varint(len(b))+b
    def attr(name,value,ns=''):
        return field(1,ns)+field(2,name)+field(3,value)
    child=field(1,field(3,'application')+field(4,attr('debuggable','true','http://schemas.android.com/apk/res/android')))
    return field(1,field(3,'manifest')+field(4,attr('package','org.example.bundle'))+field(5,child))


def elf():
    ident=b'\x7fELF'+bytes([2,1,1,0])+b'\x00'*8
    # One inert PT_LOAD segment, no executable payload, no sections.
    header=struct.pack('<HHIQQQIHHHHHH',3,183,1,0,64,0,0,64,56,1,64,0,0)
    ph=struct.pack('<IIQQQQQQ',1,4,0,0,0,120,120,4096)
    return ident+header+ph


def pe():
    b=bytearray(1024);b[:2]=b'MZ';struct.pack_into('<I',b,0x3c,0x80)
    b[0x80:0x84]=b'PE\x00\x00'
    struct.pack_into('<HHIIIHH',b,0x84,0x8664,1,0,0,0,240,0x2022)
    pos=0x98;struct.pack_into('<H',b,pos,0x20b)
    struct.pack_into('<Q',b,pos+24,0x140000000);struct.pack_into('<II',b,pos+32,4096,512)
    struct.pack_into('<II',b,pos+56,8192,512);struct.pack_into('<HH',b,pos+68,3,0x140)
    struct.pack_into('<I',b,pos+108,16)
    sec=pos+240;b[sec:sec+8]=b'.data\x00\x00\x00'
    struct.pack_into('<IIII',b,sec+8,16,4096,512,512);struct.pack_into('<I',b,sec+36,0x40000040)
    return bytes(b)


def macho():
    name=b'/usr/lib/libSystem.B.dylib\x00';size=(24+len(name)+7)//8*8
    lib=struct.pack('<IIIIII',0xc,size,24,0,0x10000,0x10000)+name
    lib+=b'\x00'*(size-len(lib))
    return struct.pack('<IIIIIIII',0xfeedfacf,0x0100000c,0,2,1,len(lib),0x200000,0)+lib


def generate(root):
    root=Path(root);root.mkdir(parents=True,exist_ok=True)
    files={
        'source.py': b'def render(value):\n    return str(value)\n',
        'review.js': b'function render(value) { element.innerHTML = value; }\n',
        'change.diff': b'--- a/view.js\n+++ b/view.js\n@@ -1 +1 @@\n-return plain;\n+element.innerHTML = value;\n',
        'api.json': json.dumps({'openapi':'3.1.0','paths':{'/status':{'get':{'security':[],'responses':{'200':{'description':'OK'}}}}}}).encode(),
        'sample.har': json.dumps({'log':{'entries':[{'request':{'url':'https://example.invalid/status','method':'GET','headers':[]},'response':{'status':200,'headers':[{'name':'X-Content-Type-Options','value':'nosniff'}]}}]}}).encode(),
        'http.jsonl': b'{"url":"https://example.invalid/status","status":200,"method":"GET","headers":{}}\n',
        'bundle.js.map': json.dumps({'version':3,'sources':['original.js'],'sourcesContent':['function safe(x) { return String(x); }'],'names':[],'mappings':''}).encode(),
        'package-lock.json': json.dumps({'lockfileVersion':3,'packages':{'node_modules/sample':{'version':'1.2.3'}}}).encode(),
        'sample.Dockerfile': b'FROM python:3.12-slim\nUSER 1000\n',
        'crash.txt': b'SIGSEGV\n#0 synthetic_function\n',
        'entitlements.plist': plistlib.dumps({'get-task-allow':False,'com.apple.security.app-sandbox':True}),
        'sample.pcap': b'\xd4\xc3\xb2\xa1'+struct.pack('<HHiIII',2,4,0,0,65535,1)+struct.pack('<IIII',0,0,4,4)+b'\x00'*4,
        'sample.elf':elf(), 'sample.exe':pe(), 'sample.macho':macho(),
        'sample.apk':archive({'AndroidManifest.xml':axml(),'classes.dex':b'SYNTHETIC_NOT_EXECUTABLE'}),
        'sample.aab':archive({'BundleConfig.pb':b'','base/manifest/AndroidManifest.xml':aab_manifest(),'base/dex/classes.dex':b'SYNTHETIC_NOT_EXECUTABLE'}),
        'sample.ipa':archive({'Payload/Sample.app/Info.plist':plistlib.dumps({'CFBundleIdentifier':'org.example.fixture','CFBundleShortVersionString':'1.0','NSAppTransportSecurity':{'NSAllowsArbitraryLoads':False},'CFBundleURLTypes':[{'CFBundleURLSchemes':['sample']}]}), 'Payload/Sample.app/entitlements.plist':plistlib.dumps({'get-task-allow':False})}),
        'sample.zip':archive({'config/example.conf':b'enabled=true\n'}),
    }
    for name,data in files.items():
        # Generation is explicitly invoked on a fresh examples/fixture directory.
        target=root/name
        if target.exists() and target.read_bytes()!=data:raise ValueError('Refusing to overwrite different fixture: '+name)
        if not target.exists():target.write_bytes(data)
    return files


if __name__=='__main__':generate(Path(__file__).parent/'synthetic')
