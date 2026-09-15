"""Package only the reviewed, explicit source manifest. Never include runtime data."""
import argparse
import hashlib
import json
from pathlib import Path,PurePosixPath
import zipfile

ROOT=Path(__file__).resolve().parents[1]
BLOCKED={'.git','.codex','.operator','.venv','__pycache__','.pytest_cache','workspace','workspace-2','work','results','ghidra-projects','ghidra-projects-2','node_modules'}


def package(output,root=ROOT):
    root=Path(root).resolve();output=Path(output)
    if output.suffix.lower()!='.zip':raise ValueError('Output must be a new ZIP path')
    names=(root/'release-files.txt').read_text().splitlines()
    if len(names)!=len(set(names)):raise ValueError('Duplicate manifest entry')
    paths=[]
    for name in names:
        p=PurePosixPath(name)
        if not name or p.is_absolute() or '..' in p.parts or '\\' in name or set(p.parts)&BLOCKED:
            raise ValueError('Unsafe release manifest entry')
        if p.name in {'auth.json','.env','.DS_Store'} or p.suffix in {'.log','.pyc'}:
            raise ValueError('Runtime file in release manifest')
        path=root
        for part in p.parts:
            path=path/part
            if path.is_symlink():raise ValueError('Release files must not use symlinks')
        if not path.is_file() or path.stat().st_size>2*1024*1024:raise ValueError('Missing or oversized release source')
        paths.append((name,path))
    with output.open('xb') as f:
        with zipfile.ZipFile(f,'w',compression=zipfile.ZIP_DEFLATED) as z:
            for name,path in paths:z.write(path,'something_finder/'+name)
    with zipfile.ZipFile(output) as z:
        if z.testzip() is not None:raise ValueError('ZIP integrity failure')
        if sorted(z.namelist())!=sorted('something_finder/'+x for x in names):raise ValueError('ZIP manifest mismatch')
    return {'zip':str(output),'files':len(names),'sha256':hashlib.sha256(output.read_bytes()).hexdigest()}


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--output',required=True);args=parser.parse_args()
    print(json.dumps(package(args.output),indent=2))


if __name__=='__main__':main()
