"""Build-time installer for reviewed, checksum-pinned official tool distributions."""
import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import platform
import shutil
import stat
import tarfile
import tempfile
import urllib.request
import zipfile

ROOT = Path(__file__).resolve().parents[1]


def install(name, destination):
    if name not in {"java", "jadx", "apktool", "ghidra"}:raise ValueError("Unknown optional tool")
    key = name
    if name == "java":
        arch = {"aarch64": "aarch64", "arm64": "aarch64", "x86_64": "x64", "amd64": "x64"}.get(platform.machine().lower())
        if arch is None:raise ValueError("No reviewed JDK asset for this architecture")
        key = "java-" + arch
    spec = json.loads((ROOT / "config/tool-downloads.json").read_text())[key]
    target = Path(destination) / name
    if target.exists():raise FileExistsError("Optional tool directory already exists")
    target.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="finder-tool-install-", dir=target.parent) as temp:
        temp = Path(temp);archive = temp / "asset"
        request = urllib.request.Request(spec["url"], headers={"User-Agent": "something-finder-build"})
        total = 0;digest = hashlib.sha256()
        with urllib.request.urlopen(request, timeout=30) as response, archive.open("xb") as output:
            while chunk := response.read(1024 * 1024):
                total += len(chunk)
                if total > spec["bytes"]:raise ValueError("Download exceeds pinned asset size")
                digest.update(chunk);output.write(chunk)
        if total != spec["bytes"] or digest.hexdigest() != spec["sha256"]:raise ValueError("Tool asset checksum mismatch")
        staged = temp / "extracted";staged.mkdir()
        if spec["url"].endswith(".jar"):
            shutil.copy2(archive, staged / "apktool.jar")
        elif spec["url"].endswith(".zip"):
            with zipfile.ZipFile(archive) as z:
                for member in z.infolist():
                    path = PurePosixPath(member.filename)
                    if path.is_absolute() or ".." in path.parts or stat.S_ISLNK(member.external_attr >> 16):raise ValueError("Unsafe tool distribution path")
                z.extractall(staged)
                for member in z.infolist():
                    path = staged / member.filename
                    if path.is_file():path.chmod((member.external_attr >> 16) & 0o755 or 0o644)
        else:
            with tarfile.open(archive) as tar:tar.extractall(staged, filter="data")
        children = list(staged.iterdir())
        source = children[0] if len(children) == 1 and children[0].is_dir() else staged
        source.rename(target)
    print(name + " installed with verified SHA-256: " + spec["version"])


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("tool", choices=["java", "jadx", "apktool", "ghidra"])
    parser.add_argument("--destination", default="/opt/finder-tools")
    args = parser.parse_args();install(args.tool, args.destination)
