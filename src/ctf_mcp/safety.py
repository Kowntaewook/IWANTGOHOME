"""Bounded reads using directory descriptors; archives are never extracted."""
import io
import json
import os
import re
from pathlib import Path, PurePosixPath
import stat
import zipfile
import yaml
from .config import Limits, Rejected


def parts(path: str):
    if not isinstance(path, str) or len(path) > 1024 or "\\" in path or "\x00" in path:
        raise Rejected("invalid_path")
    p = PurePosixPath(path)
    if p.is_absolute() or ".." in p.parts or any(":" in x for x in p.parts):
        raise Rejected("path_escape")
    return p.parts


class SafeRoot:
    def __init__(self, root: Path, limits: Limits):
        self.root, self.limits = root, limits

    def open_fd(self, path: str, directory=False):
        # Linux Docker implementation: reject symlinks at every hop, including
        # the leaf; dir_fd closes the check/use race under writable host inputs.
        if not hasattr(os, "O_NOFOLLOW"):
            raise Rejected("safe_file_access_requires_posix")
        fd = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            segs = parts(path)
            for i, segment in enumerate(segs):
                flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
                if i < len(segs) - 1 or directory:
                    flags |= os.O_DIRECTORY
                newfd = os.open(segment, flags, dir_fd=fd)
                os.close(fd)
                fd = newfd
            st = os.fstat(fd)
            if not (stat.S_ISDIR(st.st_mode) if directory else stat.S_ISREG(st.st_mode)):
                raise Rejected("not_regular_file_or_directory")
            return fd
        except BaseException:
            os.close(fd)
            raise

    def read(self, path: str, limit=None):
        cap = min(limit or self.limits.file_bytes, self.limits.file_bytes)
        try:
            fd = self.open_fd(path)
            with os.fdopen(fd, "rb") as f:
                if os.fstat(f.fileno()).st_size > cap:
                    raise Rejected("file_too_large")
                data = f.read(cap + 1)
            if len(data) > cap:
                raise Rejected("file_too_large")
            return data
        except OSError:
            raise Rejected("file_missing_or_unsafe") from None

    def walk(self, path="."):
        out = []
        def visit(rel, depth):
            if depth > self.limits.depth:
                raise Rejected("directory_depth_limit")
            try:
                fd = self.open_fd(rel, directory=True)
                try:
                    with os.scandir(fd) as it:
                        for item in it:
                            if len(out) >= self.limits.files:
                                raise Rejected("directory_entry_limit")
                            child = str(PurePosixPath(rel) / item.name)
                            if item.is_symlink():
                                out.append({"path": child, "kind": "symlink_skipped"})
                            elif item.is_dir(follow_symlinks=False):
                                out.append({"path": child, "kind": "directory"})
                                if item.name not in {".git", "node_modules", ".venv", "__pycache__"}:
                                    visit(child, depth + 1)
                            elif item.is_file(follow_symlinks=False):
                                out.append({"path": child, "kind": "file", "bytes": item.stat(follow_symlinks=False).st_size})
                            else:
                                out.append({"path": child, "kind": "special_skipped"})
                finally:
                    os.close(fd)
            except OSError:
                raise Rejected("directory_missing_or_unsafe") from None
        visit(path, 0)
        return sorted(out, key=lambda x: x["path"])


class SafeZip:
    def __init__(self, data: bytes, limits: Limits):
        self.limits, self.read_bytes = limits, 0
        try:
            self.z = zipfile.ZipFile(io.BytesIO(data))
            infos = self.z.infolist()
            if len(infos) > limits.archive_entries:
                raise Rejected("archive_entry_limit")
            names, expanded = set(), 0
            for i in infos:
                parts(i.filename)
                canonical = str(PurePosixPath(i.filename))
                if canonical in names or canonical in {".", ""}:
                    raise Rejected("archive_duplicate_path")
                names.add(canonical)
                if stat.S_ISLNK(i.external_attr >> 16) or i.flag_bits & 1:
                    raise Rejected("archive_link_or_encrypted")
                if i.compress_type not in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED):
                    raise Rejected("archive_compression_unsupported")
                expanded += i.file_size
                if i.file_size > limits.file_bytes or expanded > limits.archive_bytes:
                    raise Rejected("archive_expanded_limit")
                if i.file_size > max(i.compress_size, 1) * limits.archive_ratio:
                    raise Rejected("archive_ratio_limit")
            self.names = [i.filename for i in infos if not i.is_dir()]
        except (zipfile.BadZipFile, ValueError, OSError):
            raise Rejected("invalid_archive") from None

    def read(self, name):
        try:
            cap = min(self.limits.file_bytes, self.limits.archive_bytes - self.read_bytes)
            with self.z.open(name) as f:
                data = f.read(cap + 1)
            self.read_bytes += len(data)
            if len(data) > cap:
                raise Rejected("archive_read_limit")
            return data
        except (KeyError, zipfile.BadZipFile, RuntimeError, EOFError):
            raise Rejected("invalid_archive_member") from None


def bounded_tree(obj, depth=0, budget=None):
    if budget is None:
        budget = [100000]
    budget[0] -= 1
    if depth > 32 or budget[0] < 0:
        raise Rejected("structured_input_limit")
    if isinstance(obj, dict):
        for k, v in obj.items():
            if not isinstance(k, str):
                raise Rejected("non_string_object_key")
            bounded_tree(v, depth + 1, budget)
    elif isinstance(obj, list):
        for v in obj:
            bounded_tree(v, depth + 1, budget)
    return obj


class NoAliasLoader(yaml.SafeLoader):
    def compose_node(self, parent, index):
        if self.check_event(yaml.AliasEvent):
            raise Rejected("yaml_alias_not_supported")
        return super().compose_node(parent, index)


# GitHub Actions uses `on` as a string key. Keep YAML 1.2 boolean semantics,
# without modifying PyYAML's global loader or enabling aliases/custom tags.
NoAliasLoader.yaml_implicit_resolvers = {
    key: [(tag, pattern) for tag, pattern in rules if tag != "tag:yaml.org,2002:bool"]
    for key, rules in yaml.SafeLoader.yaml_implicit_resolvers.items()}
NoAliasLoader.add_implicit_resolver("tag:yaml.org,2002:bool", re.compile(r"^(?:true|false|True|False|TRUE|FALSE)$"), list("tTfF"))


def structured(data: bytes):
    try:
        if data.lstrip().startswith((b"{", b"[")):
            obj = json.loads(data)
        else:
            obj = yaml.load(data, Loader=NoAliasLoader)
        return bounded_tree(obj)
    except (ValueError, RecursionError, yaml.YAMLError, UnicodeError):
        raise Rejected("invalid_structured_input") from None


def text_input(data):
    if b"\x00" in data:
        raise Rejected("expected_text")
    try:
        return data.decode("utf-8")
    except UnicodeError:
        raise Rejected("invalid_utf8") from None
