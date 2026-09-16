"""Operator-owned configuration. No tool can change these limits."""
from dataclasses import dataclass, fields
import json
import os
from pathlib import Path


class Rejected(Exception):
    """A public error code; never contains input data or parser exception text."""


@dataclass(frozen=True)
class Limits:
    file_bytes: int = 16 * 1024 * 1024
    total_bytes: int = 64 * 1024 * 1024
    files: int = 500
    depth: int = 12
    archive_entries: int = 2048
    archive_bytes: int = 128 * 1024 * 1024
    archive_ratio: int = 100
    seconds: int = 30
    output_bytes: int = 512 * 1024

    def __post_init__(self):
        ceilings = {f.name: f.default * 4 for f in fields(self)}
        for f in fields(self):
            v = getattr(self, f.name)
            if type(v) is not int or not 1 <= v <= ceilings[f.name]:
                raise Rejected("invalid_limit")


@dataclass(frozen=True)
class Settings:
    input_root: Path
    results_root: Path
    grants_root: Path
    limits: Limits = Limits()
    browser_root: Path | None = None
    programs_root: Path | None = None

    @classmethod
    def load(cls):
        filename = os.environ.get("FINDER_CONFIG")
        if not filename:
            raise Rejected("missing_config_set_FINDER_CONFIG")
        try:
            p = Path(filename)
            if p.stat().st_size > 16384:
                raise Rejected("config_too_large")
            data = json.loads(p.read_bytes())
            if set(data) - {"input_root", "results_root", "grants_root", "limits", "browser_root", "programs_root"}:
                raise Rejected("unknown_config_key")
            paths = [Path(data[k]).resolve(strict=True) for k in
                     ("input_root", "results_root", "grants_root")]
            browser_root = Path(data["browser_root"]).resolve(strict=True) if data.get("browser_root") else None
            programs_root = Path(data["programs_root"]).absolute() if data.get("programs_root") else None
            if programs_root is not None:
                from .program_store import ProgramStore
                with ProgramStore(programs_root).directory():pass
            validation_paths = paths + ([browser_root] if browser_root else []) + ([programs_root] if programs_root else [])
            if not all(p.is_dir() for p in validation_paths):
                raise Rejected("config_root_not_directory")
            if any(a == b or a in b.parents or b in a.parents
                   for i, a in enumerate(validation_paths) for b in validation_paths[i + 1:]):
                raise Rejected("config_roots_must_be_disjoint")
            return cls(*paths, Limits(**data.get("limits", {})), browser_root, programs_root)
        except Rejected:
            raise
        except (OSError, ValueError, KeyError, TypeError):
            raise Rejected("invalid_or_missing_config") from None
