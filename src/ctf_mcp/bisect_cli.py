"""Host command for adapter-provided immutable version boundary searches."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
from typing import Callable, Sequence

from ctf_mcp.full_hunt.bisect import VersionBisector, write_bisect_report
from ctf_mcp.local_targets import LocalTargetError, load_adapter


def bisect_command(
    root: Path, args: Sequence[str], env: dict[str, str] | None = None,
) -> dict:
    parser = argparse.ArgumentParser(prog="IWANTGOHOME bisect")
    parser.add_argument("candidate")
    parser.add_argument("--mode", required=True, choices=("introduced", "fixed"))
    parser.add_argument("--from", required=True, dest="start")
    parser.add_argument("--to", required=True, dest="end")
    parser.add_argument("--run-id")
    options = parser.parse_args(list(args))
    selected = (env or os.environ).get("FINDER_TARGET")
    adapter = load_adapter(root, selected)
    provider_factory = getattr(adapter, "version_provider", None)
    if not callable(provider_factory):
        raise LocalTargetError("BISECT_UNAVAILABLE")
    provider = provider_factory(options.candidate)
    result = VersionBisector(provider).run(
        candidate_id=options.candidate,
        mode=options.mode,
        start=options.start,
        end=options.end,
    )
    artifacts = write_bisect_report(
        root=root,
        target_id=adapter.target_id,
        candidate_id=options.candidate,
        result=result,
        run_id=options.run_id,
    )
    return {**result.to_dict(), **artifacts}


def run_bisect(
    root: Path,
    args: Sequence[str],
    env: dict[str, str] | None = None,
    *,
    output: Callable[[str], None] = print,
) -> int:
    output(json.dumps(bisect_command(root, args, env), ensure_ascii=True, sort_keys=True))
    return 0

