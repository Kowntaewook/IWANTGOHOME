"""Credential-free target plugin metadata and compatibility commands."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Callable, Sequence

from ctf_mcp.local_targets.plugin_registry import get_target_registry


def target_command(root: Path, args: Sequence[str]) -> dict[str, Any]:
    parser = argparse.ArgumentParser(prog="IWANTGOHOME target")
    commands = parser.add_subparsers(dest="operation", required=True)
    commands.add_parser("list")
    info = commands.add_parser("info")
    info.add_argument("target")
    doctor = commands.add_parser("doctor")
    doctor.add_argument("target")
    options = parser.parse_args(list(args))
    registry = get_target_registry()
    if options.operation == "list":
        return {
            "targets": [item.to_dict() for item in registry.list()],
            "imports_performed": False,
        }
    if options.operation == "info":
        return registry.info(options.target).to_dict()
    return registry.doctor(options.target, root=root)


def run_target(
    root: Path,
    args: Sequence[str],
    *,
    output: Callable[[str], None] = print,
) -> int:
    value = target_command(root, args)
    output(json.dumps(value, ensure_ascii=True, sort_keys=True))
    return 0

