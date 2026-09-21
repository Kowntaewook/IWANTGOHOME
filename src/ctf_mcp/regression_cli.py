"""Declarative regression spec listing, inspection, and replay commands."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
from typing import Any, Callable, Sequence

from ctf_mcp.full_hunt.regression import RegressionRunner, RegressionSpecStore
from ctf_mcp.local_targets.base import LocalTargetError, TARGET_ID
from ctf_mcp.local_targets.plugin_registry import get_target_registry


def regression_command(
    root: Path, args: Sequence[str], env: dict[str, str] | None = None,
) -> dict[str, Any] | list[dict[str, Any]]:
    parser = argparse.ArgumentParser(prog="IWANTGOHOME regression")
    commands = parser.add_subparsers(dest="operation", required=True)
    commands.add_parser("list")
    inspect = commands.add_parser("inspect")
    inspect.add_argument("candidate")
    run = commands.add_parser("run")
    run.add_argument("candidate")
    options = parser.parse_args(list(args))
    target_id = (env or os.environ).get("FINDER_TARGET")
    if not isinstance(target_id, str) or not TARGET_ID.fullmatch(target_id):
        raise LocalTargetError("invalid_local_target")
    store = RegressionSpecStore(root)
    if options.operation == "list":
        return store.list(target_id)
    if options.operation == "inspect":
        return store.inspect(target_id, options.candidate)
    return RegressionRunner(root, get_target_registry()).run(target_id, options.candidate)


def run_regression(
    root: Path,
    args: Sequence[str],
    env: dict[str, str] | None = None,
    *,
    output: Callable[[str], None] = print,
) -> int:
    output(json.dumps(regression_command(root, args, env), ensure_ascii=True, sort_keys=True))
    return 0
