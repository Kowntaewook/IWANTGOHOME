"""Explicit host CLI for trusted local-target actions."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
from typing import Sequence

from ctf_mcp.local_targets import LocalTargetError, load_adapter


ACTIONS = {"prepare", "up", "status", "bootstrap", "validate", "stop", "reset"}


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="IWANTGOHOME local", add_help=True)
    parser.add_argument("action", choices=sorted(ACTIONS))
    parser.add_argument("candidate", nargs="?")
    return parser


def run_local(root: Path, args: Sequence[str], env: dict[str, str] | None = None) -> int:
    env = env or os.environ
    if not args or args[0] not in ACTIONS:
        raise LocalTargetError("invalid_local_action")
    try:
        options = _parser().parse_args(list(args))
    except SystemExit:
        raise LocalTargetError("invalid_local_action") from None
    if options.action != "validate" and options.candidate is not None:
        raise LocalTargetError("invalid_local_action")
    if options.action == "validate" and options.candidate is not None and options.candidate not in {"S12", "S13", "S15"}:
        raise LocalTargetError("unknown_local_candidate")
    adapter = load_adapter(root, env.get("FINDER_TARGET"))
    if options.action == "prepare":
        _print_mapping(adapter.prepare())
    elif options.action == "up":
        _print_status(adapter.up(progress=print))
    elif options.action == "status":
        _print_status(adapter.status())
    elif options.action == "bootstrap":
        _print_mapping(adapter.bootstrap())
    elif options.action == "validate":
        for result in adapter.validate(options.candidate):
            _print_validation(result)
    elif options.action == "stop":
        _print_mapping(adapter.stop())
    elif options.action == "reset":
        _print_mapping(adapter.reset())
    return 0


def _label(key: str) -> str:
    return key.replace("_", " ").capitalize()


def _safe(value):
    if isinstance(value, (dict, list)):
        return json.dumps(value, ensure_ascii=True, sort_keys=True)
    if value is None:
        return "not available"
    return str(value).lower() if isinstance(value, bool) else str(value)


def _print_mapping(result: dict) -> None:
    for key, value in result.items():
        print(f"{_label(key)}: {_safe(value)}")


def _print_status(result: dict) -> None:
    order = (
        "target", "repository", "expected_commit", "actual_commit", "source_status", "health",
        "server_process", "dependency", "host_endpoint", "observer_endpoint", "observer_linux_mapping",
        "synthetic_bootstrap_status",
    )
    for key in order:
        if key in result:
            print(f"{_label(key)}: {_safe(result[key])}")


def _print_validation(result: dict) -> None:
    for key in ("target", "candidate", "control", "bulk", "candidate_result", "synthetic_marker_returned",
                "victim_state_changed", "status", "evidence", "reassessment", "request_count"):
        if key in result:
            print(f"{_label(key)}: {_safe(result[key])}")


def main() -> None:
    root = Path(__file__).resolve().parent.parent
    try:
        raise SystemExit(run_local(root, os.sys.argv[1:]))
    except LocalTargetError as error:
        print(error.code, file=os.sys.stderr)
        if error.code == "ROLE_UNAVAILABLE":
            print("BLOCKED_BY_LOCAL_SETUP reason=required_supported_role_not_constructible", file=os.sys.stderr)
        raise SystemExit(2)


if __name__ == "__main__":
    main()
