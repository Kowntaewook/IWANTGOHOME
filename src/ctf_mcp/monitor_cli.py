"""Release monitor commands for the explicitly selected target plugin."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
from typing import Any, Callable, Sequence

from ctf_mcp.full_hunt.release_monitor import ReleaseMonitor
from ctf_mcp.local_targets.base import LocalTargetError, TARGET_ID
from ctf_mcp.local_targets.plugin_registry import get_target_registry
from ctf_mcp.targets import TargetPluginError


def monitor_command(
    root: Path, args: Sequence[str], env: dict[str, str] | None = None,
) -> dict[str, Any] | list[dict[str, Any]]:
    parser = argparse.ArgumentParser(prog="IWANTGOHOME monitor")
    commands = parser.add_subparsers(dest="operation", required=True)
    commands.add_parser("status")
    check = commands.add_parser("check")
    check.add_argument("candidate", nargs="?")
    commands.add_parser("history")
    options = parser.parse_args(list(args))
    target_id = (env or os.environ).get("FINDER_TARGET")
    if not isinstance(target_id, str) or not TARGET_ID.fullmatch(target_id):
        raise LocalTargetError("invalid_local_target")
    if options.operation in {"status", "history"}:
        monitor = ReleaseMonitor(
            root=root, target_id=target_id, provider=_UnavailableProvider(),
        )
        return monitor.status() if options.operation == "status" else monitor.history()
    try:
        adapter = get_target_registry().load(target_id, root=root)
    except TargetPluginError as error:
        raise LocalTargetError(
            "RELEASE_PROVIDER_UNAVAILABLE" if error.code == "TARGET_NOT_FOUND" else error.code
        ) from None
    capability = getattr(adapter, "release_provider", None)
    if capability is None:
        raise LocalTargetError("RELEASE_PROVIDER_UNAVAILABLE")
    try:
        provider = capability() if callable(capability) and not hasattr(capability, "list_releases") else capability
    except Exception:
        raise LocalTargetError("RELEASE_PROVIDER_UNAVAILABLE") from None
    required = (
        "list_releases", "retest_candidates", "prepare_revision",
        "bootstrap_revision", "validate_release_candidate", "cleanup_revision",
    )
    if any(not callable(getattr(provider, name, None)) for name in required):
        raise LocalTargetError("RELEASE_PROVIDER_UNAVAILABLE")
    return ReleaseMonitor(root=root, target_id=target_id, provider=provider).check(options.candidate)


def run_monitor(
    root: Path,
    args: Sequence[str],
    env: dict[str, str] | None = None,
    *,
    output: Callable[[str], None] = print,
) -> int:
    output(json.dumps(monitor_command(root, args, env), ensure_ascii=True, sort_keys=True))
    return 0


class _UnavailableProvider:
    """Read-only status/history placeholder; it is never called."""

