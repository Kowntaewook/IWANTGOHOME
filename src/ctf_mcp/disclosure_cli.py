"""Local disclosure pack build, inspection, and listing commands."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
from typing import Any, Callable, Sequence

from ctf_mcp.full_hunt.disclosure import DisclosurePackBuilder
from ctf_mcp.local_targets.base import LocalTargetError, TARGET_ID


def disclosure_command(
    root: Path, args: Sequence[str], env: dict[str, str] | None = None,
) -> dict[str, Any] | list[dict[str, str]]:
    parser = argparse.ArgumentParser(prog="IWANTGOHOME disclosure")
    commands = parser.add_subparsers(dest="operation", required=True)
    build = commands.add_parser("build")
    build.add_argument("candidate")
    build.add_argument("--run-id")
    build.add_argument("--ai-use-disclosure", action="store_true")
    inspect = commands.add_parser("inspect")
    inspect.add_argument("candidate")
    commands.add_parser("list")
    options = parser.parse_args(list(args))
    target_id = (env or os.environ).get("FINDER_TARGET")
    if not isinstance(target_id, str) or not TARGET_ID.fullmatch(target_id):
        raise LocalTargetError("invalid_local_target")
    builder = DisclosurePackBuilder(root)
    if options.operation == "list":
        return builder.list(target_id)
    if options.operation == "inspect":
        return builder.inspect(target_id, options.candidate)
    report = _latest_candidate_report(root, target_id, options.candidate)
    bisect = _latest_bisect(root, target_id, options.candidate)
    release_monitor = _release_monitor(root, target_id)
    regression = _regression(root, target_id, options.candidate)
    return builder.build(
        target_id=target_id,
        candidate_id=options.candidate,
        report=report,
        bisect=bisect,
        release_monitor=release_monitor,
        regression=regression,
        run_id=options.run_id,
        include_ai_disclosure=options.ai_use_disclosure,
    )


def run_disclosure(
    root: Path,
    args: Sequence[str],
    env: dict[str, str] | None = None,
    *,
    output: Callable[[str], None] = print,
) -> int:
    value = disclosure_command(root, args, env)
    output(json.dumps(value, ensure_ascii=True, sort_keys=True))
    return 0


def _latest_candidate_report(root: Path, target_id: str, candidate_id: str) -> dict[str, Any]:
    report_root = root / ".operator" / "reports" / target_id
    if not report_root.is_dir() or report_root.is_symlink():
        raise LocalTargetError("DISCLOSURE_REPORT_NOT_FOUND")
    for path in sorted(report_root.glob("*/report.json"), reverse=True):
        value = _read_json(path)
        outcomes = value.get("candidate_outcomes", value.get("outcomes", [])) if isinstance(value, dict) else []
        if any(isinstance(item, dict) and item.get("candidate_id") == candidate_id for item in outcomes):
            return value
    raise LocalTargetError("DISCLOSURE_REPORT_NOT_FOUND")


def _latest_bisect(root: Path, target_id: str, candidate_id: str) -> dict[str, Any] | None:
    path = root / ".operator" / "bisect" / target_id / candidate_id
    if not path.is_dir() or path.is_symlink():
        return None
    for value in sorted(path.glob("*/bisect.json"), reverse=True):
        result = _read_json(value)
        if isinstance(result, dict):
            return result
    return None


def _release_monitor(root: Path, target_id: str) -> dict[str, Any] | None:
    return _read_json(root / ".operator" / "monitor" / target_id / "state.json")


def _regression(root: Path, target_id: str, candidate_id: str) -> dict[str, Any] | None:
    return _read_json(
        root / ".operator" / "regressions" / target_id / candidate_id / "regression.json"
    )


def _read_json(path: Path) -> dict[str, Any] | None:
    try:
        if path.is_symlink() or path.stat().st_size > 8 * 1024 * 1024:
            return None
        value = json.loads(path.read_text(encoding="utf-8"))
        return value if isinstance(value, dict) else None
    except (OSError, ValueError, TypeError):
        return None
