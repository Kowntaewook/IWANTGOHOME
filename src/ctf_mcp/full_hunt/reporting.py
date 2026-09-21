"""Target-neutral private report artifact writer."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Callable

from ctf_mcp.local_targets.base import (
    LocalTargetError,
    atomic_private_json,
    secure_directory,
)

from .runtime import assert_secret_free


def write_private_text(path: Path, value: str, mode: int = 0o600) -> None:
    if path.exists() or path.is_symlink():
        raise LocalTargetError("hunt_artifact_exists")
    try:
        with path.open("x", encoding="utf-8") as handle:
            os.chmod(path, mode)
            handle.write(value)
    except OSError:
        raise LocalTargetError("hunt_report_failed") from None


class ReportWriter:
    def __init__(self, root: Path, target: str, run_id: str):
        if not target or not run_id or "/" in target or "/" in run_id:
            raise LocalTargetError("invalid_hunt_run_id")
        self.root = root
        self.target = target
        self.run_id = run_id
        self.run_root = root / ".operator" / "reports" / target / run_id

    def initialize(self) -> tuple[Path, Path]:
        if self.run_root.exists() or self.run_root.is_symlink():
            raise LocalTargetError("hunt_run_exists")
        findings = self.run_root / "findings"
        supporting = self.run_root / "supporting"
        secure_directory(findings)
        secure_directory(supporting)
        return findings, supporting

    def json(self, relative: str, value: dict[str, Any]) -> None:
        assert_secret_free(value)
        atomic_private_json(self.run_root / relative, value)

    def text(self, relative: str, value: str, mode: int = 0o600) -> None:
        assert_secret_free({"text": value})
        write_private_text(self.run_root / relative, value, mode)

    def write_findings(
        self,
        clusters: list[dict[str, Any]],
        *,
        render: Callable[[dict[str, Any]], str],
    ) -> None:
        for cluster in clusters:
            identifier = cluster["root_cause_id"]
            if not isinstance(identifier, str) or not identifier:
                raise LocalTargetError("invalid_root_cause_cluster")
            self.json("findings/" + identifier + ".json", cluster)
            self.text("findings/" + identifier + ".md", render(cluster))

    def result(self) -> dict[str, str]:
        return {
            "report_directory": str(self.run_root.relative_to(self.root)),
            "json_report": str((self.run_root / "report.json").relative_to(self.root)),
            "markdown_report": str((self.run_root / "report.md").relative_to(self.root)),
        }
