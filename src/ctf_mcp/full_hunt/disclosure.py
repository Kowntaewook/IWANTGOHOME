"""Human-review disclosure packs built only from existing local reports."""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
from typing import Any, Mapping

from ctf_mcp.local_targets.base import (
    LocalTargetError,
    atomic_private_json,
    secure_directory,
)
from ctf_mcp.redaction import clean, redact_text

from .reporting import write_private_text


PACK_FILES = (
    "summary.md",
    "technical-report.md",
    "reproduction.md",
    "version-impact.md",
    "duplicate-research.md",
    "report.json",
    "human-review-checklist.md",
    "public-redacted.md",
)
NO_DUPLICATE_DISCLAIMER = (
    "No public duplicate was found in the reviewed sources. "
    "This is not novelty confirmation."
)
SAFE_ID = re.compile(r"[A-Za-z0-9_.-]{1,128}\Z")
LOCAL_PATH = re.compile(
    r"(?<![A-Za-z0-9])(?:/(?:home|Users|workspace|tmp|var/tmp|root)/[^\s,;)'\"]+|"
    r"[A-Za-z]:\\(?:Users|workspace|tmp)\\[^\s,;)'\"]+)",
)
LOCAL_IDENTITY = re.compile(r"\bfinder-local-[a-z0-9_-]+\b", re.IGNORECASE)
SENSITIVE_KEYS = re.compile(
    r"(?i)(?:password|passwd|secret|token|authorization|cookie|private.?key|"
    r"credential|username|usernames|identity|identities|user|users|email|"
    r"body|text|content|postdata|sourcescontent)$",
)


class DisclosurePackBuilder:
    def __init__(self, root: Path):
        self.root = root.resolve()

    def build(
        self,
        *,
        target_id: str,
        candidate_id: str,
        report: Mapping[str, Any],
        bisect: Mapping[str, Any] | None = None,
        release_monitor: Mapping[str, Any] | None = None,
        regression: Mapping[str, Any] | None = None,
        run_id: str | None = None,
        include_ai_disclosure: bool = False,
    ) -> dict[str, Any]:
        run = run_id or datetime.now(timezone.utc).strftime("%Y%m%dt%H%M%S%fZ")
        if not all(SAFE_ID.fullmatch(item) for item in (target_id, candidate_id, run)):
            raise LocalTargetError("INVALID_DISCLOSURE_PACK_ID")
        outcome = _find_outcome(report, candidate_id)
        status = outcome.get("classification", outcome.get("final_status"))
        explicitly_approved = (
            outcome.get("review_status") == "READY_FOR_HUMAN_REVIEW"
            and outcome.get("human_approved") is True
        )
        if status != "NEW_SECURITY_CANDIDATE" and not explicitly_approved:
            raise LocalTargetError("DISCLOSURE_CANDIDATE_NOT_READY")
        safe_outcome = _sanitize(outcome, self.root)
        safe_report = _sanitize(dict(report), self.root)
        safe_bisect = _sanitize(dict(bisect), self.root) if bisect else None
        safe_monitor = _sanitize(dict(release_monitor), self.root) if release_monitor else None
        safe_regression = _sanitize(dict(regression), self.root) if regression else None
        retests = (
            safe_monitor.get("candidate_states", {}).get(candidate_id, [])
            if isinstance(safe_monitor, dict) else []
        )
        latest_retest = retests[-1] if isinstance(retests, list) and retests else None
        run_root = (
            self.root / ".operator" / "disclosure-packs"
            / target_id / candidate_id / run
        )
        if run_root.exists() or run_root.is_symlink():
            raise LocalTargetError("DISCLOSURE_PACK_EXISTS")
        secure_directory(run_root)
        texts = {
            "summary.md": _summary(candidate_id, safe_outcome, safe_bisect),
            "technical-report.md": _technical(candidate_id, safe_outcome),
            "reproduction.md": _reproduction(candidate_id, safe_outcome),
            "version-impact.md": _version_impact(safe_outcome, safe_bisect),
            "duplicate-research.md": _duplicate_research(safe_outcome),
            "human-review-checklist.md": _checklist(),
            "public-redacted.md": _public_redacted(candidate_id, safe_outcome, safe_bisect),
        }
        for name, content in texts.items():
            write_private_text(run_root / name, _redact_local(content, self.root))
        if safe_monitor is not None:
            name = "release-monitor.md"
            write_private_text(run_root / name, _release_monitor(candidate_id, safe_monitor))
            texts[name] = ""
        if safe_regression is not None:
            name = "regression-status.md"
            write_private_text(run_root / name, _regression_status(candidate_id, safe_regression, latest_retest))
            texts[name] = ""
        pack_report = {
            "schema_version": 1,
            "target": target_id,
            "candidate_id": candidate_id,
            "classification": status,
            "source_report": {
                "schema_version": safe_report.get("schema_version"),
                "source": safe_report.get("source"),
            },
            "outcome": safe_outcome,
            "bisect": safe_bisect,
            "external_submission_performed": False,
            "human_review_required": True,
        }
        if safe_monitor is not None:
            pack_report["release_monitor"] = safe_monitor
            pack_report["latest_retest"] = latest_retest
        if safe_regression is not None:
            pack_report["regression"] = safe_regression
        atomic_private_json(run_root / "report.json", pack_report)
        generated = list(PACK_FILES) + [
            name for name in ("release-monitor.md", "regression-status.md")
            if name in texts
        ]
        if include_ai_disclosure:
            name = "ai-use-disclosure.md"
            write_private_text(run_root / name, _ai_disclosure())
            generated.append(name)
        manifest = {
            "schema_version": 1,
            "target": target_id,
            "candidate_id": candidate_id,
            "files": [
                {
                    "name": name,
                    "sha256": hashlib.sha256((run_root / name).read_bytes()).hexdigest(),
                    "size": (run_root / name).stat().st_size,
                }
                for name in generated
            ],
            "external_submission_performed": False,
        }
        atomic_private_json(run_root / "evidence-manifest.json", manifest)
        generated.append("evidence-manifest.json")
        return {
            "status": "DISCLOSURE_PACK_READY_FOR_HUMAN_REVIEW",
            "target": target_id,
            "candidate_id": candidate_id,
            "report_directory": str(run_root.relative_to(self.root)),
            "files": sorted(generated),
            "external_submission_performed": False,
        }

    def inspect(self, target_id: str, candidate_id: str) -> dict[str, Any]:
        runs = self._runs(target_id, candidate_id)
        if not runs:
            raise LocalTargetError("DISCLOSURE_PACK_NOT_FOUND")
        run_root = runs[-1]
        manifest = _read_json(run_root / "evidence-manifest.json")
        if not isinstance(manifest, dict):
            raise LocalTargetError("INVALID_DISCLOSURE_PACK")
        expected = manifest.get("files")
        valid = isinstance(expected, list) and all(
            isinstance(item, dict)
            and isinstance(item.get("name"), str)
            and SAFE_ID.fullmatch(item["name"])
            and (run_root / item["name"]).is_file()
            and not (run_root / item["name"]).is_symlink()
            and hashlib.sha256((run_root / item["name"]).read_bytes()).hexdigest()
            == item.get("sha256")
            for item in expected
        )
        return {
            "target": target_id,
            "candidate_id": candidate_id,
            "run_id": run_root.name,
            "valid": valid,
            "files": sorted(item["name"] for item in expected) if valid else [],
            "external_submission_performed": False,
        }

    def list(self, target_id: str | None = None) -> list[dict[str, str]]:
        base = self.root / ".operator" / "disclosure-packs"
        if not base.is_dir() or base.is_symlink():
            return []
        targets = [base / target_id] if target_id else sorted(base.iterdir())
        result = []
        for target_root in targets:
            if not target_root.is_dir() or target_root.is_symlink():
                continue
            for candidate_root in sorted(target_root.iterdir()):
                if not candidate_root.is_dir() or candidate_root.is_symlink():
                    continue
                for run_root in sorted(candidate_root.iterdir()):
                    if run_root.is_dir() and not run_root.is_symlink():
                        result.append({
                            "target": target_root.name,
                            "candidate_id": candidate_root.name,
                            "run_id": run_root.name,
                            "report_directory": str(run_root.relative_to(self.root)),
                        })
        return result

    def _runs(self, target_id: str, candidate_id: str) -> list[Path]:
        if not all(SAFE_ID.fullmatch(item) for item in (target_id, candidate_id)):
            raise LocalTargetError("INVALID_DISCLOSURE_PACK_ID")
        root = self.root / ".operator" / "disclosure-packs" / target_id / candidate_id
        if not root.is_dir() or root.is_symlink():
            return []
        return sorted(
            item for item in root.iterdir()
            if item.is_dir() and not item.is_symlink()
        )


def _find_outcome(report: Mapping[str, Any], candidate_id: str) -> dict[str, Any]:
    outcomes = report.get("candidate_outcomes", report.get("outcomes"))
    if not isinstance(outcomes, list):
        raise LocalTargetError("INVALID_DISCLOSURE_REPORT")
    matches = [
        item for item in outcomes
        if isinstance(item, dict) and item.get("candidate_id") == candidate_id
    ]
    if len(matches) != 1:
        raise LocalTargetError("INVALID_DISCLOSURE_REPORT")
    return matches[0]


def _sanitize(value: Any, root: Path) -> Any:
    if isinstance(value, dict):
        return {
            str(key): "[REDACTED]" if SENSITIVE_KEYS.search(str(key))
            else _sanitize(item, root)
            for key, item in value.items()
            if str(key).lower() not in {"private_notes", "internal_notes"}
        }
    if isinstance(value, (list, tuple)):
        return [_sanitize(item, root) for item in value]
    if isinstance(value, str):
        return _redact_local(str(clean(value)), root)
    return value


def _redact_local(value: str, root: Path) -> str:
    result = redact_text(value).replace(str(root), "[LOCAL_PATH]")
    return LOCAL_PATH.sub("[LOCAL_PATH]", result)


def _public_text(value: Any) -> str:
    if value is None:
        return "unknown"
    if isinstance(value, (dict, list)):
        value = json.dumps(value, ensure_ascii=True, sort_keys=True)
    return LOCAL_IDENTITY.sub("[LOCAL_IDENTITY]", str(value))


def _summary(candidate_id: str, outcome: Mapping[str, Any], bisect: Mapping[str, Any] | None) -> str:
    candidate = outcome.get("candidate") if isinstance(outcome.get("candidate"), dict) else {}
    matrix = outcome.get("version_matrix") if isinstance(outcome.get("version_matrix"), dict) else {}
    duplicate = outcome.get("duplicate_research") if isinstance(outcome.get("duplicate_research"), dict) else {}
    boundary = bisect.get("boundary_revision") if isinstance(bisect, dict) else None
    bisect_mode = bisect.get("mode") if isinstance(bisect, dict) else None
    targets = matrix.get("targets") if isinstance(matrix.get("targets"), list) else []
    latest = _matrix_target(targets, "latest")
    main = _matrix_target(targets, "main")
    return "\n".join((
        f"# {_public_text(candidate.get('title') or 'Security candidate ' + candidate_id)}", "",
        f"- Candidate ID: {candidate_id}",
        f"- Impact summary: {_public_text(candidate.get('impact') or candidate.get('security_invariant'))}",
        f"- Security conditions: {_public_text(candidate.get('security_conditions'))}",
        f"- Required permissions: {_public_text(candidate.get('required_permissions'))}",
        f"- Verified versions: {_public_text(matrix.get('targets'))}",
        f"- Latest status: {_public_text(latest)}",
        f"- Main status: {_public_text(main)}",
        f"- First affected revision: {_public_text(boundary if bisect_mode == 'introduced' else None)}",
        f"- First fixed revision: {_public_text(boundary if bisect_mode == 'fixed' else None)}",
        f"- Duplicate research: {_public_text(duplicate.get('duplicate_status'))}", "",
        "Human review is required before any private disclosure or public release.", "",
    ))


def _technical(candidate_id: str, outcome: Mapping[str, Any]) -> str:
    candidate = outcome.get("candidate") if isinstance(outcome.get("candidate"), dict) else {}
    local = outcome.get("local_validation")
    return "\n".join((
        f"# Technical report: {candidate_id}", "",
        "## Source assertion", _public_text(outcome.get("source_assertions") or candidate.get("source_assertions")), "",
        "## Control", _public_text(local), "",
        "## Probe", _public_text(candidate.get("probe_hypothesis")), "",
        "## Observed invariant violation", _public_text(candidate.get("security_invariant")), "",
        "## Root cause", _public_text(outcome.get("root_cause")), "",
        "## Affected versions", _public_text(outcome.get("version_matrix")), "",
    ))


def _reproduction(candidate_id: str, outcome: Mapping[str, Any]) -> str:
    candidate = outcome.get("candidate") if isinstance(outcome.get("candidate"), dict) else {}
    scenario = outcome.get("scenario_synthesis")
    return "\n".join((
        f"# Reproduction: {candidate_id}", "",
        "## Required environment", _public_text(candidate.get("required_environment") or "Authorized isolated local target runtime"), "",
        "## Synthetic fixture", _public_text(scenario or candidate.get("fixture")), "",
        "## Normal behavior", _public_text(candidate.get("control_hypothesis")), "",
        "## Suspected behavior", _public_text(candidate.get("probe_hypothesis")), "",
        "## Expected result", _public_text(candidate.get("security_invariant")), "",
    ))


def _version_impact(outcome: Mapping[str, Any], bisect: Mapping[str, Any] | None) -> str:
    matrix = outcome.get("version_matrix")
    targets = matrix.get("targets") if isinstance(matrix, dict) and isinstance(matrix.get("targets"), list) else []
    affected = [item for item in targets if isinstance(item, dict) and _matrix_status(item) == "AFFECTED"]
    unaffected = [item for item in targets if isinstance(item, dict) and _matrix_status(item) in {"UNAFFECTED", "INTENDED_BEHAVIOR"}]
    main = _matrix_target(targets, "main")
    boundary = bisect.get("boundary_revision") if isinstance(bisect, dict) else None
    status = bisect.get("status") if isinstance(bisect, dict) else "unknown"
    mode = bisect.get("mode") if isinstance(bisect, dict) else None
    return "\n".join((
        "# Version impact", "",
        "## Known affected", _public_text(affected or "unknown/inconclusive"), "",
        "## Known unaffected", _public_text(unaffected or "unknown/inconclusive"), "",
        "## First affected", _public_text(boundary if mode == "introduced" else "unknown/inconclusive"), "",
        "## First fixed", _public_text(boundary if mode == "fixed" else "unknown/inconclusive"), "",
        "## Current main", _public_text(main or "unknown/inconclusive"), "",
        "## Boundary search status", _public_text(status), "",
        "## Complete version matrix", _public_text(matrix or "unknown/inconclusive"), "",
        "Unverified version ranges remain unknown/inconclusive.", "",
    ))


def _duplicate_research(outcome: Mapping[str, Any]) -> str:
    duplicate = outcome.get("duplicate_research")
    duplicate_status = (
        duplicate.get("duplicate_status") if isinstance(duplicate, dict) else None
    )
    interpretation = (
        NO_DUPLICATE_DISCLAIMER
        if duplicate_status == "NO_PUBLIC_DUPLICATE_FOUND"
        else "The recorded duplicate status must be reviewed before disclosure."
    )
    return "\n".join((
        "# Duplicate research", "",
        _public_text(duplicate or "Duplicate research unavailable."), "",
        interpretation, "",
    ))


def _release_monitor(
    candidate_id: str, monitor: Mapping[str, Any],
) -> str:
    states = monitor.get("candidate_states")
    retests = states.get(candidate_id, []) if isinstance(states, dict) else []
    affected = [item for item in retests if isinstance(item, dict) and item.get("status") in {"AFFECTED", "REGRESSION"}]
    fixed = [item for item in retests if isinstance(item, dict) and item.get("status") == "FIXED"]
    uncertain = [item for item in retests if isinstance(item, dict) and item.get("status") in {"BLOCKED", "INCONCLUSIVE"}]
    latest = retests[-1] if retests else None
    return "\n".join((
        f"# Release monitor: {candidate_id}", "",
        f"- First affected release: {_public_text(_release_version(affected[0]) if affected else None)}",
        f"- First fixed release: {_public_text(_release_version(fixed[0]) if fixed else None)}",
        f"- Latest release status: {_public_text(latest.get('status') if isinstance(latest, dict) else None)}",
        f"- Regression observed: {_public_text(any(item.get('status') == 'REGRESSION' for item in retests if isinstance(item, dict)))}",
        f"- Last retested: {_public_text(latest.get('observed_at') if isinstance(latest, dict) else None)}", "",
        "## Blocked or inconclusive history", _public_text(uncertain or "none"), "",
    ))


def _regression_status(
    candidate_id: str,
    regression: Mapping[str, Any],
    latest_retest: Mapping[str, Any] | None,
) -> str:
    return "\n".join((
        f"# Regression status: {candidate_id}", "",
        f"- Latest monitor status: {_public_text(latest_retest.get('status') if latest_retest else None)}",
        f"- Declarative spec: {_public_text(regression)}", "",
        "Replay requires the installed target adapter and an authorized isolated local runtime.", "",
    ))


def _release_version(value: Mapping[str, Any]) -> Any:
    release = value.get("release")
    return release.get("version") if isinstance(release, dict) else None


def _checklist() -> str:
    return "\n".join((
        "# Human review checklist", "",
        "- [ ] Reproduction personally reviewed",
        "- [ ] Version impact reviewed",
        "- [ ] Duplicate search reviewed",
        "- [ ] Secrets checked",
        "- [ ] PoC checked",
        "- [ ] Vendor disclosure policy checked",
        "- [ ] AI-use statement reviewed",
        "- [ ] Public release timing checked", "",
    ))


def _public_redacted(
    candidate_id: str, outcome: Mapping[str, Any], bisect: Mapping[str, Any] | None,
) -> str:
    candidate = outcome.get("candidate") if isinstance(outcome.get("candidate"), dict) else {}
    matrix = _public_version_matrix(outcome.get("version_matrix"))
    return LOCAL_IDENTITY.sub("[LOCAL_IDENTITY]", "\n".join((
        f"# Public redacted summary: {candidate_id}", "",
        "This file is a review draft and does not authorize publication.", "",
        "## Technical root cause", _public_text(outcome.get("root_cause")), "",
        "## Impact scope", _public_text(candidate.get("impact") or candidate.get("security_invariant")), "",
        "## Fix status", _public_text(matrix or "unknown/inconclusive"), "",
        "## Safe reproduction summary", "An authorized isolated local fixture was used to compare the normal control with the deterministic probe.", "",
        "## Version boundary", _public_text(bisect.get("boundary_revision") if bisect else "unknown/inconclusive"), "",
    )))


def _public_version_matrix(value: Any) -> Any:
    if not isinstance(value, dict):
        return "unknown/inconclusive"
    targets = value.get("targets")
    public_targets = []
    if isinstance(targets, list):
        for item in targets:
            if isinstance(item, dict):
                public_targets.append({
                    key: item[key]
                    for key in ("target", "version", "commit", "status", "result", "blocked_reason")
                    if key in item
                })
    return {
        "status": value.get("status", "unknown/inconclusive"),
        "targets": public_targets,
    }


def _matrix_target(targets: list[Any], name: str) -> dict[str, Any] | None:
    return next((
        item for item in targets
        if isinstance(item, dict) and item.get("target", item.get("kind")) == name
    ), None)


def _matrix_status(value: Mapping[str, Any]) -> str | None:
    status = value.get("result", value.get("status"))
    return status if isinstance(status, str) else None


def _ai_disclosure() -> str:
    return "\n".join((
        "# AI use disclosure", "",
        "- Automated tools assisted source review.",
        "- Automated tools assisted defensive test generation.",
        "- Reported runtime behavior must be independently reproduced in the authorized local environment.",
        "- A human reviewer must edit this statement for the vendor's policy.", "",
    ))


def _read_json(path: Path) -> Any:
    try:
        if path.is_symlink() or path.stat().st_size > 8 * 1024 * 1024:
            return None
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, TypeError):
        return None
