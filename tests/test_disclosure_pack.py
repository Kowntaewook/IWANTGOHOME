import json
from pathlib import Path
import socket

import pytest

from ctf_mcp.full_hunt.disclosure import (
    NO_DUPLICATE_DISCLAIMER,
    PACK_FILES,
    DisclosurePackBuilder,
)
from ctf_mcp.local_targets.base import LocalTargetError
from ctf_mcp.full_hunt.schema import normalized_outcome


def report(classification="NEW_SECURITY_CANDIDATE"):
    return {
        "schema_version": 1,
        "target": "sample",
        "source": {"revision": "a" * 40},
        "candidate_outcomes": [{
            "candidate_id": "CAND-001",
            "classification": classification,
            "candidate": {
                "title": "Restricted object metadata exposure",
                "impact": "Bearer very-secret-token-value observed at /workspace/private/run.json",
                "security_invariant": "restricted object stays hidden",
                "security_conditions": "authenticated low privilege viewer",
                "required_permissions": ["read_public_metadata"],
                "source_assertions": {"route": True, "guard": True},
                "control_hypothesis": "owner sees synthetic fixture",
                "probe_hypothesis": "viewer must not see synthetic fixture",
                "fixture": {"username": "finder-local-owner", "object": "synthetic-private"},
                "private_notes": "never publish this note",
            },
            "source_assertions": {"route": True, "guard": True},
            "local_validation": {
                "status": "VERIFIED_LOCAL",
                "assertions": {"control_passed": True, "invariant_violated": True},
                "password": "do-not-copy",
            },
            "root_cause": {"key": "visibility/filter-order"},
            "version_matrix": {
                "status": "AFFECTS_MAIN",
                "targets": [
                    {"target": "pinned", "version": "1.0", "status": "AFFECTED"},
                    {"target": "main", "commit": "b" * 40, "status": "AFFECTED",
                     "runtime_id": "private-runtime-42", "endpoint": "127.0.0.1:19999"},
                ],
            },
            "duplicate_research": {
                "duplicate_status": "NO_PUBLIC_DUPLICATE_FOUND",
                "reviewed_sources": ["public-tracker", "public-advisories"],
            },
            "scenario_synthesis": {
                "required_identities": ["finder-local-owner", "finder-local-viewer"],
                "required_resources": ["finder-local-private-object"],
            },
        }],
        "external_submission_performed": False,
    }


def bisect():
    return {
        "status": "FIRST_AFFECTED_FOUND",
        "mode": "introduced",
        "boundary_revision": {
            "version": "1.0.0",
            "commit": "c" * 40,
            "immutable_identity": "source:" + "c" * 40,
        },
        "lower_bound": {"version": "0.9.9", "commit": "d" * 40},
    }


def monitor(latest="REGRESSION"):
    return {
        "schema_version": 1,
        "target_id": "sample",
        "last_checked_at": "2026-03-05T00:00:00+00:00",
        "known_releases": [
            {"version": "v1", "fingerprint": "a" * 64},
            {"version": "v3", "fingerprint": "c" * 64},
            {"version": "v5", "fingerprint": "e" * 64},
        ],
        "latest_seen": {"version": "v5", "fingerprint": "e" * 64},
        "candidate_states": {
            "CAND-001": [
                {"status": "AFFECTED", "observed_at": "2026-03-01T00:00:00+00:00",
                 "release": {"version": "v1", "fingerprint": "a" * 64}},
                {"status": "FIXED", "observed_at": "2026-03-03T00:00:00+00:00",
                 "release": {"version": "v3", "fingerprint": "c" * 64}},
                {"status": latest, "observed_at": "2026-03-05T00:00:00+00:00",
                 "release": {"version": "v5", "fingerprint": "e" * 64}},
            ],
        },
    }


def regression():
    return {
        "schema_version": 1,
        "target_id": "sample",
        "candidate_id": "CAND-001",
        "request_budget": 4,
        "known_fixed": [{"version": "v3", "fingerprint": "c" * 64}],
    }


def build(tmp_path, **changes):
    options = {
        "target_id": "sample",
        "candidate_id": "CAND-001",
        "report": report(),
        "bisect": bisect(),
        "run_id": "run-001",
    }
    options.update(changes)
    return DisclosurePackBuilder(tmp_path).build(**options)


def test_valid_candidate_generates_review_pack(tmp_path):
    result = build(tmp_path, include_ai_disclosure=True)
    pack = tmp_path / result["report_directory"]
    assert result["status"] == "DISCLOSURE_PACK_READY_FOR_HUMAN_REVIEW"
    assert result["external_submission_performed"] is False
    assert set(PACK_FILES) <= set(result["files"])
    assert {"evidence-manifest.json", "ai-use-disclosure.md"} <= set(result["files"])
    assert all((pack / name).is_file() for name in result["files"])
    saved = json.loads((pack / "report.json").read_text())
    assert saved["external_submission_performed"] is False
    assert saved["human_review_required"] is True


def test_monitor_and_regression_status_are_optional_pack_extensions(tmp_path):
    result = build(tmp_path, release_monitor=monitor(), regression=regression())
    pack = tmp_path / result["report_directory"]
    assert {"release-monitor.md", "regression-status.md"} <= set(result["files"])
    release_text = (pack / "release-monitor.md").read_text()
    regression_text = (pack / "regression-status.md").read_text()
    saved = json.loads((pack / "report.json").read_text())
    assert "v1" in release_text and "v3" in release_text and "REGRESSION" in release_text
    assert "REGRESSION" in regression_text
    assert saved["latest_retest"]["status"] == "REGRESSION"
    assert saved["release_monitor"]["latest_seen"]["version"] == "v5"
    assert saved["regression"]["request_budget"] == 4


def test_pack_without_monitor_or_regression_remains_backward_compatible(tmp_path):
    result = build(tmp_path)
    pack = tmp_path / result["report_directory"]
    saved = json.loads((pack / "report.json").read_text())
    assert "release-monitor.md" not in result["files"]
    assert "regression-status.md" not in result["files"]
    assert "release_monitor" not in saved
    assert "latest_retest" not in saved
    assert "regression" not in saved


@pytest.mark.parametrize("status", [
    "DISCOVERED", "NEEDS_LOCAL_VALIDATION", "NEEDS_MANUAL_SCENARIO",
])
def test_invalid_candidate_status_is_rejected(tmp_path, status):
    with pytest.raises(LocalTargetError, match="DISCLOSURE_CANDIDATE_NOT_READY"):
        build(tmp_path, report=report(status))


def test_explicit_human_approval_allows_report_ready_candidate(tmp_path):
    value = report("VERIFIED_LOCAL")
    outcome = value["candidate_outcomes"][0]
    outcome["review_status"] = "READY_FOR_HUMAN_REVIEW"
    outcome["human_approved"] = True
    assert build(tmp_path, report=value)["status"] == "DISCLOSURE_PACK_READY_FOR_HUMAN_REVIEW"


def test_secret_and_absolute_path_are_redacted_from_every_file(tmp_path):
    result = build(tmp_path)
    pack = tmp_path / result["report_directory"]
    combined = "\n".join(
        path.read_text(errors="replace")
        for path in pack.iterdir()
        if path.is_file()
    )
    assert "very-secret-token-value" not in combined
    assert "do-not-copy" not in combined
    assert "/workspace/private/run.json" not in combined
    assert "[REDACTED]" in combined
    assert "[LOCAL_PATH]" in combined


def test_version_matrix_and_bisect_are_merged(tmp_path):
    result = build(tmp_path)
    pack = tmp_path / result["report_directory"]
    version = (pack / "version-impact.md").read_text()
    summary = (pack / "summary.md").read_text()
    assert "AFFECTS_MAIN" in version
    assert "FIRST_AFFECTED_FOUND" in version
    assert "1.0.0" in version
    assert "First affected revision" in summary
    assert "Main status" in summary


def test_duplicate_disclaimer_public_redaction_and_checklist(tmp_path):
    result = build(tmp_path)
    pack = tmp_path / result["report_directory"]
    duplicate = (pack / "duplicate-research.md").read_text()
    public = (pack / "public-redacted.md").read_text()
    checklist = (pack / "human-review-checklist.md").read_text()
    assert NO_DUPLICATE_DISCLAIMER in duplicate
    assert "finder-local-" not in public
    assert "never publish this note" not in public
    assert "private-runtime-42" not in public and "127.0.0.1:19999" not in public
    assert "does not authorize publication" in public
    assert checklist.count("- [ ]") == 8


def test_inspect_and_list_verify_local_manifest(tmp_path):
    result = build(tmp_path)
    builder = DisclosurePackBuilder(tmp_path)
    inspected = builder.inspect("sample", "CAND-001")
    assert inspected["valid"] is True
    assert inspected["external_submission_performed"] is False
    assert builder.list("sample") == [{
        "target": "sample",
        "candidate_id": "CAND-001",
        "run_id": "run-001",
        "report_directory": result["report_directory"],
    }]


def test_builder_has_no_network_or_submission_surface(tmp_path, monkeypatch):
    monkeypatch.setattr(socket, "create_connection", lambda *args, **kwargs: (_ for _ in ()).throw(
        AssertionError("network submission attempted")
    ))
    result = build(tmp_path)
    assert result["external_submission_performed"] is False
    source = Path(__file__).parents[1].joinpath(
        "src/ctf_mcp/full_hunt/disclosure.py"
    ).read_text()
    for forbidden in ("http.client", "requests.", "smtplib", "subprocess", "github.com/issues"):
        assert forbidden not in source


def test_common_outcome_schema_adds_optional_references_without_requiring_them():
    candidate = {
        "candidate_id": "CAND-001",
        "bisect": {"status": "FIRST_AFFECTED_FOUND", "path": "bisect.json"},
        "disclosure_pack": {"path": "summary.md"},
        "release_monitor": {"path": "state.json"},
        "latest_retest": {"status": "FIXED"},
        "regression": {"path": "regression.json"},
    }
    outcome = normalized_outcome(
        target="sample",
        candidate=candidate,
        root_cause_id="ROOT-001",
        local_validation=None,
        duplicate_research=None,
        version_matrix=None,
        classification="NEW_SECURITY_CANDIDATE",
    )
    assert outcome["bisect"]["status"] == "FIRST_AFFECTED_FOUND"
    assert outcome["disclosure_pack"] == {"path": "summary.md"}
    assert outcome["release_monitor"] == {"path": "state.json"}
    assert outcome["latest_retest"] == {"status": "FIXED"}
    assert outcome["regression"] == {"path": "regression.json"}
    candidate.pop("bisect")
    candidate.pop("disclosure_pack")
    candidate.pop("release_monitor")
    candidate.pop("latest_retest")
    candidate.pop("regression")
    compatible = normalized_outcome(
        target="sample",
        candidate=candidate,
        root_cause_id="ROOT-001",
        local_validation=None,
        duplicate_research=None,
        version_matrix=None,
        classification="NEW_SECURITY_CANDIDATE",
    )
    assert all(key not in compatible for key in (
        "bisect", "disclosure_pack", "release_monitor", "latest_retest", "regression",
    ))
