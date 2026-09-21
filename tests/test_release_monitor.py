import hashlib
import json

import pytest

from ctf_mcp.full_hunt.release_monitor import (
    MonitorState,
    ReleaseIdentity,
    ReleaseMonitor,
)
from ctf_mcp.full_hunt.bisect import (
    REQUIRED_BISECT_CAPABILITIES,
    BisectObservation,
    BisectRevision,
    VersionBisector,
)
from ctf_mcp.full_hunt.disclosure import DisclosurePackBuilder
from ctf_mcp.full_hunt.regression import RegressionSpecStore
from ctf_mcp.local_targets.base import LocalTargetError
from ctf_mcp.monitor_cli import monitor_command


TARGET = "sample"
CANDIDATE = "CAND-001"


def release(number):
    version = f"v{number}"
    return ReleaseIdentity(
        target_id=TARGET,
        version=version,
        revision=f"revision-{number}",
        immutable_commit=f"{number:040x}",
        released_at=f"2026-01-{number:02d}T00:00:00+00:00",
        source="provider-release-metadata",
        metadata_hash=hashlib.sha256(version.encode()).hexdigest(),
        source_identity=f"source:{number:040x}",
    )


def candidate(**changes):
    value = {
        "candidate_id": CANDIDATE,
        "prior_status": "VERIFIED_LOCAL",
        "deterministic_scenario": {
            "binding_id": "binding-001",
            "expected_control": {"resource_id": "control-resource", "result": "allowed"},
            "violation_condition": {"resource_id": "probe-resource", "result": "denied"},
        },
        "source_assertions": {"guard_present": True},
        "revision_supported": True,
        "safety_gate": True,
        "root_cause_id": "ROOT-001",
        "scenario_id": "SCENARIO-001",
        "invariant_hash": "a" * 64,
        "request_budget": 4,
    }
    value.update(changes)
    return value


def evidence(violation, **changes):
    value = {
        "fixture_valid": True,
        "control_passed": True,
        "source_assertion_valid": True,
        "probe_status": 200,
        "probe_empty": False,
        "response_status_only": False,
        "deterministic": True,
        "ambiguous": False,
        "probe_valid": True,
        "request_count": 2,
        "final_urls": ["http://127.0.0.1:18181/probe"],
        "violation_observed": violation,
        "evidence_ids": ["evidence-001"],
    }
    value.update(changes)
    return value


class FakeProvider:
    def __init__(self):
        self.releases = []
        self.outcomes = {}
        self.candidates = [candidate()]
        self.prepared = []
        self.bootstrapped = []
        self.validated = []
        self.cleaned = []

    def list_releases(self):
        return list(self.releases)

    def resolve_release(self, version):
        return next(item for item in self.releases if item.version == version)

    def latest_stable(self):
        return self.releases[-1]

    def revision_identity(self, value):
        return {"commit": value.immutable_commit}

    def retest_candidates(self, selected=None):
        return [item for item in self.candidates if selected in {None, item["candidate_id"]}]

    def prepare_revision(self, value):
        self.prepared.append(value.version)
        return "runtime-" + value.fingerprint

    def bootstrap_revision(self, value, prepared):
        assert prepared.startswith("runtime-")
        self.bootstrapped.append(value.version)

    def validate_release_candidate(self, selected, value, prepared):
        assert selected["candidate_id"] == CANDIDATE and prepared.startswith("runtime-")
        self.validated.append(value.version)
        return self.outcomes[value.version]

    def cleanup_revision(self, value, prepared):
        assert prepared.startswith("runtime-")
        self.cleaned.append(value.version)

    def patch_correlation(self, previous, current):
        return {
            "previous_commit": previous["immutable_commit"] if previous else None,
            "new_commit": current["immutable_commit"],
            "changed_files": ["component.txt"],
        }


class Clock:
    def __init__(self):
        self.index = 0

    def __call__(self):
        self.index += 1
        return f"2026-02-{self.index:02d}T00:00:00+00:00"


def monitored(tmp_path, provider=None):
    return ReleaseMonitor(
        root=tmp_path,
        target_id=TARGET,
        provider=provider or FakeProvider(),
        now=Clock(),
    )


def test_first_check_and_state_serialization(tmp_path):
    provider = FakeProvider()
    provider.releases = [release(1)]
    provider.outcomes = {"v1": evidence(True)}
    monitor = monitored(tmp_path, provider)
    result = monitor.check(run_id="run-001")
    assert result["status"] == "RELEASES_PROCESSED"
    assert result["candidate_retests"][0]["status"] == "AFFECTED"
    saved = json.loads((tmp_path / ".operator/monitor/sample/state.json").read_text())
    assert MonitorState.from_dict(saved, TARGET).latest_seen["version"] == "v1"
    assert provider.prepared == provider.bootstrapped == provider.validated == provider.cleaned == ["v1"]


def test_no_new_release_and_duplicate_observation_are_ignored(tmp_path):
    provider = FakeProvider()
    provider.releases = [release(1)]
    provider.outcomes = {"v1": evidence(True)}
    monitor = monitored(tmp_path, provider)
    monitor.check(run_id="run-001")
    result = monitor.check(run_id="run-002")
    assert result["status"] == "NO_NEW_RELEASE"
    assert provider.validated == ["v1"]
    assert len(monitor.history()) == 2


def test_new_release_appends_history_and_retests(tmp_path):
    provider = FakeProvider()
    provider.releases = [release(1)]
    provider.outcomes = {"v1": evidence(True), "v2": evidence(False)}
    monitor = monitored(tmp_path, provider)
    monitor.check(run_id="run-001")
    provider.releases.append(release(2))
    result = monitor.check(run_id="run-002")
    retest = result["candidate_retests"][0]
    assert retest["status"] == "FIXED"
    assert retest["patch_correlation"]["status"] == "PATCH_CORRELATION_AVAILABLE"
    assert retest["patch_correlation"]["security_patch_confirmed"] is False
    assert retest["regression"]["status"] == "REGRESSION_SPEC_GENERATED"
    assert len(monitor.history()) == 4


@pytest.mark.parametrize("changes", [
    {"immutable_commit": None, "source_identity": None, "image_identity": None},
    {"revision": "main", "immutable_commit": None, "source_identity": "main"},
])
def test_immutable_identity_required(changes):
    values = release(1).to_dict()
    values.update(changes)
    with pytest.raises(LocalTargetError, match="RELEASE_IDENTITY_UNRESOLVED"):
        ReleaseIdentity(**values)


@pytest.mark.parametrize("returned", [None, {}, [object()], [release(1), release(1)]])
def test_malformed_provider_is_blocked(tmp_path, returned):
    class Malformed(FakeProvider):
        def list_releases(self):
            return returned

    result = monitored(tmp_path, Malformed()).check(run_id="run-001")
    assert result["status"] == "MONITOR_BLOCKED"
    assert result["blocker"] == "RELEASE_IDENTITY_UNRESOLVED"


def test_provider_unavailable(tmp_path):
    class Unavailable(FakeProvider):
        def list_releases(self):
            raise OSError("offline")

    result = monitored(tmp_path, Unavailable()).check(run_id="run-001")
    assert result["blocker"] == "RELEASE_PROVIDER_UNAVAILABLE"


@pytest.mark.parametrize(("prior", "current", "expected"), [
    (True, True, "AFFECTED"),
    (True, False, "FIXED"),
    (False, False, "FIXED"),
    (False, True, "REGRESSION"),
])
def test_automatic_retest_transitions(tmp_path, prior, current, expected):
    provider = FakeProvider()
    provider.releases = [release(1)]
    provider.outcomes = {"v1": evidence(prior), "v2": evidence(current)}
    monitor = monitored(tmp_path, provider)
    monitor.check(run_id="run-001")
    provider.releases.append(release(2))
    result = monitor.check(run_id="run-002")
    assert result["candidate_retests"][0]["status"] == expected


@pytest.mark.parametrize(("changes", "status", "blocker"), [
    ({"control_passed": False}, "BLOCKED", "CONTROL_FAILED"),
    ({"source_assertion_valid": False}, "BLOCKED", "SOURCE_ASSERTION_CHANGED"),
    ({"ambiguous": True}, "INCONCLUSIVE", "RETEST_INCONCLUSIVE"),
    ({"probe_status": 404, "violation_observed": False}, "INCONCLUSIVE", "RETEST_INCONCLUSIVE"),
    ({"timeout": True, "violation_observed": False}, "INCONCLUSIVE", "RETEST_INCONCLUSIVE"),
])
def test_unreliable_observation_is_never_fixed(tmp_path, changes, status, blocker):
    provider = FakeProvider()
    provider.releases = [release(1)]
    provider.outcomes = {"v1": evidence(False, **changes)}
    result = monitored(tmp_path, provider).check(run_id="run-001")
    retest = result["candidate_retests"][0]
    assert (retest["status"], retest["blocker"]) == (status, blocker)


def test_bootstrap_failure_blocks_and_never_validates(tmp_path):
    class BrokenBootstrap(FakeProvider):
        def bootstrap_revision(self, value, prepared):
            raise LocalTargetError("BOOTSTRAP_FAILED")

    provider = BrokenBootstrap()
    provider.releases = [release(1)]
    provider.outcomes = {"v1": evidence(False)}
    result = monitored(tmp_path, provider).check(run_id="run-001")
    assert result["candidate_retests"][0]["status"] == "BLOCKED"
    assert result["candidate_retests"][0]["blocker"] == "BOOTSTRAP_FAILED"
    assert provider.validated == []


def test_monitor_cli_status_is_lazy_and_check_loads_only_selected(tmp_path, monkeypatch):
    provider = FakeProvider()
    provider.releases = [release(1)]
    provider.outcomes = {"v1": evidence(True)}

    class Adapter:
        def release_provider(self):
            return provider

    class Registry:
        def __init__(self):
            self.loads = []

        def load(self, selected, root):
            self.loads.append(selected)
            assert root == tmp_path
            return Adapter()

    registry = Registry()
    monkeypatch.setattr("ctf_mcp.monitor_cli.get_target_registry", lambda: registry)
    env = {"FINDER_TARGET": TARGET}
    assert monitor_command(tmp_path, ["status"], env)["known_releases"] == []
    assert registry.loads == []
    assert monitor_command(tmp_path, ["check"], env)["status"] == "RELEASES_PROCESSED"
    assert registry.loads == [TARGET]


def test_fake_release_sequence_v1_through_v5(tmp_path):
    provider = FakeProvider()
    provider.outcomes = {
        "v1": evidence(True), "v2": evidence(True), "v3": evidence(False),
        "v4": evidence(False), "v5": evidence(True),
    }
    monitor = monitored(tmp_path, provider)
    statuses = []
    for number in range(1, 6):
        provider.releases.append(release(number))
        result = monitor.check(run_id=f"run-{number:03d}")
        statuses.append(result["candidate_retests"][0]["status"])
    assert statuses == ["AFFECTED", "AFFECTED", "FIXED", "FIXED", "REGRESSION"]
    assert [item["version"] for item in monitor.status()["known_releases"]] == [
        "v1", "v2", "v3", "v4", "v5",
    ]


def test_fake_target_end_to_end_monitor_bisect_regression_and_disclosure(tmp_path):
    provider = FakeProvider()
    provider.outcomes = {
        "v1": evidence(True), "v2": evidence(True), "v3": evidence(False),
        "v4": evidence(False), "v5": evidence(True),
    }
    monitor = monitored(tmp_path, provider)
    for number in range(1, 6):
        provider.releases.append(release(number))
        monitor.check(run_id=f"monitor-{number:03d}")
    state = monitor.status()
    history = state["candidate_states"][CANDIDATE]
    assert [item["status"] for item in history] == [
        "AFFECTED", "AFFECTED", "FIXED", "FIXED", "REGRESSION",
    ]

    class BisectProvider:
        revisions = [
            BisectRevision(
                revision=f"v{number}", version=f"v{number}", commit=f"{number:040x}",
                immutable_identity=f"source:{number:040x}", order_key=number - 1,
            ) for number in range(1, 6)
        ]

        def bisect_capabilities(self, selected):
            return {key: True for key in REQUIRED_BISECT_CAPABILITIES}

        def ordered_revisions(self, selected, start, end):
            return self.revisions

        def observe_revision(self, selected, revision):
            affected = revision.order_key < 2
            return BisectObservation(
                revision=revision,
                status="AFFECTED" if affected else "UNAFFECTED",
                control_status="PASS",
                candidate_status="AFFECTED" if affected else "UNAFFECTED",
                evidence=(f"bisect-{revision.revision}",),
                runtime_identity=f"runtime-{revision.commit}",
            )

        def cleanup_revision(self, revision):
            pass

    boundary = VersionBisector(BisectProvider()).run(
        candidate_id=CANDIDATE, mode="fixed", start="v1", end="v5",
    )
    assert boundary.status == "FIRST_FIXED_FOUND"
    assert boundary.boundary_revision.version == "v3"

    store = RegressionSpecStore(tmp_path)
    generated = history[-1]["regression"]
    assert generated["status"] == "REGRESSION_SPEC_GENERATED"
    assert (tmp_path / generated["regression_json"]).is_file()

    report = {
        "schema_version": 1,
        "source": {"revision": "a" * 40},
        "candidate_outcomes": [{
            "candidate_id": CANDIDATE,
            "classification": "NEW_SECURITY_CANDIDATE",
            "candidate": {"title": "Generic visibility invariant"},
        }],
    }
    disclosure = DisclosurePackBuilder(tmp_path).build(
        target_id=TARGET,
        candidate_id=CANDIDATE,
        report=report,
        release_monitor=state,
        regression=store.inspect(TARGET, CANDIDATE),
        run_id="end-to-end",
    )
    pack = tmp_path / disclosure["report_directory"]
    assert "Latest release status: REGRESSION" in (pack / "release-monitor.md").read_text()
    saved = json.loads((pack / "report.json").read_text())
    assert saved["latest_retest"]["status"] == "REGRESSION"
