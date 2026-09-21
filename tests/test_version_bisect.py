import json

from ctf_mcp.full_hunt.bisect import (
    REQUIRED_BISECT_CAPABILITIES,
    BisectObservation,
    BisectRevision,
    VersionBisector,
    write_bisect_report,
)


def revisions(count=8):
    return [
        BisectRevision(
            revision=f"v{index}",
            version=f"1.0.{index}",
            commit=f"{index + 1:040x}",
            immutable_identity=f"source:{index + 1:040x}|image:sha256:{index + 1:064x}",
            order_key=index,
        )
        for index in range(count)
    ]


class FakeProvider:
    def __init__(self, statuses, *, control=None, mutate=None):
        self.revisions = revisions(len(statuses))
        self.statuses = list(statuses)
        self.control = control or {}
        self.mutate = mutate
        self.calls = []
        self.cleanups = []

    def bisect_capabilities(self, candidate_id):
        assert candidate_id == "CAND-001"
        return {key: True for key in REQUIRED_BISECT_CAPABILITIES}

    def ordered_revisions(self, candidate_id, start, end):
        assert (candidate_id, start, end) == ("CAND-001", "v0", f"v{len(self.revisions) - 1}")
        if self.mutate:
            self.mutate(self.revisions)
        return self.revisions

    def observe_revision(self, candidate_id, revision):
        assert candidate_id == "CAND-001"
        index = revision.order_key
        self.calls.append(index)
        status = self.statuses[index]
        return BisectObservation(
            revision=revision,
            status=status,
            control_status=self.control.get(index, "PASS"),
            candidate_status=status,
            evidence=(f"evidence-{index}",),
            runtime_identity=f"runtime-{revision.commit}",
            blocker=(f"blocked-{index}" if status in {"BLOCKED", "INCONCLUSIVE"} else None),
        )

    def cleanup_revision(self, revision):
        self.cleanups.append(revision.order_key)


def run(provider, mode="introduced"):
    return VersionBisector(provider).run(
        candidate_id="CAND-001",
        mode=mode,
        start="v0",
        end=f"v{len(provider.revisions) - 1}",
    )


def test_first_affected_boundary_and_cache_reuse():
    provider = FakeProvider(["UNAFFECTED"] * 3 + ["AFFECTED"] * 5)
    result = run(provider)
    assert result.status == "FIRST_AFFECTED_FOUND"
    assert result.boundary_revision.revision == "v3"
    assert result.lower_bound.revision == "v2"
    assert result.monotonic is True
    assert result.cache_hits > 0
    assert len(provider.calls) == len(set(provider.calls))
    assert sorted(provider.cleanups) == sorted(provider.calls)


def test_first_fixed_boundary():
    provider = FakeProvider(["AFFECTED"] * 5 + ["UNAFFECTED"] * 3)
    result = run(provider, "fixed")
    assert result.status == "FIRST_FIXED_FOUND"
    assert result.boundary_revision.revision == "v5"
    assert result.lower_bound.revision == "v4"


def test_endpoint_mismatch_does_not_start_search():
    provider = FakeProvider(["AFFECTED"] * 8)
    result = run(provider)
    assert result.status == "BOUNDARY_NOT_FOUND"
    assert result.blocker == "ENDPOINT_STATUS_MISMATCH"
    assert provider.calls == [0, 7]


def test_midpoint_blocked_is_never_treated_as_safe():
    provider = FakeProvider([
        "UNAFFECTED", "UNAFFECTED", "UNAFFECTED", "BLOCKED",
        "AFFECTED", "AFFECTED", "AFFECTED", "AFFECTED",
    ])
    result = run(provider)
    assert result.status == "BISECT_BLOCKED"
    assert result.blocker == "blocked-3"
    assert result.boundary_revision is None


def test_non_monotonic_neighbor_is_reported_without_boundary_claim():
    provider = FakeProvider([
        "UNAFFECTED", "UNAFFECTED", "UNAFFECTED", "AFFECTED",
        "UNAFFECTED", "AFFECTED", "AFFECTED", "AFFECTED",
    ])
    result = run(provider)
    assert result.status == "NON_MONOTONIC"
    assert result.monotonic is False
    assert result.boundary_revision is None


def test_floating_revision_identity_blocks_bisect():
    def make_floating(values):
        object.__setattr__(values[0], "commit", "main")

    provider = FakeProvider(["UNAFFECTED", "AFFECTED"], mutate=make_floating)
    result = run(provider)
    assert result.status == "BISECT_BLOCKED"
    assert result.blocker == "IMMUTABLE_REVISION_REQUIRED"
    assert provider.calls == []


def test_control_failure_and_inconclusive_are_distinct_blockers():
    failed_control = FakeProvider(
        ["UNAFFECTED"] * 3 + ["AFFECTED"] * 5,
        control={3: "FAIL"},
    )
    assert run(failed_control).blocker == "CONTROL_FAILED"

    inconclusive = FakeProvider([
        "UNAFFECTED", "UNAFFECTED", "UNAFFECTED", "INCONCLUSIVE",
        "AFFECTED", "AFFECTED", "AFFECTED", "AFFECTED",
    ])
    result = run(inconclusive)
    assert result.status == "BISECT_BLOCKED"
    assert result.blocker == "blocked-3"


def test_bisect_report_serialization(tmp_path):
    result = run(FakeProvider(["UNAFFECTED"] * 3 + ["AFFECTED"] * 5))
    artifacts = write_bisect_report(
        root=tmp_path,
        target_id="sample",
        candidate_id="CAND-001",
        result=result,
        run_id="run-001",
    )
    payload = json.loads((tmp_path / artifacts["bisect_json"]).read_text())
    matrix = json.loads((tmp_path / artifacts["version_matrix"]).read_text())
    assert payload["status"] == "FIRST_AFFECTED_FOUND"
    assert payload["boundary_revision"]["commit"] == f"{4:040x}"
    assert len(payload["observations"]) == payload["tested_revisions"]
    assert len(matrix["targets"]) == payload["tested_revisions"]
    observation_files = list((tmp_path / artifacts["report_directory"] / "observations").iterdir())
    assert len(observation_files) == payload["tested_revisions"]


def test_explicit_provider_lifecycle_stays_adapter_owned():
    class LifecycleProvider(FakeProvider):
        observe_revision = None

        def __init__(self):
            super().__init__(["UNAFFECTED", "AFFECTED"])
            self.events = []

        def resolve_revision(self, revision):
            self.events.append(("resolve", revision.order_key))
            return revision

        def checkout_source(self, revision):
            self.events.append(("checkout", revision.order_key))
            return "source-" + revision.commit

        def build_runtime(self, revision, source):
            self.events.append(("build", revision.order_key, source))
            return "runtime-" + revision.commit

        def bootstrap_runtime(self, revision, runtime):
            self.events.append(("bootstrap", revision.order_key, runtime))

        def validate_candidate(self, candidate_id, revision, runtime):
            self.events.append(("validate", revision.order_key, candidate_id))
            status = self.statuses[revision.order_key]
            return BisectObservation(
                revision=revision,
                status=status,
                control_status="PASS",
                candidate_status=status,
                evidence=("evidence",),
                runtime_identity=runtime,
            )

    provider = LifecycleProvider()
    result = run(provider)
    assert result.status == "FIRST_AFFECTED_FOUND"
    for index in (0, 1):
        assert [(event[0], event[1]) for event in provider.events].count(("build", index)) == 1
        assert provider.cleanups.count(index) == 1
