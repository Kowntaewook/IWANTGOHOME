import json

import pytest

from ctf_mcp.full_hunt.regression import (
    RUNNER_CAPABILITIES,
    RegressionRunner,
    RegressionSpec,
    RegressionSpecStore,
)
from ctf_mcp.local_targets.base import LocalTargetError
from ctf_mcp.targets import TargetPluginError


TARGET = "sample"
CANDIDATE = "CAND-001"


def release_record(version, digit="a"):
    return {
        "version": version,
        "fingerprint": digit * 64,
    }


def retest(status="FIXED", version="v3", digit="c"):
    return {
        "candidate_id": CANDIDATE,
        "status": status,
        "observed_at": "2026-03-03T00:00:00+00:00",
        "release": release_record(version, digit),
    }


def candidate(**changes):
    value = {
        "candidate_id": CANDIDATE,
        "root_cause_id": "ROOT-001",
        "scenario_id": "SCENARIO-001",
        "required_capabilities": list(RUNNER_CAPABILITIES),
        "source_assertions": {"guard_present": True},
        "control_expectation": {"resource_id": "control-resource", "result": "allowed"},
        "probe_expectation": {"resource_id": "probe-resource", "result": "denied"},
        "invariant": {"kind": "visibility-boundary", "expected": "private-hidden"},
        "request_budget": 4,
        "evidence_ids": ["evidence-001"],
    }
    value.update(changes)
    return value


def spec_dict(**changes):
    value = {
        "schema_version": 1,
        "target_id": TARGET,
        "candidate_id": CANDIDATE,
        "root_cause_id": "ROOT-001",
        "scenario_id": "SCENARIO-001",
        "required_capabilities": list(RUNNER_CAPABILITIES),
        "source_assertions": {"guard_present": True},
        "control_expectation": {"resource_id": "control-resource", "result": "allowed"},
        "probe_expectation": {"resource_id": "probe-resource", "result": "denied"},
        "invariant": {"kind": "visibility-boundary"},
        "request_budget": 4,
        "safety_policy": {
            "local_only": True,
            "no_external_redirects": True,
            "nondestructive": True,
            "no_credential_guessing": True,
            "redact_secrets": True,
        },
        "known_affected": [release_record("v1")],
        "known_fixed": [release_record("v3", "c")],
        "generated_from_evidence": ["evidence-001"],
    }
    value.update(changes)
    return value


@pytest.mark.parametrize("status", ["FIXED", "REGRESSION"])
def test_valid_spec_generation_for_fixed_and_regression(tmp_path, status):
    store = RegressionSpecStore(tmp_path)
    history = [retest("AFFECTED", "v1", "a"), retest("FIXED", "v3", "c")]
    latest = retest(status, "v5" if status == "REGRESSION" else "v3", "e" if status == "REGRESSION" else "c")
    result = store.generate(
        target_id=TARGET, candidate=candidate(), latest_retest=latest, history=history,
    )
    assert result["status"] == "REGRESSION_SPEC_GENERATED"
    saved = store.load(TARGET, CANDIDATE)
    assert saved.request_budget == 4
    assert saved.known_affected
    assert (tmp_path / result["readme"]).is_file()


def test_ineligible_status_does_not_generate(tmp_path):
    with pytest.raises(LocalTargetError, match="REGRESSION_SPEC_STATUS_INELIGIBLE"):
        RegressionSpecStore(tmp_path).generate(
            target_id=TARGET,
            candidate=candidate(),
            latest_retest=retest("BLOCKED"),
        )


def test_secret_is_redacted_from_generated_artifacts(tmp_path):
    value = candidate(
        invariant={"kind": "visibility-boundary", "note": "token=ghp_abcdefghijklmnopqrstuvwxyz123456"}
    )
    result = RegressionSpecStore(tmp_path).generate(
        target_id=TARGET, candidate=value, latest_retest=retest(),
    )
    combined = (tmp_path / result["regression_json"]).read_text() + (tmp_path / result["readme"]).read_text()
    assert "ghp_abcdefghijklmnopqrstuvwxyz123456" not in combined


@pytest.mark.parametrize(("field", "value", "reason"), [
    ("probe_expectation", {"resource_id": "https://outside.invalid/probe"}, "REGRESSION_SPEC_URL_REJECTED"),
    ("control_expectation", {"resource_id": "safe", "operation": "echo && id"}, "REGRESSION_SPEC_SHELL_REJECTED"),
    ("control_expectation", {"resource_id": "safe", "operation": "echo ok; id"}, "REGRESSION_SPEC_SHELL_REJECTED"),
    ("invariant", {"kind": "read", "location": "/tmp/private"}, "REGRESSION_SPEC_PATH_REJECTED"),
    ("invariant", {"kind": "read", "location": "../private/data"}, "REGRESSION_SPEC_PATH_REJECTED"),
    ("invariant", {"kind": "read", "location": "private/data.json"}, "REGRESSION_SPEC_PATH_REJECTED"),
])
def test_active_content_is_rejected(field, value, reason):
    spec = spec_dict(**{field: value})
    with pytest.raises(LocalTargetError, match=reason):
        RegressionSpec.from_dict(spec)


def test_arbitrary_execution_keys_are_rejected():
    value = spec_dict(probe_expectation={"resource_id": "safe", "shell_command": "safe"})
    with pytest.raises(LocalTargetError, match="REGRESSION_SPEC_ACTIVE_CONTENT_REJECTED"):
        RegressionSpec.from_dict(value)


def test_request_budget_is_preserved_and_capped():
    assert RegressionSpec.from_dict(spec_dict(request_budget=7)).request_budget == 7
    with pytest.raises(LocalTargetError, match="INVALID_REGRESSION_SPEC"):
        RegressionSpec.from_dict(spec_dict(request_budget=13))


class ReplayAdapter:
    def regression_capabilities(self, candidate_id):
        assert candidate_id == CANDIDATE
        return {item: True for item in RUNNER_CAPABILITIES}

    def run_regression(self, spec):
        assert spec["request_budget"] == 4
        return {
            "fixture_valid": True,
            "control_passed": True,
            "source_assertion_valid": True,
            "deterministic": True,
            "request_count": 2,
            "final_urls": ["http://localhost:18181/control", "http://localhost:18181/probe"],
            "violation_observed": False,
        }


class Registry:
    def __init__(self, adapter=None, error=None):
        self.adapter = adapter
        self.error = error

    def load(self, target_id, root):
        assert target_id == TARGET and root.is_absolute()
        if self.error:
            raise self.error
        return self.adapter


def generated(tmp_path):
    RegressionSpecStore(tmp_path).generate(
        target_id=TARGET, candidate=candidate(), latest_retest=retest(),
    )


def test_deterministic_replay_through_fake_target(tmp_path):
    generated(tmp_path)
    result = RegressionRunner(tmp_path, Registry(ReplayAdapter())).run(TARGET, CANDIDATE)
    assert result["status"] == "PASS"
    assert result["request_budget"] == 4


def test_missing_target_plugin(tmp_path):
    generated(tmp_path)
    runner = RegressionRunner(
        tmp_path, Registry(error=TargetPluginError("TARGET_NOT_FOUND")),
    )
    with pytest.raises(LocalTargetError, match="REGRESSION_TARGET_UNAVAILABLE"):
        runner.run(TARGET, CANDIDATE)


def test_incompatible_capability(tmp_path):
    generated(tmp_path)

    class Incompatible(ReplayAdapter):
        def regression_capabilities(self, candidate_id):
            return {item: item != "fixture" for item in RUNNER_CAPABILITIES}

    with pytest.raises(LocalTargetError, match="REGRESSION_CAPABILITY_MISSING"):
        RegressionRunner(tmp_path, Registry(Incompatible())).run(TARGET, CANDIDATE)


def test_external_redirect_and_budget_are_blocked(tmp_path):
    generated(tmp_path)

    class Unsafe(ReplayAdapter):
        def run_regression(self, spec):
            value = super().run_regression(spec)
            value["final_urls"] = ["https://outside.invalid/probe"]
            value["request_count"] = 5
            return value

    result = RegressionRunner(tmp_path, Registry(Unsafe())).run(TARGET, CANDIDATE)
    assert result["status"] == "BLOCKED"
    assert result["blocker"] == "REGRESSION_REQUEST_BUDGET_EXCEEDED"


def test_list_and_inspect_use_validated_specs(tmp_path):
    generated(tmp_path)
    store = RegressionSpecStore(tmp_path)
    assert store.list(TARGET) == [{
        "target_id": TARGET, "candidate_id": CANDIDATE, "request_budget": 4,
    }]
    assert store.inspect(TARGET, CANDIDATE)["schema_version"] == 1
    json.loads((tmp_path / ".operator/regressions/sample/CAND-001/regression.json").read_text())
