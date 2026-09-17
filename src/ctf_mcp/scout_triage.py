"""Deterministic, low-cost triage before optional model review."""

from dataclasses import dataclass
import re

from .programs import scope_decision
from .scouts.base import CandidateProposal


@dataclass(frozen=True)
class TriagePolicy:
    eligible_threshold: float = 0.52
    minimum_evidence: float = 0.5
    minimum_cost: float = 0.05


class CheapTriager:
    def __init__(self, policy: TriagePolicy = TriagePolicy()):
        self.policy = policy

    def triage(self, proposal: CandidateProposal, profile: dict, *, graph_support=None, feedback=None) -> dict:
        graph_support = graph_support or {"cross_artifact": False, "artifact_kind_count": 0,
                                          "corroborating_proposal_count": 0}
        feedback = feedback or {"active": False, "sample_count": 0, "confidence_factor": 1.0,
                                "cost_factor": 1.0, "authorization_effect": False}
        scope = scope_decision(profile, proposal.asset, "GET")
        excluded = proposal.finding_category in profile["excluded_finding_categories"]
        linked = int(graph_support.get("independent_record_count",
            len(set(proposal.source_record_ids + proposal.observation_ids))))
        graph_bonus = 0.1 if graph_support.get("cross_artifact") else 0.0
        evidence_completeness = min(1.0, linked * 0.35 +
            (0.2 if proposal.observed_fact else 0) + (0.15 if proposal.missing_evidence else 0) + graph_bonus)
        reproducibility = min(1.0, 0.35 + len(proposal.observation_ids) * 0.2 +
                              (0.15 if proposal.endpoint_shape != "not_available" else 0))
        required_identities = 2 if "_vs_" in proposal.identity_context else (
            0 if proposal.identity_context == "not_applicable" else 1)
        named_identities = set(re.findall(r"anonymous|user_a|user_b", proposal.identity_context))
        identities_available = named_identities <= set(profile["identities"])
        required_requests = proposal.estimated_requests
        budget_valid = required_requests <= profile["network_policy"]["max_total_requests_per_session"]
        estimated_cost = min(1.0, max(self.policy.minimum_cost,
            0.08 + required_requests * 0.08 + required_identities * 0.08 +
            (1.0 - evidence_completeness) * 0.28))
        estimated_cost = min(1.0, max(self.policy.minimum_cost,
            estimated_cost * float(feedback.get("cost_factor", 1.0))))
        calibrated_confidence = min(1.0, max(0.0,
            proposal.confidence * float(feedback.get("confidence_factor", 1.0))))
        triage_score = round(
            proposal.estimated_impact * 0.30 + calibrated_confidence * 0.25 +
            proposal.novelty * 0.15 + evidence_completeness * 0.20 +
            reproducibility * 0.10, 6)
        expected_value = round(
            proposal.estimated_impact * calibrated_confidence * proposal.novelty / estimated_cost, 6)
        if not scope["allowed"]:
            decision = "BLOCKED_SCOPE"
        elif excluded:
            decision = "PROGRAM_EXCLUDED"
        elif not identities_available:
            decision = "IDENTITY_UNAVAILABLE"
        elif not budget_valid:
            decision = "PROGRAM_BUDGET_EXCEEDED"
        elif evidence_completeness < self.policy.minimum_evidence:
            decision = "LOW_EVIDENCE"
        elif triage_score < self.policy.eligible_threshold:
            decision = "BELOW_THRESHOLD"
        else:
            decision = "ELIGIBLE"
        return {
            "proposal_id": proposal.proposal_id, "program_id": proposal.program_id,
            "scope_valid": scope["allowed"], "scope_reason": scope.get("reason"),
            "program_excluded": excluded, "evidence_completeness": round(evidence_completeness, 6),
            "reproducibility_hint": round(reproducibility, 6),
            "estimated_impact": proposal.estimated_impact, "confidence": proposal.confidence,
            "calibrated_confidence": round(calibrated_confidence, 6),
            "novelty": proposal.novelty, "required_request_count": required_requests,
            "required_identities": required_identities, "identities_available": identities_available,
            "program_budget_valid": budget_valid,
            "prohibited_actions_considered": profile["prohibited_actions"],
            "estimated_cost": round(estimated_cost, 6),
            "triage_score": triage_score, "expected_value": expected_value,
            "graph_support": graph_support, "outcome_calibration": feedback,
            "calibration_is_authorization": False,
            "decision": decision, "impact_is_estimate": True, "cvss_assigned": False,
        }
