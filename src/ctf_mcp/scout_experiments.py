"""Minimal, non-authorizing experiment planning over approved program metadata."""

import hashlib
import json
import re
from typing import Any
from uuid import uuid4

from .config import Rejected
from .programs import scope_decision
from .scouts.base import CandidateProposal, ExperimentRequest, utcnow


class MinimalExperimentPlanner:
    version = "1"
    maximum_requests = 3

    def plan(self, proposal: CandidateProposal, profile: dict, program_reference: dict) -> dict[str, Any]:
        if proposal.program_id != profile["program_id"] or proposal.program != program_reference:
            raise Rejected("experiment_program_mismatch")
        if proposal.finding_category in profile["excluded_finding_categories"]:
            raise Rejected("experiment_program_excluded")
        method = next((value for value in ("GET", "HEAD", "OPTIONS")
                       if value in profile["network_policy"]["allowed_methods"]), None)
        if method is None:
            raise Rejected("experiment_method_unavailable")
        decision = scope_decision(profile, proposal.asset, method)
        if not decision["allowed"]:
            raise Rejected(decision.get("reason") or "experiment_scope_blocked")
        named = [value for value in ("anonymous", "user_a", "user_b")
                 if re.search(r"(?:^|_vs_|\b)" + re.escape(value) + r"(?:$|_vs_|\b)", proposal.identity_context)]
        if set(named) - set(profile["identities"]):
            raise Rejected("experiment_identity_unavailable")
        identities = [value for value in named if value in profile["identities"]]
        if not identities:
            identities = [profile["identities"][0]]
        if proposal.scout_type != "auth_tenant":
            identities = identities[:1]
        identities = list(dict.fromkeys(identities))[:self.maximum_requests]
        request_count = min(len(identities), proposal.estimated_requests or 1,
                            profile["network_policy"]["max_total_requests_per_session"], self.maximum_requests)
        identities = identities[:max(1, request_count)]
        requests = [ExperimentRequest(
            proposal_id=proposal.proposal_id, program_id=proposal.program_id,
            identity=identity, method=method, url=proposal.asset,
            purpose="Collect the minimum bounded observation needed to test the stated security invariant.",
            expected_signal=proposal.missing_evidence, estimated_requests=1).to_dict()
            for identity in identities]
        request_shapes = [{key: request[key] for key in
            ("identity", "method", "url", "purpose", "expected_signal", "estimated_requests")}
            for request in requests]
        fingerprint = hashlib.sha256(json.dumps({"proposal_id": proposal.proposal_id,
            "profile": program_reference, "requests": request_shapes, "version": self.version},
            sort_keys=True, ensure_ascii=True).encode()).hexdigest()
        return {"plan_id": uuid4().hex, "proposal_id": proposal.proposal_id,
            "program_id": proposal.program_id, "program": program_reference,
            "planner_version": self.version, "plan_fingerprint": fingerprint,
            "purpose": proposal.why_may_matter, "missing_evidence": proposal.missing_evidence,
            "requests": requests, "estimated_requests": len(requests),
            "required_checks": ["active_approved_program", "scope_check", "allowed_method",
                                "program_budget", "session_plan_and_grant", "existing_bounded_runner"],
            "authorization": False, "executable": False, "network_requests_sent": 0,
            "created_at": utcnow()}
