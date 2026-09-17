"""Offline comparison of already-captured user_a/user_b observations."""

import json

from .base import BaseScout, ScoutContext, analysis_ids, endpoint_shape


def _without_weak_differences(value):
    if isinstance(value, dict):
        return {k: _without_weak_differences(v) for k, v in value.items()
                if k.lower() not in {"status", "size", "bytes", "content_length", "response_size"}}
    if isinstance(value, list):
        return [_without_weak_differences(v) for v in value]
    return value


class AuthTenantScout(BaseScout):
    scout_type = "auth_tenant"
    version = "1"

    def analyze(self, context: ScoutContext, limit: int):
        record = context.record
        if record.get("kind") != "session_comparison" or limit <= 0:
            return []
        payload = record.get("payload", {})
        differences = payload.get("DIFFERENCES", [])
        if not isinstance(differences, list):
            return []
        meaningful = []
        asset = None
        for item in differences[:100]:
            if not isinstance(item, dict):
                continue
            a, b = item.get("user_a"), item.get("user_b")
            if _without_weak_differences(a) == _without_weak_differences(b):
                continue
            if not isinstance(a, dict) and not isinstance(b, dict):
                continue
            meaningful.append(item)
            for side in (a, b):
                if isinstance(side, dict) and isinstance(side.get("url"), str):
                    asset = side["url"]
                    break
            if asset:
                break
        if not meaningful or not asset:
            return []
        fact = ("A saved user_a/user_b comparison contains a response or request structure difference "
                "after status-only and size-only differences were ignored.")
        return [self.proposal(context, asset=asset,
            title="Review an observed identity-boundary structure difference",
            finding_category="authorization-boundary", observation_ids=analysis_ids(context),
            source_record_ids=[record["id"]],
            invariant="Equivalent authorized actions must preserve tenant and object authorization boundaries across identities.",
            evidence_summary="Structural A/B comparison is recorded in immutable record " + record["id"] + ".",
            observed_fact=fact,
            why_may_matter="A structural difference can identify where a role, account, or tenant policy needs focused verification.",
            missing_evidence="Confirm both captures represent the same intended action and review server-side policy without cross-using object identifiers.",
            confidence=0.62, estimated_impact=0.82, novelty=0.68,
            required_followup=["Independent policy review of the matching endpoint and roles.",
                "If a request is needed, create a separately approved same-account experiment plan."],
            identity_context="user_a_vs_user_b", endpoint_shape=endpoint_shape(asset),
            resource_type="identity_bound_resource", estimated_requests=1)]
