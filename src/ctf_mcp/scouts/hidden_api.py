"""Offline hidden/admin API scout requiring an authorization-impact signal."""

import re

from .base import BaseScout, ScoutContext, analysis_ids, endpoint_shape


SENSITIVE = re.compile(r"(?:^|/)(admin|internal|management|staff|operator|debug|private)(?:/|$)", re.I)


class HiddenAPIScout(BaseScout):
    scout_type = "hidden_api"
    version = "1"

    def analyze(self, context: ScoutContext, limit: int):
        record = context.record
        if record.get("kind") != "analysis" or limit <= 0:
            return []
        payload = record.get("payload", {})
        result = payload.get("result", {})
        if not isinstance(result, dict):
            return []
        observations = result.get("observations", [])
        if isinstance(observations, dict):
            observations = observations.get("operations", [])
        if not isinstance(observations, list):
            return []
        proposals = []
        for op in observations[:500]:
            if not isinstance(op, dict):
                continue
            asset = op.get("url", op.get("path"))
            if not isinstance(asset, str) or not SENSITIVE.search(asset):
                continue
            declaration = op.get("security_declaration")
            status = op.get("status")
            # Route existence alone is insufficient: require weak/unknown declared auth or a successful saved response.
            impact_signal = declaration in {"unspecified", "optional_or_none"} or isinstance(status, int) and 200 <= status < 300
            if not impact_signal:
                continue
            method = op.get("method", "GET") if isinstance(op.get("method", "GET"), str) else "GET"
            proposals.append(self.proposal(context, asset=asset,
                title="Review a sensitive API operation with an authorization-impact signal",
                finding_category="hidden-api-authorization", observation_ids=analysis_ids(context),
                source_record_ids=[record["id"]],
                invariant="Sensitive administrative and internal operations must enforce server-side authorization independent of discoverability or client routing.",
                evidence_summary="A sensitive route is paired with absent/optional contract security or a saved successful response structure.",
                observed_fact="The route name is sensitive and the same immutable record includes an authorization-impact signal beyond route existence.",
                why_may_matter="A privileged operation with incomplete server-side enforcement could cross a role or tenant boundary.",
                missing_evidence="Runtime server authorization, intended audience, response semantics, and role policy remain unverified.",
                confidence=0.48, estimated_impact=0.84, novelty=0.69,
                required_followup=["Compare the operation with documented policy and existing authorized observations.",
                    "Do not infer a finding from path disclosure alone."], identity_context="least_privileged_authorized_identity",
                endpoint_shape=endpoint_shape(asset, method), resource_type="privileged_operation", estimated_requests=1))
            if len(proposals) >= limit:
                break
        return proposals
