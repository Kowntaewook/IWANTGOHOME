"""Offline browser/client trust scout over sanitized source observations."""

import re

from .base import BaseScout, ScoutContext, analysis_ids, asset_candidates, endpoint_shape, walk_values


CLIENT_STATE = re.compile(r"localStorage|sessionStorage|hidden(?:Field|Input)?|client[-_ ]?side", re.I)
AUTH_HINT = re.compile(r"isAdmin|role|permission|privilege|authorize|access[-_ ]?control", re.I)


class BrowserTrustScout(BaseScout):
    scout_type = "browser_trust"
    version = "1"

    def analyze(self, context: ScoutContext, limit: int):
        record = context.record
        if record.get("kind") != "analysis" or limit <= 0:
            return []
        analyzer = record.get("payload", {}).get("analyzer")
        if analyzer not in {"source", "source_tree", "source_context", "source_map", "web_spa"}:
            return []
        pairs = walk_values(record.get("payload", {}))
        # Both a mutable-client-state hint and an authorization hint are required.
        if not any(CLIENT_STATE.search(value) for _, value in pairs) or not any(
                AUTH_HINT.search(value) for _, value in pairs):
            return []
        assets = asset_candidates(record)
        if not assets:
            return []
        return [self.proposal(context, asset=asset,
            title="Review a mutable client-state authorization assumption",
            finding_category="client-trust-boundary", observation_ids=analysis_ids(context),
            source_record_ids=[record["id"]],
            invariant="Authorization and security-critical validation must be enforced by the server rather than mutable browser state or hidden UI fields.",
            evidence_summary="The same sanitized record contains both mutable client-state and role/permission control hints.",
            observed_fact="Client storage, hidden input, or client-only state is structurally associated with a role or permission hint.",
            why_may_matter="A server that trusts mutable client state could accept a privilege or validation decision controlled by the browser.",
            missing_evidence="No server-side inconsistency is established. The backend handler and an independently captured authorized response must be reviewed.",
            confidence=0.45, estimated_impact=0.71, novelty=0.57,
            required_followup=["Trace the corresponding server-side enforcement using existing source or contract evidence.",
                "Do not promote self-XSS or a UI-only visibility issue."], identity_context="browser_session",
            endpoint_shape=endpoint_shape(asset), resource_type="server_authorization_decision", estimated_requests=1)
            for asset in assets[:limit]]
