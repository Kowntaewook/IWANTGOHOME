"""Offline structural scout for server-side outbound HTTP features."""

import re

from .base import BaseScout, ScoutContext, analysis_ids, asset_candidates, endpoint_shape, walk_values


FEATURE = re.compile(r"webhook|callback|preview|proxy|fetch|import[-_/]?by[-_/]?url|remote[-_/]?(?:url|image|resource)", re.I)
URL_INPUT = re.compile(r"(?:^|[_-])(url|uri|callback|webhook|target|source)(?:$|[_-])", re.I)


class OutboundHTTPScout(BaseScout):
    scout_type = "outbound_http"
    version = "1"

    def analyze(self, context: ScoutContext, limit: int):
        record = context.record
        if record.get("kind") != "analysis" or limit <= 0:
            return []
        pairs = walk_values(record.get("payload", {}))
        if not any(FEATURE.search(value) for _, value in pairs) or not any(
                URL_INPUT.search(key) or URL_INPUT.search(value) for key, value in pairs):
            return []
        assets = [asset for asset in asset_candidates(record) if FEATURE.search(asset)]
        if not assets:
            return []
        return [self.proposal(context, asset=asset,
            title="Review an outbound resource-fetch boundary",
            finding_category="outbound-request-boundary", observation_ids=analysis_ids(context),
            source_record_ids=[record["id"]],
            invariant="Server-side URL consumers must constrain schemes, destinations, redirects, DNS results, response size, and returned content.",
            evidence_summary="A saved contract or observation contains an outbound-fetch feature and a URL-like input structure.",
            observed_fact="The offline record links a webhook, callback, preview, proxy, fetch, or remote-import feature with URL input.",
            why_may_matter="A server-side fetch boundary can expose internal destinations or relay data if destination controls are incomplete.",
            missing_evidence="No callback or arbitrary URL was sent. Destination validation, redirect handling, DNS checks, and response use remain unknown.",
            confidence=0.55, estimated_impact=0.78, novelty=0.66,
            required_followup=["Create an ExperimentRequest only if static evidence cannot resolve destination controls.",
                "Any observation still requires active approval, scope check, allowed method, budget, exact plan, grant, and bounded runner."],
            identity_context="authorized_feature_user", endpoint_shape=endpoint_shape(asset, "POST"),
            resource_type="server_side_url_consumer", estimated_requests=1)
            for asset in assets[:limit]]
