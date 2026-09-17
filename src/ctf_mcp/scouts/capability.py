"""Offline recognition of redacted capability URL/token structures."""

import hashlib
import re

from .base import BaseScout, ScoutContext, analysis_ids, asset_candidates, endpoint_shape, walk_values


CAPABILITY = re.compile(r"(?:^|[/_.?&=-])(share|invite|reset|magic|download|access|capability|signed)(?:[/_.?&=-]|$)", re.I)
TOKEN_KEY = re.compile(r"(?:^|[?&])(token|key|signature|sig|code|secret|access_token)=", re.I)


class CapabilityScout(BaseScout):
    scout_type = "capability"
    version = "1"

    def analyze(self, context: ScoutContext, limit: int):
        if context.record.get("kind") not in {"analysis", "session_comparison"} or limit <= 0:
            return []
        record = context.record
        analyzer = record.get("payload", {}).get("analyzer")
        if analyzer not in {"har", "http_log", "openapi", "source", "source_tree", "source_map",
                            "web_read", "web_spa", "android_find_urls", "ios"}:
            return []
        candidates = []
        for asset in asset_candidates(record):
            if CAPABILITY.search(asset) and (TOKEN_KEY.search(asset) or re.search(r"share|invite|reset|magic|signed", asset, re.I)):
                candidates.append(asset)
        # Key names can show a token-bearing structure even when its value was correctly removed.
        pairs = walk_values(record.get("payload", {}))
        key_signal = any(re.search(r"token|signature|capability|share[_-]?key", key, re.I) or
                         re.fullmatch(r"token|signature|sig|capability|share[_-]?key|code", value, re.I)
                         for key, value in pairs)
        query_shape = any(key == "query_parameter_count" and value != "0" for key, value in pairs)
        if not candidates or not key_signal and not query_shape and not any(TOKEN_KEY.search(value) for value in candidates):
            return []
        proposals = []
        for asset in candidates[:limit]:
            structural_asset = re.sub(
                r"(?i)(/(?:share|invite|reset|magic|download|capability|signed)/)[^/?#]+",
                r"\1[REDACTED]", asset)
            fingerprint = hashlib.sha256(structural_asset.encode()).hexdigest()[:16]
            proposals.append(self.proposal(context, asset=structural_asset,
                title="Review a redacted capability-bearing URL structure",
                finding_category="capability-token", observation_ids=analysis_ids(context),
                source_record_ids=[record["id"]],
                invariant="Capability URLs and tokens must be unguessable, narrowly scoped, revocable, and protected from unintended disclosure.",
                evidence_summary="A capability-like route/query structure was observed; redacted structure fingerprint=" + fingerprint + ".",
                observed_fact="The sanitized immutable record contains a capability route plus a token-bearing or sharing structure.",
                why_may_matter="Possession may grant access, so scope, lifetime, audience binding, and leakage paths require review.",
                missing_evidence="No token value was retained or called. Authorization scope, expiry, replay behavior, and disclosure path remain unverified.",
                confidence=0.58, estimated_impact=0.67, novelty=0.64,
                required_followup=["Review token lifecycle and audience binding from existing source or contract evidence.",
                    "Do not call the discovered URL without a separate exact session plan and grant."],
                identity_context="capability_holder", endpoint_shape=endpoint_shape(asset),
                resource_type="capability_protected_resource", estimated_requests=1))
        return proposals
