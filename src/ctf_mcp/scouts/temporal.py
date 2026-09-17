"""Offline temporal comparison of immutable analysis records."""

import json
import re

from .base import BaseScout, ScoutContext, endpoint_shape


SENSITIVE = re.compile(r"(?:admin|internal|tenant|account|billing|role|permission|privilege)", re.I)
WEAK_AUTH = re.compile(r"(?:optional|none|public|false|disabled|no[_ -]?auth)", re.I)
AUTH_KEYS = {"security", "security_declaration", "auth_required", "authorization_required", "requires_auth"}
PRIVILEGED_FIELD = re.compile(r"(?:role|permission|privilege|tenant|billing|admin)", re.I)


def _observations(record):
    payload = record.get("payload", {})
    if not isinstance(payload, dict):
        return {}
    result_value = payload.get("result", {})
    if not isinstance(result_value, dict):
        return {}
    values = result_value.get("observations", [])
    result = {}
    if not isinstance(values, list):
        return result
    for item in values[:500]:
        if not isinstance(item, dict):
            continue
        asset = item.get("url") or item.get("path") or item.get("asset")
        if not isinstance(asset, str) or not asset.startswith(("http://", "https://", "/")):
            continue
        method = item.get("method", "GET") if isinstance(item.get("method", "GET"), str) else "GET"
        auth = {key: item[key] for key in AUTH_KEYS if key in item}
        fields = []
        for key in ("fields", "response_fields", "properties"):
            value = item.get(key)
            if isinstance(value, list): fields += [str(v) for v in value[:100]]
            elif isinstance(value, dict): fields += [str(v) for v in list(value)[:100]]
        result[endpoint_shape(asset, method)] = {"asset": asset, "auth": auth, "fields": fields}
    return result


def _weaker(old, current):
    if not old:
        return False
    old_text = json.dumps(old, sort_keys=True).lower()
    current_text = json.dumps(current, sort_keys=True).lower()
    return (not current or bool(WEAK_AUTH.search(current_text))) and not bool(WEAK_AUTH.search(old_text))


class TemporalChangeScout(BaseScout):
    scout_type = "temporal_change"
    version = "1"

    def analyze(self, context: ScoutContext, limit: int):
        if limit <= 0 or context.record.get("kind") != "analysis":
            return []
        current = _observations(context.record)
        if not current:
            return []
        analyzer = context.record.get("payload", {}).get("analyzer")
        previous = []
        for record in context.previous_records:
            if record.get("kind") != "analysis" or record.get("payload", {}).get("analyzer") != analyzer:
                continue
            previous.append((record, _observations(record)))
        if not previous:
            return []
        prior_record, prior = previous[-1]
        proposals = []
        for shape, value in current.items():
            old = prior.get(shape)
            added_sensitive = old is None and SENSITIVE.search(shape) and WEAK_AUTH.search(json.dumps(value["auth"]))
            auth_regression = old is not None and _weaker(old["auth"], value["auth"])
            new_privileged = old is not None and any(PRIVILEGED_FIELD.search(field) for field in
                set(value["fields"]) - set(old["fields"]))
            if not (added_sensitive or auth_regression or new_privileged):
                continue
            reason = "authorization metadata became weaker" if auth_regression else (
                "a privileged response field appeared" if new_privileged else
                "a sensitive operation appeared with weak authorization metadata")
            source_ids = [record["id"] for record in (prior_record, context.record)
                          if isinstance(record.get("id"), str)]
            proposals.append(self.proposal(context, asset=value["asset"],
                title="Review a security-relevant temporal API change",
                finding_category="temporal-authorization-regression",
                observation_ids=[], source_record_ids=source_ids,
                invariant="Security-sensitive operations and fields must retain server-side authorization across revisions.",
                evidence_summary="Two immutable analysis revisions contain a security-relevant structural difference.",
                observed_fact="The latest saved contract differs from the prior revision: " + reason + ".",
                why_may_matter="A revision may have weakened an authorization boundary or exposed a privileged field.",
                missing_evidence="Independent runtime evidence must establish server behavior and affected identity boundaries.",
                confidence=.58 if auth_regression else .48, estimated_impact=.8, novelty=.82,
                required_followup=["Review both immutable revisions", "Collect a minimal independently authorized observation"],
                identity_context="user_a_vs_user_b" if {"user_a", "user_b"} <= set(context.profile["identities"]) else context.profile["identities"][0],
                endpoint_shape=shape, resource_type="authorization_boundary", estimated_requests=2))
            if len(proposals) >= limit:
                break
        return proposals
