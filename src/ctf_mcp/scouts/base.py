"""Shared Scout schemas and bounded helpers. This module never performs I/O."""

from dataclasses import dataclass, field
from datetime import datetime, timezone
import hashlib
import json
import re
from typing import Any
from uuid import uuid4

from ..config import Rejected
from ..redaction import clean, public_url
from ..safety import bounded_tree


PROPOSAL_STATUSES = {
    "PROPOSED", "DEDUPED", "TRIAGED", "SELECTED", "PROMOTED", "REJECTED",
    "BLOCKED_SCOPE", "NEEDS_MORE_EVIDENCE",
}
SCOUT_TYPES = {
    "auth_tenant", "capability", "parser_boundary", "outbound_http",
    "hidden_api", "browser_trust", "temporal_change",
}


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


def bounded_text(value: Any, name: str, maximum: int = 4000) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > maximum:
        raise Rejected("invalid_" + name)
    return value.strip()


def unit(value: Any, name: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise Rejected("invalid_" + name)
    result = float(value)
    if not 0.0 <= result <= 1.0:
        raise Rejected("invalid_" + name)
    return round(result, 6)


def ids(value: Any, name: str, maximum: int = 40) -> list[str]:
    if not isinstance(value, list) or len(value) > maximum:
        raise Rejected("invalid_" + name)
    if any(not isinstance(item, str) or not re.fullmatch(r"[0-9a-f]{32}", item) for item in value):
        raise Rejected("invalid_" + name)
    return list(dict.fromkeys(value))


@dataclass(frozen=True)
class CandidateProposal:
    program_id: str
    scout_type: str
    asset: str
    title: str
    finding_category: str
    observation_ids: list[str]
    source_record_ids: list[str]
    invariant: str
    evidence_summary: str
    observed_fact: str
    why_may_matter: str
    missing_evidence: str
    confidence: float
    estimated_impact: float
    novelty: float
    required_followup: list[str]
    identity_context: str = "not_applicable"
    endpoint_shape: str = "not_available"
    resource_type: str = "not_available"
    estimated_requests: int = 0
    proposal_id: str = field(default_factory=lambda: uuid4().hex)
    created_at: str = field(default_factory=utcnow)
    status: str = "PROPOSED"
    program: dict[str, str] | None = None

    def validated(self) -> "CandidateProposal":
        from ..programs import program_id
        program_id(self.program_id)
        if self.scout_type not in SCOUT_TYPES:
            raise Rejected("invalid_scout_type")
        if not re.fullmatch(r"[0-9a-f]{32}", self.proposal_id):
            raise Rejected("invalid_proposal_id")
        if self.status not in PROPOSAL_STATUSES:
            raise Rejected("invalid_proposal_status")
        bounded_text(self.asset, "proposal_asset", 2048)
        bounded_text(self.title, "proposal_title", 512)
        if not re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,127}", self.finding_category):
            raise Rejected("invalid_finding_category")
        ids(self.observation_ids, "observation_ids")
        ids(self.source_record_ids, "source_record_ids")
        for name in ("invariant", "evidence_summary", "observed_fact", "why_may_matter", "missing_evidence",
                     "identity_context", "endpoint_shape", "resource_type"):
            bounded_text(getattr(self, name), name)
        unit(self.confidence, "confidence")
        unit(self.estimated_impact, "estimated_impact")
        unit(self.novelty, "novelty")
        if not isinstance(self.required_followup, list) or len(self.required_followup) > 20 or any(
                not isinstance(item, str) or not 1 <= len(item) <= 512 for item in self.required_followup):
            raise Rejected("invalid_required_followup")
        if type(self.estimated_requests) is not int or not 0 <= self.estimated_requests <= 100:
            raise Rejected("invalid_estimated_requests")
        if self.program is not None:
            if not isinstance(self.program, dict) or set(self.program) != {"program_id", "approval_id", "sha256"}:
                raise Rejected("invalid_program_reference")
            if self.program["program_id"] != self.program_id:
                raise Rejected("proposal_program_mismatch")
            if not re.fullmatch(r"[0-9a-f]{32}", self.program["approval_id"]) or not re.fullmatch(r"[0-9a-f]{64}", self.program["sha256"]):
                raise Rejected("invalid_program_reference")
        bounded_tree(self.to_dict(validate=False))
        return self

    def to_dict(self, *, validate: bool = True) -> dict[str, Any]:
        if validate:
            self.validated()
        value = {
            "proposal_id": self.proposal_id, "program_id": self.program_id,
            "scout_type": self.scout_type, "asset": public_url(self.asset) if "://" in self.asset else self.asset,
            "title": self.title, "finding_category": self.finding_category,
            "observation_ids": self.observation_ids, "source_record_ids": self.source_record_ids,
            "invariant": self.invariant, "evidence_summary": self.evidence_summary,
            "observed_fact": self.observed_fact, "why_may_matter": self.why_may_matter,
            "missing_evidence": self.missing_evidence, "confidence": self.confidence,
            "estimated_impact": self.estimated_impact, "novelty": self.novelty,
            "required_followup": self.required_followup, "identity_context": self.identity_context,
            "endpoint_shape": self.endpoint_shape, "resource_type": self.resource_type,
            "estimated_requests": self.estimated_requests, "created_at": self.created_at,
            "status": self.status,
        }
        if self.program is not None:
            value["program"] = self.program
        return clean(value)

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "CandidateProposal":
        allowed = set(cls.__dataclass_fields__)
        if not isinstance(value, dict) or set(value) - allowed:
            raise Rejected("invalid_candidate_proposal")
        try:
            return cls(**value).validated()
        except TypeError:
            raise Rejected("invalid_candidate_proposal") from None


@dataclass(frozen=True)
class ExperimentRequest:
    proposal_id: str
    program_id: str
    identity: str
    method: str
    url: str
    purpose: str
    expected_signal: str
    estimated_requests: int
    created_at: str = field(default_factory=utcnow)
    authorization: bool = False

    def to_dict(self) -> dict[str, Any]:
        from ..programs import program_id
        from ..research_policy import IDENTITIES
        if not re.fullmatch(r"[0-9a-f]{32}", self.proposal_id):
            raise Rejected("invalid_proposal_id")
        program_id(self.program_id)
        if self.identity not in IDENTITIES or self.method not in {"GET", "HEAD", "OPTIONS"}:
            raise Rejected("invalid_experiment_request")
        if type(self.estimated_requests) is not int or not 1 <= self.estimated_requests <= 100:
            raise Rejected("invalid_experiment_request")
        if self.authorization is not False:
            raise Rejected("experiment_request_cannot_authorize")
        result = {
            "proposal_id": self.proposal_id, "program_id": self.program_id,
            "identity": self.identity, "method": self.method,
            "url": public_url(bounded_text(self.url, "experiment_url", 2048)),
            "purpose": bounded_text(self.purpose, "experiment_purpose", 1000),
            "expected_signal": bounded_text(self.expected_signal, "expected_signal", 1000),
            "estimated_requests": self.estimated_requests, "created_at": self.created_at,
            "authorization": False, "session_grant_required": True,
        }
        result = clean(result)
        # The shared redactor treats every value under an authorization-shaped key as secret.
        # Restore this schema boolean after cleaning; it is always false by validation.
        result["authorization"] = False
        return result


@dataclass(frozen=True)
class ScoutContext:
    profile: dict[str, Any]
    program_reference: dict[str, str]
    record: dict[str, Any]
    previous_records: tuple[dict[str, Any], ...] = ()


class BaseScout:
    scout_type = "base"
    version = "1"

    def analyze(self, context: ScoutContext, limit: int) -> list[CandidateProposal]:
        raise NotImplementedError

    def proposal(self, context: ScoutContext, **values: Any) -> CandidateProposal:
        asset = values.get("asset")
        if isinstance(asset, str) and asset.startswith("/"):
            rules = [rule for rule in context.profile["scope"]["in_scope"]
                     if not rule["host"].startswith("*.")]
            origins = []
            for rule in rules:
                scheme = "https" if "https" in rule["schemes"] else (
                    rule["schemes"][0] if len(rule["schemes"]) == 1 else None)
                ports = rule.get("ports")
                if scheme is None or ports is not None and len(ports) != 1:
                    continue
                authority = rule["host"]
                if ports and ports[0] != (443 if scheme in {"https", "wss"} else 80):
                    authority += ":" + str(ports[0])
                origins.append(scheme + "://" + authority)
            if len(set(origins)) == 1:
                from ..programs import scope_decision
                resolved = origins[0] + asset
                if scope_decision(context.profile, resolved)["allowed"]:
                    values["asset"] = resolved
        return CandidateProposal(program_id=context.profile["program_id"], scout_type=self.scout_type,
            program=context.program_reference, **values).validated()


def record_hash(record: dict[str, Any]) -> str:
    # IDs, timestamps and provenance paths are storage metadata. The Scout input
    # is the immutable, sanitized semantic payload plus its parser version.
    material = {
        "kind": record.get("kind"),
        "analyzer_version": record.get("analyzer_version", "unknown"),
        "payload": record.get("payload"),
    }
    raw = json.dumps(material, sort_keys=True, ensure_ascii=True,
                     separators=(",", ":"), allow_nan=False).encode()
    return hashlib.sha256(raw).hexdigest()


def walk_values(value: Any, *, limit: int = 4000) -> list[tuple[str, str]]:
    """Return bounded key/string pairs for recognition only; callers never persist raw values."""
    result: list[tuple[str, str]] = []
    stack: list[tuple[str, Any, int]] = [("root", value, 0)]
    while stack and len(result) < limit:
        key, item, depth = stack.pop()
        if depth > 24:
            continue
        if isinstance(item, dict):
            for child_key, child in list(item.items())[:500]:
                stack.append((str(child_key)[:128], child, depth + 1))
        elif isinstance(item, list):
            for child in item[:500]:
                stack.append((key, child, depth + 1))
        elif isinstance(item, str):
            result.append((key, item[:4096]))
    return result


def analysis_ids(context: ScoutContext) -> list[str]:
    record = context.record
    if record.get("kind") == "analysis":
        return [record["id"]]
    if record.get("kind") == "session_comparison":
        facts = record.get("payload", {}).get("FACTS", {})
        return [value for key, value in facts.items() if key.endswith("_evidence") and isinstance(value, str)
                and re.fullmatch(r"[0-9a-f]{32}", value)]
    return []


def asset_candidates(record: dict[str, Any]) -> list[str]:
    result: list[str] = []
    for key, value in walk_values(record.get("payload", {})):
        if key in {"url", "asset", "path", "start_url"} and value.startswith(("http://", "https://", "/")):
            safe = public_url(value) if value.startswith(("http://", "https://")) else value.split("?", 1)[0]
            if safe not in result:
                result.append(safe)
        if len(result) >= 40:
            break
    return result


def endpoint_shape(asset: str, method: str = "GET") -> str:
    path = asset.split("?", 1)[0]
    path = re.sub(r"(?<=/)(?:\d{2,}|[0-9a-f]{16,})(?=/|$)", "{id}", path, flags=re.I)
    return method + " " + path[:1900]


def method_for_asset(record: dict[str, Any], asset: str) -> str:
    payload = record.get("payload", {})
    for item in payload.get("result", {}).get("observations", []):
        if isinstance(item, dict) and item.get("url") == asset and isinstance(item.get("method"), str):
            return item["method"]
    return "GET"
