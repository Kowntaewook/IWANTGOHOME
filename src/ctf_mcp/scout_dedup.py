"""Structural-first semantic deduplication for Scout proposals."""

import hashlib
import re
from typing import Callable
from urllib.parse import urlsplit, urlunsplit

from .redaction import public_url
from .scouts.base import CandidateProposal


def _normalized_text(value: str) -> str:
    return " ".join(re.findall(r"[a-z0-9]+", value.lower()))


def _normalized_asset(value: str) -> tuple[str, str]:
    safe = public_url(value) if "://" in value else value.split("?", 1)[0]
    if "://" not in safe:
        path = safe
        origin = "relative"
    else:
        parsed = urlsplit(safe)
        authority = (parsed.hostname or "").lower()
        if parsed.port:
            authority += ":" + str(parsed.port)
        origin = urlunsplit((parsed.scheme.lower(), authority, "", "", ""))
        path = parsed.path
    path = re.sub(r"(?<=/)(?:\d{2,}|[0-9a-f]{16,}|[A-Za-z0-9_-]{32,})(?=/|$)", "{id}", path, flags=re.I)
    return origin, path.rstrip("/") or "/"


def _tokens(proposal: CandidateProposal) -> set[str]:
    text = " ".join((proposal.title, proposal.invariant, proposal.observed_fact,
                     proposal.why_may_matter, proposal.resource_type))
    return set(re.findall(r"[a-z0-9]{3,}", text.lower()))


class SemanticDeduplicator:
    """Deduplicate only with a full structural match; semantics rank/explain matches."""

    def __init__(self, semantic_backend: Callable[[str, str], float] | None = None):
        self.semantic_backend = semantic_backend

    def structure(self, proposal: CandidateProposal) -> dict[str, str]:
        origin, asset = _normalized_asset(proposal.asset)
        return {
            "program_id": proposal.program_id,
            "origin": origin,
            "asset": asset,
            "finding_category": proposal.finding_category,
            "scout_type": proposal.scout_type,
            "identity_context": _normalized_text(proposal.identity_context),
            "endpoint_shape": _normalized_text(proposal.endpoint_shape),
            "resource_type": _normalized_text(proposal.resource_type),
            "security_invariant": _normalized_text(proposal.invariant),
        }

    def fingerprint(self, proposal: CandidateProposal) -> str:
        structure = self.structure(proposal)
        value = "\n".join(structure[key] for key in sorted(structure))
        return hashlib.sha256(value.encode()).hexdigest()

    def similarity(self, left: CandidateProposal, right: CandidateProposal) -> float:
        if self.semantic_backend is not None:
            try:
                value = float(self.semantic_backend(left.invariant, right.invariant))
                if 0 <= value <= 1:
                    return round(value, 6)
            except Exception:
                pass
        a, b = _tokens(left), _tokens(right)
        return round(len(a & b) / len(a | b), 6) if a or b else 1.0

    def compare(self, proposal: CandidateProposal, existing: CandidateProposal) -> dict:
        same_program = proposal.program_id == existing.program_id
        structural = same_program and self.structure(proposal) == self.structure(existing)
        similarity = self.similarity(proposal, existing) if same_program else 0.0
        return {
            "proposal_id": proposal.proposal_id, "duplicate": structural,
            "duplicate_of": existing.proposal_id if structural else None,
            "similarity": similarity, "structural_match": structural,
            "reason": ("same_program_full_structural_fingerprint" if structural else
                       "different_program" if not same_program else "structural_fingerprint_differs"),
            "structural_fingerprint": self.fingerprint(proposal),
        }

    def find(self, proposal: CandidateProposal, existing: list[CandidateProposal]) -> dict:
        matches = [self.compare(proposal, item) for item in existing if item.proposal_id != proposal.proposal_id]
        duplicate = next((item for item in matches if item["duplicate"]), None)
        if duplicate:
            return duplicate
        best = max(matches, key=lambda item: item["similarity"], default=None)
        return best or {"proposal_id": proposal.proposal_id, "duplicate": False, "duplicate_of": None,
            "similarity": 0.0, "structural_match": False, "reason": "no_prior_proposals",
            "structural_fingerprint": self.fingerprint(proposal)}
