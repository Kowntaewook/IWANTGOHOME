"""Outcome-derived calibration for Scout ranking; never an authorization source."""

from collections import Counter
from dataclasses import dataclass
from datetime import datetime
from statistics import mean
from typing import Any

from .config import Rejected
from .scout_pipeline import proposal_records, scout_events
from .scouts.base import CandidateProposal, utcnow


RESOLVED_OUTCOMES = {
    "READY_FOR_HUMAN_REVIEW": "REVIEW_READY",
    "REJECTED": "REJECTED",
    "rejected": "REJECTED",
    "NOT_SECURITY_RELEVANT": "NOT_SECURITY_RELEVANT",
    "DUPLICATE": "DUPLICATE",
    "BLOCKED_SCOPE": "BLOCKED_SCOPE",
}
POSITIVE_OUTCOMES = {"REVIEW_READY"}
NEGATIVE_OUTCOMES = {"REJECTED", "NOT_SECURITY_RELEVANT"}


def _seconds(start: str | None, end: str) -> int:
    try:
        if start is None:
            return 0
        return max(0, min(31_536_000, int((datetime.fromisoformat(end) - datetime.fromisoformat(start)).total_seconds())))
    except (TypeError, ValueError):
        return 0


@dataclass(frozen=True)
class FeedbackPolicy:
    minimum_samples: int = 3
    baseline_investigation_seconds: int = 900

    def __post_init__(self):
        if type(self.minimum_samples) is not int or not 1 <= self.minimum_samples <= 100:
            raise Rejected("invalid_feedback_policy")
        if type(self.baseline_investigation_seconds) is not int or not 60 <= self.baseline_investigation_seconds <= 86_400:
            raise Rejected("invalid_feedback_policy")


class ScoutOutcomeFeedback:
    """Derive outcomes from existing candidate records and produce bounded calibration."""

    version = "1"

    def __init__(self, records, ledger, policy: FeedbackPolicy = FeedbackPolicy()):
        self.records = records
        self.ledger = ledger
        self.policy = policy

    def _promotion_times(self) -> dict[str, str]:
        return {r["payload"]["proposal_id"]: r["created_at"]
                for r in scout_events(self.records, "scout_promotion")}

    def reconcile(self, program_id: str | None = None) -> dict[str, Any]:
        proposals = {p.proposal_id: p for p, _ in proposal_records(self.records, program_id)}
        prior = {r["payload"].get("candidate_record_id")
                 for r in scout_events(self.records, "scout_outcome", program_id)}
        promoted_at = self._promotion_times()
        created = []
        index_batch = []
        for record_id in self.records.list():
            record = self.records.read(record_id)
            if record["kind"] != "candidate" or record_id in prior:
                continue
            payload = record["payload"]
            proposal_id = payload.get("proposal_id")
            proposal = proposals.get(proposal_id)
            outcome = RESOLVED_OUTCOMES.get(payload.get("review_status"))
            if proposal is None or outcome is None:
                continue
            if payload.get("program_id") != proposal.program_id or payload.get("program") != proposal.program:
                continue
            value = {
                "proposal_id": proposal_id,
                "program_id": proposal.program_id,
                "scout_type": proposal.scout_type,
                "finding_category": proposal.finding_category,
                "candidate_record_id": record_id,
                "candidate_review_status": payload["review_status"],
                "outcome": outcome,
                "investigation_seconds": _seconds(promoted_at.get(proposal_id), record["created_at"]),
                "feedback_version": self.version,
                "authorization_source": False,
                "created_at": utcnow(),
            }
            saved = self.records.save("scout_outcome", value)
            index_batch.append(saved)
            created.append(value)
        self.ledger.record_batch(index_batch)
        return {"program_id": program_id, "outcomes_recorded": len(created),
                "outcomes": created, "authorization_effect": False}

    def calibration(self, proposal: CandidateProposal) -> dict[str, Any]:
        rows = [r["payload"] for r in scout_events(self.records, "scout_outcome", proposal.program_id)
                if r["payload"].get("scout_type") == proposal.scout_type]
        # One latest resolved candidate record per proposal prevents repeated updates from overweighting it.
        latest: dict[str, dict] = {}
        for row in rows:
            if row.get("proposal_id") != proposal.proposal_id:
                latest[row["proposal_id"]] = row
        resolved = [r for r in latest.values() if r["outcome"] in POSITIVE_OUTCOMES | NEGATIVE_OUTCOMES]
        positives = sum(r["outcome"] in POSITIVE_OUTCOMES for r in resolved)
        sample_count = len(resolved)
        precision = (positives + 1) / (sample_count + 2)
        durations = [r["investigation_seconds"] for r in resolved if r.get("investigation_seconds", 0) > 0]
        average_seconds = round(mean(durations), 3) if durations else 0.0
        active = sample_count >= self.policy.minimum_samples
        confidence_factor = min(1.25, max(0.75, 0.75 + 0.5 * precision)) if active else 1.0
        cost_factor = min(2.0, max(0.5, average_seconds / self.policy.baseline_investigation_seconds)) \
            if active and average_seconds else 1.0
        return {"sample_count": sample_count, "positive_count": positives,
                "estimated_precision": round(precision, 6), "average_investigation_seconds": average_seconds,
                "confidence_factor": round(confidence_factor, 6), "cost_factor": round(cost_factor, 6),
                "active": active, "authorization_effect": False}

    def status(self, program_id: str | None = None) -> dict[str, Any]:
        rows = [r["payload"] for r in scout_events(self.records, "scout_outcome", program_id)]
        return {"outcome_count": len(rows),
                "outcomes": dict(sorted(Counter(r["outcome"] for r in rows).items())),
                "by_scout": dict(sorted(Counter(r["scout_type"] for r in rows).items())),
                "by_category": dict(sorted(Counter(r["finding_category"] for r in rows).items())),
                "calibration_is_authorization": False, "records": rows[-100:]}
