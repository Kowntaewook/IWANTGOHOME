"""Bounded offline Scout execution over immutable, sanitized records."""

from dataclasses import dataclass
import os
import time
from typing import Any

from .config import Rejected
from .program_store import ProgramStore
from .records import Records, valid_id
from .scout_dedup import SemanticDeduplicator
from .scout_ledger import ScoutLedger
from .scouts import SCOUTS
from .scouts.base import CandidateProposal, ScoutContext, record_hash, utcnow


@dataclass(frozen=True)
class OfflineAnalysisBudget:
    max_proposals_per_scout: int = 20
    max_proposals_per_run: int = 100
    max_model_calls: int = 4
    max_runtime_seconds: int = 30
    max_promoted_candidates: int = 10

    def __post_init__(self):
        ceilings = {"max_proposals_per_scout": 200, "max_proposals_per_run": 1000,
            "max_model_calls": 50, "max_runtime_seconds": 300, "max_promoted_candidates": 100}
        for key, ceiling in ceilings.items():
            value = getattr(self, key)
            if type(value) is not int or not 0 <= value <= ceiling or key == "max_runtime_seconds" and value < 1:
                raise Rejected("invalid_offline_analysis_budget")


class ModelRouting:
    ROLES = {"Scout": "SCOUT", "CheapTriager": "CHEAP_TRIAGER",
        "PortfolioReviewer": "PORTFOLIO_REVIEWER", "Investigator": "INVESTIGATOR",
        "Verifier": "VERIFIER", "Reporter": "REPORTER"}
    DEFAULT_EFFORT = {"Scout": "low", "CheapTriager": "low", "PortfolioReviewer": "medium",
        "Investigator": "high", "Verifier": "high", "Reporter": "medium"}

    @classmethod
    def from_env(cls) -> dict[str, dict[str, str | None]]:
        result = {}
        for role, key in cls.ROLES.items():
            model = os.environ.get("FINDER_MODEL_" + key) or os.environ.get("FINDER_MODEL") or None
            effort = os.environ.get("FINDER_EFFORT_" + key) or cls.DEFAULT_EFFORT[role]
            if effort not in {None, "low", "medium", "high", "xhigh"}:
                raise Rejected("invalid_model_effort")
            result[role] = {"model": model, "effort": effort}
        return result


def proposal_records(records: Records, program_id: str | None = None) -> list[tuple[CandidateProposal, dict]]:
    found = []
    for record_id in records.list():
        record = records.read(record_id)
        if record["kind"] != "scout_proposal":
            continue
        proposal = CandidateProposal.from_dict(record["payload"])
        if program_id is None or proposal.program_id == program_id:
            found.append((proposal, record))
    return sorted(found, key=lambda item: (item[0].created_at, item[0].proposal_id))


def scout_events(records: Records, kind: str, program_id: str | None = None) -> list[dict]:
    result = []
    for record_id in records.list():
        record = records.read(record_id)
        if record["kind"] != kind:
            continue
        payload = record["payload"]
        if program_id is None or payload.get("program_id") == program_id:
            result.append(record)
    return sorted(result, key=lambda item: (item["created_at"], item["id"]))


class ScoutPipeline:
    def __init__(self, settings, *, budget: OfflineAnalysisBudget = OfflineAnalysisBudget(), scouts=None,
                 deduplicator=None, ledger=None):
        if settings.programs_root is None:
            raise Rejected("program_store_not_configured")
        self.settings = settings
        self.records = Records(settings.results_root, settings.limits, settings.programs_root)
        self.programs = ProgramStore(settings.programs_root)
        self.budget = budget
        self.scouts = tuple(cls() for cls in SCOUTS) if scouts is None else tuple(scouts)
        self.deduplicator = deduplicator or SemanticDeduplicator()
        self.ledger = ledger or ScoutLedger(settings.results_root)
        self.ledger.sync(self.records)

    def _program(self, ident):
        if ident is None:
            profile, approval = self.programs.selected()
        else:
            profile, approval = self.programs.approved(ident)
        reference = {"program_id": profile["program_id"], "approval_id": approval["approval_id"],
                     "sha256": approval["sha256"]}
        return profile, reference

    def _inputs(self, record_id):
        if record_id is not None:
            return [self.records.read(valid_id(record_id))]
        values = []
        for item_id in self.records.list():
            record = self.records.read(item_id)
            if record["kind"] in {"analysis", "session_comparison"}:
                values.append(record)
        return sorted(values, key=lambda item: (item["created_at"], item["id"]))

    def run(self, *, program_id: str | None = None, record_id: str | None = None,
            force: bool = False) -> dict[str, Any]:
        if type(force) is not bool:
            raise Rejected("invalid_force_flag")
        started = time.monotonic()
        profile, reference = self._program(program_id)
        existing = [proposal for proposal, _ in proposal_records(self.records, profile["program_id"])]
        created: list[CandidateProposal] = []
        skipped_fresh = skipped_program = malformed = 0
        evaluated = 0
        by_scout = {scout.scout_type: 0 for scout in self.scouts}
        for record in self._inputs(record_id):
            if time.monotonic() - started >= self.budget.max_runtime_seconds:
                break
            bound = record.get("payload", {}).get("program")
            if bound is not None and bound != reference:
                if record_id is not None:
                    raise Rejected("scout_record_program_mismatch")
                skipped_program += 1
                continue
            context = ScoutContext(profile, reference, record)
            digest = record_hash(record)
            for scout in self.scouts:
                if len(created) >= self.budget.max_proposals_per_run or time.monotonic() - started >= self.budget.max_runtime_seconds:
                    break
                if by_scout[scout.scout_type] >= self.budget.max_proposals_per_scout:
                    continue
                if not force and self.ledger.was_evaluated(digest, scout.scout_type, scout.version):
                    skipped_fresh += 1
                    continue
                available = min(self.budget.max_proposals_per_scout - by_scout[scout.scout_type],
                                self.budget.max_proposals_per_run - len(created))
                try:
                    proposals = scout.analyze(context, available)
                    if not isinstance(proposals, list) or len(proposals) > available:
                        raise Rejected("scout_proposal_budget_exceeded")
                    proposals = [proposal.validated() for proposal in proposals]
                except (Rejected, KeyError, TypeError, ValueError):
                    proposals = []
                    malformed += 1
                for proposal in proposals:
                    proposal_record = self.records.save("scout_proposal", proposal.to_dict())
                    self.ledger.record_proposal(proposal_record)
                    relation = self.deduplicator.find(proposal, existing)
                    relation_record = self.records.save("scout_dedup", {
                        **relation, "program_id": proposal.program_id, "created_at": utcnow()})
                    self.ledger.record_dedup(relation_record)
                    existing.append(proposal)
                    created.append(proposal)
                    by_scout[scout.scout_type] += 1
                evaluation = self.records.save("scout_evaluation", {
                    "input_record_id": record["id"], "input_record_hash": digest,
                    "analyzer_version": record.get("analyzer_version", "unknown"),
                    "scout_type": scout.scout_type, "scout_version": scout.version,
                    "last_evaluated_at": utcnow(), "proposal_count": len(proposals)})
                self.ledger.record_evaluation(evaluation)
                evaluated += 1
        return {"program_id": profile["program_id"], "proposal_count": len(created),
            "proposal_ids": [proposal.proposal_id for proposal in created], "by_scout": by_scout,
            "records_evaluated": evaluated, "freshness_skips": skipped_fresh,
            "program_mismatch_skips": skipped_program, "malformed_inputs": malformed,
            "duration_ms": int((time.monotonic() - started) * 1000),
            "network_requests_sent": 0, "model_calls": 0,
            "budget": self.budget.__dict__}
