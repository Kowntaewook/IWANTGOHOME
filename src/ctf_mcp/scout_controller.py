"""Scout orchestration and guarded promotion into the existing candidate lifecycle."""

from collections import Counter
from dataclasses import asdict
import time
from typing import Any
from uuid import uuid4

from .config import Rejected
from .program_store import ProgramStore
from .programs import scope_decision
from .records import Records, valid_id
from .scout_ledger import ScoutLedger
from .scout_pipeline import (ModelRouting, OfflineAnalysisBudget, ScoutPipeline,
                             proposal_records, scout_events)
from .scout_portfolio import ModelPortfolioSelector, PortfolioPolicy
from .scout_triage import CheapTriager, TriagePolicy
from .scouts.base import CandidateProposal, ExperimentRequest, utcnow


class ScoutPortfolioController:
    def __init__(self, settings, *, budget: OfflineAnalysisBudget = OfflineAnalysisBudget(),
                 triager=None, selector=None, ledger=None):
        if settings.programs_root is None:
            raise Rejected("program_store_not_configured")
        self.settings = settings
        self.records = Records(settings.results_root, settings.limits, settings.programs_root)
        self.programs = ProgramStore(settings.programs_root)
        self.budget = budget
        self.triager = triager or CheapTriager()
        self.selector = selector or ModelPortfolioSelector(PortfolioPolicy.from_env())
        self.ledger = ledger or ScoutLedger(settings.results_root)
        self.ledger.sync(self.records)

    def _profile(self, ident=None, *, active=False):
        if ident is None:
            return self.programs.selected()
        return self.programs.approved(ident, require_active=active)

    def _proposal(self, proposal_id: str) -> tuple[CandidateProposal, dict]:
        valid_id(proposal_id)
        for proposal, record in proposal_records(self.records):
            if proposal.proposal_id == proposal_id:
                return proposal, record
        raise Rejected("scout_proposal_not_found")

    def _latest(self, kind: str) -> dict[str, dict]:
        result = {}
        for record in scout_events(self.records, kind):
            proposal_id = record["payload"].get("proposal_id")
            if proposal_id:
                result[proposal_id] = record
        return result

    def run(self, *, program_id=None, record_id=None, force=False, portfolio_slots=10):
        pipeline = ScoutPipeline(self.settings, budget=self.budget, ledger=self.ledger)
        scan = pipeline.run(program_id=program_id, record_id=record_id, force=force)
        triage = self.triage(program_id=scan["program_id"], proposal_ids=scan["proposal_ids"], force=force)
        portfolio = self.portfolio(program_id=scan["program_id"], slots=portfolio_slots)
        return {"scan": scan, "triage": triage, "portfolio": portfolio,
            "automatic_promotion": False, "network_requests_sent": 0}

    def triage(self, *, program_id=None, proposal_ids=None, force=False):
        profile, approval = self._profile(program_id)
        wanted = set(proposal_ids) if proposal_ids is not None else None
        previous = self._latest("scout_triage")
        duplicates = self._latest("scout_dedup")
        results = []
        for proposal, _ in proposal_records(self.records, profile["program_id"]):
            if wanted is not None and proposal.proposal_id not in wanted:
                continue
            relation = duplicates.get(proposal.proposal_id, {}).get("payload", {})
            if relation.get("duplicate"):
                continue
            if not force and proposal.proposal_id in previous:
                results.append(previous[proposal.proposal_id]["payload"])
                continue
            result = self.triager.triage(proposal, profile)
            current = {"program_id": proposal.program_id, **result, "created_at": utcnow()}
            record = self.records.save("scout_triage", current)
            self.ledger.record_triage(record)
            results.append(current)
        counts = Counter(result["decision"] for result in results)
        return {"program_id": profile["program_id"], "triaged_count": len(results),
            "decisions": dict(sorted(counts.items())), "results": results,
            "model_calls": 0, "model_role": "deterministic_core"}

    def portfolio(self, *, program_id=None, slots=10, policy: PortfolioPolicy | None = None):
        if type(slots) is not int or not 1 <= slots <= 1000:
            raise Rejected("invalid_portfolio_slots")
        profile, _ = self._profile(program_id)
        latest_triage = self._latest("scout_triage")
        duplicates = self._latest("scout_dedup")
        promotions = self._latest("scout_promotion")
        items = []
        for proposal, _ in proposal_records(self.records, profile["program_id"]):
            if duplicates.get(proposal.proposal_id, {}).get("payload", {}).get("duplicate"):
                continue
            if proposal.proposal_id in promotions:
                continue
            triage_record = latest_triage.get(proposal.proposal_id)
            if triage_record:
                items.append((proposal, triage_record["payload"]))
        selector = ModelPortfolioSelector(policy or self.selector.policy,
            strategy=self.selector.strategy,
            reviewer=self.selector.reviewer if self.budget.max_model_calls else None)
        allowed_slots = min(slots, self.budget.max_promoted_candidates)
        if allowed_slots:
            result = selector.select(items, allowed_slots)
        else:
            result = {"proposal_count": len(items), "eligible_count": 0, "selected_count": 0,
                "members": [], "quotas": {}, "model_calls": 0,
                "model_role": "deterministic_core", "final_status": "EMPTY"}
        run_id = uuid4().hex
        route = ModelRouting.from_env()["PortfolioReviewer"]
        payload = {"run_id": run_id, "program_id": profile["program_id"], **result,
            "policy": asdict(selector.policy), "investigation_seconds": 0,
            "created_at": utcnow(), "automatic_promotion": False, "model_route": route,
            "model_estimated_cost": 0, "model_duration_ms": 0}
        record = self.records.save("scout_portfolio", payload)
        self.ledger.record_portfolio(record)
        return payload

    def _selected(self, proposal_id: str) -> bool:
        return any(any(member.get("proposal_id") == proposal_id for member in record["payload"].get("members", []))
                   for record in scout_events(self.records, "scout_portfolio"))

    def _existing_candidate(self, proposal_id: str):
        for record_id in self.records.list():
            record = self.records.read(record_id)
            if record["kind"] == "candidate" and record["payload"].get("proposal_id") == proposal_id:
                return record
        return None

    def _save_state(self, proposal: CandidateProposal, status: str, reason: str):
        record = self.records.save("scout_state", {"proposal_id": proposal.proposal_id,
            "program_id": proposal.program_id, "status": status, "reason": reason, "created_at": utcnow()})
        self.ledger.update_state(proposal.proposal_id, status)
        return record

    def promote(self, proposal_id: str) -> dict[str, Any]:
        started = time.monotonic()
        proposal, _ = self._proposal(proposal_id)
        # Promotion is tied to the currently active, still-approved exact profile revision.
        profile, approval = self._profile(proposal.program_id, active=True)
        reference = {"program_id": proposal.program_id, "approval_id": approval["approval_id"],
                     "sha256": approval["sha256"]}
        if proposal.program != reference:
            raise Rejected("proposal_program_approval_changed")
        decision = scope_decision(profile, proposal.asset, "GET")
        if not decision["allowed"]:
            self._save_state(proposal, "BLOCKED_SCOPE", decision.get("reason") or "scope_blocked")
            raise Rejected("proposal_asset_outside_program")
        if proposal.finding_category in profile["excluded_finding_categories"]:
            self._save_state(proposal, "REJECTED", "program_excluded")
            raise Rejected("proposal_program_excluded")
        relation = self._latest("scout_dedup").get(proposal_id, {}).get("payload", {})
        if relation.get("duplicate"):
            raise Rejected("duplicate_proposal_cannot_promote")
        triage = self._latest("scout_triage").get(proposal_id)
        if triage is None or triage["payload"].get("decision") != "ELIGIBLE" or \
                triage["payload"].get("triage_score", 0) < self.triager.policy.eligible_threshold:
            raise Rejected("eligible_triage_required")
        if not self._selected(proposal_id):
            raise Rejected("portfolio_selection_required")
        existing = self._existing_candidate(proposal_id)
        if existing is not None:
            previous = self._latest("scout_promotion").get(proposal_id)
            if previous is None:
                recovered = self.records.save("scout_promotion", {"proposal_id": proposal.proposal_id,
                    "program_id": proposal.program_id, "candidate_id": existing["id"],
                    "duration_ms": int((time.monotonic() - started) * 1000), "created_at": utcnow(),
                    "candidate_status": "DISCOVERED", "confirmed": False, "recovered_after_restart": True})
                self.ledger.record_promotion(recovered)
            return {"proposal_id": proposal_id, "candidate_id": existing["id"],
                    "status": "PROMOTED", "already_promoted": True}
        evidence_ids = []
        for record_id in dict.fromkeys(proposal.observation_ids + proposal.source_record_ids):
            record = self.records.read(record_id)
            if record["kind"] != "analysis":
                continue
            bound = record["payload"].get("program")
            if bound is not None and bound != reference:
                raise Rejected("candidate_evidence_program_mismatch")
            evidence_ids.append(record_id)
        if not evidence_ids:
            identity = "user_a" if "user_a" in proposal.identity_context and "user_a" in profile["identities"] else profile["identities"][0]
            request = ExperimentRequest(proposal_id=proposal.proposal_id, program_id=proposal.program_id,
                identity=identity, method="GET", url=proposal.asset,
                purpose="Collect the minimum missing observation for independent investigation.",
                expected_signal=proposal.missing_evidence, estimated_requests=max(1, proposal.estimated_requests)).to_dict()
            request_record = self.records.save("scout_experiment_request", request)
            self._save_state(proposal, "NEEDS_MORE_EVIDENCE", "analysis_evidence_required")
            return {"proposal_id": proposal_id, "status": "NEEDS_MORE_EVIDENCE",
                "experiment_request_record_id": request_record["id"], "authorization": False,
                "session_grant_required": True}
        candidate = self.records.candidate({"project": proposal.program_id, "title": proposal.title,
            "facts": proposal.observed_fact, "concerns": proposal.why_may_matter,
            "assumptions": "Scout output is a hypothesis derived from approved offline evidence, not a finding or authorization.",
            "counterarguments": "The observed structure can be intentional; independent verification must test the stated invariant.",
            "missing_evidence": proposal.missing_evidence, "review_status": "DISCOVERED",
            "remediation": "Determine remediation only after investigation and independent evidence-based verification.",
            "evidence_ids": evidence_ids[:20], "program_id": proposal.program_id,
            "asset": proposal.asset, "finding_category": proposal.finding_category,
            "proposal_id": proposal.proposal_id})
        promotion = self.records.save("scout_promotion", {"proposal_id": proposal.proposal_id,
            "program_id": proposal.program_id, "candidate_id": candidate["id"],
            "duration_ms": int((time.monotonic() - started) * 1000), "created_at": utcnow(),
            "candidate_status": "DISCOVERED", "confirmed": False})
        self.ledger.record_promotion(promotion)
        return {"proposal_id": proposal_id, "candidate_id": candidate["id"],
            "promotion_record_id": promotion["id"], "status": "PROMOTED",
            "candidate_status": "DISCOVERED", "confirmed": False}

    def status(self):
        rows = self.ledger.rows("proposals")
        return {"proposal_count": len(rows), "states": dict(sorted(Counter(
            row["final_status"] for row in rows).items())),
            "portfolio_runs": len(self.ledger.rows("portfolio_runs")),
            "promotions": len(self.ledger.rows("promotions")),
            "ledger_is_evidence_source": False, "immutable_records_are_authoritative": True,
            "ledger_recovered_from_corruption": self.ledger.recovered_corruption,
            "network_requests_sent": 0}

    def proposals(self, program_id=None, limit=100):
        if program_id is not None:
            from .programs import program_id as validate_program_id
            validate_program_id(program_id)
        if type(limit) is not int or not 1 <= limit <= 1000:
            raise Rejected("invalid_scout_proposal_limit")
        states = {row["proposal_id"]: row["final_status"] for row in self.ledger.rows("proposals", limit=1000)}
        values = []
        for proposal, record in proposal_records(self.records, program_id):
            values.append({"record_id": record["id"], **proposal.to_dict(),
                           "current_status": states.get(proposal.proposal_id, proposal.status)})
        return {"proposals": values[-limit:]}

    def proposal(self, proposal_id):
        proposal, record = self._proposal(proposal_id)
        return {"record_id": record["id"], "proposal": proposal.to_dict(),
            "dedup": [r["payload"] for r in scout_events(self.records, "scout_dedup") if r["payload"]["proposal_id"] == proposal_id],
            "triage": [r["payload"] for r in scout_events(self.records, "scout_triage") if r["payload"]["proposal_id"] == proposal_id],
            "promotion": [r["payload"] for r in scout_events(self.records, "scout_promotion") if r["payload"]["proposal_id"] == proposal_id]}

    def dedup_status(self):
        rows = self.ledger.rows("dedup_relations")
        return {"relations": rows, "duplicate_count": sum(row["duplicate_of"] is not None for row in rows)}

    def triage_status(self):
        rows = self.ledger.rows("triage_results")
        return {"results": rows, "decisions": dict(sorted(Counter(row["decision"] for row in rows).items()))}

    def portfolio_status(self):
        return {"runs": self.ledger.rows("portfolio_runs"), "members": self.ledger.rows("portfolio_members")}

    def doctor(self):
        profile = None
        try:
            profile, _ = self.programs.selected()
        except Rejected:
            pass
        return {"status": "ok", "active_program": profile["program_id"] if profile else None,
            "results_root_available": self.settings.results_root.is_dir(),
            "programs_root_available": self.settings.programs_root.is_dir(),
            "ledger_path": str(self.ledger.path), "ledger_is_evidence_source": False,
            "immutable_event_rebuild": True, "network_capability_in_scouts": False,
            "model_routing": ModelRouting.from_env(), "deterministic_fallback": True,
            "offline_budget": self.budget.__dict__}
