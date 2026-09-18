"""Scout orchestration and guarded promotion into the existing candidate lifecycle."""

from collections import Counter
from dataclasses import asdict
import hashlib
import json
import time
from typing import Any
from uuid import uuid4

from .config import Rejected
from .program_store import ProgramStore
from .programs import scope_decision
from .perf import PerformanceMetrics, performance_summary
from .records import Records, valid_id
from .scout_ledger import ScoutLedger
from .scout_experiments import MinimalExperimentPlanner
from .scout_feedback import ScoutOutcomeFeedback
from .scout_graph import EvidenceGraphBuilder
from .scout_pipeline import (ModelRouting, OfflineAnalysisBudget, ScoutPipeline,
                             proposal_records, scout_events)
from .scout_portfolio import ModelPortfolioSelector, PortfolioPolicy
from .scout_triage import CheapTriager, TriagePolicy
from .scouts.base import CandidateProposal, utcnow


class ScoutPortfolioController:
    def __init__(self, settings, *, budget: OfflineAnalysisBudget | None = None,
                 triager=None, selector=None, ledger=None, feedback=None, graph=None, planner=None,
                 metrics: PerformanceMetrics | None = None):
        if settings.programs_root is None:
            raise Rejected("program_store_not_configured")
        self.settings = settings
        self.records = Records(settings.results_root, settings.limits, settings.programs_root)
        self.programs = ProgramStore(settings.programs_root)
        self.budget = budget or OfflineAnalysisBudget.from_env()
        self.metrics = metrics or PerformanceMetrics()
        self.triager = triager or CheapTriager()
        self.selector = selector or ModelPortfolioSelector(PortfolioPolicy.from_env())
        self.ledger = ledger or ScoutLedger(settings.results_root, metrics=self.metrics)
        self.ledger.sync(self.records)
        self.feedback = feedback or ScoutOutcomeFeedback(self.records, self.ledger)
        self.graph = graph or EvidenceGraphBuilder(self.records, self.ledger)
        self.planner = planner or MinimalExperimentPlanner()

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
        self.metrics.reset()
        total_started = time.perf_counter_ns()
        pipeline = ScoutPipeline(self.settings, budget=self.budget, ledger=self.ledger,
                                 metrics=self.metrics)
        scan = pipeline.run(program_id=program_id, record_id=record_id, force=force)
        with self.metrics.stage("feedback_runtime_ms"):
            feedback = self.feedback.reconcile(scan["program_id"])
        with self.metrics.stage("graph_runtime_ms"):
            graph = self.graph.refresh(scan["program_id"])
        triage = self.triage(program_id=scan["program_id"], proposal_ids=scan["proposal_ids"],
                             force=force, _prepared=True)
        portfolio = self.portfolio(program_id=scan["program_id"], slots=portfolio_slots, force=force)
        self.metrics.add("total_runtime_ms", (time.perf_counter_ns() - total_started) / 1_000_000)
        metrics = self.metrics.snapshot()
        performance = self.records.save("scout_performance", {
            "program_id": scan["program_id"], "performance_version": "1",
            "metrics": metrics, "summary": performance_summary(metrics), "created_at": utcnow()})
        self.ledger.record_performance(performance)
        return {"scan": scan, "feedback": feedback, "graph": {
                    "record_id": graph["record_id"], "node_count": graph["node_count"],
                    "edge_count": graph["edge_count"], "freshness_skip": graph["freshness_skip"]},
            "triage": triage, "portfolio": portfolio,
            "performance": {"record_id": performance["id"], **performance["payload"]},
            "automatic_promotion": False, "network_requests_sent": 0}

    def triage(self, *, program_id=None, proposal_ids=None, force=False, _prepared=False):
        started = time.perf_counter_ns()
        profile, approval = self._profile(program_id)
        if not _prepared:
            self.feedback.reconcile(profile["program_id"])
        all_proposals = [p for p, _ in proposal_records(self.records, profile["program_id"])]
        if not _prepared:
            self.graph.refresh(profile["program_id"])
        wanted = set(proposal_ids) if proposal_ids is not None else None
        previous = self._latest("scout_triage")
        duplicates = self._latest("scout_dedup")
        results = []
        index_batch = []
        for proposal, _ in proposal_records(self.records, profile["program_id"]):
            if wanted is not None and proposal.proposal_id not in wanted:
                continue
            relation = duplicates.get(proposal.proposal_id, {}).get("payload", {})
            if relation.get("duplicate"):
                continue
            support = self.graph.support(proposal, all_proposals)
            calibration = self.feedback.calibration(proposal)
            old = previous.get(proposal.proposal_id, {}).get("payload", {})
            unchanged_inputs = (old.get("graph_support") == support and
                                old.get("outcome_calibration") == calibration)
            if not force and proposal.proposal_id in previous and unchanged_inputs:
                results.append(previous[proposal.proposal_id]["payload"])
                continue
            result = self.triager.triage(proposal, profile,
                graph_support=support, feedback=calibration)
            current = {"program_id": proposal.program_id, **result, "created_at": utcnow()}
            record = self.records.save("scout_triage", current)
            index_batch.append(record)
            self.metrics.add("proposals_triaged")
            results.append(current)
        self.ledger.record_batch(index_batch)
        counts = Counter(result["decision"] for result in results)
        self.metrics.add("triage_runtime_ms", (time.perf_counter_ns() - started) / 1_000_000)
        return {"program_id": profile["program_id"], "triaged_count": len(results),
            "decisions": dict(sorted(counts.items())), "results": results,
            "model_calls": 0, "model_role": "deterministic_core"}

    def portfolio(self, *, program_id=None, slots=10, policy: PortfolioPolicy | None = None,
                  force=False):
        started = time.perf_counter_ns()
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
            reviewer=self.selector.reviewer if self.budget.max_model_calls and
                self.budget.max_model_calls_per_proposal else None)
        allowed_slots = min(slots, self.budget.max_promoted_candidates)
        route = ModelRouting.from_env()["PortfolioReviewer"]
        fingerprint_material = {
            "prompt_version": "portfolio-review-v1", "slots": allowed_slots,
            "policy": asdict(selector.policy), "model_route": route,
            "items": [{"proposal_id": proposal.proposal_id,
                "decision": triage.get("decision"), "triage_score": triage.get("triage_score"),
                "expected_value": triage.get("expected_value"),
                "calibrated_confidence": triage.get("calibrated_confidence")}
                for proposal, triage in items],
        }
        input_fingerprint = hashlib.sha256(json.dumps(fingerprint_material, sort_keys=True,
            separators=(",", ":")).encode()).hexdigest()
        prior = scout_events(self.records, "scout_portfolio", profile["program_id"])
        if not force and prior and prior[-1]["payload"].get("input_fingerprint") == input_fingerprint:
            self.metrics.add("cache_hits")
            self.metrics.add("portfolio_runtime_ms", (time.perf_counter_ns() - started) / 1_000_000)
            return {**prior[-1]["payload"], "record_id": prior[-1]["id"], "cache_hit": True,
                    "model_calls_this_run": 0}
        if allowed_slots:
            result = selector.select(items, allowed_slots)
        else:
            result = {"proposal_count": len(items), "eligible_count": 0, "selected_count": 0,
                "members": [], "quotas": {}, "model_calls": 0,
                "model_role": "deterministic_core", "model_failures": 0, "final_status": "EMPTY"}
        run_id = uuid4().hex
        payload = {"run_id": run_id, "program_id": profile["program_id"], **result,
            "policy": asdict(selector.policy), "investigation_seconds": 0,
            "created_at": utcnow(), "automatic_promotion": False, "model_route": route,
            "model_estimated_cost": 0, "model_duration_ms": 0,
            "input_fingerprint": input_fingerprint, "prompt_version": "portfolio-review-v1",
            "cache_hit": False, "model_calls_this_run": result["model_calls"]}
        record = self.records.save("scout_portfolio", payload)
        self.ledger.record_portfolio(record)
        self.metrics.add("proposals_selected", result["selected_count"])
        self.metrics.add("model_calls", min(result["model_calls"], self.budget.max_model_calls))
        self.metrics.add("model_failures", result.get("model_failures", 0))
        if result["model_calls"]:
            self.metrics.model_route("PortfolioReviewer", route.get("effort"))
        self.metrics.add("portfolio_runtime_ms", (time.perf_counter_ns() - started) / 1_000_000)
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

    def plan_experiment(self, proposal_id: str) -> dict[str, Any]:
        proposal, _ = self._proposal(proposal_id)
        profile, approval = self._profile(proposal.program_id, active=True)
        reference = {"program_id": proposal.program_id, "approval_id": approval["approval_id"],
                     "sha256": approval["sha256"]}
        if self._latest("scout_dedup").get(proposal_id, {}).get("payload", {}).get("duplicate"):
            raise Rejected("duplicate_proposal_cannot_plan_experiment")
        plan = self.planner.plan(proposal, profile, reference)
        for record in scout_events(self.records, "scout_experiment_plan", proposal.program_id):
            if record["payload"].get("plan_fingerprint") == plan["plan_fingerprint"]:
                requests = [{**item, "authorization": False}
                            for item in record["payload"].get("requests", [])]
                return {**record["payload"], "requests": requests, "authorization": False,
                        "record_id": record["id"], "already_planned": True}
        saved = self.records.save("scout_experiment_plan", plan)
        self.ledger.record_experiment_plan(saved)
        return {**plan, "record_id": saved["id"], "already_planned": False}

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
            plan = self.plan_experiment(proposal_id)
            self._save_state(proposal, "NEEDS_MORE_EVIDENCE", "analysis_evidence_required")
            return {"proposal_id": proposal_id, "status": "NEEDS_MORE_EVIDENCE",
                "experiment_plan_record_id": plan["record_id"], "estimated_requests": plan["estimated_requests"],
                "authorization": False,
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
        self.metrics.add("candidate_promotions")
        return {"proposal_id": proposal_id, "candidate_id": candidate["id"],
            "promotion_record_id": promotion["id"], "status": "PROMOTED",
            "candidate_status": "DISCOVERED", "confirmed": False}

    def status(self):
        rows = self.ledger.rows("proposals")
        return {"proposal_count": len(rows), "states": dict(sorted(Counter(
            row["final_status"] for row in rows).items())),
            "portfolio_runs": len(self.ledger.rows("portfolio_runs")),
            "promotions": len(self.ledger.rows("promotions")),
            "outcomes": len(self.ledger.rows("outcomes")),
            "graph_snapshots": len(self.ledger.rows("graph_snapshots")),
            "performance_runs": len(self.ledger.rows("performance_runs")),
            "experiment_plans": len(self.ledger.rows("experiment_plans")),
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
            "promotion": [r["payload"] for r in scout_events(self.records, "scout_promotion") if r["payload"]["proposal_id"] == proposal_id],
            "outcomes": [r["payload"] for r in scout_events(self.records, "scout_outcome") if r["payload"]["proposal_id"] == proposal_id],
            "experiment_plans": [r["payload"] for r in scout_events(self.records, "scout_experiment_plan") if r["payload"]["proposal_id"] == proposal_id],
            "evidence_graph": self.graph.neighborhood(proposal_id)}

    def dedup_status(self):
        rows = self.ledger.rows("dedup_relations")
        return {"relations": rows, "duplicate_count": sum(row["duplicate_of"] is not None for row in rows)}

    def triage_status(self):
        rows = self.ledger.rows("triage_results")
        return {"results": rows, "decisions": dict(sorted(Counter(row["decision"] for row in rows).items()))}

    def portfolio_status(self):
        return {"runs": self.ledger.rows("portfolio_runs"), "members": self.ledger.rows("portfolio_members")}

    def feedback_status(self, program_id=None):
        return self.feedback.status(program_id)

    def reconcile_feedback(self, program_id=None):
        profile, _ = self._profile(program_id)
        result = self.feedback.reconcile(profile["program_id"])
        return {**result, "status": self.feedback.status(profile["program_id"])}

    def graph_status(self, program_id=None, proposal_id=None):
        if proposal_id is not None:
            valid_id(proposal_id)
            return self.graph.neighborhood(proposal_id)
        values = [r for r in scout_events(self.records, "scout_graph", program_id)]
        return {"snapshots": [{"record_id": r["id"], **{k: r["payload"][k] for k in
            ("program_id", "graph_version", "source_hash", "node_count", "edge_count", "created_at")}}
            for r in values[-100:]], "contains_raw_source_payloads": False}

    def experiment_status(self, proposal_id=None):
        if proposal_id is not None:
            valid_id(proposal_id)
        values = [r for r in scout_events(self.records, "scout_experiment_plan")
                  if proposal_id is None or r["payload"].get("proposal_id") == proposal_id]
        return {"plans": [{"record_id": r["id"], **r["payload"],
                            "requests": [{**item, "authorization": False}
                                         for item in r["payload"].get("requests", [])],
                            "authorization": False}
                          for r in values[-100:]],
                "authorization": False, "network_requests_sent": 0}

    def explain(self, proposal_id: str):
        proposal, _ = self._proposal(proposal_id)
        exact_approval = scope_valid = category_allowed = False
        scope_reason = approval_reason = None
        reference = None
        try:
            profile, approval = self._profile(proposal.program_id, active=True)
            reference = {"program_id": proposal.program_id, "approval_id": approval["approval_id"],
                         "sha256": approval["sha256"]}
            exact_approval = proposal.program == reference
            decision = scope_decision(profile, proposal.asset, "GET")
            scope_valid, scope_reason = decision["allowed"], decision.get("reason")
            category_allowed = proposal.finding_category not in profile["excluded_finding_categories"]
        except Rejected as exc:
            approval_reason = str(exc)
        dedup = self._latest("scout_dedup").get(proposal_id, {}).get("payload", {})
        triage = self._latest("scout_triage").get(proposal_id, {}).get("payload", {})
        evaluations = [record["payload"] for record in scout_events(self.records, "scout_evaluation")
            if record["payload"].get("scout_type") == proposal.scout_type and
            record["payload"].get("input_record_id") in set(proposal.source_record_ids + proposal.observation_ids)]
        evidence_count = 0
        for record_id in dict.fromkeys(proposal.observation_ids + proposal.source_record_ids):
            try:
                record = self.records.read(record_id)
                bound = record.get("payload", {}).get("program")
                evidence_count += record["kind"] == "analysis" and reference is not None and \
                    (bound is None or bound == reference)
            except Rejected: pass
        gates = {"active_exact_approval": exact_approval, "scope_valid": scope_valid,
            "category_allowed": category_allowed, "not_duplicate": not dedup.get("duplicate", False),
            "triage_eligible": triage.get("decision") == "ELIGIBLE",
            "portfolio_selected": self._selected(proposal_id), "analysis_evidence_present": evidence_count > 0}
        return {"proposal_id": proposal_id, "why_created": proposal.observed_fact,
            "why_it_may_matter": proposal.why_may_matter, "missing_evidence": proposal.missing_evidence,
            "gates": gates, "promotion_ready": all(gates.values()),
            "approval_reason": approval_reason, "scope_reason": scope_reason,
            "triage_decision": triage.get("decision"), "dedup_reason": dedup.get("reason"),
            "cache": ({"eligible": True, "cache_key": evaluations[-1].get("cache_key"),
                       "input_record_hash": evaluations[-1].get("input_record_hash"),
                       "scout_version": evaluations[-1].get("scout_version"),
                       "program_policy_hash": evaluations[-1].get("program_policy_hash"),
                       "relevant_config_hash": evaluations[-1].get("relevant_config_hash")}
                      if evaluations else {"eligible": False, "reason": "evaluation_record_unavailable"}),
            "model_output_is_authorization": False}

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
            "offline_budget": self.budget.__dict__, "outcome_feedback_version": self.feedback.version,
            "evidence_graph_version": self.graph.version,
            "experiment_planner_version": self.planner.version}
