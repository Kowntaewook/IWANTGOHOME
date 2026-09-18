"""Bounded offline Scout execution over immutable, sanitized records."""

from dataclasses import dataclass
import hashlib
import json
import os
import time
from typing import Any

from .config import Rejected
from .program_store import ProgramStore
from .perf import PerformanceMetrics
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
    max_model_calls_per_proposal: int = 1
    max_runtime_seconds: int = 30
    max_promoted_candidates: int = 10

    def __post_init__(self):
        ceilings = {"max_proposals_per_scout": 200, "max_proposals_per_run": 1000,
            "max_model_calls": 50, "max_model_calls_per_proposal": 10,
            "max_runtime_seconds": 300, "max_promoted_candidates": 100}
        for key, ceiling in ceilings.items():
            value = getattr(self, key)
            if type(value) is not int or not 0 <= value <= ceiling or key == "max_runtime_seconds" and value < 1:
                raise Rejected("invalid_offline_analysis_budget")

    @classmethod
    def from_env(cls):
        mapping = {
            "max_model_calls": "FINDER_MAX_MODEL_CALLS_PER_RUN",
            "max_model_calls_per_proposal": "FINDER_MAX_MODEL_CALLS_PER_PROPOSAL",
            "max_proposals_per_scout": "FINDER_MAX_PROPOSALS_PER_SCOUT",
            "max_proposals_per_run": "FINDER_MAX_PROPOSALS_PER_RUN",
            "max_runtime_seconds": "FINDER_SCOUT_MAX_RUNTIME_SECONDS",
            "max_promoted_candidates": "FINDER_MAX_PROMOTED_CANDIDATES",
        }
        values = {}
        for field, variable in mapping.items():
            raw = os.environ.get(variable)
            if raw is not None:
                try:
                    values[field] = int(raw)
                except ValueError:
                    raise Rejected("invalid_offline_analysis_budget") from None
        return cls(**values)


class ModelRouting:
    ROLES = {"Scout": ("SCOUT",), "CheapTriager": ("TRIAGE", "CHEAP_TRIAGER"),
        "PortfolioReviewer": ("PORTFOLIO", "PORTFOLIO_REVIEWER"),
        "Investigator": ("INVESTIGATOR",), "Verifier": ("VERIFIER",),
        "Reporter": ("REPORTER",)}
    DEFAULT_EFFORT = {"Scout": "medium", "CheapTriager": "low", "PortfolioReviewer": "high",
        "Investigator": "high", "Verifier": "high", "Reporter": "medium"}

    @classmethod
    def from_env(cls) -> dict[str, dict[str, str | None]]:
        result = {}
        for role, keys in cls.ROLES.items():
            model = next((os.environ.get("FINDER_MODEL_" + key) for key in keys
                          if os.environ.get("FINDER_MODEL_" + key)), None)
            model = model or os.environ.get("FINDER_MODEL_DEFAULT") or os.environ.get("FINDER_MODEL") or None
            effort = next((os.environ.get("FINDER_EFFORT_" + key) for key in keys
                           if os.environ.get("FINDER_EFFORT_" + key)), None) or cls.DEFAULT_EFFORT[role]
            if effort not in {None, "low", "medium", "high", "xhigh"}:
                raise Rejected("invalid_model_effort")
            result[role] = {"model": model, "effort": effort}
        return result


def cache_key(input_record_hash: str, scout_type: str, scout_version: str,
              program_policy_hash: str, relevant_config_hash: str) -> str:
    material = {"input_record_hash": input_record_hash, "scout_type": scout_type,
        "scout_version": scout_version, "program_policy_hash": program_policy_hash,
        "relevant_config_hash": relevant_config_hash}
    raw = json.dumps(material, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(raw).hexdigest()


def affected_scout_types(record: dict, previous: dict | None) -> set[str]:
    """Small explicit temporal dependency map with an all-scout safe fallback."""
    all_types = {scout.scout_type for scout in SCOUTS}
    if previous is None:
        return all_types
    if record.get("kind") == "session_comparison":
        return {"auth_tenant"}
    analyzer = record.get("payload", {}).get("analyzer")
    mapping = {
        "openapi": {"capability", "parser_boundary", "outbound_http", "hidden_api", "temporal_change"},
        "source_map": {"capability", "parser_boundary", "outbound_http", "hidden_api",
                       "browser_trust", "temporal_change"},
        "source": {"capability", "parser_boundary", "outbound_http", "hidden_api", "browser_trust"},
        "source_tree": {"capability", "parser_boundary", "outbound_http", "hidden_api", "browser_trust"},
        "har": {"capability", "parser_boundary", "outbound_http", "hidden_api", "temporal_change"},
        "http_log": {"capability", "parser_boundary", "outbound_http", "hidden_api", "temporal_change"},
    }
    return mapping.get(analyzer, all_types)


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
    def __init__(self, settings, *, budget: OfflineAnalysisBudget | None = None, scouts=None,
                 deduplicator=None, ledger=None, metrics: PerformanceMetrics | None = None):
        if settings.programs_root is None:
            raise Rejected("program_store_not_configured")
        self.settings = settings
        self.records = Records(settings.results_root, settings.limits, settings.programs_root)
        self.programs = ProgramStore(settings.programs_root)
        self.budget = budget or OfflineAnalysisBudget.from_env()
        self.scouts = tuple(cls() for cls in SCOUTS) if scouts is None else tuple(scouts)
        self.deduplicator = deduplicator or SemanticDeduplicator()
        self.metrics = metrics or PerformanceMetrics()
        self._owns_metrics = metrics is None
        self.ledger = ledger or ScoutLedger(settings.results_root, metrics=self.metrics)
        # A controller-supplied ledger was already synchronized. Avoid a second
        # complete evidence-index pass in the same orchestration run.
        if ledger is None:
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

    @staticmethod
    def _revision_key(record: dict) -> tuple[str, str]:
        return (record.get("kind", ""), str(record.get("payload", {}).get("analyzer", "")))

    def _previous_for(self, record: dict, history: list[dict]) -> dict | None:
        key = self._revision_key(record)
        bound = record.get("payload", {}).get("program")
        candidates = [item for item in history
            if (item["created_at"], item["id"]) < (record["created_at"], record["id"])
            and self._revision_key(item) == key
            and item.get("payload", {}).get("program") == bound]
        return candidates[-1] if candidates else None

    def _config_hash(self) -> str:
        material = {"cache_version": 2,
            "max_proposals_per_scout": self.budget.max_proposals_per_scout,
            "max_proposals_per_run": self.budget.max_proposals_per_run}
        return hashlib.sha256(json.dumps(material, sort_keys=True,
            separators=(",", ":")).encode()).hexdigest()

    def run(self, *, program_id: str | None = None, record_id: str | None = None,
            force: bool = False) -> dict[str, Any]:
        if type(force) is not bool:
            raise Rejected("invalid_force_flag")
        if self._owns_metrics:
            self.metrics.reset()
        started = time.monotonic()
        profile, reference = self._program(program_id)
        existing = [proposal for proposal, _ in proposal_records(self.records, profile["program_id"])]
        created: list[CandidateProposal] = []
        skipped_fresh = skipped_program = skipped_incremental = malformed = 0
        evaluated = 0
        by_scout = {scout.scout_type: 0 for scout in self.scouts}
        inputs = self._inputs(record_id)
        history_inputs = self._inputs(None) if record_id is not None else inputs
        previous_inputs: list[dict[str, Any]] = []
        config_hash = self._config_hash()
        cache_decisions = []
        index_batch = []
        self.metrics.add("records_scanned", len(inputs))
        for record in inputs:
            if time.monotonic() - started >= self.budget.max_runtime_seconds:
                break
            bound = record.get("payload", {}).get("program")
            if bound is not None and bound != reference:
                if record_id is not None:
                    raise Rejected("scout_record_program_mismatch")
                skipped_program += 1
                self.metrics.add("records_skipped")
                continue
            history = history_inputs if record_id is not None else previous_inputs
            previous = self._previous_for(record, history)
            compatible_previous = (previous,) if previous is not None else ()
            context = ScoutContext(profile, reference, record, compatible_previous)
            digest = record_hash(record)
            affected = affected_scout_types(record, previous)
            for scout in self.scouts:
                if len(created) >= self.budget.max_proposals_per_run or time.monotonic() - started >= self.budget.max_runtime_seconds:
                    break
                if by_scout[scout.scout_type] >= self.budget.max_proposals_per_scout:
                    continue
                if scout.scout_type not in affected:
                    skipped_incremental += 1
                    self.metrics.add("records_skipped")
                    cache_decisions.append({"input_record_id": record["id"],
                        "scout_type": scout.scout_type, "decision": "not_affected"})
                    continue
                key = cache_key(digest, scout.scout_type, scout.version,
                                reference["sha256"], config_hash)
                if not force and self.ledger.was_evaluated(digest, scout.scout_type, scout.version,
                        reference["sha256"], config_hash):
                    skipped_fresh += 1
                    self.metrics.add("cache_hits")
                    self.metrics.add("records_skipped")
                    cache_decisions.append({"input_record_id": record["id"],
                        "scout_type": scout.scout_type, "decision": "cache_hit",
                        "cache_key": key})
                    continue
                self.metrics.add("cache_misses")
                self.metrics.add("records_reanalyzed")
                cache_decisions.append({"input_record_id": record["id"],
                    "scout_type": scout.scout_type,
                    "decision": "force_bypass" if force else "cache_miss", "cache_key": key})
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
                    index_batch.append(proposal_record)
                    with self.metrics.stage("dedup_runtime_ms"):
                        relation = self.deduplicator.find(proposal, existing)
                    relation_record = self.records.save("scout_dedup", {
                        **relation, "program_id": proposal.program_id, "created_at": utcnow()})
                    index_batch.append(relation_record)
                    existing.append(proposal)
                    created.append(proposal)
                    self.metrics.add("proposals_created")
                    if relation["duplicate"]:
                        self.metrics.add("proposals_deduped")
                    by_scout[scout.scout_type] += 1
                evaluation = self.records.save("scout_evaluation", {
                    "input_record_id": record["id"], "input_record_hash": digest,
                    "program_id": profile["program_id"],
                    "analyzer_version": record.get("analyzer_version", "unknown"),
                    "scout_type": scout.scout_type, "scout_version": scout.version,
                    "program_policy_hash": reference["sha256"],
                    "relevant_config_hash": config_hash, "cache_key": key,
                    "last_evaluated_at": utcnow(), "proposal_count": len(proposals)})
                index_batch.append(evaluation)
                evaluated += 1
            previous_inputs.append(record)
        self.ledger.record_batch(index_batch)
        duration_ms = (time.monotonic() - started) * 1000
        self.metrics.add("scout_runtime_ms", duration_ms)
        result = {"program_id": profile["program_id"], "proposal_count": len(created),
            "proposal_ids": [proposal.proposal_id for proposal in created], "by_scout": by_scout,
            "records_evaluated": evaluated, "freshness_skips": skipped_fresh,
            "cache_hits": skipped_fresh, "cache_misses": evaluated,
            "incremental_scout_skips": skipped_incremental,
            "cache_decisions": cache_decisions[:200],
            "program_mismatch_skips": skipped_program, "malformed_inputs": malformed,
            "duration_ms": int(duration_ms),
            "network_requests_sent": 0, "model_calls": 0,
            "budget": self.budget.__dict__}
        result["performance"] = self.metrics.snapshot()
        return result
