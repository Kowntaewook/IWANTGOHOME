"""Configurable exploration/exploitation portfolio selection."""

from dataclasses import dataclass
import math
import os
import random
from typing import Callable

from .config import Rejected
from .scouts.base import CandidateProposal


class ExpectedValueStrategy:
    def score(self, proposal: CandidateProposal, triage: dict) -> float:
        cost = max(float(triage["estimated_cost"]), 0.05)
        confidence = float(triage.get("calibrated_confidence", proposal.confidence))
        return proposal.estimated_impact * confidence * proposal.novelty / cost


@dataclass(frozen=True)
class PortfolioPolicy:
    highest_ev_ratio: float = 0.60
    high_impact_low_confidence_ratio: float = 0.20
    novel_ratio: float = 0.10
    exploration_ratio: float = 0.10
    max_per_asset_category: int = 2
    per_program_cap: int | None = None
    seed: int = 0

    @classmethod
    def from_env(cls):
        values = {}
        mapping = {"highest_ev_ratio": "HIGHEST_EV_RATIO",
            "high_impact_low_confidence_ratio": "HIGH_IMPACT_LOW_CONFIDENCE_RATIO",
            "novel_ratio": "NOVEL_RATIO", "exploration_ratio": "EXPLORATION_RATIO"}
        for field, suffix in mapping.items():
            raw = os.environ.get("FINDER_SCOUT_" + suffix)
            if raw is not None:
                try: values[field] = float(raw)
                except ValueError: raise Rejected("invalid_portfolio_ratios") from None
        for field, suffix in (("max_per_asset_category", "MAX_PER_ASSET_CATEGORY"),
                              ("per_program_cap", "PER_PROGRAM_CAP"), ("seed", "SEED")):
            raw = os.environ.get("FINDER_SCOUT_" + suffix)
            if raw is not None:
                try: values[field] = int(raw)
                except ValueError: raise Rejected("invalid_portfolio_configuration") from None
        return cls(**values)

    def __post_init__(self):
        ratios = (self.highest_ev_ratio, self.high_impact_low_confidence_ratio,
                  self.novel_ratio, self.exploration_ratio)
        if any(isinstance(v, bool) or not isinstance(v, (int, float)) or v < 0 for v in ratios):
            raise Rejected("invalid_portfolio_ratios")
        if abs(sum(ratios) - 1.0) > 1e-9:
            raise Rejected("portfolio_ratios_must_sum_to_one")
        if type(self.max_per_asset_category) is not int or self.max_per_asset_category < 1:
            raise Rejected("invalid_portfolio_diversity_limit")
        if self.per_program_cap is not None and (type(self.per_program_cap) is not int or self.per_program_cap < 1):
            raise Rejected("invalid_portfolio_program_cap")


class ModelPortfolioSelector:
    """Deterministic selector with an optional bounded reviewer supplied by the Codex backend."""

    def __init__(self, policy: PortfolioPolicy = PortfolioPolicy(), strategy=None,
                 reviewer: Callable[[list[dict]], list[str]] | None = None):
        self.policy = policy
        self.strategy = strategy or ExpectedValueStrategy()
        self.reviewer = reviewer

    def _quotas(self, slots: int) -> dict[str, int]:
        ratios = {"highest_ev": self.policy.highest_ev_ratio,
            "high_impact_low_confidence": self.policy.high_impact_low_confidence_ratio,
            "novel": self.policy.novel_ratio, "exploration": self.policy.exploration_ratio}
        raw = {name: slots * ratio for name, ratio in ratios.items()}
        quotas = {name: math.floor(value) for name, value in raw.items()}
        for name in sorted(raw, key=lambda key: (raw[key] - quotas[key], ratios[key], key), reverse=True)[:slots - sum(quotas.values())]:
            quotas[name] += 1
        return quotas

    def select(self, items: list[tuple[CandidateProposal, dict]], slots: int) -> dict:
        if type(slots) is not int or not 1 <= slots <= 1000:
            raise Rejected("invalid_portfolio_slots")
        eligible = [(p, t) for p, t in items if t.get("decision") == "ELIGIBLE"]
        rng = random.Random(self.policy.seed)
        random_order = list(eligible)
        rng.shuffle(random_order)
        stages = {
            "highest_ev": sorted(eligible, key=lambda item: (-self.strategy.score(*item), item[0].proposal_id)),
            "high_impact_low_confidence": sorted(eligible,
                key=lambda item: (-(item[0].estimated_impact *
                    (1.0 - float(item[1].get("calibrated_confidence", item[0].confidence)))),
                    -item[0].estimated_impact,
                    float(item[1].get("calibrated_confidence", item[0].confidence)), item[0].proposal_id)),
            "novel": sorted(eligible, key=lambda item: (-item[0].novelty, item[0].proposal_id)),
            "exploration": random_order,
        }
        selected: list[tuple[CandidateProposal, dict, str]] = []
        chosen: set[str] = set()
        diversity: dict[tuple[str, str], int] = {}
        programs: dict[str, int] = {}
        categories: set[str] = set()

        def add(item, reason):
            proposal, triage = item
            key = (proposal.asset, proposal.finding_category)
            if proposal.proposal_id in chosen or diversity.get(key, 0) >= self.policy.max_per_asset_category:
                return False
            if self.policy.per_program_cap is not None and programs.get(proposal.program_id, 0) >= self.policy.per_program_cap:
                return False
            chosen.add(proposal.proposal_id)
            diversity[key] = diversity.get(key, 0) + 1
            programs[proposal.program_id] = programs.get(proposal.program_id, 0) + 1
            categories.add(proposal.finding_category)
            selected.append((proposal, triage, reason))
            return True

        quotas = self._quotas(min(slots, len(eligible)))
        for reason in ("highest_ev", "high_impact_low_confidence", "novel", "exploration"):
            filled = 0
            for item in stages[reason]:
                if reason == "novel" and item[0].finding_category in categories:
                    continue
                if add(item, reason):
                    filled += 1
                    if filled >= quotas[reason]:
                        break
        for item in stages["highest_ev"]:
            if len(selected) >= slots:
                break
            add(item, "diversity_fallback")

        model_calls = 0
        model_failures = 0
        if self.reviewer is not None and selected:
            try:
                # Only minimized scores/hypotheses are supplied; reviewer output cannot authorize or promote.
                proposed = [{"proposal_id": p.proposal_id, "hypothesis": p.why_may_matter,
                             "expected_value": round(self.strategy.score(p, t), 6)} for p, t, _ in selected]
                order = self.reviewer(proposed)
                rank = {value: index for index, value in enumerate(order) if value in chosen}
                selected.sort(key=lambda item: rank.get(item[0].proposal_id, len(rank)))
                model_calls = 1
            except Exception:
                model_calls = 1
                model_failures = 1
        members = [{"proposal_id": p.proposal_id, "program_id": p.program_id,
            "selection_reason": reason, "expected_value": round(self.strategy.score(p, t), 6),
            "estimated_cost": t["estimated_cost"]} for p, t, reason in selected]
        return {"proposal_count": len(items), "eligible_count": len(eligible),
            "selected_count": len(members), "members": members, "quotas": quotas,
            "model_calls": model_calls, "model_role": "PortfolioReviewer" if model_calls else "deterministic_core",
            "model_failures": model_failures,
            "final_status": "SELECTED" if members else "EMPTY"}
