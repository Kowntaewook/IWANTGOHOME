"""Target-neutral duplicate research decision engine."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Iterable

from ctf_mcp.local_targets.base import LocalTargetError


SOURCE_STATUSES = frozenset({"ok", "empty", "unavailable", "error"})


@dataclass(frozen=True)
class DuplicateResearchPolicy:
    sources: tuple[str, ...]
    core_sources: tuple[str, ...]
    minimum_core_coverage: int

    def __post_init__(self) -> None:
        if (not self.sources or not self.core_sources
                or not set(self.core_sources) <= set(self.sources)
                or self.minimum_core_coverage < 1
                or self.minimum_core_coverage > len(self.core_sources)):
            raise LocalTargetError("invalid_duplicate_research_policy")


def evaluate_duplicate_research(
    *,
    candidate_id: str,
    terms: list[str],
    policy: DuplicateResearchPolicy,
    records: Iterable[dict[str, Any]],
    source_statuses: dict[str, str],
    known_exact: Iterable[dict[str, Any]] = (),
    known_possible: Iterable[dict[str, Any]] = (),
    match_strength: Callable[[dict[str, Any]], str | None],
    sanitize_match: Callable[[dict[str, Any], list[str]], dict[str, Any]],
    deduplicate: Callable[[list[dict[str, Any]]], list[dict[str, Any]]],
) -> dict[str, Any]:
    statuses = {
        source: (
            source_statuses.get(source)
            if source_statuses.get(source) in SOURCE_STATUSES
            else "error"
        )
        for source in policy.sources
    }
    checked = [
        source for source in policy.core_sources if statuses[source] in {"ok", "empty"}
    ]
    coverage_met = len(checked) >= policy.minimum_core_coverage
    unavailable = [
        source for source in policy.sources if statuses[source] in {"unavailable", "error"}
    ]
    exact = list(known_exact)
    possible = list(known_possible)
    for record in records:
        strength = match_strength(record)
        if strength == "exact":
            exact.append(sanitize_match(record, ["exact_endpoint", "shared_query_path"]))
        elif strength == "possible":
            possible.append(sanitize_match(record, ["shared_query_path", "semantic_overlap"]))
    matches = deduplicate(exact + possible)
    if exact:
        status, confidence = "KNOWN_DUPLICATE", "high"
        reasoning = ["public_record_matches_endpoint_and_query_path"]
    elif possible:
        status, confidence = "POSSIBLE_DUPLICATE", "medium"
        reasoning = ["public_record_shares_query_path_but_not_all_invariants"]
    elif coverage_met:
        status, confidence = "NO_PUBLIC_DUPLICATE_FOUND", "low"
        reasoning = ["no_endpoint_and_query_path_match_in_checked_core_sources"]
        if unavailable:
            reasoning.append("research_incomplete_but_minimum_core_coverage_met")
    else:
        status, confidence = "DUPLICATE_CHECK_BLOCKED", "none"
        reasoning = ["minimum_core_duplicate_research_coverage_not_met"]
    return {
        "candidate_id": candidate_id,
        "duplicate_status": status,
        "possible_matches": matches,
        "searched_terms": terms,
        "searched_sources": list(policy.sources),
        "source_statuses": statuses,
        "unavailable_sources": unavailable,
        "research_incomplete": bool(unavailable),
        "core_sources_checked": checked,
        "minimum_core_source_coverage": policy.minimum_core_coverage,
        "core_coverage_met": coverage_met,
        "reasoning_facts": reasoning,
        "confidence": confidence,
        "no_public_match_is_not_novelty_confirmation": True,
    }
