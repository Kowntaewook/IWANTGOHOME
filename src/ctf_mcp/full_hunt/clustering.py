"""Target-neutral root-cause grouping."""

from __future__ import annotations

from collections import defaultdict
from typing import Any, Callable


def cluster_outcomes(
    outcomes: list[dict[str, Any]],
    *,
    key_for: Callable[[dict[str, Any]], str],
    metadata_for: Callable[[str, list[dict[str, Any]]], dict[str, Any]],
    excluded: frozenset[str] = frozenset({
        "REJECTED_STATIC", "NEEDS_MANUAL_SCENARIO", "BLOCKED_BY_LOCAL_SETUP",
    }),
) -> list[dict[str, Any]]:
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for outcome in outcomes:
        if outcome["classification"] not in excluded:
            grouped[key_for(outcome)].append(outcome)
    clusters = []
    for key in sorted(grouped):
        items = grouped[key]
        metadata = metadata_for(key, items)
        clusters.append({
            "root_cause_id": metadata["root_cause_id"],
            "root_cause_key": key,
            "candidate_ids": [item["candidate_id"] for item in items],
            "classification": metadata["classification"],
            "metadata": metadata.get("metadata", {}),
            "outcomes": items,
        })
    return clusters
