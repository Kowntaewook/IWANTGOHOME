"""Minimized structural graph over immutable Scout records."""

import hashlib
import json
from typing import Any
from urllib.parse import urlsplit

from .config import Rejected
from .scout_pipeline import proposal_records, scout_events
from .scouts.base import CandidateProposal, utcnow


def _digest(kind: str, value: str) -> str:
    return kind + ":" + hashlib.sha256(value.encode()).hexdigest()[:24]


def _origin_path(asset: str) -> str:
    if "://" not in asset:
        return asset.split("?", 1)[0]
    value = urlsplit(asset)
    return value.scheme.lower() + "://" + (value.netloc or "").lower() + (value.path or "/")


class EvidenceGraphBuilder:
    """Build correlations without copying source payloads or credential-shaped values."""

    version = "1"

    def __init__(self, records, ledger, *, max_nodes: int = 600, max_edges: int = 1500):
        self.records, self.ledger = records, ledger
        self.max_nodes, self.max_edges = max_nodes, max_edges

    def _material(self, program_id: str) -> tuple[list[CandidateProposal], str]:
        proposals = [p for p, _ in proposal_records(self.records, program_id)]
        material = [{"proposal_id": p.proposal_id, "asset": _origin_path(p.asset),
                     "category": p.finding_category, "invariant": p.invariant,
                     "sources": sorted(set(p.source_record_ids + p.observation_ids))}
                    for p in proposals]
        digest = hashlib.sha256(json.dumps(material, sort_keys=True, ensure_ascii=True).encode()).hexdigest()
        return proposals, digest

    def _compatible_record_ids(self, proposal: CandidateProposal) -> tuple[set[str], int, set[str]]:
        compatible, mismatches, artifact_kinds = set(), 0, set()
        for record_id in set(proposal.source_record_ids + proposal.observation_ids):
            try:
                record = self.records.read(record_id)
            except (Rejected, OSError, ValueError):
                mismatches += 1
                continue
            if record.get("kind") not in {"analysis", "session_comparison"}:
                mismatches += 1
                continue
            bound = record.get("payload", {}).get("program")
            if bound is not None and bound != proposal.program:
                mismatches += 1
                continue
            compatible.add(record_id)
            artifact_kinds.add(str(record.get("payload", {}).get("analyzer", record["kind"]))[:128])
        return compatible, mismatches, artifact_kinds

    def support(self, proposal: CandidateProposal, proposals: list[CandidateProposal] | None = None) -> dict[str, Any]:
        proposals = proposals if proposals is not None else [p for p, _ in proposal_records(self.records, proposal.program_id)]
        referenced_records = set(proposal.source_record_ids + proposal.observation_ids)
        own_records, mismatch_count, artifact_kinds = self._compatible_record_ids(proposal)
        correlated = []
        normalized = _origin_path(proposal.asset)
        for other in proposals:
            if other.proposal_id == proposal.proposal_id or other.program_id != proposal.program_id:
                continue
            same_structure = (_origin_path(other.asset) == normalized and
                              (other.finding_category == proposal.finding_category or other.invariant == proposal.invariant))
            other_records, _, _ = self._compatible_record_ids(other)
            if same_structure and other_records - own_records:
                correlated.append(other.proposal_id)
        return {"referenced_record_count": len(referenced_records),
                "independent_record_count": len(own_records), "program_mismatch_or_missing_count": mismatch_count,
                "artifact_kinds": sorted(artifact_kinds)[:20],
                "artifact_kind_count": len(artifact_kinds), "corroborating_proposal_ids": sorted(correlated)[:20],
                "corroborating_proposal_count": len(correlated),
                "cross_artifact": len(artifact_kinds) > 1 or bool(correlated)}

    def refresh(self, program_id: str) -> dict[str, Any]:
        proposals, source_hash = self._material(program_id)
        prior = scout_events(self.records, "scout_graph", program_id)
        if prior and prior[-1]["payload"].get("source_hash") == source_hash and \
                prior[-1]["payload"].get("graph_version") == self.version:
            return {**prior[-1]["payload"], "record_id": prior[-1]["id"], "freshness_skip": True}
        nodes: dict[str, dict] = {}
        edges: set[tuple[str, str, str]] = set()
        truncated = False
        pending = proposals
        incremental_update = False
        if prior and prior[-1]["payload"].get("graph_version") == self.version:
            previous = prior[-1]["payload"]
            try:
                previous_ids = {item["label"] for item in previous.get("nodes", [])
                                if item.get("type") == "proposal"}
                current_ids = {proposal.proposal_id for proposal in proposals}
                if previous_ids <= current_ids and previous.get("proposals_considered") == len(previous_ids):
                    nodes = {item["id"]: item for item in previous.get("nodes", [])}
                    edges = {(item["source"], item["relation"], item["target"])
                             for item in previous.get("edges", [])}
                    truncated = bool(previous.get("coverage_truncated"))
                    pending = [proposal for proposal in proposals if proposal.proposal_id not in previous_ids]
                    incremental_update = True
            except (KeyError, TypeError, ValueError):
                # A graph snapshot is derived cache only; rebuild from immutable proposals.
                nodes, edges, pending, truncated, incremental_update = {}, set(), proposals, False, False

        def node(kind: str, value: str, label: str | None = None) -> str:
            nonlocal truncated
            ident = _digest(kind, value)
            if len(nodes) < self.max_nodes or ident in nodes:
                nodes[ident] = {"id": ident, "type": kind, "label": (label or value)[:128]}
            else:
                truncated = True
            return ident

        def edge(source: str, relation: str, target: str):
            nonlocal truncated
            if source in nodes and target in nodes and len(edges) < self.max_edges:
                edges.add((source, relation, target))
            elif source in nodes and target in nodes and (source, relation, target) not in edges:
                truncated = True

        program_node = node("program", program_id)
        for proposal in pending:
            pnode = node("proposal", proposal.proposal_id)
            edge(program_node, "contains", pnode)
            dimensions = [
                ("scout", proposal.scout_type, "generated_by"),
                ("asset", _origin_path(proposal.asset), "targets"),
                ("category", proposal.finding_category, "classified_as"),
                ("invariant", proposal.invariant, "tests_invariant"),
                ("identity", proposal.identity_context, "uses_identity"),
                ("resource", proposal.resource_type, "affects_resource"),
            ]
            for kind, value, relation in dimensions:
                edge(pnode, relation, node(kind, value))
            compatible_records, _, _ = self._compatible_record_ids(proposal)
            for record_id in sorted(compatible_records):
                edge(pnode, "derived_from", node("record", record_id))
        payload = {"program_id": program_id, "graph_version": self.version,
            "source_hash": source_hash, "node_count": len(nodes), "edge_count": len(edges),
            "nodes": sorted(nodes.values(), key=lambda v: v["id"]),
            "edges": [{"source": a, "relation": b, "target": c} for a, b, c in sorted(edges)],
            "proposals_considered": len(proposals),
            "coverage_truncated": truncated,
            "node_limit": self.max_nodes, "edge_limit": self.max_edges,
            "contains_raw_source_payloads": False, "authorization_source": False, "created_at": utcnow()}
        payload["incremental_update"] = incremental_update
        payload["proposals_added"] = len(pending)
        saved = self.records.save("scout_graph", payload)
        self.ledger.record_graph(saved)
        return {**payload, "record_id": saved["id"], "freshness_skip": False}

    def neighborhood(self, proposal_id: str) -> dict[str, Any]:
        target = _digest("proposal", proposal_id)
        related = []
        for record in reversed(scout_events(self.records, "scout_graph")):
            payload = record["payload"]
            if any(node["id"] == target for node in payload.get("nodes", [])):
                edge_values = [e for e in payload["edges"] if e["source"] == target or e["target"] == target]
                ids = {target} | {e["source"] for e in edge_values} | {e["target"] for e in edge_values}
                nodes = [n for n in payload["nodes"] if n["id"] in ids]
                related.append({"record_id": record["id"], "program_id": payload["program_id"],
                                "nodes": nodes, "edges": edge_values})
                break
        return {"proposal_id": proposal_id, "neighborhoods": related}
