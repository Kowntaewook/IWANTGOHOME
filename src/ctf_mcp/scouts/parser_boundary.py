"""Offline file, upload, import, export, and parser-boundary scout."""

import re

from .base import BaseScout, ScoutContext, analysis_ids, asset_candidates, endpoint_shape, walk_values


ACTION = re.compile(r"upload|import|export|extract|convert|archive|attachment", re.I)
BOUNDARY = re.compile(r"file|filename|path|mime|content[_-]?type|parser|image|document|zip|archive", re.I)


class ParserBoundaryScout(BaseScout):
    scout_type = "parser_boundary"
    version = "1"

    def analyze(self, context: ScoutContext, limit: int):
        record = context.record
        if record.get("kind") != "analysis" or limit <= 0:
            return []
        pairs = walk_values(record.get("payload", {}))
        combined = [(key + " " + value)[:5000] for key, value in pairs]
        if not any(ACTION.search(value) for value in combined) or not any(BOUNDARY.search(value) for value in combined):
            return []
        assets = [asset for asset in asset_candidates(record) if ACTION.search(asset)]
        if not assets:
            return []
        proposals = []
        for asset in assets[:limit]:
            proposals.append(self.proposal(context, asset=asset,
                title="Review an observed file or parser trust boundary",
                finding_category="file-parser-boundary", observation_ids=analysis_ids(context),
                source_record_ids=[record["id"]],
                invariant="Untrusted files, names, paths, MIME declarations, and archive members must remain confined and be parsed according to trusted server-side rules.",
                evidence_summary="An immutable static or contract record contains both a file-processing action and a parser-boundary structure.",
                observed_fact="Upload/import/export or conversion structure appears together with file, path, MIME, parser, or archive metadata.",
                why_may_matter="A mismatch between validation and downstream parsing can cross storage, extraction, or conversion boundaries.",
                missing_evidence="Parser implementation, normalization order, storage destination, and accepted formats have not been verified.",
                confidence=0.52, estimated_impact=0.7, novelty=0.61,
                required_followup=["Review existing parser and storage evidence before designing any test file.",
                    "Never upload an attack file automatically."], identity_context="authorized_uploader",
                endpoint_shape=endpoint_shape(asset, "POST"), resource_type="uploaded_or_generated_file",
                estimated_requests=1))
        return proposals
