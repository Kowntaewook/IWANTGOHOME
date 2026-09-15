import hashlib
import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4
from .config import Rejected, Limits
from .redaction import clean
from .safety import SafeRoot, bounded_tree


VERSION = "0.3.0"
REVIEW_STATUSES = {"DISCOVERED", "VALIDATING", "NEEDS_MORE_EVIDENCE", "REJECTED",
                  "BLOCKED_SCOPE", "DUPLICATE", "NOT_SECURITY_RELEVANT", "READY_FOR_HUMAN_REVIEW"}
# Existing immutable records and callers remain readable during the incremental upgrade.
LEGACY_REVIEW_STATUSES = {"needs_review", "rejected", "needs_evidence", "remediated_pending_test"}


def now():
    return datetime.now(timezone.utc).isoformat()


def valid_id(value):
    if not re.fullmatch(r"[0-9a-f]{32}", value):
        raise Rejected("invalid_record_id")
    return value


class Records:
    def __init__(self, root: Path, limits=Limits()):
        self.root, self.limits = root, limits
        self.reader = SafeRoot(root, limits)

    def save(self, kind, payload):
        record_id, timestamp = uuid4().hex, now()
        provenance = {"analysis_id": record_id, "timestamp_utc": timestamp,
            "input_sha256": payload.get("input", {}).get("sha256") if isinstance(payload, dict) else None,
            "analyzer": payload.get("analyzer", kind) if isinstance(payload, dict) else kind,
            "analyzer_version": VERSION,
            "identity_label": payload.get("identity_label", "not_applicable") if isinstance(payload, dict) else "not_applicable",
            "tool_result_path": record_id + ".json",
            "redaction_status": "minimized_and_pattern_redacted; manual_privacy_review_required"}
        record = clean({"id": record_id, "kind": kind, "created_at": timestamp,
                        "analyzer_version": VERSION, "trust": "untrusted_input_derived",
                        "provenance": provenance, "payload": payload})
        raw = json.dumps(record, ensure_ascii=True, sort_keys=True, allow_nan=False).encode()
        if len(raw) > self.limits.output_bytes:
            raise Rejected("result_too_large")
        # Write a private temp file, fsync, then link without replacing an existing name.
        temp = self.root / (".pending-" + uuid4().hex)
        try:
            with temp.open("xb") as f:
                os.chmod(temp, 0o600)
                f.write(raw)
                f.flush()
                os.fsync(f.fileno())
            os.link(temp, self.root / (record["id"] + ".json"))
        finally:
            temp.unlink(missing_ok=True)
        return record

    def read(self, record_id):
        obj = json.loads(self.reader.read(valid_id(record_id) + ".json", self.limits.output_bytes))
        if obj.get("id") != record_id:
            raise Rejected("record_integrity_error")
        return obj

    def list(self):
        ids, scanned = [], 0
        with os.scandir(self.root) as it:
            for entry in it:
                scanned += 1
                if scanned > 20000:raise Rejected("record_listing_limit")
                if re.fullmatch(r"[0-9a-f]{32}\.json", entry.name) and entry.is_file(follow_symlinks=False):
                    ids.append(entry.name[:-5])
                    if len(ids) > 10000:
                        raise Rejected("record_listing_limit")
        return sorted(ids)

    def candidate(self, data):
        required = {"project", "title", "facts", "concerns", "assumptions", "counterarguments",
                    "missing_evidence", "review_status", "remediation", "evidence_ids"}
        if not isinstance(data, dict) or set(data) != required:
            raise Rejected("invalid_candidate_fields")
        bounded_tree(data)
        if not isinstance(data["project"], str) or not re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,63}", data["project"]):
            raise Rejected("invalid_project")
        if data["review_status"] not in REVIEW_STATUSES | LEGACY_REVIEW_STATUSES:
            raise Rejected("confirmation_requires_human_review_outside_mcp")
        for k in required - {"evidence_ids"}:
            if not isinstance(data[k], str) or len(data[k]) > 8000:
                raise Rejected("invalid_candidate_field")
        if not isinstance(data["evidence_ids"], list) or not 1 <= len(data["evidence_ids"]) <= 20:
            raise Rejected("evidence_required")
        for record_id in data["evidence_ids"]:
            if self.read(record_id)["kind"] != "analysis":
                raise Rejected("analysis_evidence_required")
        return self.save("candidate", data)

    def resume(self, project):
        selected, size = [], 0
        for i in self.list():
            record = self.read(i)
            if record["kind"] == "candidate" and record["payload"]["project"] == project:
                size += len(json.dumps(record).encode())
                if size > self.limits.output_bytes:raise Rejected("research_resume_limit")
                selected.append(record)
        return selected

    def report(self, project):
        candidates = self.resume(project)
        lines = ["# Research report", "", "Human review required. No automatic submission or CONFIRMED status.", ""]
        for c in candidates:
            p = c["payload"]
            lines += ["## " + p["title"], "", "Record: " + c["id"], ""]
            for k, v in p.items():
                lines += ["### " + k.replace("_", " "), "", str(v), ""]
        return self.save("report", {"project": project, "markdown": "\n".join(lines), "candidate_count": len(candidates)})


def digest(data):
    return hashlib.sha256(data).hexdigest()
