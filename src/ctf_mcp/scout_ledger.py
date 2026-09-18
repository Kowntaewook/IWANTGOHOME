"""Rebuildable SQLite telemetry index; immutable JSON records remain authoritative."""

from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import sqlite3
from uuid import uuid4

from .config import Rejected
from .perf import PerformanceMetrics
from .scouts.base import utcnow


SCHEMA = """
CREATE TABLE IF NOT EXISTS proposals (
    proposal_id TEXT PRIMARY KEY, record_id TEXT NOT NULL UNIQUE, program_id TEXT NOT NULL,
    scout_type TEXT NOT NULL, asset_fingerprint TEXT NOT NULL, dedup_group TEXT,
    triage_score REAL, estimated_impact REAL NOT NULL, confidence REAL NOT NULL,
    novelty REAL NOT NULL, expected_value REAL, selected INTEGER NOT NULL DEFAULT 0,
    model_role TEXT, duration_ms INTEGER NOT NULL DEFAULT 0, final_status TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS dedup_relations (
    relation_record_id TEXT PRIMARY KEY, proposal_id TEXT NOT NULL, duplicate_of TEXT,
    similarity REAL NOT NULL, structural_match INTEGER NOT NULL, reason TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS triage_results (
    result_record_id TEXT PRIMARY KEY, proposal_id TEXT NOT NULL, triage_score REAL NOT NULL,
    estimated_cost REAL NOT NULL, expected_value REAL NOT NULL, decision TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS portfolio_runs (
    run_id TEXT PRIMARY KEY, record_id TEXT NOT NULL UNIQUE, proposal_count INTEGER NOT NULL,
    selected_count INTEGER NOT NULL, investigation_seconds REAL NOT NULL DEFAULT 0,
    model_calls INTEGER NOT NULL DEFAULT 0, model_role TEXT NOT NULL,
    estimated_cost REAL NOT NULL DEFAULT 0, final_status TEXT NOT NULL, created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS portfolio_members (
    run_id TEXT NOT NULL, proposal_id TEXT NOT NULL, selected INTEGER NOT NULL,
    selection_reason TEXT NOT NULL, expected_value REAL NOT NULL,
    PRIMARY KEY (run_id, proposal_id)
);
CREATE TABLE IF NOT EXISTS promotions (
    promotion_record_id TEXT PRIMARY KEY, proposal_id TEXT NOT NULL UNIQUE,
    candidate_id TEXT NOT NULL UNIQUE, program_id TEXT NOT NULL, final_status TEXT NOT NULL,
    duration_ms INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS model_usage (
    usage_id TEXT PRIMARY KEY, proposal_id TEXT, model_role TEXT NOT NULL, model_name TEXT,
    effort TEXT, duration_ms INTEGER NOT NULL, estimated_cost REAL NOT NULL,
    final_status TEXT NOT NULL, created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS input_evaluations (
    input_record_id TEXT NOT NULL, input_record_hash TEXT NOT NULL, analyzer_version TEXT NOT NULL,
    scout_type TEXT NOT NULL, scout_version TEXT NOT NULL, last_evaluated_at TEXT NOT NULL,
    PRIMARY KEY (input_record_hash, scout_type, scout_version)
);
CREATE TABLE IF NOT EXISTS scout_cache (
    cache_key TEXT PRIMARY KEY, input_record_id TEXT NOT NULL, input_record_hash TEXT NOT NULL,
    analyzer_version TEXT NOT NULL, scout_type TEXT NOT NULL, scout_version TEXT NOT NULL,
    program_policy_hash TEXT NOT NULL, relevant_config_hash TEXT NOT NULL,
    last_evaluated_at TEXT NOT NULL, proposal_count INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS outcomes (
    outcome_record_id TEXT PRIMARY KEY, proposal_id TEXT NOT NULL,
    candidate_record_id TEXT NOT NULL UNIQUE, program_id TEXT NOT NULL,
    scout_type TEXT NOT NULL, finding_category TEXT NOT NULL, outcome TEXT NOT NULL,
    investigation_seconds INTEGER NOT NULL, created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS graph_snapshots (
    graph_record_id TEXT PRIMARY KEY, program_id TEXT NOT NULL, graph_version TEXT NOT NULL,
    source_hash TEXT NOT NULL, node_count INTEGER NOT NULL, edge_count INTEGER NOT NULL,
    created_at TEXT NOT NULL, UNIQUE(program_id, graph_version, source_hash)
);
CREATE TABLE IF NOT EXISTS experiment_plans (
    plan_record_id TEXT PRIMARY KEY, plan_id TEXT NOT NULL UNIQUE, proposal_id TEXT NOT NULL,
    program_id TEXT NOT NULL, planner_version TEXT NOT NULL, plan_fingerprint TEXT NOT NULL,
    estimated_requests INTEGER NOT NULL, authorization INTEGER NOT NULL,
    created_at TEXT NOT NULL, UNIQUE(proposal_id, planner_version, plan_fingerprint)
);
CREATE TABLE IF NOT EXISTS performance_runs (
    performance_record_id TEXT PRIMARY KEY, program_id TEXT NOT NULL,
    total_runtime_ms REAL NOT NULL, metrics_json TEXT NOT NULL, created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS indexed_records (
    record_id TEXT PRIMARY KEY, kind TEXT NOT NULL, created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_proposals_program_scout_status
    ON proposals(program_id, scout_type, final_status, created_at);
CREATE INDEX IF NOT EXISTS idx_dedup_proposal ON dedup_relations(proposal_id);
CREATE INDEX IF NOT EXISTS idx_triage_proposal ON triage_results(proposal_id);
CREATE INDEX IF NOT EXISTS idx_portfolio_member_proposal ON portfolio_members(proposal_id, selected);
CREATE INDEX IF NOT EXISTS idx_cache_input_scout
    ON scout_cache(input_record_hash, scout_type, scout_version, program_policy_hash, relevant_config_hash);
"""


class ScoutLedger:
    def __init__(self, results_root: Path, path: Path | None = None,
                 metrics: PerformanceMetrics | None = None):
        self.results_root = Path(results_root)
        self.path = Path(path) if path else self.results_root / ".scout-ledger.sqlite3"
        if self.path.parent.resolve() != self.results_root.resolve() or self.path.is_symlink():
            raise Rejected("unsafe_scout_ledger_path")
        self.recovered_corruption = False
        self.metrics = metrics
        self._initialize()

    def _connect(self):
        connection = sqlite3.connect(self.path, timeout=10)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA busy_timeout=10000")
        if self.metrics is not None:
            def trace(statement):
                operation = statement.lstrip().split(None, 1)[0].upper() if statement.strip() else ""
                if operation in {"SELECT", "PRAGMA"}:
                    self.metrics.add("sqlite_query_count")
                elif operation in {"INSERT", "UPDATE", "DELETE", "REPLACE", "CREATE", "ALTER", "DROP"}:
                    self.metrics.add("sqlite_write_count")
                elif operation == "BEGIN":
                    self.metrics.add("sqlite_transaction_count")
            connection.set_trace_callback(trace)
        return connection

    def _initialize(self):
        connection = None
        try:
            connection = self._connect()
            check = connection.execute("PRAGMA quick_check").fetchone()[0]
            if check != "ok":
                raise sqlite3.DatabaseError("quick_check_failed")
            connection.executescript(SCHEMA)
            connection.commit()
        except sqlite3.DatabaseError:
            if connection is not None:
                connection.close()
            if self.path.exists():
                backup = self.path.with_name(self.path.name + ".corrupt-" + uuid4().hex)
                self.path.rename(backup)
                self.recovered_corruption = True
            connection = self._connect()
            connection.executescript(SCHEMA)
            connection.commit()
        finally:
            if connection is not None:
                connection.close()
        if self.path.exists():
            os.chmod(self.path, 0o600)

    @contextmanager
    def transaction(self):
        connection = self._connect()
        try:
            with connection:
                yield connection
        finally:
            connection.close()

    @contextmanager
    def _writer(self, connection=None):
        if connection is not None:
            yield connection
        else:
            with self.transaction() as owned:
                yield owned

    @staticmethod
    def _mark_indexed(connection, record: dict):
        connection.execute("INSERT OR IGNORE INTO indexed_records VALUES (?,?,?)",
            (record["id"], record["kind"], record.get("created_at", "")))

    def was_evaluated(self, record_hash: str, scout_type: str, scout_version: str,
                      program_policy_hash: str | None = None,
                      relevant_config_hash: str | None = None) -> bool:
        connection = self._connect()
        try:
            if program_policy_hash is None or relevant_config_hash is None:
                row = connection.execute(
                    "SELECT 1 FROM input_evaluations WHERE input_record_hash=? AND scout_type=? AND scout_version=?",
                    (record_hash, scout_type, scout_version)).fetchone()
            else:
                row = connection.execute("""SELECT 1 FROM scout_cache
                    WHERE input_record_hash=? AND scout_type=? AND scout_version=?
                    AND program_policy_hash=? AND relevant_config_hash=?""",
                    (record_hash, scout_type, scout_version, program_policy_hash,
                     relevant_config_hash)).fetchone()
        finally:
            connection.close()
        return row is not None

    def mark_evaluated(self, record_id: str, record_hash: str, analyzer_version: str,
                       scout_type: str, scout_version: str):
        with self.transaction() as connection:
            connection.execute("INSERT OR REPLACE INTO input_evaluations VALUES (?,?,?,?,?,?)",
                (record_id, record_hash, analyzer_version, scout_type, scout_version, utcnow()))

    def record_evaluation(self, record: dict, *, connection=None):
        p = record["payload"]
        with self._writer(connection) as writer:
            writer.execute("INSERT OR REPLACE INTO input_evaluations VALUES (?,?,?,?,?,?)",
                (p["input_record_id"], p["input_record_hash"], p["analyzer_version"],
                 p["scout_type"], p["scout_version"], p["last_evaluated_at"]))
            if all(p.get(key) for key in ("cache_key", "program_policy_hash", "relevant_config_hash")):
                writer.execute("INSERT OR REPLACE INTO scout_cache VALUES (?,?,?,?,?,?,?,?,?,?)",
                    (p["cache_key"], p["input_record_id"], p["input_record_hash"],
                     p["analyzer_version"], p["scout_type"], p["scout_version"],
                     p["program_policy_hash"], p["relevant_config_hash"],
                     p["last_evaluated_at"], p.get("proposal_count", 0)))
            self._mark_indexed(writer, record)

    def record_proposal(self, record: dict, *, connection=None):
        p = record["payload"]
        fingerprint = hashlib.sha256(p["asset"].encode()).hexdigest()
        with self._writer(connection) as writer:
            writer.execute("""INSERT OR IGNORE INTO proposals
                (proposal_id,record_id,program_id,scout_type,asset_fingerprint,estimated_impact,
                 confidence,novelty,final_status,created_at) VALUES (?,?,?,?,?,?,?,?,?,?)""",
                (p["proposal_id"], record["id"], p["program_id"], p["scout_type"], fingerprint,
                 p["estimated_impact"], p["confidence"], p["novelty"], p["status"], p["created_at"]))
            self._mark_indexed(writer, record)

    def record_dedup(self, record: dict, *, connection=None):
        p = record["payload"]
        with self._writer(connection) as writer:
            writer.execute("""INSERT OR IGNORE INTO dedup_relations
                VALUES (?,?,?,?,?,?,?)""", (record["id"], p["proposal_id"], p.get("duplicate_of"),
                p["similarity"], int(p["structural_match"]), p["reason"], record["created_at"]))
            if p["duplicate"]:
                writer.execute("UPDATE proposals SET dedup_group=?, final_status='DEDUPED' WHERE proposal_id=?",
                    (p["duplicate_of"], p["proposal_id"]))
            self._mark_indexed(writer, record)

    def record_triage(self, record: dict, *, connection=None):
        p = record["payload"]
        statuses = {"ELIGIBLE": "TRIAGED", "BLOCKED_SCOPE": "BLOCKED_SCOPE",
            "LOW_EVIDENCE": "NEEDS_MORE_EVIDENCE", "PROGRAM_EXCLUDED": "REJECTED",
            "BELOW_THRESHOLD": "REJECTED", "IDENTITY_UNAVAILABLE": "REJECTED",
            "PROGRAM_BUDGET_EXCEEDED": "REJECTED"}
        with self._writer(connection) as writer:
            writer.execute("""INSERT OR IGNORE INTO triage_results
                VALUES (?,?,?,?,?,?,?)""", (record["id"], p["proposal_id"], p["triage_score"],
                p["estimated_cost"], p["expected_value"], p["decision"], record["created_at"]))
            writer.execute("""UPDATE proposals SET triage_score=?, expected_value=?,
                final_status=? WHERE proposal_id=? AND final_status NOT IN ('SELECTED','PROMOTED','DEDUPED')""",
                (p["triage_score"], p["expected_value"],
                statuses[p["decision"]], p["proposal_id"]))
            self._mark_indexed(writer, record)

    def record_portfolio(self, record: dict, *, connection=None):
        p = record["payload"]
        cost = sum(float(item.get("estimated_cost", 0)) for item in p["members"])
        with self._writer(connection) as writer:
            writer.execute("""INSERT OR IGNORE INTO portfolio_runs
                (run_id,record_id,proposal_count,selected_count,investigation_seconds,model_calls,
                 model_role,estimated_cost,final_status,created_at) VALUES (?,?,?,?,?,?,?,?,?,?)""",
                (p["run_id"], record["id"], p["proposal_count"], p["selected_count"],
                 p.get("investigation_seconds", 0), p["model_calls"], p["model_role"], cost,
                 p["final_status"], record["created_at"]))
            for item in p["members"]:
                writer.execute("INSERT OR IGNORE INTO portfolio_members VALUES (?,?,?,?,?)",
                    (p["run_id"], item["proposal_id"], 1, item["selection_reason"], item["expected_value"]))
                writer.execute("UPDATE proposals SET selected=1, final_status='SELECTED' WHERE proposal_id=?",
                    (item["proposal_id"],))
            if p["model_calls"]:
                route = p.get("model_route", {})
                writer.execute("INSERT OR IGNORE INTO model_usage VALUES (?,?,?,?,?,?,?,?,?)",
                    (record["id"], None, p["model_role"], route.get("model"), route.get("effort"),
                     p.get("model_duration_ms", 0), p.get("model_estimated_cost", 0),
                     p["final_status"], record["created_at"]))
            self._mark_indexed(writer, record)

    def record_promotion(self, record: dict, *, connection=None):
        p = record["payload"]
        with self._writer(connection) as writer:
            writer.execute("INSERT OR IGNORE INTO promotions VALUES (?,?,?,?,?,?,?)",
                (record["id"], p["proposal_id"], p["candidate_id"], p["program_id"],
                 "PROMOTED", p.get("duration_ms", 0), record["created_at"]))
            writer.execute("UPDATE proposals SET final_status='PROMOTED' WHERE proposal_id=?",
                (p["proposal_id"],))
            self._mark_indexed(writer, record)

    def record_outcome(self, record: dict, *, connection=None):
        p = record["payload"]
        with self._writer(connection) as writer:
            writer.execute("""INSERT OR IGNORE INTO outcomes VALUES (?,?,?,?,?,?,?,?,?)""",
                (record["id"], p["proposal_id"], p["candidate_record_id"], p["program_id"],
                 p["scout_type"], p["finding_category"], p["outcome"],
                 p["investigation_seconds"], record["created_at"]))
            self._mark_indexed(writer, record)

    def record_graph(self, record: dict, *, connection=None):
        p = record["payload"]
        with self._writer(connection) as writer:
            writer.execute("""INSERT OR IGNORE INTO graph_snapshots VALUES (?,?,?,?,?,?,?)""",
                (record["id"], p["program_id"], p["graph_version"], p["source_hash"],
                 p["node_count"], p["edge_count"], record["created_at"]))
            self._mark_indexed(writer, record)

    def record_experiment_plan(self, record: dict, *, connection=None):
        p = record["payload"]
        # The shared immutable-record redactor masks exact authorization-shaped keys.
        # Both accepted values represent the planner's schema-validated constant false.
        if p.get("authorization") not in {False, "[REDACTED]"}:
            raise Rejected("experiment_plan_cannot_authorize")
        with self._writer(connection) as writer:
            writer.execute("""INSERT OR IGNORE INTO experiment_plans VALUES (?,?,?,?,?,?,?,?,?)""",
                (record["id"], p["plan_id"], p["proposal_id"], p["program_id"],
                 p["planner_version"], p["plan_fingerprint"], p["estimated_requests"],
                 0, record["created_at"]))
            self._mark_indexed(writer, record)

    def update_state(self, proposal_id: str, status: str, *, record=None, connection=None):
        with self._writer(connection) as writer:
            writer.execute("UPDATE proposals SET final_status=? WHERE proposal_id=?", (status, proposal_id))
            if record is not None:
                self._mark_indexed(writer, record)

    def record_performance(self, record: dict, *, connection=None):
        p = record["payload"]
        metrics = p["metrics"]
        with self._writer(connection) as writer:
            writer.execute("INSERT OR IGNORE INTO performance_runs VALUES (?,?,?,?,?)",
                (record["id"], p["program_id"], float(metrics["total_runtime_ms"]),
                 json.dumps(metrics, sort_keys=True, separators=(",", ":")), record["created_at"]))
            self._mark_indexed(writer, record)

    def _record_event(self, record: dict, connection):
        kind = record["kind"]
        if kind == "scout_proposal": self.record_proposal(record, connection=connection)
        elif kind == "scout_dedup": self.record_dedup(record, connection=connection)
        elif kind == "scout_triage": self.record_triage(record, connection=connection)
        elif kind == "scout_portfolio": self.record_portfolio(record, connection=connection)
        elif kind == "scout_promotion": self.record_promotion(record, connection=connection)
        elif kind == "scout_state": self.update_state(record["payload"]["proposal_id"],
            record["payload"]["status"], record=record, connection=connection)
        elif kind == "scout_evaluation": self.record_evaluation(record, connection=connection)
        elif kind == "scout_outcome": self.record_outcome(record, connection=connection)
        elif kind == "scout_graph": self.record_graph(record, connection=connection)
        elif kind == "scout_experiment_plan": self.record_experiment_plan(record, connection=connection)
        elif kind == "scout_performance": self.record_performance(record, connection=connection)
        else: self._mark_indexed(connection, record)

    def record_batch(self, records: list[dict]):
        """Index an immutable event batch atomically; evidence files already remain authoritative."""
        if not records:
            return
        with self.transaction() as connection:
            for record in records:
                self._record_event(record, connection)

    def sync(self, records):
        """Rebuild missing index rows from immutable events without changing evidence."""
        with self.transaction() as connection:
            indexed = {row[0] for row in connection.execute("SELECT record_id FROM indexed_records")}
            events = [records.read(record_id) for record_id in records.list() if record_id not in indexed]
            for record in sorted(events, key=lambda item: (item.get("created_at", ""), item["id"])):
                self._record_event(record, connection)

    def rows(self, table: str, *, proposal_id: str | None = None, limit: int = 1000) -> list[dict]:
        allowed = {"proposals", "dedup_relations", "triage_results", "portfolio_runs",
                   "portfolio_members", "promotions", "model_usage", "input_evaluations",
                   "scout_cache", "outcomes", "graph_snapshots", "experiment_plans",
                   "performance_runs"}
        if table not in allowed or type(limit) is not int or not 1 <= limit <= 1000:
            raise Rejected("invalid_scout_ledger_query")
        filters = {
            "proposals": "proposal_id", "dedup_relations": "proposal_id", "triage_results": "proposal_id",
            "portfolio_members": "proposal_id", "promotions": "proposal_id", "model_usage": "proposal_id",
            "outcomes": "proposal_id", "experiment_plans": "proposal_id",
        }
        query = "SELECT * FROM " + table
        params: tuple = ()
        if proposal_id is not None:
            if table not in filters:
                raise Rejected("invalid_scout_ledger_query")
            query += " WHERE " + filters[table] + "=?"
            params = (proposal_id,)
        query += " ORDER BY rowid DESC LIMIT ?"
        connection = self._connect()
        try:
            values = connection.execute(query, (*params, limit)).fetchall()
        finally:
            connection.close()
        return [dict(row) for row in values]
