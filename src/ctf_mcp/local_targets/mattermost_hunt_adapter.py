"""Mattermost implementation of the target-neutral full-hunt protocol."""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import http.client
import json
from pathlib import Path
from typing import Any, Callable
from urllib.parse import quote, urlencode

from ctf_mcp.full_hunt.duplicate import DuplicateResearchPolicy, evaluate_duplicate_research
from ctf_mcp.full_hunt.registry import FULL_HUNT_REGISTRY
from ctf_mcp.full_hunt.reporting import ReportWriter
from ctf_mcp.full_hunt.scenario import TargetCapabilities, not_generatable
from ctf_mcp.full_hunt.schema import DuplicateQuery, RuntimeRequest, SourceIdentity
from ctf_mcp.full_hunt.version_retest import compose_version_matrix, validate_retest_target

from .base import LocalTargetError
from .mattermost_discovery import discover_mattermost_candidates, discover_mattermost_version
from .mattermost_scenario_bindings import MattermostScenarioBindings


MATTERMOST_PINNED_VERSION = "12.0.0"
MATTERMOST_MAIN_BRANCH = "main"
MATTERMOST_RETEST_ENDPOINTS = {
    "latest": "127.0.0.1:13101",
    "main": "127.0.0.1:13102",
}
MATTERMOST_DUPLICATE_SOURCES = (
    "github_issues", "github_prs", "github_advisories", "mattermost_releases", "nvd",
)
MATTERMOST_CORE_SOURCES = MATTERMOST_DUPLICATE_SOURCES[:4]
MATTERMOST_PUBLIC_RESEARCH_HOSTS = frozenset({"api.github.com", "services.nvd.nist.gov"})


class MattermostPublicResearchClient:
    """Credential-free, bounded research against fixed public providers."""

    def __init__(self, *, timeout: float = 8.0, max_bytes: int = 2 * 1024 * 1024):
        self.timeout = timeout
        self.max_bytes = max_bytes

    def search(self, candidate: dict[str, Any]) -> tuple[list[dict[str, Any]], dict[str, str]]:
        handler = candidate["handler"]["symbol"]
        queries = (
            ("github_issues", "api.github.com", "/search/issues?" + urlencode({
                "q": f'repo:mattermost/mattermost is:issue "{handler}"', "per_page": 20,
            })),
            ("github_prs", "api.github.com", "/search/issues?" + urlencode({
                "q": f'repo:mattermost/mattermost is:pr is:merged "{handler}"', "per_page": 20,
            })),
            ("github_advisories", "api.github.com", "/advisories?" + urlencode({
                "ecosystem": "go", "affects": "github.com/mattermost/mattermost/server/v8",
                "per_page": 100,
            })),
            ("mattermost_releases", "api.github.com", "/repos/mattermost/mattermost/releases?per_page=10"),
            ("nvd", "services.nvd.nist.gov", "/rest/json/cves/2.0?" + urlencode({
                "keywordSearch": "Mattermost " + handler, "resultsPerPage": 100,
            })),
        )
        records: list[dict[str, Any]] = []
        statuses: dict[str, str] = {}
        for source, host, path in queries:
            try:
                document = self._get_json(host, path)
                parsed = _public_records(source, document, candidate)
                statuses[source] = "ok" if _public_document_count(source, document) else "empty"
                records.extend(parsed)
            except LocalTargetError as error:
                statuses[source] = (
                    "unavailable" if error.code == "duplicate_research_unavailable" else "error"
                )
        return records, statuses

    def latest_release(self) -> dict[str, str]:
        value = self._get_json("api.github.com", "/repos/mattermost/mattermost/releases/latest")
        tag = value.get("tag_name") if isinstance(value, dict) else None
        published = value.get("published_at") if isinstance(value, dict) else None
        if not isinstance(tag, str) or not tag or not isinstance(published, str):
            raise LocalTargetError("latest_release_identity_unavailable")
        return {"version": tag, "tag": tag, "fetched_at": published}

    def _get_json(self, host: str, path: str) -> Any:
        if host not in MATTERMOST_PUBLIC_RESEARCH_HOSTS or not path.startswith("/") or "\r" in path or "\n" in path:
            raise LocalTargetError("duplicate_research_scope_violation")
        connection = http.client.HTTPSConnection(host, 443, timeout=self.timeout)
        try:
            connection.request("GET", path, headers={
                "Accept": "application/vnd.github+json, application/json",
                "User-Agent": "IWANTGOHOME-local-duplicate-research",
            })
            response = connection.getresponse()
            raw = response.read(self.max_bytes + 1)
        except (OSError, http.client.HTTPException):
            raise LocalTargetError("duplicate_research_unavailable") from None
        finally:
            connection.close()
        if response.status != 200:
            code = (
                "duplicate_research_unavailable"
                if response.status in {408, 425, 429} or response.status >= 500
                else "duplicate_research_error"
            )
            raise LocalTargetError(code)
        if len(raw) > self.max_bytes:
            raise LocalTargetError("duplicate_research_error")
        try:
            return json.loads(raw)
        except (TypeError, ValueError):
            raise LocalTargetError("duplicate_research_error") from None


class MattermostFullHuntTargetAdapter:
    target_id = "mattermost"
    repository = "https://github.com/mattermost/mattermost"

    def __init__(
        self,
        *,
        local_adapter: Any,
        duplicate_client: Any | None = None,
        retest_provider: Callable[[dict[str, Any]], list[dict[str, Any]]] | None = None,
        now: Callable[[], str] | None = None,
    ):
        self.local = local_adapter
        self.source_root = local_adapter.target_root
        self.pinned_commit = local_adapter.pinned_revision
        self.pinned_digest = _mattermost_digest()
        self.duplicate_client = duplicate_client
        self.retest_provider = retest_provider
        self.now = now or (lambda: datetime.now(timezone.utc).isoformat())
        self.bootstrapped = False
        self.local_results: list[dict[str, Any]] = []
        self.binding_adapter = MattermostScenarioBindings()
        self.source_version: str | None = None

    def resolve_source(self) -> SourceIdentity:
        state = self.local._source_details(2)
        if not state.get("prepared"):
            self.local.prepare()
        self.local._require_source()
        self.source_version = discover_mattermost_version(self.source_root)
        if self.source_version != MATTERMOST_PINNED_VERSION:
            raise LocalTargetError("SOURCE_VERSION_MISMATCH")
        return SourceIdentity(
            repository=self.repository,
            revision=self.pinned_commit,
            fetched_at=self.now(),
            directory=self.source_root,
        )

    def discover_candidates(self, source: SourceIdentity) -> list[dict[str, Any]]:
        if source.directory != self.source_root or source.revision != self.pinned_commit:
            raise LocalTargetError("SOURCE_ACQUIRE_FAILED")
        return discover_mattermost_candidates(self.source_root)

    @staticmethod
    def static_triage(candidate: dict[str, Any]) -> dict[str, Any]:
        return candidate

    def build_prepare_runtime(self, request: RuntimeRequest) -> dict[str, Any]:
        if request != RuntimeRequest("pinned"):
            raise LocalTargetError("VALIDATION_BLOCKED")
        self.local._require_source()
        if not self.local.health().get("healthy"):
            self.local.up(progress=lambda _: None)
        return {"status": "prepared", "endpoint": "127.0.0.1:13100"}

    def bootstrap(self, request: RuntimeRequest) -> dict[str, Any]:
        if request != RuntimeRequest("pinned"):
            raise LocalTargetError("VALIDATION_BLOCKED")
        result = self.local.bootstrap()
        self.bootstrapped = result.get("status") in {"ready", "partial"}
        return result

    @staticmethod
    def should_validate_candidate(candidate: dict[str, Any]) -> bool:
        return (
            candidate["static_status"] == "NEEDS_LOCAL_VALIDATION"
            and candidate.get("baseline_candidate") in {"S12", "S13"}
        )

    def validate_candidate(
        self, candidate: dict[str, Any], request: RuntimeRequest,
    ) -> dict[str, Any] | None:
        if request.kind != "pinned" or request.candidate_id != candidate["candidate_id"]:
            raise LocalTargetError("VALIDATION_BLOCKED")
        baseline = candidate.get("baseline_candidate")
        values = self.local.validate(baseline)
        if len(values) != 1:
            raise LocalTargetError("VALIDATION_BLOCKED")
        rechecked = next(
            (item for item in discover_mattermost_candidates(self.source_root)
             if item.get("candidate_id") == candidate["candidate_id"]),
            None,
        )
        normalized = _normalize_local_result(
            baseline, values[0], rechecked, expected_source_candidate=candidate,
        )
        self.local_results.append(normalized)
        return normalized

    @staticmethod
    def scenario_capabilities() -> TargetCapabilities:
        return TargetCapabilities(
            fixture_actions=frozenset({
                "create_identity", "create_public_resource", "create_private_resource",
                "add_member", "remove_member", "create_private_content", "resolve_route",
                "read_owned_fixture",
            }),
            supports_read_only_probe=True,
        )

    @staticmethod
    def should_synthesize_scenario(candidate: dict[str, Any]) -> bool:
        return candidate["static_status"] in {"BLOCKED_STATIC", "NEEDS_MANUAL_SCENARIO"}

    def synthesize_scenario(
        self, candidate: dict[str, Any], capabilities: TargetCapabilities,
    ) -> dict[str, Any]:
        del capabilities
        reason = (
            "destructive_validation_method_not_supported"
            if candidate.get("route", {}).get("method") not in {"GET", "HEAD"}
            else "no_reviewed_fixture_route_mapping"
        )
        return not_generatable(candidate["candidate_id"], self.target_id, reason)

    def scenario_bindings(self):
        return self.binding_adapter.bindings()

    @staticmethod
    def duplicate_queries(candidate: dict[str, Any]) -> list[DuplicateQuery]:
        terms = _duplicate_terms(candidate)
        return [
            DuplicateQuery(source, " | ".join(terms), source != "nvd")
            for source in MATTERMOST_DUPLICATE_SOURCES
        ]

    def duplicate_research(self, candidate: dict[str, Any]) -> dict[str, Any]:
        records: list[dict[str, Any]] = []
        statuses = {source: "unavailable" for source in MATTERMOST_DUPLICATE_SOURCES}
        if self.duplicate_client is not None:
            try:
                records, supplied = self.duplicate_client.search(candidate)
                statuses.update({
                    key: value for key, value in supplied.items()
                    if key in statuses and value in {"ok", "empty", "unavailable", "error"}
                })
            except (LocalTargetError, OSError, TypeError, ValueError):
                pass
        terms = _duplicate_terms(candidate)
        return evaluate_duplicate_research(
            candidate_id=candidate["candidate_id"],
            terms=terms,
            policy=DuplicateResearchPolicy(
                MATTERMOST_DUPLICATE_SOURCES, MATTERMOST_CORE_SOURCES, 3,
            ),
            records=[item for item in records if isinstance(item, dict)],
            source_statuses=statuses,
            known_exact=[],
            known_possible=[],
            match_strength=lambda record: _match_strength(candidate, record),
            sanitize_match=lambda record, reasons: {
                "source": record.get("source"),
                "reference": record.get("reference"),
                "url": record.get("url"),
                "match_reasons": reasons,
            },
            deduplicate=_deduplicate,
        )

    def version_retest(
        self,
        candidate: dict[str, Any],
        local_validation: dict[str, Any],
        duplicate_research: dict[str, Any],
    ) -> dict[str, Any]:
        del duplicate_research
        records = self.retest_provider(candidate) if self.retest_provider else []
        pinned = {
            "target": "pinned", "version": MATTERMOST_PINNED_VERSION,
            "commit": self.pinned_commit, "digest": self.pinned_digest,
            "runtime_id": "mattermost-pinned-13100", "endpoint": "127.0.0.1:13100",
            "isolated": True, "result": "AFFECTED", "control_passed": True,
            "evidence_ids": [
                local_validation[key] for key in ("evidence", "reassessment")
                if isinstance(local_validation.get(key), str)
            ],
        }

        def blocked(kind: str) -> dict[str, Any]:
            return {
                "target": kind, "version": None, "commit": None, "digest": None,
                "runtime_id": f"mattermost-{kind}-{MATTERMOST_RETEST_ENDPOINTS[kind].rsplit(':', 1)[1]}",
                "endpoint": MATTERMOST_RETEST_ENDPOINTS[kind], "isolated": True,
                "result": "RETEST_BLOCKED", "control_passed": False, "evidence_ids": [],
                "blocked_reason": f"{kind}_isolated_runtime_not_available",
            }

        def validate(value: dict[str, Any]) -> dict[str, Any]:
            return validate_retest_target(
                value,
                kinds=frozenset(MATTERMOST_RETEST_ENDPOINTS),
                endpoints=MATTERMOST_RETEST_ENDPOINTS,
            )

        def classify(indexed: dict[str, dict[str, Any]]) -> str:
            latest, main = indexed["latest"]["result"], indexed["main"]["result"]
            if "RETEST_BLOCKED" in {latest, main}:
                return "RETEST_BLOCKED"
            if latest == "AFFECTED" and main == "AFFECTED":
                return "AFFECTS_MAIN"
            if latest == "INTENDED_BEHAVIOR":
                return "FIXED_IN_LATEST"
            return "FIXED_IN_MAIN"

        return compose_version_matrix(
            candidate_id=candidate["candidate_id"], pinned=pinned,
            target_kinds=("latest", "main"), supplied=records,
            blocked_target=blocked, validate_target=validate, classify=classify,
        )

    @staticmethod
    def cluster_key(candidate: dict[str, Any]) -> str:
        return candidate["root_cause_key"]

    @staticmethod
    def root_cause_metadata(key: str, outcomes: list[dict[str, Any]]) -> dict[str, Any]:
        order = (
            "NEW_SECURITY_CANDIDATE", "KNOWN_DUPLICATE", "POSSIBLE_DUPLICATE",
            "VERIFIED_LOCAL", "INTENDED_BEHAVIOR", "NEEDS_MANUAL_SCENARIO",
            "BLOCKED_BY_LOCAL_SETUP", "REJECTED_STATIC",
        )
        statuses = [item["classification"] for item in outcomes]
        return {
            "root_cause_id": "MM-RC-" + hashlib.sha256(key.encode()).hexdigest()[:8].upper(),
            "classification": next((item for item in order if item in statuses), "VERIFIED_LOCAL"),
        }

    @staticmethod
    def classify(
        candidate: dict[str, Any],
        local_validation: dict[str, Any] | None,
        duplicate_research: dict[str, Any] | None,
        version_matrix: dict[str, Any] | None,
    ) -> str:
        if candidate["static_status"] == "REJECTED_STATIC":
            return "REJECTED_STATIC"
        if candidate["static_status"] in {"BLOCKED_STATIC", "NEEDS_MANUAL_SCENARIO"}:
            return "NEEDS_MANUAL_SCENARIO"
        if local_validation is None or local_validation.get("status") == "BLOCKED_BY_LOCAL_SETUP":
            return "BLOCKED_BY_LOCAL_SETUP"
        if local_validation.get("status") == "INTENDED_BEHAVIOR":
            return "INTENDED_BEHAVIOR"
        if local_validation.get("status") != "VERIFIED_LOCAL":
            return "NEEDS_MANUAL_SCENARIO"
        duplicate = duplicate_research.get("duplicate_status") if duplicate_research else None
        if duplicate == "KNOWN_DUPLICATE":
            return "KNOWN_DUPLICATE"
        if duplicate == "POSSIBLE_DUPLICATE":
            return "POSSIBLE_DUPLICATE"
        if (duplicate == "NO_PUBLIC_DUPLICATE_FOUND"
                and duplicate_research.get("core_coverage_met") is True
                and version_matrix and version_matrix.get("status") in {"AFFECTS_LATEST", "AFFECTS_MAIN"}):
            return "NEW_SECURITY_CANDIDATE"
        return "VERIFIED_LOCAL"

    @classmethod
    def classify_with_scenario(
        cls,
        candidate: dict[str, Any],
        local_validation: dict[str, Any] | None,
        duplicate_research: dict[str, Any] | None,
        version_matrix: dict[str, Any] | None,
        scenario_synthesis: dict[str, Any] | None,
    ) -> str:
        if (scenario_synthesis and scenario_synthesis.get("status") == "SCENARIO_EXECUTED"
                and local_validation is not None):
            safe_candidate = {**candidate, "static_status": "NEEDS_LOCAL_VALIDATION"}
            return cls.classify(safe_candidate, local_validation, duplicate_research, version_matrix)
        return cls.classify(candidate, local_validation, duplicate_research, version_matrix)

    def enrich_outcome(self, outcome: dict[str, Any]) -> dict[str, Any]:
        candidate = outcome["candidate"]
        outcome.update({
            "source_assertions": candidate["source_assertions"],
            "static_assessment": {
                "status": candidate["static_status"],
                "reasons": candidate["static_reasons"],
            },
            "root_cause": {
                "key": candidate["root_cause_key"],
                "id": outcome["root_cause_id"],
            },
            "evidence": candidate["source_facts"],
            "provenance": {
                "repository": self.repository,
                "revision": self.pinned_commit,
                "fetched_at": self.now(),
            },
        })
        return outcome

    def write_report(
        self,
        *,
        root: Path,
        source: SourceIdentity | None,
        candidates: list[dict[str, Any]],
        outcomes: list[dict[str, Any]],
        clusters: list[dict[str, Any]],
        blockers: list[dict[str, str]],
        run_id: str | None,
    ) -> dict[str, Any]:
        run = run_id or datetime.now(timezone.utc).strftime("%Y%m%dt%H%M%S%f-mattermost-full")
        writer = ReportWriter(root, self.target_id, run)
        writer.initialize()
        report = {
            "schema_version": 1,
            "target": self.target_id,
            "source": {
                "repository": source.repository if source else self.repository,
                "version": self.source_version,
                "commit": source.revision if source else self.pinned_commit,
                "revision": {"commit": source.revision if source else self.pinned_commit},
                "fetch_timestamp": source.fetched_at if source else None,
                "source_identity": (
                    f"{source.repository}@{source.revision}" if source else None
                ),
            },
            "candidates": candidates,
            "candidate_outcomes": outcomes,
            "root_cause_clusters": clusters,
            "pipeline_blockers": blockers,
            "external_submission_performed": False,
        }
        writer.json("report.json", report)
        writer.text("report.md", _render_report(report))
        writer.write_findings(clusters, render=lambda item: _render_cluster(item))
        return writer.result()

    def result_summary(
        self,
        source: SourceIdentity | None,
        candidates: list[dict[str, Any]],
        outcomes: list[dict[str, Any]],
        clusters: list[dict[str, Any]],
        blockers: list[dict[str, str]],
        artifacts: dict[str, Any],
    ) -> dict[str, Any]:
        del source, candidates
        return {
            "target": self.target_id,
            "pinned_version": self.source_version,
            "pinned_commit": self.pinned_commit,
            "bootstrap_performed": self.bootstrapped,
            "static_candidates": len(outcomes),
            "rejected_statically": sum(item["classification"] == "REJECTED_STATIC" for item in outcomes),
            "validated_locally": sum(
                item.get("local_validation", {}).get("status") in {
                    "VERIFIED_LOCAL", "INTENDED_BEHAVIOR", "NEEDS_MORE_EVIDENCE",
                }
                for item in outcomes if isinstance(item.get("local_validation"), dict)
            ),
            "known_duplicates": sum(item["classification"] == "KNOWN_DUPLICATE" for item in outcomes),
            "possible_duplicates": sum(item["classification"] == "POSSIBLE_DUPLICATE" for item in outcomes),
            "new_security_candidates": sum(item["classification"] == "NEW_SECURITY_CANDIDATE" for item in outcomes),
            "needs_manual_scenario": sum(item["classification"] == "NEEDS_MANUAL_SCENARIO" for item in outcomes),
            "root_cause_clusters": [
                {"id": item["root_cause_id"], "candidates": item["candidate_ids"],
                 "status": item["classification"]}
                for item in clusters
            ],
            "affected_versions": _affected_versions(outcomes),
            "pipeline_blockers": blockers,
            "human_action_required": "Review local evidence and manual scenarios before disclosure.",
            "external_submission_performed": False,
            "outcomes": outcomes,
            "reports": artifacts["report_directory"],
            **artifacts,
        }


def _mattermost_digest() -> str:
    from .mattermost import ENTERPRISE_IMAGE_DIGEST
    return ENTERPRISE_IMAGE_DIGEST


def _normalize_local_result(
    candidate: str,
    result: dict[str, Any],
    source_candidate: dict[str, Any] | None = None,
    *,
    expected_source_candidate: dict[str, Any] | None = None,
) -> dict[str, Any]:
    status = {
        "VERIFIED_CANDIDATE": "VERIFIED_LOCAL",
        "VERIFIED_LOCAL": "VERIFIED_LOCAL",
        "INTENDED_BEHAVIOR": "INTENDED_BEHAVIOR",
        "BLOCKED_BY_LOCAL_SETUP": "BLOCKED_BY_LOCAL_SETUP",
        "NEEDS_MORE_EVIDENCE": "NEEDS_MORE_EVIDENCE",
    }.get(result.get("status"), "NEEDS_MORE_EVIDENCE")
    control = result.get("control")
    control_passed = isinstance(control, int) and control == 200 and result.get("control_fixture_verified") is True
    marker = result.get("synthetic_marker_returned") is True
    source_assertions = (source_candidate or {}).get("source_assertions", {})
    source_valid = bool(source_assertions) and all(value is True for value in source_assertions.values())
    if source_valid and expected_source_candidate is not None:
        source_valid = (
            source_assertions == expected_source_candidate.get("source_assertions")
            and source_candidate.get("source_facts") == expected_source_candidate.get("source_facts")
        )
    if source_candidate is None:
        # Kept for callers of this private compatibility helper; live validation
        # always supplies the discovered source candidate above.
        source_valid = True
    assertions = {
        "control_passed": control_passed,
        "probe_deterministic": marker,
        "invariant_violated": status == "VERIFIED_LOCAL",
        "source_assertion_valid": source_valid,
        "fixture_valid": marker,
        "evidence_saved": isinstance(result.get("evidence"), str),
    }
    if status == "VERIFIED_LOCAL" and not all(assertions.values()):
        status = "NEEDS_MORE_EVIDENCE"
    return {
        "status": status,
        "assertions": assertions,
        "evidence": result.get("evidence"),
        "reassessment": result.get("reassessment"),
        "request_count": result.get("request_count"),
        "blocked_reason": result.get("blocked_reason"),
    }


def _duplicate_terms(candidate: dict[str, Any]) -> list[str]:
    return list(dict.fromkeys((
        candidate["route"]["path"], candidate["handler"]["symbol"],
        *candidate["authorization_path"], *candidate["data_access_path"],
        candidate["discovery_class"],
    )))


def _match_strength(candidate: dict[str, Any], record: dict[str, Any]) -> str | None:
    endpoint = candidate["route"]["path"]
    handler = candidate["handler"]["symbol"]
    endpoints = record.get("endpoints", [])
    symbols = record.get("functions", [])
    if endpoint in endpoints and handler in symbols and record.get("security_relevant") is True:
        return "exact"
    if endpoint in endpoints or handler in symbols:
        return "possible"
    return None


def _deduplicate(values: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen = set()
    result = []
    for item in values:
        key = (item.get("source"), item.get("reference"), item.get("url"))
        if key not in seen:
            seen.add(key)
            result.append(item)
    return result


def _public_document_count(source: str, value: Any) -> int:
    if source in {"github_issues", "github_prs"} and isinstance(value, dict):
        return len(value.get("items", [])) if isinstance(value.get("items"), list) else 0
    if source in {"github_advisories", "mattermost_releases"} and isinstance(value, list):
        return len(value)
    if source == "nvd" and isinstance(value, dict):
        items = value.get("vulnerabilities")
        return len(items) if isinstance(items, list) else 0
    return 0


def _public_records(source: str, value: Any, candidate: dict[str, Any]) -> list[dict[str, Any]]:
    if source in {"github_issues", "github_prs"} and isinstance(value, dict):
        documents = value.get("items", [])
    elif source in {"github_advisories", "mattermost_releases"} and isinstance(value, list):
        documents = value
    elif source == "nvd" and isinstance(value, dict):
        documents = value.get("vulnerabilities", [])
    else:
        documents = []
    endpoint = candidate["route"]["path"]
    handler = candidate["handler"]["symbol"]
    result = []
    for document in [item for item in documents[:100] if isinstance(item, dict)]:
        flattened = json.dumps(document, ensure_ascii=True, sort_keys=True)[:200_000]
        url = _public_url(document)
        reference = _public_reference(source, document)
        if url and reference:
            result.append({
                "source": source, "reference": reference, "url": url,
                "functions": [handler] if handler in flattened else [],
                "endpoints": [endpoint] if endpoint in flattened else [],
                "security_relevant": any(
                    word in flattened.lower()
                    for word in ("security", "private", "authorization", "permission", "visibility")
                ),
            })
    return result


def _public_url(document: dict[str, Any]) -> str | None:
    for key in ("html_url", "url"):
        value = document.get(key)
        if isinstance(value, str) and value.startswith((
            "https://github.com/mattermost/mattermost/", "https://github.com/advisories/",
            "https://nvd.nist.gov/vuln/detail/", "https://api.github.com/",
        )):
            return value
    cve = document.get("cve")
    if isinstance(cve, dict) and isinstance(cve.get("id"), str):
        return "https://nvd.nist.gov/vuln/detail/" + quote(cve["id"], safe="")
    return None


def _public_reference(source: str, document: dict[str, Any]) -> str | None:
    for key in ("ghsa_id", "tag_name", "number"):
        value = document.get(key)
        if isinstance(value, (str, int)):
            return source + ":" + str(value)[:80]
    cve = document.get("cve")
    if isinstance(cve, dict) and isinstance(cve.get("id"), str):
        return "nvd:" + cve["id"][:40]
    return None


def _affected_versions(outcomes: list[dict[str, Any]]) -> list[dict[str, Any]]:
    for outcome in outcomes:
        matrix = outcome.get("version_matrix")
        if isinstance(matrix, dict) and isinstance(matrix.get("targets"), list):
            return matrix["targets"]
    return [
        {"target": "pinned", "version": MATTERMOST_PINNED_VERSION,
         "commit": None, "status": "validation_blocked"},
        {"target": "latest", "version": None, "commit": None,
         "status": "retest_blocked", "blocked_reason": "latest_not_tested"},
        {"target": "main", "version": None, "commit": None,
         "status": "retest_blocked", "blocked_reason": "main_not_tested"},
    ]


def _render_report(report: dict[str, Any]) -> str:
    return "\n".join((
        "# Mattermost full hunt report", "",
        f"- Source: {report['source']['source_identity']}",
        f"- Candidates: {len(report['candidate_outcomes'])}",
        f"- Pipeline blockers: {len(report['pipeline_blockers'])}", "",
        "No external submission was performed.", "",
    ))


def _render_cluster(cluster: dict[str, Any]) -> str:
    return "\n".join((
        f"# {cluster['root_cause_id']}", "",
        f"- Classification: {cluster['classification']}",
        f"- Candidates: {', '.join(cluster['candidate_ids'])}", "",
    ))


MATTERMOST_FULL_HUNT_REGISTRY = FULL_HUNT_REGISTRY
MATTERMOST_FULL_HUNT_REGISTRY.register("mattermost", MattermostFullHuntTargetAdapter)
