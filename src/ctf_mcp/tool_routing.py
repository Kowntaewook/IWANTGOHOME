"""Efficiency-only MCP catalog routing for model roles.

Tool visibility is not authorization. Program approval, ScopeGuard-equivalent
policy checks, session grants and request budgets remain authoritative inside
the called tools.
"""

from __future__ import annotations

import json
from typing import Iterable


ROLE_ALIASES = {
    "scout": "Scout",
    "triage": "Triage",
    "cheaptriager": "Triage",
    "cheap_triager": "Triage",
    "portfolio": "Portfolio",
    "portfolioreviewer": "Portfolio",
    "portfolio_reviewer": "Portfolio",
    "investigator": "Investigator",
    "verifier": "Verifier",
    "reporter": "Reporter",
}

PROGRAM_TOOLS = {
    "program_status", "active_program", "program_scope", "scope_check", "program_rules",
}
SCOUT_READ_TOOLS = {
    "scout_status", "list_scout_proposals", "read_scout_proposal",
    "scout_dedup_status", "scout_triage_status", "scout_portfolio_status",
    "scout_feedback_status", "scout_evidence_graph", "scout_experiment_plans",
    "scout_explain_proposal",
}
EVIDENCE_READ_TOOLS = {"health", "read_record", "list_records", "compare_records"}

ROLE_TOOL_ALLOWLISTS = {
    "Scout": PROGRAM_TOOLS | SCOUT_READ_TOOLS | EVIDENCE_READ_TOOLS | {
        "inventory", "read_source_context", "source_search", "source_entrypoints",
        "source_dependency_map", "openapi_summary", "openapi_operations",
    },
    "Triage": PROGRAM_TOOLS | SCOUT_READ_TOOLS | EVIDENCE_READ_TOOLS,
    "Portfolio": PROGRAM_TOOLS | SCOUT_READ_TOOLS | EVIDENCE_READ_TOOLS,
    "Investigator": PROGRAM_TOOLS | SCOUT_READ_TOOLS | EVIDENCE_READ_TOOLS | {
        "inventory", "read_source_context", "source_search", "source_entrypoints",
        "source_dependency_map", "source_diff_review", "openapi_summary",
        "openapi_operations", "openapi_auth_schemes", "openapi_sensitive_operations",
        "openapi_compare_versions", "graphql_document_summary",
        "graphql_operations_from_file", "analyze_har", "analyze_http_log",
        "review_openapi", "analyze_source_map", "review_diff", "review_source",
        "review_source_tree", "compare_session_observations", "web_status",
    },
    "Verifier": PROGRAM_TOOLS | SCOUT_READ_TOOLS | EVIDENCE_READ_TOOLS | {
        "compare_session_observations", "web_status", "resume_research",
    },
    "Reporter": PROGRAM_TOOLS | SCOUT_READ_TOOLS | EVIDENCE_READ_TOOLS | {
        "resume_research", "write_report",
    },
}


def canonical_model_role(role: str | None) -> str | None:
    """Return a known role or None for the legacy/unknown compatibility path."""
    if not isinstance(role, str) or not role.strip():
        return None
    return ROLE_ALIASES.get(role.strip().lower().replace("-", "_"))


def allowed_tool_names(role: str | None, available: Iterable[str]) -> set[str]:
    """Filter known roles; legacy and unknown callers retain the full surface."""
    names = set(available)
    canonical = canonical_model_role(role)
    if canonical is None:
        return names
    return names & ROLE_TOOL_ALLOWLISTS[canonical]


def apply_tool_filter(mcp, role: str | None) -> str | None:
    """Remove unrelated schemas from one server instance using the SDK API."""
    canonical = canonical_model_role(role)
    if canonical is None:
        return None
    current = {tool.name for tool in mcp._tool_manager.list_tools()}
    for name in sorted(current - allowed_tool_names(canonical, current)):
        mcp.remove_tool(name)
    return canonical


def serialized_tool_schema_bytes(tools) -> int:
    payload = []
    for tool in tools:
        if hasattr(tool, "fn") and hasattr(tool, "parameters"):
            value = {"name": tool.name, "description": tool.description,
                     "inputSchema": tool.parameters}
            if tool.output_schema is not None:
                value["outputSchema"] = tool.output_schema
            if tool.annotations is not None:
                value["annotations"] = tool.annotations.model_dump(mode="json", exclude_none=True)
            payload.append(value)
        else:
            payload.append(tool.model_dump(mode="json", exclude_none=True))
    return len(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode())


def tool_schema_metric(role: str, tools) -> dict:
    return {
        "role": role,
        "available_tool_count": len(tools),
        "serialized_tool_schema_bytes": serialized_tool_schema_bytes(tools),
    }
