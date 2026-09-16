"""Read-only program MCP tools. There are no approval or selection mutations."""
from typing import Any

from .program_store import ProgramStore
from .programs import scope_decision


def register(mcp, settings, readonly):
    def store():
        return ProgramStore(settings.programs_root)

    @mcp.tool(annotations=readonly)
    def program_status(program_id: str | None = None) -> dict[str, Any]:
        """Read approval state and hashes. DRAFT/REVOKED policies grant no network authority."""
        if settings.programs_root is None:return {"state": "DRAFT", "reason": "program_store_not_configured"}
        return store().status(program_id)

    @mcp.tool(annotations=readonly)
    def active_program() -> dict[str, Any]:
        """Read the human-selected active program; cannot select, approve or modify it."""
        return program_status()

    @mcp.tool(annotations=readonly)
    def program_scope() -> dict[str, Any]:
        """Read only the approved canonical active scope. Exact session grants remain necessary."""
        profile, approval = store().selected()
        return {"program_id": profile["program_id"], "sha256": approval["sha256"], "scope": profile["scope"],
                "wildcard_apex_included": False, "wildcard_nested_subdomains_included": True,
                "exclusions_take_precedence": True}

    @mcp.tool(annotations=readonly)
    def scope_check(url: str, method: str = "GET") -> dict[str, Any]:
        """Offline active-policy URL/method decision; no DNS or HTTP. This is not a session grant."""
        profile, approval = store().selected()
        return {**scope_decision(profile, url, method), "approval_id": approval["approval_id"],
                "sha256": approval["sha256"], "session_grant_required": True}

    @mcp.tool(annotations=readonly)
    def program_rules() -> dict[str, Any]:
        """Read approved limits, identities, prohibitions and finding/report classification policy."""
        profile, approval = store().selected()
        return {"program_id": profile["program_id"], "sha256": approval["sha256"],
                **{k: profile[k] for k in ("network_policy", "prohibited_actions", "excluded_finding_categories",
                    "identities", "allow_private_targets", "private_cidrs", "reporting")}}
