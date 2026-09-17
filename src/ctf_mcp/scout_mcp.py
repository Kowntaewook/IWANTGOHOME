"""Fixed-purpose read-only Scout MCP tools; no SQL or mutation arguments."""

from typing import Any

from .scout_controller import ScoutPortfolioController


def register(mcp, settings, readonly):
    def controller():
        return ScoutPortfolioController(settings)

    @mcp.tool(annotations=readonly)
    def scout_status() -> dict[str, Any]:
        """Read Scout counts and lifecycle states. SQLite is a rebuildable index only."""
        return controller().status()

    @mcp.tool(annotations=readonly)
    def list_scout_proposals(program_id: str | None = None, limit: int = 100) -> dict[str, Any]:
        """List sanitized immutable proposal records; proposals are not findings or authorization."""
        return controller().proposals(program_id, limit)

    @mcp.tool(annotations=readonly)
    def read_scout_proposal(proposal_id: str) -> dict[str, Any]:
        """Read one proposal and its immutable dedup, triage, and promotion relations."""
        return controller().proposal(proposal_id)

    @mcp.tool(annotations=readonly)
    def scout_dedup_status() -> dict[str, Any]:
        """Read recorded structural-first dedup relations; accepts no SQL."""
        return controller().dedup_status()

    @mcp.tool(annotations=readonly)
    def scout_triage_status() -> dict[str, Any]:
        """Read deterministic triage telemetry; scores are estimates, not severity."""
        return controller().triage_status()

    @mcp.tool(annotations=readonly)
    def scout_portfolio_status() -> dict[str, Any]:
        """Read portfolio runs and selected members; selection does not promote a candidate."""
        return controller().portfolio_status()

    @mcp.tool(annotations=readonly)
    def scout_feedback_status(program_id: str | None = None) -> dict[str, Any]:
        """Read candidate-outcome calibration records; feedback cannot grant authorization."""
        return controller().feedback_status(program_id)

    @mcp.tool(annotations=readonly)
    def scout_evidence_graph(program_id: str | None = None, proposal_id: str | None = None) -> dict[str, Any]:
        """Read minimized graph snapshots or one proposal neighborhood; source payloads are omitted."""
        return controller().graph_status(program_id, proposal_id)

    @mcp.tool(annotations=readonly)
    def scout_experiment_plans(proposal_id: str | None = None) -> dict[str, Any]:
        """Read non-authorizing bounded experiment plans; this tool never creates or executes one."""
        return controller().experiment_status(proposal_id)

    @mcp.tool(annotations=readonly)
    def scout_explain_proposal(proposal_id: str) -> dict[str, Any]:
        """Explain immutable promotion gates without changing state or authorizing execution."""
        return controller().explain(proposal_id)
