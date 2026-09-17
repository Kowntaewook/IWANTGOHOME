# Scout security model

Scout is an offline hypothesis layer in front of the existing IWANTGOHOME research pipeline. Program Profile policy is the source of truth. Website text, source comments, model output, proposal text, scores, and `ExperimentRequest` records grant no authority.

## Authorization boundaries

Scouts contain no HTTP client, socket, Playwright navigation, device command, Frida script, or shell execution. They consume minimized immutable records and approved program metadata only.

A selected proposal is promoted only after all of these checks pass again:

1. the program is still approved and active;
2. its approval ID and canonical profile hash match the proposal;
3. the asset passes the existing program scope matcher, where exclusions win;
4. the finding category is not excluded by program policy;
5. the proposal is not a recorded duplicate;
6. deterministic triage is eligible and over threshold;
7. a portfolio run selected the proposal;
8. at least one immutable analysis record is valid and any program binding matches;
9. `Records.candidate()` accepts the final data.

The resulting candidate starts at `DISCOVERED`. No Scout path can write `CONFIRMED` or bypass candidate validation.

If evidence is insufficient, promotion writes a bounded experiment plan and `NEEDS_MORE_EVIDENCE` state. Its `ExperimentRequest` entries contain `authorization: false`; the plan is non-executable and is never run by Scout. A future observation must independently perform, in order, active approval verification, offline scope and method checks, program budget checks, exact session plan/grant verification, and execution through the existing bounded runner.

Outcome feedback cannot create a positive result. It only observes existing candidate lifecycle records, requires a minimum sample, and adjusts ranking estimates within fixed bounds. `READY_FOR_HUMAN_REVIEW` remains a human-review state and never becomes `CONFIRMED`. Evidence graph support likewise changes evidence-completeness prediction only. Neither input is consulted as an approval, scope, grant, or evidence source of truth.

Temporal comparison stays within immutable records bound to the same Program Profile revision. It compares structure only, emits a hypothesis with both source record IDs, and requires independent runtime evidence before promotion or review readiness.

## Secret handling and discovery quality

Proposals use the existing minimization and redaction layer. Capability candidates retain only redacted URL structure and a fingerprint; token, cookie, password, and authorization values are never copied. Discovered capability URLs are not called.

Every proposal states a security invariant, observed fact, possible relevance, and missing evidence. The rules suppress common unsupported claims: status-only or size-only A/B differences, route existence alone, security-header absence, a version string, a secret-like source string by itself, and a client-side check without a matching mutable-state authorization hint.

## Ledger and recovery

`.scout-ledger.sqlite3` lives beside immutable result records and contains indexes and telemetry only. Tables cover proposals, dedup relations, triage results, portfolio runs/members, promotions, model usage, input evaluations, outcomes, graph snapshots, and experiment plans. SQL statements and table choices are fixed in code; MCP accepts no SQL.

Every material lifecycle transition also has an immutable JSON record. On restart, the ledger synchronizes from those records. If SQLite fails its integrity check, IWANTGOHOME preserves the corrupt file under a unique `.corrupt-*` name, creates a new index, and rebuilds it. Existing evidence, approvals, browser sessions, Codex state, research records, and reports are never migrated, rewritten, or deleted.

The read-only MCP surface is limited to status, proposal listing/reading, dedup/triage/portfolio/feedback status, minimized graph views, experiment-plan views, and gate explanations. It has no approval, execution, promotion, SQL, or shell tool.
