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

If evidence is insufficient, promotion writes an `ExperimentRequest` and `NEEDS_MORE_EVIDENCE` state. The request contains `authorization: false` and is never executed by Scout. A future observation must independently perform, in order, active approval verification, offline scope and method checks, program budget checks, exact session plan/grant verification, and execution through the existing bounded runner.

## Secret handling and discovery quality

Proposals use the existing minimization and redaction layer. Capability candidates retain only redacted URL structure and a fingerprint; token, cookie, password, and authorization values are never copied. Discovered capability URLs are not called.

Every proposal states a security invariant, observed fact, possible relevance, and missing evidence. The rules suppress common unsupported claims: status-only or size-only A/B differences, route existence alone, security-header absence, a version string, a secret-like source string by itself, and a client-side check without a matching mutable-state authorization hint.

## Ledger and recovery

`.scout-ledger.sqlite3` lives beside immutable result records and contains indexes and telemetry only. Tables cover proposals, dedup relations, triage results, portfolio runs/members, promotions, model usage, and input evaluations. SQL statements and table choices are fixed in code; MCP accepts no SQL.

Every material lifecycle transition also has an immutable JSON record. On restart, the ledger synchronizes from those records. If SQLite fails its integrity check, IWANTGOHOME preserves the corrupt file under a unique `.corrupt-*` name, creates a new index, and rebuilds it. Existing evidence, approvals, browser sessions, Codex state, research records, and reports are never migrated, rewritten, or deleted.

The read-only MCP surface is limited to status, proposal listing/reading, and dedup/triage/portfolio status. It has no approval, execution, promotion, SQL, or shell tool.
