# Optimization architecture

## Baseline

The pre-change Linux/aarch64 baseline on 2026-09-18 used Python 3.14.6 and the same optional dependency profile as the full test image:

- Full tests: 253 passed, 2 skipped, 0 failed in 93,195 ms.
- Synthetic cold Scout orchestration: 87.689 ms.
- The identical warm input: 36.508 ms (7 freshness skips).
- Legacy analysis catalog exposed to every model role: 67 tools, 33,989 serialized bytes.
- The two baseline fixture runs issued 15 measured SQLite reads and 58 writes.

The ignored raw baseline is `.operator/benchmarks/baseline-20260918.json`. Billing/token cost is not exposed by the local CLI and is therefore reported as `not measurable in current environment`, never estimated.

## Identified bottlenecks

The largest avoidable context cost was the same analysis catalog being offered to Scout, triage, portfolio, verification, and reporting work. The warm Scout scan itself took only 3 ms while repeated ledger synchronization, feedback, graph, triage, and portfolio passes kept orchestration at 36.5 ms. Ledger sync replayed already indexed immutable events and opened many small transactions. Temporal comparison also supplied every earlier compatible record when only the previous matching analyzer revision was used. Finally, `src` invalidated Docker dependency, native-tool, and Playwright layers.

## Role tool routing

`FINDER_AGENT_ROLE` optionally selects `Scout`, `Triage`, `Portfolio`, `Investigator`, `Verifier`, or `Reporter`. The server removes unrelated schemas from that instance before tools/list is returned. Unknown, empty, and legacy callers retain the complete historical surface.

This filter is only an efficiency layer. A visible or hidden tool does not grant or revoke authority. Program approval, exact policy-hash binding, scope checks, session grants, RequestBudget controls, and every in-tool validation remain the source of truth. Reporter and verifier catalogs intentionally omit unrelated binary/browser execution and candidate mutation tools.

Tool calls, unique tools used, exposed count, and serialized schema bytes are available in `health.tool_telemetry`. No arguments, session values, tokens, or payloads are recorded.

## Model and effort routing

No model name is mandatory. `FINDER_MODEL_DEFAULT` (with legacy `FINDER_MODEL` fallback) and these optional role overrides are read in one place:

```text
FINDER_MODEL_SCOUT / FINDER_EFFORT_SCOUT
FINDER_MODEL_TRIAGE / FINDER_EFFORT_TRIAGE
FINDER_MODEL_PORTFOLIO / FINDER_EFFORT_PORTFOLIO
FINDER_MODEL_INVESTIGATOR / FINDER_EFFORT_INVESTIGATOR
FINDER_MODEL_VERIFIER / FINDER_EFFORT_VERIFIER
FINDER_MODEL_REPORTER / FINDER_EFFORT_REPORTER
```

The older `CHEAP_TRIAGER` and `PORTFOLIO_REVIEWER` suffixes remain aliases. Defaults are Scout medium, deterministic triage low, portfolio high, investigator high, verifier high, and reporter medium. Invalid effort names are rejected. Missing/unavailable model or CLI support leaves deterministic stages working. Per-run and per-proposal limits are controlled by `FINDER_MAX_MODEL_CALLS_PER_RUN` and `FINDER_MAX_MODEL_CALLS_PER_PROPOSAL`; defaults are 4 and 1.

Portfolio input/model/policy/prompt fingerprints prevent an unchanged optional review from being called again. Cached model output is ranking input only and cannot authorize, confirm, execute, or promote anything.

## Incremental Scout cache

The v2 cache key contains exactly these dimensions:

```text
semantic input record hash
scout type and version
approved program policy hash
relevant bounded Scout configuration hash
```

Storage IDs, provenance paths, and timestamps are excluded from the semantic record hash. Payload or parser changes still miss. `--force` records a bypass decision and re-evaluates. Each scan returns bounded `cache_decisions`; proposal explain output reports the cache key and its policy/config/version bindings. SQLite is only the rebuildable cache/index. Immutable JSON evaluation records remain authoritative.

Temporal Scout receives only the previous compatible revision for the same record kind/analyzer. Known analyzers use a small explicit affected-Scout map. The first revision and every unknown analyzer safely fall back to all offline Scouts. Graph snapshots reuse prior derived nodes/edges only for append-only proposal updates and rebuild from immutable proposals if that cache is malformed.

## Pipeline short circuit

Scout generation and structural dedup remain deterministic. Exact structural duplicates never enter triage or portfolio review. Scope-blocked, excluded, identity-incompatible, over-budget, and low-evidence proposals are classified by deterministic triage and only `ELIGIBLE` proposals can enter optional model review. Records explaining each decision remain immutable. Model output still cannot bypass promotion gates.

## SQLite and memory decisions

The ledger now keeps an `indexed_records` high-water set, reads only unseen JSON events on sync, and replays them in one transaction. Pipeline evaluations, proposals, dedup relations, triage results, and feedback outcomes use batch transactions. Focused indexes cover observed program/scout/status, proposal-relation, selected portfolio member, and five-part cache lookups.

No raw HAR, source-map, browser body, token, or session value is cached globally. Temporal contexts share references to one minimized previous record instead of copying all history. Small bounded Scout concurrency was not enabled: benchmark data showed filesystem durability and orchestration/index work, not Scout CPU, as the bottleneck, while concurrent writers would weaken deterministic ordering.

## Compatibility and migration

Existing immutable records, approvals, browser sessions, Scout ledgers, reports, Codex state, and auth are never removed or reset. New SQLite tables and indexes are additive. Legacy `input_evaluations` remains readable while v2 cache rows are rebuilt from new immutable evaluations. A corrupt derived ledger retains its existing backup-and-rebuild behavior.

The macOS worker rule that omits `RLIMIT_AS` and the macOS `~/Library/Caches/ms-playwright` default remain unchanged.
