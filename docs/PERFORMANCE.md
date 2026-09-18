# Performance operations

## Commands

```bash
IWANTGOHOME perf status
IWANTGOHOME perf benchmark
IWANTGOHOME perf benchmark --record RECORD_ID
IWANTGOHOME perf compare
IWANTGOHOME perf compare --before BENCHMARK_ID --after BENCHMARK_ID

IWANTGOHOME test fast
IWANTGOHOME test integration
IWANTGOHOME test full
```

`perf benchmark` copies one already sanitized, program-compatible immutable input and the exact active approval into a temporary isolated store. It performs cold and warm local-only runs, deletes the temporary store, and persists only secret-free aggregate metrics as a `performance_benchmark` record. It sends no network request and creates no finding or authorization.

`perf status` reports the latest Scout performance event, cache hit/reduction ratios, model/tool counts, SQLite counts, promotions, and current role schema sizes. `perf compare` compares the latest two benchmark records unless explicit IDs are supplied.

## Telemetry fields

All durations use a monotonic clock and are non-negative milliseconds:

```text
total, Scout, dedup, triage, portfolio, feedback, graph
records scanned/skipped/reanalyzed
proposals created/deduped/triaged/selected
cache hits/misses
model calls/role/effort/failures
tool calls/exposed/used/schema bytes
SQLite reads/writes/transactions
candidate promotions
```

Telemetry APIs accept counters and role labels only. They never accept or store tool arguments, raw inputs, prompts, credentials, authorization tokens, cookies, or browser state.

## Before and after

The same synthetic input was measured before and after the Scout/index changes. Values below are direct local measurements; they are not billing estimates.

| Metric | Before | After optimization checkpoint |
|---|---:|---:|
| Cold orchestration wall time | 87.689 ms | 48.817 ms |
| Warm orchestration wall time | 36.508 ms | 18.425 ms |
| Warm Scout runtime | 3 ms | 3.957 ms |
| Warm cache hits | 7 Scout | 7 Scout + 1 portfolio |
| Cold + warm SQLite core writes | 58 | 43 |
| Warm SQLite core writes / transactions | not separately measurable | 0 / 0 |
| Scout tools / schema | 67 / 33,989 B | 26 / 12,027 B |
| Triage tools / schema | 67 / 33,989 B | 19 / 8,462 B |
| Portfolio tools / schema | 67 / 33,989 B | 19 / 8,462 B |
| Verifier tools / schema | 67 / 33,989 B | 20 / 8,912 B |
| Reporter tools / schema | 67 / 33,989 B | 21 / 9,355 B |
| Model calls | 0 | 0 |
| Billing/token usage | not measurable | not measurable |

The full suite grew from 253 to 262 passing tests and measured 101,045 ms versus the 93,195 ms baseline, so no full-suite runtime improvement is claimed. The final developer fast tier ran 114 tests with 150 integration tests deselected in 15,778 ms.

Run `perf benchmark` after deployment for host-specific values. Do not compare runs with different `fixture_content_hash` values as if they were the same input.

## Test tiers

`fast` contains deterministic Scout, dedup, triage, portfolio, program-policy, offline-record, lifecycle, and performance tests. `integration` contains worker subprocess, MCP stdio, browser/session, native adapter, and program integration tests. `full` runs every test exactly as plain `pytest -q`; tiering does not add skips or weaken timeouts/security assertions.

Parallel pytest execution is not enabled by default. Browser ports, subprocesses, SQLite paths, Docker state, and persistent session resources remain isolated by the existing serial suite. Independent local tests can be sharded by the two markers in CI after each shard receives separate temporary roots.

## Docker layers

Core, platform, device, browser, native Java tool, and test dependencies now live in source-independent stages. `COPY src` and the fast `--no-deps --no-build-isolation` package install occur after dependency and Playwright layers. Base image digests, package constraints, read-only runtime settings, and security controls are unchanged.

## Known limitations and host validation

- Model provider tokens/billing are not exposed locally.
- Docker cache improvement requires a real Docker/BuildKit build comparison.
- This Linux environment cannot validate the macOS worker and Playwright paths; macOS host validation is required.
- Native optional tool execution remains separately reviewed and is skipped when the tools are absent.
