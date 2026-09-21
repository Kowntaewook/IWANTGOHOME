# Release monitoring

IWANTGOHOME can record stable releases exposed by the currently selected external target
plugin and retest eligible local candidates. Core does not know a hosting provider, version
syntax, product route, image, or port.

```bash
FINDER_TARGET=sample IWANTTOGOHOME monitor status
FINDER_TARGET=sample IWANTTOGOHOME monitor check
FINDER_TARGET=sample IWANTTOGOHOME monitor check CAND-001
FINDER_TARGET=sample IWANTTOGOHOME monitor history
```

## Target capability

The adapter's optional `release_provider()` returns a provider that supplies release
metadata and owns revision preparation, bootstrap, validation, and cleanup. A release must
have immutable metadata plus at least one immutable commit, source identity, or image
identity. Floating names such as `latest`, `main`, and `HEAD` are rejected as result
identities.

Core stores private state below `.operator/monitor/<target>/`:

- `state.json` contains known fingerprints and the latest candidate state.
- `history.jsonl` is appended for new release observations and candidate retests.
- `runs/<run-id>/monitor.json` records each check.

An already known fingerprint is not retested. Listing target metadata does not import every
installed plugin; `monitor check` imports only the selected target.

## Automatic retest

A candidate is eligible only when it has a prior verified or report ready state, a
deterministic scenario, valid source assertions, revision support, a passing local safety
gate, and a bounded request count. The target provider prepares an isolated local revision,
bootstraps its fixture, and performs the control and probe.

Results are `AFFECTED`, `FIXED`, `BLOCKED`, `INCONCLUSIVE`, or `REGRESSION`. `FIXED`
requires a valid fixture, successful control, unchanged source assertion, a deterministic
valid probe, local final URLs, and an explicit absence of the original violation. A 404,
empty body, timeout, API error, route change, build failure, fixture failure, or control
failure cannot establish `FIXED`.

`REGRESSION` requires an earlier `FIXED` result for the same root cause, scenario, and
invariant hash. Change correlation records only provider supplied commit range metadata and
uses `PATCH_CORRELATION_AVAILABLE` or `PATCH_CORRELATION_UNAVAILABLE`; it never declares a
security patch.

Metadata checks may read public release metadata. Security validation remains confined to
an authorized local or self hosted runtime. External redirects, credential guessing,
destructive checks, secret retention, and automatic vendor submission are prohibited.

