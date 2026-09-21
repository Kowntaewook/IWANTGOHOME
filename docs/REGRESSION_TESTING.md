# Declarative regression testing

After a candidate is confirmed `FIXED` or `REGRESSION`, Core can write a declarative check:

```text
.operator/regressions/<target>/<candidate>/regression.json
.operator/regressions/<target>/<candidate>/README.md
```

The JSON records target and candidate IDs, root cause and scenario IDs, required adapter
capabilities, source assertions, control and probe expectations, the invariant, request
budget, safety policy, immutable known affected and fixed releases, and evidence IDs.

```bash
FINDER_TARGET=sample IWANTTOGOHOME regression list
FINDER_TARGET=sample IWANTTOGOHOME regression inspect CAND-001
FINDER_TARGET=sample IWANTTOGOHOME regression run CAND-001
```

The runner loads only the selected installed target adapter. Before replay it rechecks the
local runtime, safety gate, fixture support, deterministic replay capability, and request
budget. Adapter results must report successful fixture, control, and source assertions;
all final URLs must remain on loopback.

Specs cannot contain commands, shell or Python expressions, subprocess settings, URLs, or
filesystem paths. They identify only adapter reviewed resources. The adapter implements the
fixed route and fixture mapping; Core never turns spec text into executable code.

Disclosure packs optionally include `release-monitor.md` and `regression-status.md` when
local monitor and regression records exist. Packs generated without either record retain
their previous format and behavior.

