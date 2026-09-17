# Scout pipeline

The Scout pipeline discovers review hypotheses from immutable records that already exist in IWANTGOHOME. It does not navigate, replay, scan, upload, invoke a callback, or send any other request.

The flow is:

```text
approved Program Profile
  -> fresh immutable records
  -> six offline Scouts
  -> CandidateProposal records
  -> structural-first semantic dedup
  -> deterministic cheap triage
  -> exploration/exploitation portfolio
  -> guarded promotion to Candidate(DISCOVERED)
```

Every stage writes a new immutable JSON event. A proposal remains distinct from the existing candidate lifecycle. Dedup records relate proposals instead of deleting them. Triage and portfolio scores are estimates and never set a finding severity or confirmation state.

## Inputs and freshness

Scouts read only `analysis` and `session_comparison` records. Program-bound records must match the selected profile's exact `program_id`, `approval_id`, and profile hash. Unbound local static-analysis records may be reviewed under the explicitly selected approved program, but promotion still applies the current program scope and the existing evidence validation.

The ledger records the input record hash, analyzer version, Scout type/version, and evaluation time. An identical input and Scout version is skipped unless `--force` is supplied. Limits are separate from the network request budget:

```text
max proposals per Scout: 20
max proposals per run: 100
max model calls: 4
max runtime: 30 seconds
max promoted candidates per portfolio: 10
```

The current deterministic core makes zero model calls. Optional model review can reorder an already selected, minimized portfolio but cannot authorize, execute, confirm, or promote anything.

## Commands

```bash
IWANTTOGOHOME program use example
IWANTTOGOHOME scout run
IWANTTOGOHOME scout run --program example
IWANTTOGOHOME scout run --record 0123456789abcdef0123456789abcdef
IWANTTOGOHOME scout status
IWANTTOGOHOME scout proposals
IWANTTOGOHOME scout proposal 0123456789abcdef0123456789abcdef
IWANTTOGOHOME scout triage
IWANTTOGOHOME scout portfolio
IWANTTOGOHOME scout promote 0123456789abcdef0123456789abcdef
IWANTTOGOHOME scout doctor
```

`scout run` performs discovery, dedup, triage, and selection. Promotion remains explicit. `scout promote` creates at most one existing-pipeline candidate and starts it at `DISCOVERED`.

## Triage and expected value

Cheap triage considers policy scope, excluded categories, evidence completeness, reproducibility hints, estimated impact, confidence, novelty, required requests, identities, and investigation cost. Its weighted triage score is:

```text
30% estimated impact
25% confidence
15% novelty
20% evidence completeness
10% reproducibility hint
```

The separate expected-value strategy is:

```text
estimated impact * confidence * novelty / max(estimated investigation cost, 0.05)
```

The default portfolio allocates 60% to highest expected value, 20% to high-impact/low-confidence hypotheses, 10% to novel categories, and 10% to seeded exploration. `FINDER_SCOUT_HIGHEST_EV_RATIO`, `FINDER_SCOUT_HIGH_IMPACT_LOW_CONFIDENCE_RATIO`, `FINDER_SCOUT_NOVEL_RATIO`, and `FINDER_SCOUT_EXPLORATION_RATIO` configure ratios and must total 1. Diversity and program caps use `FINDER_SCOUT_MAX_PER_ASSET_CATEGORY` and `FINDER_SCOUT_PER_PROGRAM_CAP`; `FINDER_SCOUT_SEED` makes exploration repeatable.

## Model routing

IWANTGOHOME keeps the existing Codex backend. It does not install or force another provider or model. Each role reads an optional `FINDER_MODEL_<ROLE>` and `FINDER_EFFORT_<ROLE>` setting, falling back to `FINDER_MODEL` and then to the deterministic implementation. Role suffixes are `SCOUT`, `CHEAP_TRIAGER`, `PORTFOLIO_REVIEWER`, `INVESTIGATOR`, `VERIFIER`, and `REPORTER`.

Independent verification should receive the immutable evidence IDs and the stated invariant/hypothesis. It should not be prompted with the full Scout reasoning or an investigator's conclusion as an answer to endorse.
