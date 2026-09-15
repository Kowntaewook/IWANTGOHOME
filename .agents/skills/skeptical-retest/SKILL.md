---
name: skeptical-retest
description: "Challenge existing candidate conclusions against stored counterevidence and defensive regressions; keep unverified findings unconfirmed."
---

# skeptical-retest

## Trigger

Challenge existing candidate conclusions against stored counterevidence and defensive regressions; keep unverified findings unconfirmed.

## Prerequisites

Candidate/evidence IDs, original scope, relevant source/config and any actually executed defensive test output.

## Inputs

Use only the selected files, IDs and context above. Preserve the user's existing authorization and exclusions.

## Available tools

- tool: `read_record`
- tool: `read_source_context`
- tool: `compare_records`
- tool: `record_candidate`
- tool: `resume_research`

Service dependency: analysis. Check the actual running tools/list; an absent service is a coverage gap.

## Procedure

1. Read actual cited evidence and identify each assumption between observation and claimed impact.
2. Check variant, role, framework enforcement, reachability, sampling and blocked dependencies.
3. Explain the strongest plausible safe interpretation and the evidence needed to distinguish it.
4. Append a revision with an explicit supported state: DISCOVERED, VALIDATING, NEEDS_MORE_EVIDENCE, REJECTED, BLOCKED_SCOPE, DUPLICATE, NOT_SECURITY_RELEVANT or READY_FOR_HUMAN_REVIEW.
5. Retest means reviewing supplied normal observations or synthetic defensive test results. This skill switch is not an independent agent and does not initiate attack reproduction.

## Evidence

Supporting/counterevidence IDs and hashes, locations, matching revisions and actual test provenance.

## Common false positives

Scanner severity, confidence and multiple model statements do not provide independent confirmation.

## Stop conditions

Missing scope, a need to reproduce exploitation, or pressure to set CONFIRMED.

## Output

Return the following review structure with evidence-backed values. It is a report schema, not a tool invocation:

```json
{
  "observation_check": [],
  "counterarguments": [],
  "missing_evidence": [],
  "review_status": "NEEDS_MORE_EVIDENCE",
  "safe_validation_proposal": []
}
```

## Sources

- https://owasp.github.io/www-project-web-security-testing-guide/

