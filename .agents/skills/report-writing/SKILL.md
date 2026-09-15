---
name: report-writing
description: "Create evidence-based draft reports from existing candidates for human review, preserving history and uncertainty."
---

# report-writing

## Trigger

Create evidence-based draft reports from existing candidates for human review, preserving history and uncertainty.

## Prerequisites

Project slug and actual evidence/candidate records; intended audience and scope when known.

## Inputs

Use only the selected files, IDs and context above. Preserve the user's existing authorization and exclusions.

## Available tools

- tool: `record_candidate`
- tool: `resume_research`
- tool: `read_record`
- tool: `write_report`
- tool: `compare_records`

Service dependency: analysis. Check the actual running tools/list; an absent service is a coverage gap.

## Procedure

1. Read each cited analysis record and reconcile duplicate/superseded candidates in the narrative.
2. Keep facts, concerns, assumptions, counterarguments, missing_evidence, review_status and remediation separate.
3. Append candidate revisions instead of editing old evidence. READY_FOR_HUMAN_REVIEW is not CONFIRMED.
4. Generate write_report and inspect the returned markdown for privacy, unsupported impact claims and actual validation limits.
5. Return the draft. The tools neither overwrite a report file nor submit externally; local export is the operator's explicit action.

## Evidence

Record IDs, input hashes, UTC/analyzer versions, identities, relevant locations and actually executed checks.

## Common false positives

Version matches, crash flags, declared security or model confidence alone do not establish impact.

## Stop conditions

Evidence absent, disclosure scope unresolved or a request for automatic report submission.

## Output

Return the following review structure with evidence-backed values. It is a report schema, not a tool invocation:

```json
{
  "facts": [],
  "concerns": [],
  "assumptions": [],
  "counterarguments": [],
  "missing_evidence": [],
  "review_status": "READY_FOR_HUMAN_REVIEW",
  "remediation": [],
  "validation_limits": []
}
```

## Sources

- https://owasp.github.io/www-project-web-security-testing-guide/

