---
name: business-logic-review
description: "Review documented business rules and stored normal-workflow evidence for inconsistencies and missing enforcement evidence."
---

# business-logic-review

## Trigger

Review documented business rules and stored normal-workflow evidence for inconsistencies and missing enforcement evidence.

## Prerequisites

User-provided expected invariants/workflow, matching source or API contract and existing normal observations.

## Inputs

Use only the selected files, IDs and context above. Preserve the user's existing authorization and exclusions.

## Available tools

- tool: `read_record`
- tool: `source_entrypoints`
- tool: `read_source_context`
- tool: `openapi_operations`
- tool: `compare_records`
- tool: `record_candidate`

Service dependency: analysis. Check the actual running tools/list; an absent service is a coverage gap.

## Procedure

1. Write the expected invariant in concrete terms using supplied requirements, such as which role may approve a record.
2. Map the documented normal states/actions to supplied source/contract and stored observations.
3. Separate demonstrated state transitions from inferred checks, and identify legitimate business exceptions.
4. Recommend a guard or defensive unit test using synthetic state. This role does not initiate payments, races, replay or state-changing network actions.

## Evidence

Requirement source, relevant state/role, source locations and stored normal-observation IDs.

## Common false positives

Undocumented business exceptions, asynchronous state, stale data and role-specific workflows.

## Stop conditions

Expected invariant unknown, evidence from different workflows, or a task requiring active abuse/reproduction.

## Output

Return the following review structure with evidence-backed values. It is a report schema, not a tool invocation:

```json
{
  "expected_invariants": [],
  "observed_normal_flow": [],
  "inconsistencies": [],
  "counterarguments": [],
  "missing_evidence": [],
  "defensive_test_proposals": []
}
```

## Sources

- https://owasp.github.io/www-project-web-security-testing-guide/

