---
name: authz-comparison
description: "Compare stored user_a/user_b observations of the same normal action and separate differences from evidence of authorization enforcement."
---

# authz-comparison

## Trigger

Compare stored user_a/user_b observations of the same normal action and separate differences from evidence of authorization enforcement.

## Prerequisites

Two completed web_spa evidence IDs for different account identities; user context confirming the same normal action and expected roles.

## Inputs

Use only the selected files, IDs and context above. Preserve the user's existing authorization and exclusions.

## Available tools

- tool: `compare_session_observations`
- tool: `read_record`
- tool: `record_candidate`

Service dependency: web for comparison; analysis for candidate recording. Check the actual running tools/list; an absent service is a coverage gap.

## Procedure

1. Read both records and compare action, build, time, role and blocked-request coverage.
2. Call compare_session_observations on the stored IDs. It compares structure and does not issue network requests.
3. Explain differences using expected role/data/cache behavior before proposing security relevance.
4. Record only supported candidates, normally NEEDS_MORE_EVIDENCE or READY_FOR_HUMAN_REVIEW. A structural difference cannot establish unauthorized access.

## Evidence

Both record IDs, identity labels, input/grant provenance, matched method/path and structural differences.

## Common false positives

Different legitimate roles, account-owned data, feature flags, caching, timing and blocked dependencies.

## Stop conditions

Different actions or incomplete context prevent meaningful comparison; never swap object IDs, mutate requests or replay across accounts.

## Output

Return the following review structure with evidence-backed values. It is a report schema, not a tool invocation:

```json
{
  "FACTS": [],
  "DIFFERENCES": [],
  "POSSIBLE_SECURITY_RELEVANCE": [],
  "MISSING_EVIDENCE": []
}
```

## Sources

- https://api-security.owasp.org/editions/2023/en/0x11-t10/
