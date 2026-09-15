---
name: authenticated-session-review
description: "Review normal authenticated SPA observations using the isolated user_a and user_b persistent browser profiles."
---

# authenticated-session-review

## Trigger

Review normal authenticated SPA observations using the isolated user_a and user_b persistent browser profiles.

## Prerequisites

Web profile, dedicated browser volume, host-imported storage state kept private for the selected identity, and a matching human-reviewed session grant.

## Inputs

Use only the selected files, IDs and context above. Preserve the user's existing authorization and exclusions.

## Available tools

- tool: `observe_session`
- tool: `web_status`
- tool: `research_pause`
- tool: `research_resume`
- tool: `research_abort`
- tool: `read_record`

Service dependency: web. Check the actual running tools/list; an absent service is a coverage gap.

## Procedure

1. Select the grant for anonymous, user_a or user_b. The identity comes from the host grant; tool arguments cannot supply tokens.
2. Have the host operator import storage once through session-import when needed. Never read or paste the storage file or Codex auth volume into the model.
3. Observe initial navigation and its normal activity. Exact approved POST body hashes permit normal queries; mutations and remote introspection stay blocked.
4. Inspect credential presence metadata and blocked origins. Credentials are forwarded only to the grant's credential origin.
5. Record persistence/coverage limitations. Account expiry or blocked app dependencies are missing evidence, not authorization findings.

## Evidence

Identity label, grant hash, observation/audit IDs, structural request/response and tool versions; secret values withheld.

## Common false positives

Expired cookies, role differences, different data and partial page loads can resemble session failures.

## Stop conditions

Missing profile/grant, session in use, login refresh needed, or a request to expose/import credentials through MCP.

## Output

Return the following review structure with evidence-backed values. It is a report schema, not a tool invocation:

```json
{
  "identity_label": null,
  "observed_normal_action": null,
  "evidence_ids": [],
  "session_limitations": [],
  "missing_evidence": []
}
```

## Sources

- https://playwright.dev/python/docs/api/class-browsertype#browser-type-launch-persistent-context
