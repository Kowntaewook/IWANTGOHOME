---
name: privacy-review
description: "Check selected evidence and draft exports for credential or personal-data exposure, recognizing limits of heuristic redaction."
---

# privacy-review

## Trigger

Check selected evidence and draft exports for credential or personal-data exposure, recognizing limits of heuristic redaction.

## Prerequisites

Selected sanitized inputs/results and intended output/recipient. Never inspect Codex or browser credential stores.

## Inputs

Use only the selected files, IDs and context above. Preserve the user's existing authorization and exclusions.

## Available tools

- tool: `source_secret_indicators`
- tool: `read_record`
- tool: `record_candidate`
- tool: `write_report`

Service dependency: analysis. Check the actual running tools/list; an absent service is a coverage gap.

## Procedure

1. Prefer metadata that omits bodies, query values and Cookie/Authorization/Set-Cookie values.
2. Use secret indicators for locations/categories, then review selected input outside the model before exposing source excerpts.
3. Review URLs, filenames, arbitrary JSON keys, device tags/names and candidate text that patterns can miss.
4. Keep raw evidence in the user-controlled input area; only reviewed derived output is ready for export. Packaging uses an explicit source allowlist.

## Evidence

Record IDs and redaction categories/locations, with secret values omitted.

## Common false positives

Synthetic keys/public certificates can match patterns; arbitrary identifiers can evade patterns.

## Stop conditions

Sensitive values remain or recipient scope is unresolved. Do not request tokens or claim complete anonymization.

## Output

Return the following review structure with evidence-backed values. It is a report schema, not a tool invocation:

```json
{
  "exposure_categories": [],
  "sanitized_references": [],
  "manual_review_gaps": [],
  "export_ready": false
}
```

## Sources

- https://modelcontextprotocol.io/docs/draft/tutorials/security/security_best_practices
- https://learn.chatgpt.com/docs/auth

