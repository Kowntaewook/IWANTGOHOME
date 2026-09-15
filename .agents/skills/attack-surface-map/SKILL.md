---
name: attack-surface-map
description: "Map declared entry points and trust boundaries from user-selected local artifacts and stored observations, without discovering or contacting new targets."
---

# attack-surface-map

## Trigger

Map declared entry points and trust boundaries from user-selected local artifacts and stored observations, without discovering or contacting new targets.

## Prerequisites

Authorized source/configuration/package files or existing observation IDs; known system context.

## Inputs

Use only the selected files, IDs and context above. Preserve the user's existing authorization and exclusions.

## Available tools

- tool: `inventory`
- tool: `source_entrypoints`
- tool: `source_dependency_map`
- tool: `openapi_operations`
- tool: `read_record`

Service dependency: analysis. Check the actual running tools/list; an absent service is a coverage gap.

## Procedure

1. Inventory only the selected input subtree and record parser coverage.
2. Extract declared routes, API operations, imports and origins from existing evidence. Keep declared, observed and inferred entries distinct.
3. Group entries by component and expected authentication boundary. Reference file/line or observation IDs.
4. Mark missing source and runtime enforcement evidence. Newly mentioned domains remain uncontacted.

## Evidence

File hashes, source locations, operation method/path, observation identity/time and coverage limits.

## Common false positives

Unused routes, generated code, test fixtures and imports are not necessarily reachable production surfaces.

## Stop conditions

Input/path limits, unsupported formats or a need to crawl, scan or expand the user's target set.

## Output

Return the following review structure with evidence-backed values. It is a report schema, not a tool invocation:

```json
{
  "declared_entries": [],
  "observed_entries": [],
  "inferred_boundaries": [],
  "coverage": [],
  "missing_evidence": []
}
```

## Sources

- https://spec.openapis.org/oas/latest.html
- https://docs.python.org/3/library/ast.html

