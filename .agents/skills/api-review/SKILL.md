---
name: api-review
description: "Review local OpenAPI contracts and GraphQL documents, compare contract versions and correlate with supplied request evidence."
---

# api-review

## Trigger

Review local OpenAPI contracts and GraphQL documents, compare contract versions and correlate with supplied request evidence.

## Prerequisites

Selected local OpenAPI JSON/YAML or GraphQL text, optional before/after paths and stored observations.

## Inputs

Use only the selected files, IDs and context above. Preserve the user's existing authorization and exclusions.

## Available tools

- tool: `openapi_summary`
- tool: `openapi_operations`
- tool: `openapi_auth_schemes`
- tool: `openapi_sensitive_operations`
- tool: `openapi_compare_versions`
- tool: `graphql_document_summary`
- tool: `graphql_operations_from_file`
- tool: `graphql_schema_summary`
- tool: `analyze_har`
- tool: `read_record`

Service dependency: analysis. Check the actual running tools/list; an absent service is a coverage gap.

## Procedure

1. Choose the document-specific parser. Remote references and GraphQL introspection are not executed.
2. Review declared operations, security schemes, field/type names and potentially sensitive declarations.
3. Compare supplied OpenAPI versions with before_path and after_path; distinguish added/removed declarations from deployed behavior.
4. Correlate with existing observations where available. Never send queries or construct authorization probes from a contract.

## Evidence

Document hashes, operation paths/methods, field names/locations, version comparison and observation IDs.

## Common false positives

Contract drift, inherited security, intentionally public operations and schema-only fields do not prove missing enforcement.

## Stop conditions

Malformed documents, parser limits, missing external definitions or a request for remote introspection.

## Output

Return the following review structure with evidence-backed values. It is a report schema, not a tool invocation:

```json
{
  "contract_facts": [],
  "changes": [],
  "observed_correlations": [],
  "concerns": [],
  "counterarguments": [],
  "missing_evidence": []
}
```

## Sources

- https://spec.openapis.org/oas/latest.html
- https://graphql-core-3.readthedocs.io/en/latest/

