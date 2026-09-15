---
name: evidence-capture
description: "Assemble provenance and cited immutable analysis records for an existing review without copying raw secrets or overwriting history."
---

# evidence-capture

## Trigger

Assemble provenance and cited immutable analysis records for an existing review without copying raw secrets or overwriting history.

## Prerequisites

Existing analysis IDs and the authorized review question; known identities/revisions where applicable.

## Inputs

Use only the selected files, IDs and context above. Preserve the user's existing authorization and exclusions.

## Available tools

- tool: `list_records`
- tool: `read_record`
- tool: `compare_records`
- tool: `record_candidate`
- tool: `resume_research`

Service dependency: analysis; read_record is also available on optional services. Check the actual running tools/list; an absent service is a coverage gap.

## Procedure

1. Read the referenced records and check kind, analyzer, input hash, UTC time, identity and redaction status.
2. Describe unavailable provenance as unknown; directory inventory may have no aggregate input hash.
3. Link facts to file/line/member or event locations and cite partial failures and audit records.
4. Append a candidate only with actual stored analysis evidence IDs. Revised candidates preserve prior records.

## Evidence

analysis_id, timestamp_utc, input_sha256, analyzer/version, identity_label, tool_result_path and redaction_status where available.

## Common false positives

A saved record can contain a failed or partial operation; parser acceptance is not authenticity or a confirmed finding.

## Stop conditions

Missing records, incompatible comparisons, sensitive values awaiting manual review or invented provenance.

## Output

Return the following review structure with evidence-backed values. It is a report schema, not a tool invocation:

```json
{
  "evidence_ids": [],
  "provenance": [],
  "facts": [],
  "coverage_gaps": [],
  "redaction_gaps": [],
  "review_status": "NEEDS_MORE_EVIDENCE"
}
```

## Sources

- https://modelcontextprotocol.io/docs/draft/tutorials/security/security_best_practices

