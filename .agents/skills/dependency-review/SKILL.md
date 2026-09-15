---
name: dependency-review
description: "Review local dependency inventories and Docker/Compose/CI/IaC declarations; generate a bounded CycloneDX inventory."
---

# dependency-review

## Trigger

Review local dependency inventories and Docker/Compose/CI/IaC declarations; generate a bounded CycloneDX inventory.

## Prerequisites

Selected lockfile/SBOM/configuration and deployment context. External registries and cloud credentials are unnecessary.

## Inputs

Use only the selected files, IDs and context above. Preserve the user's existing authorization and exclusions.

## Available tools

- tool: `dependency_inventory`
- tool: `dependency_lockfile_summary`
- tool: `dockerfile_review`
- tool: `compose_review`
- tool: `github_actions_review`
- tool: `terraform_review`
- tool: `kubernetes_manifest_review`
- tool: `sbom_generate`

Service dependency: analysis. Check the actual running tools/list; an absent service is a coverage gap.

## Procedure

1. Choose the format-specific view and preserve version/source provenance.
2. Review mounts, privilege, deployment exposure, CI trigger/permissions and unpinned action references using local configuration only.
3. Generate CycloneDX 1.6 inventory from a supported supplied dependency file; it is not a complete build-derived SBOM.
4. Separate inventory, advisory matches supplied by the user, reachability and actual exploitability. The tools do not query a CVE database.
5. Propose narrower privileges and defensive configuration validation without deploying or running package managers.

## Evidence

Lock/config hash, package/version or line/key location, build/runtime scope and deployment assumptions.

## Common false positives

Build-only root, dev profiles, examples, overrides and unused dependencies may not affect production.

## Stop conditions

Unsupported format, missing context or a request for registry/install hooks, Docker socket or live cloud actions.

## Output

Return the following review structure with evidence-backed values. It is a report schema, not a tool invocation:

```json
{
  "inventory": [],
  "configuration_concerns": [],
  "deployment_assumptions": [],
  "advisory_lookup": "not_performed",
  "reachability": "unverified",
  "fixes": []
}
```

## Sources

- https://docs.docker.com/compose/compose-file/
- https://cyclonedx.org/docs/1.6/json/
- https://spdx.github.io/spdx-spec/v2.3/

