---
name: binary-review
description: "Inspect PE/ELF/Mach-O metadata and run fixed bounded Ghidra headless metadata extraction without executing targets."
---

# binary-review

## Trigger

Inspect PE/ELF/Mach-O metadata and run fixed bounded Ghidra headless metadata extraction without executing targets.

## Prerequisites

Authorized local executable, binary profile for Ghidra, optional supplied crash/symbol text and build context.

## Inputs

Use only the selected files, IDs and context above. Preserve the user's existing authorization and exclusions.

## Available tools

- tool: `binary_identify`
- tool: `binary_metadata`
- tool: `binary_imports`
- tool: `binary_exports`
- tool: `binary_strings`
- tool: `ghidra_analyze`
- tool: `ghidra_functions`
- tool: `ghidra_symbols`
- tool: `review_crash`

Service dependency: binary for native parsing; analysis for crash text. Check the actual running tools/list; an absent service is a coverage gap.

## Procedure

1. Identify format/architecture and inspect imports, exports, headers and bounded strings.
2. Use ghidra_analyze only when function/symbol metadata adds value. It creates a fresh temporary project using the bundled fixed script.
3. Read ghidra_functions/ghidra_symbols with the returned analysis record ID; these views do not rerun analysis.
4. Record timeout/partial coverage and inferred function boundaries. Existing Ghidra projects are never imported or rewritten.
5. Correlate supplied crash locations with exact build provenance; keep mitigation recommendations distinct from exploitability.

## Evidence

Input SHA-256, LIEF/Ghidra version, architecture, symbol/entry addresses, partial status and crash text locations.

## Common false positives

Header flags, imports, strings and crashes alone do not prove reachable corruption or impact.

## Stop conditions

Size/time/parser limits, optional tool absent, or a requirement for target execution, debugger attachment or exploit development.

## Output

Return the following review structure with evidence-backed values. It is a report schema, not a tool invocation:

```json
{
  "format": null,
  "metadata": [],
  "functions": [],
  "symbols": [],
  "concerns": [],
  "counterarguments": [],
  "coverage": [],
  "runtime_unverified": true
}
```

## Sources

- https://lief.re/doc/latest/intro.html
- https://github.com/NationalSecurityAgency/ghidra

