---
name: ios-static-review
description: "Review supplied IPA/plist/entitlement declarations and included Mach-O metadata on Linux."
---

# ios-static-review

## Trigger

Review supplied IPA/plist/entitlement declarations and included Mach-O metadata on Linux.

## Prerequisites

Authorized IPA or provided entitlement plist; binary profile for Mach-O parsing; OS/build context when available.

## Inputs

Use only the selected files, IDs and context above. Preserve the user's existing authorization and exclusions.

## Available tools

- tool: `ios_package_info`
- tool: `ios_info_plist`
- tool: `ios_entitlements`
- tool: `ios_url_schemes`
- tool: `ios_ats_config`
- tool: `ios_frameworks`
- tool: `ios_macho_info`

Service dependency: analysis for plist/package views; binary or legacy platform for ios_macho_info. Check the actual running tools/list; an absent service is a coverage gap.

## Procedure

1. Inspect bundle identity, allowlisted Info.plist fields, ATS configuration, URL schemes and included frameworks.
2. Keep provided entitlement plists separate from verified signed entitlements.
3. Use ios_macho_info on an IPA for the selected bundle executable and record encryption/header limits.
4. Identify missing signing/device evidence for the user; Linux does not supply codesign, keychain, simulator or device validation.

## Evidence

IPA/plist hashes, bundle/member names, entitlement keys, ATS declarations and LIEF metadata.

## Common false positives

OS-dependent ATS behavior, legitimate schemes and a signature directory alone do not establish security impact or signature validity.

## Stop conditions

Malformed archive/plist, encrypted code, missing binary parser or a required macOS/device action.

## Output

Return the following review structure with evidence-backed values. It is a report schema, not a tool invocation:

```json
{
  "bundle_facts": [],
  "configuration_concerns": [],
  "counterarguments": [],
  "signing_unverified": true,
  "runtime_unverified": true,
  "evidence_ids": []
}
```

## Sources

- https://developer.apple.com/documentation/bundleresources/information-property-list/nsapptransportsecurity
- https://lief.re/doc/latest/intro.html

