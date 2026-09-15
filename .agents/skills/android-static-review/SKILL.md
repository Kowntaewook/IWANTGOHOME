---
name: android-static-review
description: "Review supplied Android APK/AAB manifests and bounded JADX-derived source without installing or executing the app."
---

# android-static-review

## Trigger

Review supplied Android APK/AAB manifests and bounded JADX-derived source without installing or executing the app.

## Prerequisites

Authorized package or source path; android profile for native decompilation; build variant/SDK context when available.

## Inputs

Use only the selected files, IDs and context above. Preserve the user's existing authorization and exclusions.

## Available tools

- tool: `android_package_info`
- tool: `android_manifest`
- tool: `android_permissions`
- tool: `android_exported_components`
- tool: `android_network_security`
- tool: `android_certificate_info`
- tool: `android_decompile_summary`
- tool: `android_search_code`
- tool: `android_find_urls`
- tool: `android_find_webviews`
- tool: `android_find_deeplinks`
- tool: `read_source_context`

Service dependency: android; legacy platform supports metadata but may report OPTIONAL_TOOL_REQUIRED for JADX. Check the actual running tools/list; an absent service is a coverage gap.

## Procedure

1. Inspect package/manifest facts, SDK, permissions, exported/permission declarations and network-security elements.
2. Review deep links, WebView hints and URL declarations without fetching URLs or opening links.
3. Use fixed JADX only when derived source is necessary. Search is literal and bounded; source paths/lines are derived and may be incomplete.
4. Distinguish certificate metadata from signature verification. Installed apktool/aapt/apksigner utilities are not arbitrary-command MCP tools.
5. Record missing resources, split context and decompilation warnings before suggesting remediation.

## Evidence

Package hash, analyzer/native versions, manifest member/element, source locations and partial-decompilation status.

## Common false positives

Intentional exported components, SDK defaults, debug builds, unused URLs and incomplete decompilation.

## Stop conditions

Malformed/oversized input, unresolved compiled values, missing optional tool or a task requiring app installation/runtime hooks.

## Output

Return the following review structure with evidence-backed values. It is a report schema, not a tool invocation:

```json
{
  "package_facts": [],
  "manifest_concerns": [],
  "source_observations": [],
  "counterarguments": [],
  "missing_resources": [],
  "runtime_unverified": true
}
```

## Sources

- https://developer.android.com/guide/topics/manifest/manifest-intro
- https://github.com/skylot/jadx
- https://androguard.readthedocs.io/en/latest/intro/axml.html

