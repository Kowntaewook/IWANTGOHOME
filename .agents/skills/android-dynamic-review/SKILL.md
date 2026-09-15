---
name: android-dynamic-review
description: "Read limited metadata from an operator-configured host ADB or Frida adapter for an owned test device."
---

# android-dynamic-review

## Trigger

Read limited metadata from an operator-configured host ADB or Frida adapter for an owned test device.

## Prerequisites

android-dynamic profile, host ADB/Frida already running at an explicit operator endpoint, authorized device and selected package.

## Inputs

Use only the selected files, IDs and context above. Preserve the user's existing authorization and exclusions.

## Available tools

- tool: `adb_devices`
- tool: `adb_package_info`
- tool: `adb_logcat_snapshot`
- tool: `frida_devices`
- tool: `frida_process_list`

Service dependency: android-dynamic. Check the actual running tools/list; an absent service is a coverage gap.

## Procedure

1. Discover only devices already listed by the configured host adapter; use returned opaque device IDs.
2. Read selected package metadata or a bounded package-PID log snapshot. All log message text is withheld.
3. Frida permits configured-device/process metadata only. No attach, JS, hooks, spawn, package install or app launch tool exists.
4. Treat HOST_ADAPTER_REQUIRED as unavailable coverage and explain the host prerequisite. Local mock tests do not validate the user's device.

## Evidence

Opaque device ID, package, metadata record hash/time, host adapter status and log level/tag indicators without message values.

## Common false positives

Offline/unauthorized devices, unavailable package PID and connection failure do not describe app security.

## Stop conditions

Missing adapter/device, invalid selected package, timeout, or a request for arbitrary shell/Frida code.

## Output

Return the following review structure with evidence-backed values. It is a report schema, not a tool invocation:

```json
{
  "adapter_status": null,
  "device_id": null,
  "package": null,
  "metadata": [],
  "limitations": [],
  "actual_device_validation": null
}
```

## Sources

- https://developer.android.com/tools/adb
- https://frida.re/docs/home/

