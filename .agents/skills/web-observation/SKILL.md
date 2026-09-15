---
name: web-observation
description: "Observe normal page loading under an existing host grant or review supplied HAR/HTTP evidence; inspect blocked and incomplete activity."
---

# web-observation

## Trigger

Observe normal page loading under an existing host grant or review supplied HAR/HTTP evidence; inspect blocked and incomplete activity.

## Prerequisites

Existing host grant for live work, or sanitized local HAR/HTTP input. Select legacy read/browser or persistent SPA deliberately.

## Inputs

Use only the selected files, IDs and context above. Preserve the user's existing authorization and exclusions.

## Available tools

- tool: `observe_web`
- tool: `observe_session`
- tool: `web_status`
- tool: `research_pause`
- tool: `research_resume`
- tool: `research_abort`
- tool: `analyze_har`
- tool: `analyze_http_log`
- tool: `compare_records`
- tool: `write_regression_test`
- tool: `burp_capabilities`
- tool: `burp_proxy_history`
- tool: `burp_saved_requests`
- tool: `burp_websocket_history`

Service dependency: web for observation/control; analysis for local artifacts; optional burp for existing host history. Check the actual running tools/list; an absent service is a coverage gap.

## Procedure

1. For local evidence use its parser. For a grant, read is GET-only and browser is script-free; observe_session enables initial SPA navigation and associated requests.
2. Poll web_status to a terminal state. Inspect audit IDs and blocked_or_incomplete before interpreting page behavior.
3. Review navigation, fetch/XHR, GraphQL shapes, iframe/resource origins, bounded SSE and WebSocket handshake metadata.
4. Use pause/resume for temporary control, abort for termination. Pause cannot recall in-flight requests; abort acknowledges worker termination.
5. Compare stored evidence. write_regression_test checks saved web_read response headers offline; it does not replay requests.
6. If the user selected host Burp history, call burp_capabilities first. Read only discovered supported history tools. Missing remote comparison/OpenAPI/GraphQL functions remain unavailable; use existing local evidence tools instead.

## Evidence

Grant digest, identities, request method/path/status, structural responses, budgets, audit IDs and incomplete dependencies. No raw cookies or bodies.

## Common false positives

Blocked dependencies, caching, content types and application defaults can explain missing requests or headers.

## Stop conditions

Revocation, any budget limit, unapproved redirect or a request for automatic clicks/forms/replay. Do not retry with widened scope.

## Output

Return the following review structure with evidence-backed values. It is a report schema, not a tool invocation:

```json
{
  "observations": [],
  "blocked_or_incomplete": [],
  "security_metadata": [],
  "counterarguments": [],
  "evidence_ids": [],
  "limits": []
}
```

## Sources

- https://playwright.dev/python/docs/network
- https://playwright.dev/python/docs/api/class-browsercontext#browser-context-route-web-socket
