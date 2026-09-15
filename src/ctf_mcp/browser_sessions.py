"""Persistent SPA observation, with every admitted HTTP request sent by a guarded transport."""
import base64
import hashlib
import http.client
import json
import os
import socket
import ssl
import time
from urllib.parse import urlsplit, urljoin
from .artifacts import header_metadata
from .config import Rejected
from .records import digest
from .redaction import public_url, clean
from .research_control import FileControl
from .research_policy import RequestBudget, origin
from .sessions import SessionStore
from .safety import bounded_tree


def structure(raw):
    """Only JSON key/type structure, never scalar values or GraphQL argument values."""
    if not raw:return {"kind": "empty"}
    try:value = bounded_tree(json.loads(raw))
    except (ValueError, UnicodeError, Rejected):return {"kind": "non_json", "bytes": len(raw)}
    def shape(obj, depth=0):
        if depth > 5:return "depth_limited"
        if isinstance(obj, dict):
            return {str(k)[:64]: shape(v, depth + 1) for k, v in list(obj.items())[:40]}
        if isinstance(obj, list):return {"array_items": [shape(x, depth + 1) for x in obj[:3]], "length": len(obj)}
        return "null" if obj is None else "boolean" if isinstance(obj, bool) else "number" if isinstance(obj, (int, float)) else "string"
    return {"kind": "json", "shape": shape(value)}


class SessionBrowser:
    def __init__(self, settings, grant, job, audit):
        self.settings, self.grant, self.audit = settings, grant, audit
        self.plan = grant.plan
        self.identity = self.plan["identity_label"]
        self.budget = RequestBudget(self.plan)
        self.control = FileControl(settings, job, grant)
        self.observations = []

    def check(self):
        if self.control.is_set():raise Rejected("observation_stopped")
        self.grant.live()
        if time.monotonic() - self.budget.started >= self.plan["seconds"]:raise Rejected("observation_time_limit")

    def event(self, kind, **data):
        if len(self.observations) >= 1000:raise Rejected("observation_event_limit")
        entry = clean({"event": kind, **data})
        self.observations.append(entry)
        self.audit("session_" + kind, {"identity_label": self.identity, **entry})

    def headers(self, url, incoming):
        # Credential values stay inside this process and only reach the approved
        # credential origin. Domain cookies and JS headers do not expand that origin.
        permitted = {"accept", "accept-language", "content-type", "origin", "range", "if-none-match", "if-modified-since"}
        if self.identity != "anonymous" and origin(url) == origin(self.plan["credential_origin"]):
            permitted |= {"authorization", "cookie"}
        out = {k.lower(): v for k, v in incoming.items() if k.lower() in permitted}
        out.update({"accept-encoding": "identity", "connection": "close", "user-agent": "something-finder/0.3 normal-session-observation"})
        return out

    def request(self, url, method="GET", headers=None, body=None, resource="other", websocket=False):
        self.check()
        url = self.grant.check_url(url)
        if method not in {"GET", "HEAD", "OPTIONS", "POST"}:raise Rejected("session_method_blocked")
        body = body or b""
        if len(body) > 65536:raise Rejected("request_body_limit")
        request_shape = structure(body)
        if method == "POST":
            if {"url": url, "sha256": digest(body)} not in self.plan["allowed_post_requests"]:
                raise Rejected("post_body_not_human_approved")
            try:obj = json.loads(body)
            except (ValueError, UnicodeError):obj = None
            if isinstance(obj, dict) and isinstance(obj.get("query"), str):
                from .api_analysis import graphql_view
                parsed = graphql_view(obj["query"].encode(), self.settings.limits, "graphql_operations_from_file")
                operations = parsed["observations"]["operations"]
                from graphql import parse
                from graphql.language.visitor import visit, Visitor
                forbidden = []
                class IntrospectionCheck(Visitor):
                    def enter_field(self, node, *_):
                        if node.name.value in {"__schema", "__type"}:forbidden.append(True)
                visit(parse(obj["query"], max_tokens=50000), IntrospectionCheck())
                if forbidden or any(op["operation"] != "query" for op in operations):raise Rejected("graphql_mutation_or_introspection_blocked")
                resource = "graphql"
                request_shape = {"kind": "graphql", "operations": operations,
                    "variable_shape": structure(json.dumps(obj.get("variables", {})).encode())}
        # GET-based remote introspection is also refused, even if the URL was listed.
        from urllib.parse import parse_qs
        query = parse_qs(urlsplit(url).query).get("query", [])
        if query:
            from graphql import parse
            from graphql.language.ast import OperationDefinitionNode
            doc = parse(query[0], max_tokens=50000)
            if "__schema" in query[0] or "__type" in query[0] or any(isinstance(d, OperationDefinitionNode) and d.operation.value != "query" for d in doc.definitions):
                raise Rejected("graphql_mutation_or_introspection_blocked")
        ips = self.grant.addresses(url)
        outgoing = self.headers(url, headers or {})
        ws_key = None
        if websocket:
            ws_key = base64.b64encode(os.urandom(16)).decode()
            outgoing.update({"upgrade": "websocket", "connection": "Upgrade", "sec-websocket-version": "13", "sec-websocket-key": ws_key})
        u = urlsplit(url);port = u.port or (443 if u.scheme in {"https", "wss"} else 80)
        with self.budget.request():
            self.check()
            self.event("request", url=public_url(url), method=method, resource_type=resource,
                credential_headers_present=any(k in outgoing for k in ("cookie", "authorization")))
            conn = http.client.HTTPConnection(u.hostname, port, timeout=1)
            raw = None
            try:
                raw = socket.create_connection((ips[0], port), timeout=1)
                conn.sock = raw
                if u.scheme in {"https", "wss"}:conn.sock = ssl.create_default_context().wrap_socket(raw, server_hostname=u.hostname)
                self.check()
                conn.request(method, u.path + ("?" + u.query if u.query else ""), body=body or None, headers=outgoing)
                response = conn.getresponse()
                header_list = response.getheaders()
                lower = {k.lower(): v for k, v in header_list}
                if response.status in {301, 302, 303, 307, 308}:
                    if "location" not in lower:raise Rejected("redirect_missing_location")
                    self.grant.check_url(urljoin(url, lower["location"]))
                if websocket:
                    expected = base64.b64encode(hashlib.sha1((ws_key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode()).digest()).decode()
                    valid = response.status == 101 and lower.get("sec-websocket-accept") == expected
                    self.event("response", url=public_url(url), method=method, resource_type="websocket_handshake",
                        status=response.status, handshake_valid=valid, request_shape={"kind": "websocket_handshake"},
                        response_shape={"kind": "handshake_only_no_frames"}, response_security=header_metadata(dict(header_list)))
                    return response.status, [], b""
                if lower.get("content-encoding", "identity").lower() not in {"", "identity"}:raise Rejected("compressed_response_not_supported")
                declared = lower.get("content-length")
                if declared is not None and (not declared.isdigit() or int(declared) > self.plan["max_response_bytes"]):raise Rejected("response_size_limit")
                sse = lower.get("content-type", "").split(";", 1)[0].strip() == "text/event-stream"
                received, pieces, partial = 0, [], False
                while method != "HEAD":
                    self.check()
                    allowance = min(self.plan["max_response_bytes"] - received, self.plan["max_download_bytes"] - self.budget.downloaded)
                    if allowance <= 0:
                        if declared is not None and received == int(declared):break
                        raise Rejected("response_read_limit")
                    try:block = response.read1(min(16384, allowance))
                    except (TimeoutError, socket.timeout):
                        if sse and pieces:partial = True;break
                        raise
                    self.budget.received(len(block));received += len(block)
                    if not block:break
                    pieces.append(block)
                    if sse and received >= min(65536, self.plan["max_response_bytes"]):partial = True;break
                payload = b"".join(pieces)
                if declared is not None and method != "HEAD" and not partial and received != int(declared):raise Rejected("truncated_http_response")
                safe = [(k, v) for k, v in header_list if k.lower() not in {"content-length", "transfer-encoding", "connection", "content-encoding", "alt-svc", "report-to", "nel"}
                    and (k.lower() != "set-cookie" or self.identity != "anonymous" and origin(url) == origin(self.plan["credential_origin"]))]
                self.event("response", url=public_url(url), method=method, resource_type="eventsource" if sse else resource,
                    status=response.status, bytes_read=received, request_shape=request_shape,
                    response_shape=structure(payload) if resource in {"fetch", "xhr", "graphql"} else {"kind": "event_stream_snapshot" if sse else "resource", "partial": partial},
                    response_security=header_metadata(dict(header_list)))
                return response.status, safe, payload
            finally:
                conn.close()
                if raw:raw.close()

    def run(self):
        import asyncio
        return asyncio.run(self._run())

    async def _run(self):
        from playwright.async_api import async_playwright
        store = SessionStore(self.settings)
        violations = []
        with store.locked(self.identity) as directory:
            async with async_playwright() as pw:
                context = await pw.chromium.launch_persistent_context(str(directory), headless=True,
                    java_script_enabled=True, service_workers="block", accept_downloads=False,
                    proxy={"server": "http://127.0.0.1:1"},
                    args=["--proxy-bypass-list=<-loopback>", "--disable-background-networking", "--disable-dns-prefetch", "--disable-quic", "--force-webrtc-ip-handling-policy=disable_non_proxied_udp"])
                try:
                    seed = store.seed(directory)
                    if seed:
                        # Seed is local operator input; filtered to the one approved account origin.
                        approved = origin(self.plan["credential_origin"])
                        cookies = [c for c in seed.get("cookies", []) if isinstance(c, dict) and
                            (approved[1] == c.get("domain", "").lstrip(".") or approved[1].endswith("." + c.get("domain", "").lstrip(".")))]
                        if cookies:await context.add_cookies(cookies)
                        origins = [o for o in seed.get("origins", []) if isinstance(o, dict) and origin(o.get("origin", "")) == approved]
                        # This fixed initializer runs only for the exact supplied origin.
                        await context.add_init_script("(() => { const seed = " + json.dumps(origins) + "; for (const item of seed) { if (location.origin === item.origin) { for (const pair of (item.localStorage || [])) localStorage.setItem(pair.name, pair.value); } } })();")
                    async def route_handler(route):
                        request = route.request
                        try:
                            # all_headers() can wait for extra network metadata while an
                            # intercepted frame is stalled. Use the already available
                            # headers and retrieve cookies locally from this context.
                            incoming = dict(request.headers)
                            if self.identity != "anonymous" and origin(request.url) == origin(self.plan["credential_origin"]):
                                cookies = await context.cookies(request.url)
                                if cookies:incoming["cookie"] = "; ".join(c["name"] + "=" + c["value"] for c in cookies)
                            status, headers, payload = self.request(request.url, request.method,
                                incoming, request.post_data_buffer, request.resource_type)
                            # Playwright accepts newline-separated repeated headers.
                            # In particular, never comma-fold or discard Set-Cookie.
                            fulfilled = {}
                            for key, value in headers:
                                key = key.lower()
                                fulfilled[key] = fulfilled[key] + "\n" + value if key in fulfilled else value
                            await route.fulfill(status=status, headers=fulfilled, body=payload)
                        except Rejected as exc:
                            violations.append(str(exc));self.event("blocked", url=public_url(request.url), resource_type=request.resource_type, reason=str(exc))
                            await route.abort("blockedbyclient")
                        except Exception:
                            violations.append("session_request_failed");self.event("blocked", url=public_url(request.url), reason="session_request_failed")
                            await route.abort("failed")
                    await context.route("**/*", route_handler)
                    async def websocket_handler(ws):
                        try:
                            # Only the normal opening handshake is observed. No payload or frame
                            # forwarding, replay, subscription, mutation or model-supplied messages.
                            cookies = await context.cookies(ws.url.replace("wss:", "https:", 1).replace("ws:", "http:", 1))
                            header = {"cookie": "; ".join(c["name"] + "=" + c["value"] for c in cookies)}
                            self.request(ws.url, headers=header, resource="websocket_handshake", websocket=True)
                        except Rejected as exc:
                            violations.append(str(exc));self.event("blocked", url=public_url(ws.url), resource_type="websocket_handshake", reason=str(exc))
                        except Exception:
                            violations.append("websocket_handshake_failed")
                        finally:await ws.close()
                    await context.route_web_socket("**/*", websocket_handler)
                    final_status = None
                    page = context.pages[0] if context.pages else await context.new_page()
                    page.on("framenavigated", lambda frame: self.event("navigation", url=public_url(frame.url), main_frame=frame == page.main_frame))
                    try:
                        response = await page.goto(self.plan["start_url"], wait_until="domcontentloaded", timeout=self.plan["seconds"] * 1000)
                        final_status = response.status if response else None
                        until = time.monotonic() + self.plan["observation_seconds"]
                        while time.monotonic() < until:
                            self.check();await page.wait_for_timeout(50)
                    except Rejected:raise
                    except Exception:violations.append("page_observation_incomplete")
                    self.check()
                    if seed:
                        with (directory / ".import-applied").open("x") as f:f.write("applied")
                finally:await context.close()
        return {"mode": "spa", "identity_label": self.identity, "final_status": final_status,
            "observations": self.observations, "blocked_or_incomplete": violations,
            "limitations": ["Passive initial navigation and its normal resource/API activity. No automated clicks, forms, endpoint discovery or cross-account replay.",
                "POST requires an exact body hash in the human grant. GraphQL mutations and remote introspection are blocked.",
                "WebSocket opening handshake only; frames are not forwarded. SSE is a bounded snapshot, not a continuing subscription.",
                "Service workers, downloads and direct browser HTTP proxy egress are disabled. This is not an OS destination firewall.",
                "Browser profile isolation is by separate directories and locks, not separate OS users. Storage is private, not encrypted by this application."]}
