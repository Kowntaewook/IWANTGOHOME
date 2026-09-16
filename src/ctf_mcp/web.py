"""Human-granted, one-use normal observations. No discovery, payloads or sessions."""
from dataclasses import dataclass
from datetime import datetime, timezone
import http.client
import ipaddress
import json
import os
import re
import socket
import ssl
import threading
import time
from urllib.parse import urlsplit, urlunsplit, urljoin, unquote, quote, parse_qsl
from uuid import uuid4
from .artifacts import header_metadata
from .config import Rejected
from .records import Records, digest, now, valid_id
from .redaction import public_url, clean
from .safety import SafeRoot

STATE_PATH = re.compile(r"(?:^|/)(?:login|logout|signin|signout|delete|remove|upload|checkout|purchase|payment|pay|billing|account|settings|password|reset|token|session|oauth|callback|unsubscribe)(?:/|$)", re.I)


def canonical_url(value, browser=False):
    if not isinstance(value, str) or len(value) > 2048 or re.search(r"[\x00-\x20\x7f\\]", value):
        raise Rejected("invalid_url")
    try:
        u = urlsplit(value)
        if u.scheme not in ({"http", "https", "ws", "wss"} if browser else {"http", "https"}) or not u.hostname or u.username is not None or u.password is not None or u.fragment:
            raise Rejected("url_scheme_credentials_or_fragment")
        host = u.hostname.encode("idna").decode("ascii").lower()
        if host.endswith(".") or "%" in host or not re.fullmatch(r"[a-z0-9.:-]+", host):
            raise Rejected("invalid_host")
        port = u.port if u.port is not None else (443 if u.scheme in {"https", "wss"} else 80)
        if not 1 <= port <= 65535:raise Rejected("invalid_port")
        path = unquote(u.path or "/", errors="strict")
        if "%" in path or "\\" in path or "//" in path or any(s in {"..", "."} for s in path.split("/")) or re.search(r"[\x00-\x20\x7f]", path):
            raise Rejected("ambiguous_path")
        if STATE_PATH.search(path) and not browser:raise Rejected("state_changing_path_excluded")
        if browser and re.search(r"(?:^|/)(?:logout|signout|delete|remove|purchase|checkout|unsubscribe)(?:/|$)", path, re.I):
            raise Rejected("state_changing_path_excluded")
        if u.query:
            # Explicitly approve ordinary query strings; credential/action-like parameters are refused.
            for k, _ in parse_qsl(u.query, keep_blank_values=True, strict_parsing=True):
                if re.search(r"token|secret|pass|auth|session|cookie|action|delete|redirect|callback|url", k, re.I):
                    raise Rejected("sensitive_or_action_query")
        authority = "[" + host + "]" if ":" in host else host
        if port != (443 if u.scheme in {"https", "wss"} else 80):authority += ":" + str(port)
        return urlunsplit((u.scheme, authority, quote(path, safe="/~._-"), u.query, ""))
    except (ValueError, UnicodeError):
        raise Rejected("invalid_url") from None


def validate_plan(obj):
    if isinstance(obj, dict) and "identity_label" in obj:
        from .research_policy import session_plan
        return session_plan(obj)
    keys = {"start_url", "allowed_urls", "excluded_urls", "private_cidrs", "max_requests", "max_bytes", "max_response_bytes", "seconds"}
    if not isinstance(obj, dict) or set(obj) != keys:raise Rejected("invalid_web_plan_fields")
    for name in ("allowed_urls", "excluded_urls", "private_cidrs"):
        if not isinstance(obj[name], list) or len(obj[name]) > 100:raise Rejected("invalid_web_plan_list")
    plan = dict(obj)
    plan["start_url"] = canonical_url(obj["start_url"])
    plan["allowed_urls"] = sorted({canonical_url(u) for u in obj["allowed_urls"]})
    # Exclusions can include state-changing paths; compare their raw URL and canonical safe forms.
    plan["excluded_urls"] = list(obj["excluded_urls"])
    if not all(isinstance(u, str) and len(u) < 2048 for u in plan["excluded_urls"]):raise Rejected("invalid_exclusions")
    for field, ceiling in (("max_requests", 30), ("max_bytes", 8 * 1024 * 1024), ("max_response_bytes", 2 * 1024 * 1024), ("seconds", 45)):
        if type(plan[field]) is not int or not 1 <= plan[field] <= ceiling:raise Rejected("invalid_web_limit")
    if plan["max_response_bytes"] > plan["max_bytes"]:raise Rejected("invalid_web_byte_limits")
    try:
        nets = [ipaddress.ip_network(c, strict=True) for c in plan["private_cidrs"]]
    except ValueError:raise Rejected("invalid_private_cidr") from None
    if any(n.prefixlen == 0 for n in nets):raise Rejected("private_cidr_too_broad")
    if plan["start_url"] not in plan["allowed_urls"]:raise Rejected("start_url_not_allowlisted")
    return plan


class Grant:
    def __init__(self, settings, grant_id):
        self.settings, self.id = settings, valid_id(grant_id)
        self.reader = SafeRoot(settings.grants_root, settings.limits)
        self.raw = self.reader.read(self.id + ".json", 32768)
        try:
            obj = json.loads(self.raw)
            if set(obj) != {"id", "plan", "expires_at", "approved_at", "approval_method"} or obj["id"] != self.id or obj["approval_method"] != "host_tty_review":
                raise Rejected("invalid_grant")
            self.plan = validate_plan(obj["plan"])
            self.expires = datetime.fromisoformat(obj["expires_at"])
            if self.expires.tzinfo is None:raise Rejected("invalid_grant_expiry")
        except (ValueError, KeyError, TypeError):raise Rejected("invalid_grant") from None
        self.program_profile = None
        if "program" in self.plan:
            from .program_store import ProgramStore
            from .programs import validate_program_plan
            self.program_store = ProgramStore(settings.programs_root)
            self.program_profile = self.program_store.bound(self.plan["program"])
            validate_program_plan(self.plan, self.program_profile)
        self.live()

    def live(self):
        if datetime.now(timezone.utc) >= self.expires:raise Rejected("grant_expired")
        if self.reader.read(self.id + ".json", 32768) != self.raw:raise Rejected("grant_changed_or_revoked")
        if self.program_profile is not None:self.program_store.bound(self.plan["program"])

    def check_url(self, value, method="GET"):
        self.live()
        if value in self.plan["excluded_urls"]:raise Rejected("url_excluded")
        browser = "identity_label" in self.plan
        canonical = canonical_url(value, browser=browser)
        for excluded in self.plan["excluded_urls"]:
            try:
                if canonical_url(excluded, browser=browser) == canonical:raise Rejected("url_excluded")
            except Rejected as exc:
                if str(exc) == "url_excluded":raise
        if canonical not in self.plan["allowed_urls"]:raise Rejected("url_not_approved")
        if self.program_profile is not None:
            from .programs import scope_decision
            if method not in self.plan["allowed_methods"]:raise Rejected("program_method_blocked")
            decision = scope_decision(self.program_profile, canonical, method)
            if not decision["allowed"]:raise Rejected(decision["reason"])
        return canonical

    def addresses(self, value, method="GET"):
        u = urlsplit(self.check_url(value, method))
        # Resolution occurs once per request. Connections below use the checked numeric
        # address, retaining the original hostname only for TLS verification and Host.
        records = socket.getaddrinfo(u.hostname, u.port or (443 if u.scheme in {"https", "wss"} else 80), type=socket.SOCK_STREAM)
        ips = sorted({r[4][0] for r in records})
        if not ips:raise Rejected("dns_no_addresses")
        nets = [ipaddress.ip_network(c) for c in self.plan["private_cidrs"]]
        for value in ips:
            addr = ipaddress.ip_address(value)
            if self.program_profile is not None:
                from .programs import address_allowed
                if not address_allowed(self.program_profile, value):raise Rejected("program_destination_blocked")
            if addr.is_multicast or addr.is_unspecified:raise Rejected("destination_address_blocked")
            if not addr.is_global and not any(addr.version == n.version and addr in n for n in nets):
                raise Rejected("private_destination_not_approved")
        return ips


class Fetcher:
    def __init__(self, grant, stop, audit):
        self.grant, self.stop, self.audit = grant, stop, audit
        self.started, self.requests, self.bytes = time.monotonic(), 0, 0
        self.plan = grant.plan
        from .research_policy import RequestBudget
        self.budget = RequestBudget(self.plan) if "program" in self.plan else None

    def check(self):
        if self.stop.is_set():raise Rejected("observation_stopped")
        self.grant.live()
        if time.monotonic() - self.started >= self.plan["seconds"]:raise Rejected("observation_time_limit")

    def timeout(self):
        self.check()
        return max(0.01, min(2.0, self.plan["seconds"] - (time.monotonic() - self.started)))

    def get(self, url):
        if self.budget:
            with self.budget.request():return self._get(url)
        return self._get(url)

    def _get(self, url):
        self.check()
        if self.requests >= self.plan["max_requests"]:raise Rejected("request_limit")
        url = self.grant.check_url(url)
        ips = self.grant.addresses(url)
        self.check()
        u = urlsplit(url)
        port = u.port or (443 if u.scheme == "https" else 80)
        self.requests += 1
        self.audit("request_started", {"url": public_url(url), "number": self.requests})
        conn = http.client.HTTPConnection(u.hostname, port=port, timeout=self.timeout())
        raw = socket.create_connection((ips[0], port), timeout=self.timeout())
        try:
            conn.sock = raw
            if u.scheme == "https":
                conn.sock = ssl.create_default_context().wrap_socket(raw, server_hostname=u.hostname)
            self.check()
            conn.request("GET", u.path + ("?" + u.query if u.query else ""), headers={"Accept-Encoding": "identity", "User-Agent": "something-finder/0.2 normal-observation", "Connection": "close"})
            conn.sock.settimeout(self.timeout())
            response = conn.getresponse()
            headers = dict(response.getheaders())
            lower = {k.lower(): v for k, v in headers.items()}
            if lower.get("content-encoding", "identity").lower() not in {"", "identity"}:
                raise Rejected("compressed_response_not_supported")
            declared = lower.get("content-length")
            if declared is not None and (not declared.isdigit() or int(declared) > self.plan["max_response_bytes"]):
                raise Rejected("response_size_limit")
            pieces, received = [], 0
            while True:
                self.check()
                allowance = min(self.plan["max_response_bytes"] - received, self.plan["max_bytes"] - self.bytes)
                if allowance <= 0:
                    if declared is not None and received == int(declared):break
                    raise Rejected("response_read_limit")
                # Socket-level timeouts plus frequent stop checks bound slow responses.
                if conn.sock:conn.sock.settimeout(self.timeout())
                block = response.read1(min(16384, allowance))
                self.bytes += len(block); received += len(block)
                if not block:break
                pieces.append(block)
            if declared is not None and received != int(declared):raise Rejected("truncated_http_response")
            self.audit("response_observed", {"url": public_url(url), "status": response.status,
                "bytes_read": received, "security": header_metadata(headers)})
            return response.status, headers, b"".join(pieces)
        finally:
            conn.close()
            raw.close()

    def read(self):
        url = self.plan["start_url"]
        for _ in range(6):
            status, headers, body = self.get(url)
            lower = {k.lower(): v for k, v in headers.items()}
            if status in {301, 302, 303, 307, 308}:
                if "location" not in lower:raise Rejected("redirect_missing_location")
                url = self.grant.check_url(urljoin(url, lower["location"]))
                continue
            return {"mode": "read", "final_status": status, "response_sha256": digest(body),
                    "response_security": header_metadata(headers)}
        raise Rejected("redirect_limit")

    def browser(self):
        from playwright.sync_api import sync_playwright
        violations = []
        with sync_playwright() as pw:
            browser = pw.chromium.launch(headless=True, args=["--disable-background-networking", "--disable-dns-prefetch", "--disable-quic"])
            try:
                context = browser.new_context(java_script_enabled=False, service_workers="block", accept_downloads=False)
                context.route_web_socket("**/*", lambda ws: ws.close())
                def route_handler(route):
                    request = route.request
                    try:
                        self.check()
                        if request.method != "GET":raise Rejected("browser_method_blocked")
                        status, headers, body = self.get(request.url)
                        # Cookie credentials are never copied from the browser to Fetcher.
                        # Strip response cookies, and verify redirect targets before returning.
                        safe = {k: v for k, v in headers.items() if k.lower() not in {"set-cookie", "content-length", "transfer-encoding", "connection", "content-encoding"}}
                        location = next((v for k, v in safe.items() if k.lower() == "location"), None)
                        if location is not None:self.grant.check_url(urljoin(request.url, location))
                        route.fulfill(status=status, headers=safe, body=body)
                    except Rejected as exc:
                        violations.append(str(exc))
                        self.audit("browser_request_blocked", {"url": public_url(request.url), "reason": str(exc)})
                        route.abort("blockedbyclient")
                    except Exception:
                        violations.append("browser_request_failed")
                        self.audit("browser_request_failed", {})
                        route.abort("failed")
                context.route("**/*", route_handler)
                page = context.new_page()
                final_status = None
                try:
                    result = page.goto(self.plan["start_url"], wait_until="load", timeout=self.plan["seconds"] * 1000)
                    final_status = result.status if result else None
                except Exception:
                    violations.append("page_load_incomplete")
                self.check()
                return {"mode": "browser", "final_status": final_status, "blocked_or_incomplete": violations,
                        "limitations": ["Script-free normal document load: JS, service workers, WebSockets, downloads and all interactions disabled.",
                        "Not an authenticated browser session or full SPA observation; no screenshots or page text stored."]}
            finally:
                browser.close()


@dataclass
class Job:
    id: str
    stop: threading.Event
    state: str = "running"
    record_id: str | None = None
    done: threading.Event | None = None


class Observer:
    def __init__(self, settings):
        self.settings, self.records = settings, Records(settings.results_root, settings.limits)
        self.jobs, self.lock = {}, threading.Lock()

    def start(self, grant_id, mode):
        if mode not in {"read", "browser", "spa"}:raise Rejected("invalid_observation_mode")
        grant = Grant(self.settings, grant_id)
        if mode == "spa":
            from .sessions import SessionStore
            if "identity_label" not in grant.plan:raise Rejected("session_plan_required")
            SessionStore(self.settings)
        with self.lock:
            if any(j.state in {"running", "paused"} for j in self.jobs.values()):raise Rejected("observer_busy")
            try:
                with (self.settings.results_root / (".used-grant-" + grant.id)).open("xb") as f:
                    f.write(digest(grant.raw).encode())
            except FileExistsError:raise Rejected("grant_already_used") from None
            if len(self.jobs) >= 100:raise Rejected("job_history_limit_restart_service")
            job = Job(uuid4().hex, threading.Event(), done=threading.Event())
            from .research_control import write_control
            write_control(self.settings, job.id, "running", initial=True)
            self.jobs[job.id] = job
        def run():
            from .engine import run_worker
            result, state = None, "failed"
            try:
                result = run_worker(self.settings, {"operation": "observe", "grant_id": grant.id,
                    "mode": mode, "job_id": job.id}, seconds=grant.plan["seconds"], stop=job.stop)
                state = "complete" if "error" not in result["result"] else "failed"
            except Rejected as exc:
                result = {"analyzer": "web_" + mode,
                    "identity_label": grant.plan.get("identity_label", "anonymous"),
                    "input": {"grant_id": grant.id, "sha256": digest(grant.raw)},
                    "result": {"error": str(exc)},
                    "limitations": ["Worker stopped before final totals; inspect persisted web_audit records for this job."]}
                state = "stopped" if job.stop.is_set() else "failed"
            except Exception:
                result = {"analyzer": "web_" + mode, "result": {"error": "observer_failed"}}
            finally:
                try:
                    self.records.save("web_audit", {"job": job.id, "grant": grant.id,
                        "event": "supervisor_finished", "state": state})
                    if grant.program_profile is not None:result.update(program_evidence(grant))
                    record = self.records.save("analysis", result)
                    job.record_id = record["id"]
                except Exception:
                    state = "failed_to_persist"
                job.state = state
                job.done.set()
        threading.Thread(target=run, daemon=True, name="observation-" + job.id).start()
        result = {"job_id": job.id, "state": job.state}
        if "program" not in grant.plan:
            result["warnings"] = ["DEPRECATED: legacy plan without a program binding; migrate with program/plan CLI."]
        return result

    def status(self, job_id):
        job = self.jobs.get(valid_id(job_id))
        if not job:raise Rejected("unknown_job")
        return {"job_id": job.id, "state": job.state,
                "record": self.records.read(job.record_id) if job.record_id else None}

    def stop(self, job_id):
        job = self.jobs.get(valid_id(job_id))
        if not job:raise Rejected("unknown_job")
        job.stop.set()
        return {"job_id": job.id, "stop_requested": True, "state": job.state}

    def control(self, job_id, state):
        from .research_control import write_control
        job = self.jobs.get(valid_id(job_id))
        if not job:raise Rejected("unknown_job")
        if state not in {"paused", "running", "aborted"}:raise Rejected("invalid_research_control")
        with self.lock:
            if job.done.is_set() or job.stop.is_set():raise Rejected("research_session_terminal")
            write_control(self.settings, job.id, state)
            if state == "aborted":job.stop.set()
            else:job.state = state
        self.records.save("web_audit", {"job": job.id, "event": "research_control", "state": state})
        if state == "aborted":
            if not job.done.wait(5):raise Rejected("abort_pending_do_not_assume_network_stopped")
            return {"job_id": job.id, "state": "aborted", "worker_terminated": True}
        return {"job_id": job.id, "state": job.state,
            "note": "Pause blocks subsequent sends; already transmitted requests cannot be recalled. Runtime budget continues."}


def program_evidence(grant):
    if grant.program_profile is None:return {}
    from .programs import scope_decision
    profile = grant.program_profile
    decision = scope_decision(profile, grant.plan["start_url"], grant.plan["allowed_methods"][0])
    return {"program": grant.plan["program"], "program_id": profile["program_id"],
            "program_name": profile["name"], "asset": public_url(grant.plan["start_url"]),
            "matched_scope_rule": decision["matched_rule"]}


def worker_observe(settings, request):
    # Network/process deadline enforced by the parent even if DNS or Chromium hangs.
    grant = Grant(settings, request["grant_id"])
    records, events = Records(settings.results_root, settings.limits), []
    def audit(kind, payload):
        record = records.save("web_audit", {"job": request["job_id"], "grant": grant.id,
            "event": kind, "details": payload, **program_evidence(grant)})
        events.append(record["id"])
    from .research_control import FileControl
    fetcher = Fetcher(grant, FileControl(settings, request["job_id"], grant), audit)
    audit("observation_started", {"mode": request["mode"], "grant_sha256": digest(grant.raw)})
    try:
        if request["mode"] == "spa":
            from .browser_sessions import SessionBrowser
            browser = SessionBrowser(settings, grant, request["job_id"], audit)
            result = browser.run()
            fetcher.requests, fetcher.bytes = browser.budget.total, browser.budget.downloaded
        else:result = fetcher.read() if request["mode"] == "read" else fetcher.browser()
    except Rejected as exc:
        result = {"error": str(exc)}
        audit("observation_blocked", {"reason": str(exc)})
    except Exception:
        result = {"error": "observation_network_or_browser_failure"}
        audit("observation_failed", {})
    return {"analyzer": "web_" + request["mode"], **program_evidence(grant),
        "identity_label": grant.plan.get("identity_label", "anonymous"),
        "input": {"grant_id": grant.id, "sha256": digest(grant.raw)},
        "result": result, "audit_record_ids": events,
        "requests": fetcher.requests, "bytes_read": fetcher.bytes}
