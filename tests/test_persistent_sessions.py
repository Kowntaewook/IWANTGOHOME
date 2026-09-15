import base64
from dataclasses import replace
from datetime import datetime, timedelta, timezone
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import socket
import threading
import time
from uuid import uuid4
import pytest
from ctf_mcp.config import Rejected
from ctf_mcp.engine import Engine
from ctf_mcp.research_policy import RequestBudget, session_plan
from ctf_mcp.sessions import SessionStore, compare_sessions
from ctf_mcp.web import Observer


@pytest.fixture
def session_settings(settings, tmp_path):
    root = tmp_path / "browser-state";root.mkdir()
    return replace(settings, browser_root=root)


@pytest.fixture
def spa_server():
    seen = []
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_):pass
        def do_OPTIONS(self):
            seen.append((self.path, {k.lower(): v for k, v in self.headers.items()}, "OPTIONS"))
            self.send_response(204);self.send_header("Access-Control-Allow-Origin", self.headers.get("Origin", "*"))
            self.send_header("Access-Control-Allow-Headers", "Authorization,Content-Type")
            self.send_header("Access-Control-Allow-Credentials", "true");self.end_headers()
        def do_POST(self):
            body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
            seen.append((self.path, {k.lower(): v for k, v in self.headers.items()}, "POST"))
            self.reply(b'{"data":{"viewer":{"role":"member"}}}', "application/json")
        def reply(self, data, kind="text/html", status=200, **headers):
            self.send_response(status);self.send_header("Content-Type", kind);self.send_header("Content-Length", str(len(data)))
            self.send_header("Access-Control-Allow-Origin", self.headers.get("Origin", "*"))
            self.send_header("Access-Control-Allow-Credentials", "true")
            self.send_header("X-Content-Type-Options", "nosniff")
            if self.path == "/page":
                self.send_header("Set-Cookie", "persist2=SECOND_SYNTHETIC_COOKIE; Max-Age=3600; Path=/; HttpOnly")
            for key, value in headers.items():self.send_header(key, value)
            self.end_headers()
            try:self.wfile.write(data)
            except (BrokenPipeError, ConnectionResetError):pass
        def do_GET(self):
            seen.append((self.path, {k.lower(): v for k, v in self.headers.items()}, "GET"))
            if self.path == "/ws":
                key = self.headers.get("Sec-WebSocket-Key", "")
                accept = base64.b64encode(hashlib.sha1((key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode()).digest()).decode()
                self.send_response(101);self.send_header("Upgrade", "websocket");self.send_header("Connection", "Upgrade")
                self.send_header("Sec-WebSocket-Accept", accept);self.end_headers();self.close_connection = True;return
            if self.path == "/page":
                self.reply(b'<html><script src="/app.js"></script><iframe src="/frame"></iframe><img src="/outside"></html>',
                    **{"Set-Cookie": "persist=SYNTHETIC_PERSIST; Max-Age=3600; Path=/; HttpOnly"});return
            if self.path == "/app.js":
                script = '''fetch('/api', {headers: {Authorization: 'Bearer ' + localStorage.getItem('token')}});
                    let x = new XMLHttpRequest(); x.open('GET','/xhr'); x.send();
                    new EventSource('/events'); new WebSocket(location.origin.replace('http','ws')+'/ws');
                    fetch('/graphql', {method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({query:'query Normal { viewer { role } }'})});'''
                self.reply(script.encode(), "application/javascript");return
            if self.path == "/events":self.reply(b'data: {"synthetic":"SSE_PRIVATE_VALUE"}\n\n', "text/event-stream");return
            if self.path == "/loop":
                self.reply(b"<script>setInterval(()=>fetch('/tick'),120);</script>");return
            if self.path == "/redirect":
                self.reply(b"", status=302, **{"Location": "/forbidden"});return
            if self.path == "/cross-page":
                cross = "http://127.0.0.1:" + str(second.server_port) + "/cross"
                self.reply(("<script>fetch(" + json.dumps(cross) + ", {credentials:'include',headers:{Authorization:'Bearer CROSS_SECRET'}})</script>").encode());return
            if self.path in {"/api", "/xhr", "/cross", "/tick"}:
                token = self.headers.get("Authorization", "")
                body = b'{"profile":{"name":"PRIVATE_A"},"members":[]}' if "TOKEN_A" in token else b'{"profile":{"name":"PRIVATE_B"}}'
                self.reply(body, "application/json");return
            self.reply(b"<html>frame</html>")
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    second = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threads = [threading.Thread(target=s.serve_forever, daemon=True) for s in (server, second)]
    for t in threads:t.start()
    yield "http://127.0.0.1:" + str(server.server_port), "http://127.0.0.1:" + str(second.server_port), seen
    for s in (server, second):s.shutdown();s.server_close()
    for t in threads:t.join(2)


def grant(settings, base, identity="anonymous", start="/page", **overrides):
    plan = {"identity_label": identity, "start_url": base + start,
        "allowed_urls": [base + p for p in (start, "/app.js", "/api", "/xhr", "/frame", "/events", "/graphql", "/tick")] + [base.replace("http", "ws", 1) + "/ws"],
        "excluded_urls": [], "allow_private_targets": True, "private_cidrs": ["127.0.0.1/32"],
        "max_runtime_seconds": 20, "observation_seconds": 2,
        "allowed_post_requests": [{"url": base + "/graphql", "sha256": hashlib.sha256(b'{"query":"query Normal { viewer { role } }"}').hexdigest()}]}
    plan.update(overrides);plan = session_plan(plan)
    key = uuid4().hex;t = datetime.now(timezone.utc)
    (settings.grants_root / (key + ".json")).write_text(json.dumps({"id": key, "plan": plan,
        "approved_at": t.isoformat(), "expires_at": (t + timedelta(minutes=5)).isoformat(), "approval_method": "host_tty_review"}))
    return key


def complete(observer, job):
    deadline = time.monotonic() + 25
    while time.monotonic() < deadline:
        value = observer.status(job)
        if value["state"] not in {"running", "paused"}:return value
        time.sleep(.05)
    raise AssertionError("SPA observation did not terminate")


def run(settings, key):
    observer = Observer(settings)
    output = complete(observer, observer.start(key, "spa")["job_id"])
    assert output["state"] == "complete", output
    return output["record"]


def test_session_store_path_isolation_and_private_import(session_settings):
    store = SessionStore(session_settings)
    paths = [store.directory(name) for name in ("anonymous", "user_a", "user_b")]
    assert len(set(paths)) == 3 and all(p.stat().st_mode & 0o777 == 0o700 for p in paths)
    with pytest.raises(Rejected):store.directory("../escape")
    (session_settings.browser_root / "user_b").rmdir()
    (session_settings.browser_root / "user_b").symlink_to(session_settings.input_root)
    with pytest.raises(Rejected):store.directory("user_b")
    raw = b'{"cookies":[],"origins":[]}'
    with pytest.raises(Rejected):store.import_state("anonymous", raw)
    store.import_state("user_a", raw)
    with pytest.raises(FileExistsError):store.import_state("user_a", raw)
    with store.locked("user_a"):
        with pytest.raises(Rejected, match="identity_in_use"):
            with store.locked("user_a"):pass


def test_real_persistent_sessions_spa_shapes_and_ab_comparison(session_settings, spa_server):
    base, _, seen = spa_server
    store = SessionStore(session_settings)
    records = {}
    for identity, token in (("user_a", "TOKEN_A"), ("user_b", "TOKEN_B")):
        seed = {"cookies": [{"name": "sid", "value": "COOKIE_" + identity, "domain": "127.0.0.1", "path": "/", "expires": time.time() + 3600, "httpOnly": True, "secure": False, "sameSite": "Lax"}],
            "origins": [{"origin": base, "localStorage": [{"name": "token", "value": token}]}]}
        store.import_state(identity, json.dumps(seed).encode())
        before = len(seen);records[identity] = run(session_settings, grant(session_settings, base, identity))
        observed = seen[before:]
        assert any(path == "/api" and headers.get("authorization") == "Bearer " + token for path, headers, method in observed)
        assert not any(path == "/outside" for path, headers, method in observed)
        events = records[identity]["payload"]["result"]["observations"]
        kinds = {e.get("resource_type") for e in events if e["event"] == "response"}
        assert {"script", "fetch", "xhr", "graphql", "eventsource", "websocket_handshake", "document"} <= kinds, events
        assert any(e["event"] == "navigation" and not e["main_frame"] for e in events)
    before = len(seen)
    repeated = run(session_settings, grant(session_settings, base, "user_a"))
    assert any(path == "/page" and "SYNTHETIC_PERSIST" in headers.get("cookie", "") for path, headers, method in seen[before:])
    assert any(path == "/page" and "SECOND_SYNTHETIC_COOKIE" in headers.get("cookie", "") for path, headers, method in seen[before:])
    assert any(path == "/api" and headers.get("authorization") == "Bearer TOKEN_A" for path, headers, method in seen[before:])
    before = len(seen);anon = run(session_settings, grant(session_settings, base))
    assert all("cookie" not in h and "authorization" not in h for p, h, m in seen[before:])
    all_saved = "\n".join(p.read_text() for p in session_settings.results_root.glob("*.json"))
    assert not any(secret in all_saved for secret in ("TOKEN_A", "TOKEN_B", "COOKIE_user_a", "PRIVATE_A", "PRIVATE_B", "SSE_PRIVATE_VALUE", "SYNTHETIC_PERSIST", "SECOND_SYNTHETIC_COOKIE"))
    comparison = compare_sessions(Engine(session_settings).records, records["user_a"]["id"], records["user_b"]["id"])
    assert set(comparison["payload"]) == {"FACTS", "DIFFERENCES", "POSSIBLE_SECURITY_RELEVANCE", "MISSING_EVIDENCE"}
    assert comparison["payload"]["DIFFERENCES"]


def test_cross_origin_credentials_and_redirect_blocking(session_settings, spa_server):
    base, second, seen = spa_server
    key = grant(session_settings, base, "user_a", start="/cross-page", allowed_urls=[base + "/cross-page", second + "/cross"], allowed_post_requests=[])
    run(session_settings, key)
    cross = [h for p, h, m in seen if p == "/cross" and m == "GET"]
    assert cross and all("authorization" not in h and "cookie" not in h for h in cross)
    run(session_settings, grant(session_settings, base, start="/redirect"))
    assert not any(p == "/forbidden" for p, h, m in seen)


def test_explicit_private_option_and_actual_request_limit(session_settings, spa_server):
    base, _, seen = spa_server
    with pytest.raises(Rejected, match="explicit_allow_private"):
        grant(session_settings, base, allow_private_targets=False)
    key = grant(session_settings, base, private_cidrs=[], allow_private_targets=False)
    record = run(session_settings, key)
    assert not seen and "private_destination_not_approved" in record["payload"]["result"]["blocked_or_incomplete"]
    key = grant(session_settings, base, max_total_requests_per_session=2)
    run(session_settings, key)
    assert len(seen) <= 2


def test_budget_rate_concurrency_bytes_and_runtime():
    plan = {"max_runtime_seconds": 90, "max_requests_per_minute": 2, "max_concurrent_requests": 1,
        "max_total_requests_per_session": 3, "max_download_bytes": 10}
    clock = [0.0];budget = RequestBudget(plan, lambda: clock[0])
    with budget.request():
        with pytest.raises(Rejected, match="concurrent"):
            with budget.request():pass
    with budget.request():pass
    with pytest.raises(Rejected, match="minute"):
        with budget.request():pass
    clock[0] = 61
    with budget.request():pass
    with pytest.raises(Rejected, match="request_limit"):
        with budget.request():pass
    budget.received(10)
    with pytest.raises(Rejected, match="read_limit"):budget.received(1)
    clock[0] = 91
    with pytest.raises(Rejected, match="time_limit"):
        with budget.request():pass


def test_spa_response_budget_exclusions_and_unapproved_post(session_settings, spa_server):
    base, _, seen = spa_server
    small = run(session_settings, grant(session_settings, base, max_response_bytes=32))
    assert "response_size_limit" in small["payload"]["result"]["blocked_or_incomplete"]
    assert {path for path, _, _ in seen} == {"/page"}
    seen.clear()
    record = run(session_settings, grant(session_settings, base, excluded_urls=[base + "/api"], allowed_post_requests=[]))
    assert not any(path in {"/api", "/graphql"} for path, _, _ in seen)
    assert "post_body_not_human_approved" in record["payload"]["result"]["blocked_or_incomplete"]


def test_pause_resume_abort_prevents_further_network(session_settings, spa_server):
    base, _, seen = spa_server;observer = Observer(session_settings)
    key = grant(session_settings, base, start="/loop", observation_seconds=15, max_requests_per_minute=120)
    job = observer.start(key, "spa")["job_id"]
    deadline = time.monotonic() + 10
    while len(seen) < 3 and time.monotonic() < deadline:time.sleep(.05)
    assert len(seen) >= 3
    observer.control(job, "paused")
    time.sleep(.15);count = len(seen);time.sleep(.3)
    assert len(seen) == count
    observer.control(job, "running")
    deadline = time.monotonic() + 3
    while len(seen) == count and time.monotonic() < deadline:time.sleep(.05)
    assert len(seen) > count
    aborted = observer.control(job, "aborted")
    assert aborted["worker_terminated"]
    count = len(seen);time.sleep(.4)
    assert len(seen) == count
    with pytest.raises(Rejected, match="terminal"):observer.control(job, "running")
