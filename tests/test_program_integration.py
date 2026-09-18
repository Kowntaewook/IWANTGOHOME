"""Local-only program/CLI/MCP/browser integration and preservation checks."""
import asyncio
from dataclasses import asdict
import importlib.util
import json
import os
from pathlib import Path
import pty
import select
import subprocess
import sys
import time
from urllib.parse import urlsplit

import pytest
import yaml
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from ctf_mcp.config import Rejected
from ctf_mcp.program_cli import create_plan
from ctf_mcp.program_store import ProgramStore
from ctf_mcp.records import Records
from ctf_mcp.sessions import SessionStore, compare_sessions
from ctf_mcp.web import Grant, Observer
from conftest import ROOT
from test_programs import (approve_plan, approve_program, candidate, example, program_settings, store)
from test_persistent_sessions import spa_server, run, complete


def local_program(settings, base, ident="local-dev"):
    store = ProgramStore(settings.programs_root)
    store.create({"program_id": ident, "scope": {"in_scope": [{"host": "127.0.0.1", "schemes": ["http", "ws"],
        "ports": [urlsplit(base).port], "paths": ["/*"]}], "out_of_scope": [{"host": "127.0.0.1", "paths": ["/outside"]}]},
        "allow_private_targets": True, "private_cidrs": ["127.0.0.1/32"], "identities": ["anonymous", "user_a", "user_b"]})
    approve_program(store, ident)
    store.use(ident)
    return store


def expanded_plan(store, base, identity="anonymous", start="/page"):
    plan = create_plan(store, None, identity, base + start)
    plan["allowed_urls"] = [base + p for p in (start, "/app.js", "/api", "/xhr", "/frame", "/events")]
    plan["allowed_urls"].append(base.replace("http:", "ws:", 1) + "/ws")
    plan["observation_seconds"] = 1
    return plan


def test_real_program_browser_narrow_plan_candidates_and_no_widening(program_settings, spa_server, tmp_path):
    base, _, seen = spa_server
    store = local_program(program_settings, base)
    plan = create_plan(store, None, "anonymous", base + "/page")
    plan["observation_seconds"] = 1
    record = run(program_settings, approve_plan(program_settings, plan, tmp_path))
    assert {p for p, _, _ in seen} == {"/page"}
    candidates = record["payload"]["result"]["scope_candidates"]
    assert {c["path"] for c in candidates} >= {"/app.js", "/frame"}
    assert "/outside" not in {c["path"] for c in candidates}
    assert all(c["requires_human_approval"] and not c["network_request_sent"] for c in candidates)
    assert plan["allowed_urls"] == [base + "/page"]
    assert record["payload"]["program_id"] == "local-dev"
    assert record["payload"]["matched_scope_rule"]["host"] == "127.0.0.1"


def test_real_program_sessions_ab_restart_cross_program_isolation_and_report(program_settings, spa_server, tmp_path):
    base, _, seen = spa_server
    store = local_program(program_settings, base)
    session_store = SessionStore(program_settings, "local-dev")
    records = {}
    for identity, token in (("user_a", "TOKEN_A"), ("user_b", "TOKEN_B")):
        session_store.import_state(identity, json.dumps({"cookies": [], "origins": [{"origin": base,
            "localStorage": [{"name": "token", "value": token}]}]}).encode())
        first = len(seen)
        records[identity] = run(program_settings, approve_plan(program_settings, expanded_plan(store, base, identity), tmp_path))
        assert any(p == "/api" and h.get("authorization") == "Bearer " + token for p, h, _ in seen[first:])
        assert all(method != "POST" for _, _, method in seen[first:])
    evidence = Records(program_settings.results_root, programs_root=store.root)
    comparison = compare_sessions(evidence, records["user_a"]["id"], records["user_b"]["id"])
    assert comparison["payload"]["program"]["program_id"] == "local-dev"
    first = len(seen)
    run(program_settings, approve_plan(program_settings, expanded_plan(store, base, "user_a"), tmp_path))
    assert any(p == "/api" and h.get("authorization") == "Bearer TOKEN_A" for p, h, _ in seen[first:])
    assert any(p == "/page" and "SYNTHETIC_PERSIST" in h.get("cookie", "") for p, h, _ in seen[first:])
    evidence.candidate(candidate(records["user_a"], program_id="local-dev", asset=base + "/page", finding_category="configuration"))
    report = evidence.report("sample")
    assert report["payload"]["program_metadata"][0]["program_id"] == "local-dev"
    local_program(program_settings, base, "second")
    first = len(seen)
    run(program_settings, approve_plan(program_settings, expanded_plan(store, base, "user_a"), tmp_path))
    assert not any(h.get("authorization") == "Bearer TOKEN_A" for _, h, _ in seen[first:])
    page_headers = [h for p, h, _ in seen[first:] if p == "/page"]
    assert page_headers and all("cookie" not in h for h in page_headers)
    saved = "\n".join(p.read_text() for p in program_settings.results_root.glob("*.json"))
    assert all(secret not in saved for secret in ("TOKEN_A", "TOKEN_B", "PRIVATE_A", "SYNTHETIC_PERSIST"))


@pytest.mark.parametrize("change", ["revoke", "edit", "switch"])
def test_real_running_session_stops_after_program_change(program_settings, spa_server, tmp_path, change):
    base, _, seen = spa_server
    store = local_program(program_settings, base)
    if change == "switch":
        local_program(program_settings, base, "second")
        store.use("local-dev")
    plan = create_plan(store, None, "anonymous", base + "/loop")
    plan["allowed_urls"].append(base + "/tick")
    plan["observation_seconds"] = 6
    observer = Observer(program_settings)
    job = observer.start(approve_plan(program_settings, plan, tmp_path), "spa")["job_id"]
    deadline = time.monotonic() + 10
    while len(seen) < 3 and time.monotonic() < deadline:time.sleep(.05)
    assert len(seen) >= 3
    if change == "revoke":store.revoke("local-dev")
    elif change == "switch":store.use("second")
    else:
        path = store.root / "local-dev/program.json"
        path.write_text(path.read_text() + " ")
    finished = complete(observer, job)
    assert finished["state"] == "failed"
    reason = finished["record"]["payload"]["result"]["error"]
    assert reason in {"program_revoked", "program_changed_reapproval_required", "program_not_active"}
    count = len(seen)
    time.sleep(.3)
    assert len(seen) == count


def test_program_grant_one_use_and_all_read_mode_budgets(program_settings, spa_server, tmp_path):
    base, _, seen = spa_server
    store = local_program(program_settings, base)
    plan = create_plan(store, None, "anonymous", base + "/frame")
    plan["max_requests_per_minute"] = 1
    key = approve_plan(program_settings, plan, tmp_path)
    from ctf_mcp.web import Fetcher
    import threading
    fetcher = Fetcher(Grant(program_settings, key), threading.Event(), lambda *_: None)
    assert fetcher.get(base + "/frame")[0] == 200
    with pytest.raises(Rejected, match="minute_limit"):fetcher.get(base + "/frame")
    observer = Observer(program_settings)
    outcome = complete(observer, observer.start(key, "read")["job_id"])
    assert outcome["state"] == "complete"
    with pytest.raises(Rejected, match="already_used"):observer.start(key, "read")


def run_tty(args, cwd):
    master, slave = pty.openpty()
    process = subprocess.Popen([sys.executable, "-m", "ctf_mcp.cli", *args], stdin=slave, stdout=slave,
        stderr=slave, cwd=cwd, close_fds=True)
    os.close(slave)
    output = b""
    deadline = time.monotonic() + 10
    replied = False
    try:
        while process.poll() is None and time.monotonic() < deadline:
            if select.select([master], [], [], .1)[0]:
                try:output += os.read(master, 65536)
                except OSError:break
            if (b"to approve:" in output or b"to grant:" in output) and not replied:
                import re
                challenge = re.findall(rb"APPROVE(?: PROGRAM)? [a-f0-9]{8}", output)[-1]
                os.write(master, challenge + b"\n")
                replied = True
        assert process.wait(timeout=2) == 0, output.decode(errors="replace")
        assert replied
    finally:
        if process.poll() is None:process.kill();process.wait()
        os.close(master)


def test_actual_cli_tty_approval_use_plan_and_revoke(tmp_path):
    root = tmp_path / "programs"
    path = tmp_path / "policy.json"
    path.write_text(json.dumps(example()))
    base = ["program", "--programs", str(root)]
    def command(*args):
        result = subprocess.run([sys.executable, "-m", "ctf_mcp.cli", *args], cwd=tmp_path,
            capture_output=True, text=True, timeout=10)
        assert result.returncode == 0, result.stderr
        return json.loads(result.stdout)
    assert command(*base, "import", str(path))["state"] == "DRAFT"
    run_tty([*base, "approve", "example"], tmp_path)
    assert command(*base, "show", "example")["state"] == "APPROVED"
    assert command(*base, "use", "example")["state"] == "ACTIVE"
    plan = command("plan", "--programs", str(root), "create", "--program", "example", "--identity", "user_a",
                   "--start-url", "https://foo.example.com/")
    assert plan["allowed_urls"] == ["https://foo.example.com/"]
    plan_path = tmp_path / "session-plan.json"
    plan_path.write_text(json.dumps(plan))
    grants = tmp_path / "grants"
    grants.mkdir()
    run_tty(["plan", "--programs", str(root), "approve", str(plan_path), "--grants", str(grants)], tmp_path)
    saved_grants = list(grants.glob("*.json"))
    assert len(saved_grants) == 1
    assert json.loads(saved_grants[0].read_text())["plan"]["program"] == plan["program"]
    assert command(*base, "status")["state"] == "ACTIVE"
    assert command(*base, "revoke", "example")["state"] == "REVOKED"


def test_official_stdio_program_tools(store, program_settings, tmp_path):
    approve_program(store)
    store.use("example")
    config = tmp_path / "config.json"
    config.write_text(json.dumps(asdict(program_settings), default=str))
    async def run():
        params = StdioServerParameters(command=sys.executable, args=["-m", "ctf_mcp.server"],
            env={**os.environ, "FINDER_CONFIG": str(config)})
        async with asyncio.timeout(15):
            with open(os.devnull, "w") as errors:
                async with stdio_client(params, errlog=errors) as (read, write):
                    async with ClientSession(read, write) as client:
                        await client.initialize()
                        result = await client.call_tool("scope_check", {"url": "https://foo.example.com/", "method": "GET"})
                        assert not result.isError and result.structuredContent["allowed"]
                        assert not result.structuredContent["network_request_sent"]
                        status = await client.call_tool("active_program", {})
                        assert status.structuredContent["state"] == "ACTIVE"
                        store.revoke("example")
                        result = await client.call_tool("scope_check", {"url": "https://foo.example.com/"})
                        assert result.isError
    asyncio.run(run())


def test_docker_cli_routes_readonly_mounts_and_unchanged_named_volumes(tmp_path):
    spec = importlib.util.spec_from_file_location("program_control", ROOT / "scripts/control.py")
    control = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(control)
    policy = tmp_path / "policy.yaml"
    policy.write_text("program_id: example")
    cmd = control.commands("program", ["import", str(policy)], {})[0]
    assert cmd[-4:] == ["operator", "program", "import", "/policy.yaml"]
    assert str(policy) + ":/policy.yaml:ro" in cmd
    for action in ("list", "status", "show", "create", "approve", "revoke", "use"):
        args = [action] if action in {"list", "status"} else [action, "example"]
        assert control.commands("program", args, {})[0][-len(args):] == args
    plan = control.commands("plan", ["create", "--program", "example", "--start-url", "https://foo.example.com/"], {})[0]
    assert "plan" in plan and "create" in plan
    policy_json = tmp_path / "plan.json"
    policy_json.write_text("{}")
    assert control.commands("plan", ["approve", str(policy_json)], {})[0][-4:] == ["operator", "plan", "approve", "/plan.json"]
    config = yaml.safe_load((ROOT / "docker-compose.yml").read_text())
    assert set(config["volumes"]) == {"codex-state-v1", "evidence-v1", "browser-sessions-v1"}
    for role in ("analysis", "observer", "platform", "android", "binary", "android-dynamic", "burp"):
        mounts = [v for v in config["services"][role]["volumes"] if isinstance(v, dict) and v["target"] == "/programs"]
        assert len(mounts) == 1 and mounts[0]["read_only"]
    assert config["services"]["operator"]["network_mode"] == "none"
    codex_volumes = config["services"]["codex"]["volumes"]

    # Preserve the dedicated Codex auth/session volume.
    assert "codex-state-v1:/home/node/.codex" in codex_volumes

    bind_mounts = {
        item["target"]: item
        for item in codex_volumes
        if isinstance(item, dict) and item.get("type") == "bind"
    }

    # Runtime inputs and trusted project instructions are read-only.
    assert bind_mounts["/work/input"]["read_only"] is True
    assert bind_mounts["/etc/codex/skills"]["read_only"] is True
    assert bind_mounts["/work/AGENTS.md"]["read_only"] is True
    assert bind_mounts["/work/prompts"]["read_only"] is True

    # The private Codex state must never be replaced/exposed as a bind mount.
    assert all(
        item.get("target") != "/home/node/.codex"
        for item in codex_volumes
        if isinstance(item, dict)
    )
    linked = tmp_path / "linked"
    linked.symlink_to(tmp_path, target_is_directory=True)
    with pytest.raises(ValueError, match="symlink"):
        control.commands("program", ["import", str(linked / "policy.yaml")], {})


@pytest.mark.parametrize("state", ["DRAFT", "REVOKED"])
def test_draft_and_revoked_profile_block_before_any_network(program_settings, spa_server, tmp_path, state):
    base, _, seen = spa_server
    store = local_program(program_settings, base)
    plan = create_plan(store, None, "anonymous", base + "/page")
    key = approve_plan(program_settings, plan, tmp_path)
    if state == "DRAFT":
        (store.root / "local-dev/approval.json").unlink()
    else:store.revoke("local-dev")
    assert store.status("local-dev")["state"] == state
    with pytest.raises(Rejected):
        Observer(program_settings).start(key, "spa")
    assert not seen
