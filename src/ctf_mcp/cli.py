"""Operator/local CLI. Approval is deliberately absent from the MCP tool surface."""
import argparse
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import sys
from uuid import uuid4
from .config import Settings, Rejected


def approve(plan_path, grants_root, *, input_stream=None, output_stream=None, programs_root=None, require_program=False):
    from .web import validate_plan
    inp, out = input_stream or sys.stdin, output_stream or sys.stdout
    if not inp.isatty():raise Rejected("approval_requires_human_tty")
    from .program_store import safe_read, ProgramStore
    from .programs import validate_program_plan
    plan = validate_plan(json.loads(safe_read(plan_path, 32768)))
    store = None
    if "program" in plan:
        store = ProgramStore(programs_root or os.environ.get("FINDER_PROGRAMS_ROOT", "/programs"))
        validate_program_plan(plan, store.bound(plan["program"]))
    elif require_program:raise Rejected("program_plan_required")
    else:print("DEPRECATED: unbound legacy plan; use program import/approve/use and plan create. Existing grant rules still apply.", file=out)
    print("Review each exact URL and private-network exception. GET can have application-specific side effects.", file=out)
    print("Approve only assets you may analyze and URLs you know are ordinary, non-mutating reads.", file=out)
    print(json.dumps(plan, indent=2, ensure_ascii=True), file=out)
    grant_id = uuid4().hex
    print("One run; expires in 15 minutes. Type APPROVE " + grant_id[-8:] + " to grant:", file=out, flush=True)
    if inp.readline().strip() != "APPROVE " + grant_id[-8:]:raise Rejected("approval_cancelled")
    if store:validate_program_plan(plan, store.bound(plan["program"]))
    root = Path(grants_root).resolve(strict=True)
    t = datetime.now(timezone.utc)
    grant = {"id": grant_id, "plan": plan, "approved_at": t.isoformat(),
             "expires_at": (t + timedelta(minutes=15)).isoformat(), "approval_method": "host_tty_review"}
    target = root / (grant_id + ".json")
    fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
    # Scope grants contain no credentials. Separate service UID needs read access;
    # only the host operator has write access, and observer mounts them read-only.
    os.fchmod(fd, 0o644)
    with os.fdopen(fd, "w") as f:json.dump(grant, f)
    print("grant_id: " + grant_id, file=out)
    return grant_id


def main():
    parser = argparse.ArgumentParser(description="something-finder local operator tools")
    sub = parser.add_subparsers(dest="command", required=True)
    from .program_cli import add_commands
    add_commands(sub)
    from .scout_cli import add_commands as add_scout_commands
    add_scout_commands(sub)
    grant = sub.add_parser("approve")
    grant.add_argument("plan")
    grant.add_argument("--grants", default="/grants")
    grant.add_argument("--programs", default=os.environ.get("FINDER_PROGRAMS_ROOT", "/programs"))
    revoke = sub.add_parser("revoke")
    revoke.add_argument("grant_id")
    revoke.add_argument("--grants", default="/grants")
    session = sub.add_parser("session-import", help="Import human-provided Playwright storage state privately; never print credential values")
    session.add_argument("identity", choices=["user_a", "user_b"])
    session.add_argument("state_file")
    session.add_argument("--program")
    analysis = sub.add_parser("analyze")
    analysis.add_argument("kind", choices=["inventory", "source", "source_tree", "har", "http_log", "openapi", "source_map", "diff", "dependencies", "infrastructure", "ios", "entitlement", "android", "certificate", "binary", "crash", "packet", "archive"])
    analysis.add_argument("path")
    export = sub.add_parser("export")
    export.add_argument("record_id")
    export.add_argument("--output", required=True)
    args = parser.parse_args()
    try:
        if args.command in {"program", "plan"}:
            from .program_cli import run
            run(args)
        elif args.command == "scout":
            from .scout_cli import run
            run(args, Settings.load())
        elif args.command == "approve":approve(args.plan, args.grants, programs_root=args.programs)
        elif args.command == "session-import":
            from .sessions import SessionStore
            path = Path(args.state_file)
            if path.is_symlink() or not path.is_file() or path.stat().st_size > 2 * 1024 * 1024:raise Rejected("unsafe_session_import_file")
            with path.open("rb") as f:raw = f.read(2 * 1024 * 1024 + 1)
            settings = Settings.load()
            if args.program:
                from .program_store import ProgramStore
                profile, _ = ProgramStore(settings.programs_root).approved(args.program, require_active=True)
                if args.identity not in profile["identities"]:raise Rejected("program_identity_not_allowed")
            print(json.dumps(SessionStore(settings, args.program).import_state(args.identity, raw)))
        elif args.command == "revoke":
            from .records import valid_id
            # Human operator removal of one approval file; never touches evidence/auth.
            (Path(args.grants) / (valid_id(args.grant_id) + ".json")).unlink()
            print("Grant revoked. In-flight workers recheck before reading/sending; stop the job for immediate process termination.")
        elif args.command == "analyze":
            from .engine import Engine
            print(json.dumps(Engine(Settings.load()).analyze(args.kind, args.path), indent=2))
        elif args.command == "export":
            from .records import Records
            settings = Settings.load()
            record = Records(settings.results_root, settings.limits).read(args.record_id)
            with Path(args.output).open("x") as f:json.dump(record, f, indent=2)
    except (Rejected, OSError, ValueError) as exc:
        code = str(exc) if isinstance(exc, Rejected) else "invalid_or_unavailable_operator_input"
        print(json.dumps({"error": code}), file=sys.stderr)
        raise SystemExit(2)


if __name__ == "__main__":main()
