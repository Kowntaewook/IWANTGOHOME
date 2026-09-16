"""Human-only program lifecycle and exact-URL plan drafts."""
import json
import os
from pathlib import Path

from .program_store import ProgramStore
from .programs import program_id, validate_program_plan


def add_commands(sub):
    program = sub.add_parser("program", help="Manage local, human-reviewed program policies")
    program.add_argument("--programs", default=os.environ.get("FINDER_PROGRAMS_ROOT", "/programs"))
    actions = program.add_subparsers(dest="program_action", required=True)
    for action in ("list", "status"):
        actions.add_parser(action)
    for action in ("show", "create", "approve", "revoke", "use"):
        actions.add_parser(action).add_argument("id")
    actions.add_parser("import").add_argument("file")
    plan = sub.add_parser("plan", help="Create and separately approve a narrow session plan")
    plan.add_argument("--programs", default=os.environ.get("FINDER_PROGRAMS_ROOT", "/programs"))
    plans = plan.add_subparsers(dest="plan_action", required=True)
    create = plans.add_parser("create")
    create.add_argument("--program")
    create.add_argument("--identity", default="anonymous", choices=["anonymous", "user_a", "user_b"])
    create.add_argument("--start-url", required=True)
    create.add_argument("--output", help="Exclusive output file; otherwise prints JSON to stdout")
    approve = plans.add_parser("approve")
    approve.add_argument("file")
    approve.add_argument("--grants", default="/grants")


def create_plan(store, ident, identity, start_url):
    from .research_policy import session_plan
    from .web import canonical_url
    if ident is None:profile, approval = store.selected()
    else:profile, approval = store.approved(ident, require_active=True)
    url = canonical_url(start_url, browser=True)
    plan = session_plan({"program": {"program_id": profile["program_id"],
            "approval_id": approval["approval_id"], "sha256": approval["sha256"]},
        "start_url": url, "allowed_urls": [url], "excluded_urls": [], "identity_label": identity,
        **profile["network_policy"], "allow_private_targets": profile["allow_private_targets"],
        "private_cidrs": profile["private_cidrs"]})
    return validate_program_plan(plan, profile)


def run(args):
    store = ProgramStore(args.programs)
    if args.command == "program":
        action = args.program_action
        if action == "list":result = {"programs": store.list()}
        elif action == "status":result = store.status()
        elif action == "show":result = {**store.status(args.id), "profile": store.draft(args.id)}
        elif action == "create":result = store.create({"program_id": program_id(args.id)})
        elif action == "import":result = store.import_file(args.file)
        else:result = getattr(store, action)(args.id)
    elif args.plan_action == "approve":
        from .cli import approve
        approve(args.file, args.grants, programs_root=args.programs, require_program=True)
        return
    else:
        result = create_plan(store, args.program, args.identity, args.start_url)
        if args.output:
            path = Path(args.output)
            with path.open("x", encoding="utf-8") as f:
                json.dump(result, f, indent=2, ensure_ascii=True)
                f.write("\n")
            result = {"state": "DRAFT", "output": str(path), "program": result["program"]}
    print(json.dumps(result, indent=2, ensure_ascii=True))
