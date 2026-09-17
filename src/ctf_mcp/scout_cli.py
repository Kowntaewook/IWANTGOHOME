"""Local operator commands for the offline Scout pipeline."""

import json

from .scout_controller import ScoutPortfolioController


def add_commands(sub):
    scout = sub.add_parser("scout", help="Discover and rank hypotheses from approved offline evidence")
    actions = scout.add_subparsers(dest="scout_action", required=True)
    run = actions.add_parser("run")
    run.add_argument("--program")
    run.add_argument("--record")
    run.add_argument("--force", action="store_true")
    run.add_argument("--slots", type=int, default=10)
    actions.add_parser("status")
    proposals = actions.add_parser("proposals")
    proposals.add_argument("--program")
    proposals.add_argument("--limit", type=int, default=100)
    proposal = actions.add_parser("proposal")
    proposal.add_argument("id")
    triage = actions.add_parser("triage")
    triage.add_argument("--program")
    triage.add_argument("--force", action="store_true")
    portfolio = actions.add_parser("portfolio")
    portfolio.add_argument("--program")
    portfolio.add_argument("--slots", type=int, default=10)
    promote = actions.add_parser("promote")
    promote.add_argument("id")
    actions.add_parser("doctor")


def run(args, settings):
    controller = ScoutPortfolioController(settings)
    action = args.scout_action
    if action == "run":
        result = controller.run(program_id=args.program, record_id=args.record,
            force=args.force, portfolio_slots=args.slots)
    elif action == "status": result = controller.status()
    elif action == "proposals": result = controller.proposals(args.program, args.limit)
    elif action == "proposal": result = controller.proposal(args.id)
    elif action == "triage": result = controller.triage(program_id=args.program, force=args.force)
    elif action == "portfolio": result = controller.portfolio(program_id=args.program, slots=args.slots)
    elif action == "promote": result = controller.promote(args.id)
    else: result = controller.doctor()
    print(json.dumps(result, indent=2, ensure_ascii=True))
