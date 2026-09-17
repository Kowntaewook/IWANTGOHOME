"""Cross-platform Docker lifecycle. Does not delete containers, volumes or data."""
import argparse
import json
import os
from pathlib import Path
import shutil
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parent.parent
OPTIONAL = (("FINDER_WEB", "web", "observer"), ("FINDER_PLATFORM", "platform", "platform"),
    ("FINDER_ANDROID", "android", "android"), ("FINDER_ANDROID_DYNAMIC", "android-dynamic", "android-dynamic"),
    ("FINDER_BINARY", "binary", "binary"), ("FINDER_BURP", "burp", "burp"))


def operator_file(value):
    path = Path(value).absolute()
    if any(p.is_symlink() for p in (path, *path.parents)) or not path.is_file():
        raise ValueError("Operator inputs must be regular files without symlink ancestors")
    return path


def prepare_operator_dirs():
    for name in (".operator", ".operator/grants", ".operator/programs"):
        path = ROOT / name
        if path.is_symlink():raise ValueError("Operator directories must not be symlinks")
        path.mkdir(parents=True, exist_ok=True, mode=0o755)


def stop_oneoffs(run=subprocess.run):
    # Compose stop may exclude containers created by compose run. Stop only the
    # remaining containers with this exact new project's label, never remove data.
    result = run(["docker", "ps", "--filter", "label=com.docker.compose.project=something-finder-codex",
                  "--format", "{{.ID}}"], check=True, capture_output=True, text=True, timeout=20)
    ids = result.stdout.split()
    if any(not re.fullmatch(r"[0-9a-f]{12,64}", value) for value in ids):
        raise ValueError("Unexpected Docker container ID")
    if ids:run(["docker", "stop", *ids], check=True, timeout=60)


def commands(action, extra, env):
    compose = ["docker", "compose", "--project-directory", str(ROOT), "-p", "something-finder-codex"]
    enabled = []
    selected = {x.strip() for x in env.get("FINDER_PROFILES", "").split(",") if x.strip()}
    if selected - {"default", *(p for _, p, _ in OPTIONAL)}:raise ValueError("Unknown FINDER_PROFILES value")
    for key, profile, service in OPTIONAL:
        if env.get(key) == "1" or profile in selected:
            compose += ["--profile", profile]
            enabled.append(service)
    compose += ["--profile", "runtime"]
    if action == "build":return [compose + ["build", "analysis", "codex"] + enabled]
    if action in {"run", "resume"}:
        return [compose + ["up", "-d", "analysis"] + enabled,
                compose + ["run", "--rm", "codex", action] + extra]
    if action in {"login", "logout", "switch", "status", "doctor"}:
        return [compose + ["run", "--rm", "--no-deps", "codex", action]]
    if action == "stop":return [compose + [part for _, profile, _ in OPTIONAL for part in ("--profile", profile)] + ["stop"]]
    if action == "test":return [compose + ["--profile", "verify", "build", "test"],
                                compose + ["--profile", "verify", "run", "--rm", "test"] + extra]
    if action in {"program", "plan"}:
        cmd = compose + ["--profile", "operator", "run", "--rm", "--no-deps"]
        if hasattr(os, "getuid"):cmd += ["--user", str(os.getuid()) + ":" + str(os.getgid())]
        if action == "program":
            if not extra:raise ValueError("program requires a subcommand")
            operation = extra[0]
            counts = {"list": 1, "status": 1, "show": 2, "create": 2, "import": 2, "approve": 2, "revoke": 2, "use": 2}
            if operation not in counts or len(extra) != counts[operation]:raise ValueError("invalid program command")
            if operation == "import":
                policy = operator_file(extra[1])
                if policy.is_symlink() or not policy.is_file() or policy.suffix.lower() not in {".json", ".yaml", ".yml"}:
                    raise ValueError("program import requires a regular JSON/YAML policy file")
                cmd += ["-v", str(policy) + ":/policy" + policy.suffix.lower() + ":ro"]
                extra = ["import", "/policy" + policy.suffix.lower()]
            return [cmd + ["operator", "program", *extra]]
        if not extra or extra[0] not in {"create", "approve"}:raise ValueError("plan requires create or approve")
        if extra[0] == "approve":
            if len(extra) != 2:raise ValueError("plan approve requires one file")
            plan = operator_file(extra[1])
            if plan.is_symlink() or not plan.is_file():raise ValueError("plan must be a regular file")
            return [cmd + ["-v", str(plan) + ":/plan.json:ro", "operator", "plan", "approve", "/plan.json"]]
        parser = argparse.ArgumentParser(add_help=False)
        parser.add_argument("--program")
        parser.add_argument("--identity", default="anonymous", choices=["anonymous", "user_a", "user_b"])
        parser.add_argument("--start-url", required=True)
        parser.add_argument("--output")
        options = parser.parse_args(extra[1:])
        forwarded = ["create", "--identity", options.identity, "--start-url", options.start_url]
        if options.program:forwarded += ["--program", options.program]
        if options.output:
            output = Path(options.output).absolute()
            if output.exists() or output.is_symlink():raise ValueError("output already exists")
            if any(p.is_symlink() for p in output.parents):raise ValueError("output parent must not be a symlink")
            parent = output.parent.resolve(strict=True)
            cmd += ["-v", str(parent) + ":/plan-output"]
            forwarded += ["--output", "/plan-output/" + output.name]
        return [cmd + ["operator", "plan", *forwarded]]
    if action == "scout":
        if not extra:
            raise ValueError("scout requires a subcommand")
        parser = argparse.ArgumentParser(add_help=False)
        actions = parser.add_subparsers(dest="operation", required=True)
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
        feedback = actions.add_parser("feedback")
        feedback.add_argument("--program")
        graph = actions.add_parser("graph")
        graph.add_argument("--program")
        graph.add_argument("--proposal")
        experiment = actions.add_parser("experiment")
        experiment.add_argument("id")
        explain = actions.add_parser("explain")
        explain.add_argument("id")
        actions.add_parser("doctor")
        options = parser.parse_args(extra)
        for value in (getattr(options, "program", None), getattr(options, "id", None),
                      getattr(options, "record", None), getattr(options, "proposal", None)):
            if value is not None and not re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,63}|[0-9a-f]{32}", value):
                raise ValueError("invalid scout identifier")
        if not 1 <= getattr(options, "slots", 1) <= 100 or not 1 <= getattr(options, "limit", 1) <= 1000:
            raise ValueError("invalid scout limit")
        cmd = compose + ["--profile", "operator", "run", "--rm", "--no-deps"]
        if hasattr(os, "getuid"):cmd += ["--user", str(os.getuid()) + ":" + str(os.getgid())]
        return [cmd + ["operator", "scout", *extra]]
    if action == "session-import":
        if len(extra) not in {2, 4} or extra[0] not in {"user_a", "user_b"}:raise ValueError("session-import requires identity and storage-state file")
        if len(extra) == 4 and extra[2] != "--program":raise ValueError("expected --program ID")
        state = operator_file(extra[1])
        if not state.is_file():raise ValueError("Storage state must be a file")
        return [compose + ["--profile", "operator", "run", "--rm", "--no-deps", "--user", "1000:1000",
            "-v", str(state) + ":/session-import.json:ro", "operator", "session-import", extra[0], "/session-import.json", *extra[2:]]]
    if action in {"approve", "revoke"}:
        if len(extra) != 1:raise ValueError(action + " requires one plan path or grant ID")
        cmd = compose + ["--profile", "operator", "run", "--rm", "--no-deps"]
        if hasattr(os, "getuid"):cmd += ["--user", str(os.getuid()) + ":" + str(os.getgid())]
        if action == "approve":
            plan = operator_file(extra[0])
            if not plan.is_file():raise ValueError("plan must be a regular file")
            cmd += ["-v", str(plan) + ":/plan.json:ro", "operator", "approve", "/plan.json"]
        else:cmd += ["operator", "revoke", extra[0]]
        return [cmd]
    raise ValueError("Unknown action")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("action", nargs="?", default="run", choices=["build", "login", "logout", "switch", "run", "resume", "status", "doctor", "test", "stop", "approve", "revoke", "install", "session-import", "program", "plan", "scout"])
    args, extra = parser.parse_known_args()
    if args.action == "install":
        subprocess.run([sys.executable, str(ROOT / "scripts/install_command.py"), *extra], check=True)
        return
    if not shutil.which("docker"):
        print("Docker CLI not found. Install Docker Engine + Compose v2 (Linux) or Docker Desktop (macOS/Windows). No services or data were changed.", file=sys.stderr)
        raise SystemExit(2)
    # Create only this new project's operator directories; never adopt old volumes.
    try:
        prepare_operator_dirs()
        for cmd in commands(args.action, extra, os.environ):
            subprocess.run(cmd, cwd=ROOT, check=True, shell=False)
        if args.action == "stop":stop_oneoffs()
    except (ValueError, OSError, subprocess.CalledProcessError):
        print("Action failed. Use doctor for credential-free diagnostics; check Docker status and the requested input path.", file=sys.stderr)
        raise SystemExit(2)


if __name__ == "__main__":main()
