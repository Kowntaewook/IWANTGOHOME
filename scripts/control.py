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
    if action == "session-import":
        if len(extra) != 2 or extra[0] not in {"user_a", "user_b"}:raise ValueError("session-import requires identity and storage-state file")
        state = Path(extra[1]).resolve(strict=True)
        if not state.is_file():raise ValueError("Storage state must be a file")
        return [compose + ["--profile", "operator", "run", "--rm", "--no-deps", "--user", "1000:1000",
            "-v", str(state) + ":/session-import.json:ro", "operator", "session-import", extra[0], "/session-import.json"]]
    if action in {"approve", "revoke"}:
        if len(extra) != 1:raise ValueError(action + " requires one plan path or grant ID")
        cmd = compose + ["--profile", "operator", "run", "--rm", "--no-deps"]
        if hasattr(os, "getuid"):cmd += ["--user", str(os.getuid()) + ":" + str(os.getgid())]
        if action == "approve":
            plan = Path(extra[0]).resolve(strict=True)
            if not plan.is_file():raise ValueError("plan must be a regular file")
            cmd += ["-v", str(plan) + ":/plan.json:ro", "operator", "approve", "/plan.json"]
        else:cmd += ["operator", "revoke", extra[0]]
        return [cmd]
    raise ValueError("Unknown action")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("action", nargs="?", default="run", choices=["build", "login", "logout", "switch", "run", "resume", "status", "doctor", "test", "stop", "approve", "revoke", "install", "session-import"])
    args, extra = parser.parse_known_args()
    if args.action == "install":
        subprocess.run([sys.executable, str(ROOT / "scripts/install_command.py"), *extra], check=True)
        return
    if not shutil.which("docker"):
        print("Docker CLI not found. Install Docker Engine + Compose v2 (Linux) or Docker Desktop (macOS/Windows). No services or data were changed.", file=sys.stderr)
        raise SystemExit(2)
    # Create only this new project's operator directories; never adopt old volumes.
    (ROOT / ".operator/grants").mkdir(parents=True, exist_ok=True, mode=0o755)
    try:
        for cmd in commands(args.action, extra, os.environ):
            subprocess.run(cmd, cwd=ROOT, check=True, shell=False)
        if args.action == "stop":stop_oneoffs()
    except (ValueError, OSError, subprocess.CalledProcessError):
        print("Action failed. Use doctor for credential-free diagnostics; check Docker status and the requested input path.", file=sys.stderr)
        raise SystemExit(2)


if __name__ == "__main__":main()
