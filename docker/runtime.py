"""Codex lifecycle without inspecting or printing the credential file."""
import os
from pathlib import Path
import shutil
import subprocess
import sys


def initialize(codex_dir, template):
    codex_dir = Path(codex_dir)
    codex_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    config = codex_dir / "config.toml"
    try:
        with config.open("x") as f:
            os.chmod(config, 0o600)
            f.write(Path(template).read_text())
    except FileExistsError:
        pass
    # auth.json, session history and existing config are never read or rewritten.


def status(argv, run=subprocess.run):
    result = run(argv + ["login", "status"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=20, check=False)
    return result.returncode == 0


def main():
    os.umask(0o077)
    if len(sys.argv) < 2:raise SystemExit("Expected lifecycle action")
    action, extra = sys.argv[1], sys.argv[2:]
    if action not in {"run", "resume", "login", "logout", "switch", "status", "doctor"}:raise SystemExit("Unknown lifecycle action")
    initialize(os.environ["CODEX_HOME"], "/opt/finder/config/codex.toml")
    os.environ["RUST_LOG"] = "off"
    os.environ["RUST_BACKTRACE"] = "0"
    argv = ["codex"]
    selected = {x.strip() for x in os.environ.get("FINDER_PROFILES", "").split(",") if x.strip()}
    for name, profile, key in (("FINDER_WEB", "web", "observer"), ("FINDER_PLATFORM", "platform", "platform"),
        ("FINDER_ANDROID", "android", "android"), ("FINDER_ANDROID_DYNAMIC", "android-dynamic", "android-dynamic"),
        ("FINDER_BINARY", "binary", "binary"), ("FINDER_BURP", "burp", "burp")):
        # Session flags add new services even when the dedicated volume contains
        # the previous config. Existing config/auth/session files remain intact.
        argv += ["-c", "mcp_servers." + key + '.url="http://' + key + ':8000/mcp"',
                 "-c", "mcp_servers." + key + ".enabled=" + ("true" if os.environ.get(name) == "1" or profile in selected else "false")]
    if action in {"status", "doctor"}:
        print("Codex login: " + ("cached login available (account/model access not tested)" if status(argv) else "login required or cached login unavailable; run login"))
        if action == "doctor":
            subprocess.run(["codex", "--version"], check=True)
            print("Auth/session volume preserved. No credential contents are included in diagnostics.")
        return
    if action in {"logout", "switch"}:
        subprocess.run(argv + ["logout"], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        print("Logged out of this dedicated Codex volume. Research records are preserved.")
        if action == "logout":return
    if action in {"login", "switch"}:
        print("Open the official URL shown by Codex and enter its one-time code. Enable device-code login in ChatGPT security/workspace settings if required.", flush=True)
        os.execvp(argv[0], argv + ["login", "--device-auth"])
    if not status(argv):
        raise SystemExit("Login required: run scripts/finder.sh login (or finder.ps1 login). For expiry or 401, reauthenticate; for 403/model denial, check account/workspace access.")
    if os.environ.get("FINDER_MODEL"):
        argv += ["--model", os.environ["FINDER_MODEL"]]
    if action == "resume":argv += ["resume", "--last"]
    os.execvp(argv[0], argv + extra)


if __name__ == "__main__":main()
