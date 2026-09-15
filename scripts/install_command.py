"""Install a local shell command pointing at this existing checkout; never move data."""
import argparse
import os
from pathlib import Path
import shlex

ROOT = Path(__file__).resolve().parents[1]


def install(bin_dir, shell_config, project_root=ROOT):
    bin_dir, shell_config = Path(bin_dir).expanduser().absolute(), Path(shell_config).expanduser().absolute()
    launcher = Path(project_root).absolute() / "scripts" / "finder.sh"
    if not launcher.is_file():raise ValueError("Existing finder.sh not found")
    if bin_dir.is_symlink() or shell_config.is_symlink():raise ValueError("Choose a real directory and shell configuration file")
    bin_dir.mkdir(parents=True, exist_ok=True)
    target = bin_dir / "IWANTTOGOHOME"
    content = "#!/bin/sh\n# something-finder local command\nexec sh " + shlex.quote(str(launcher)) + ' "$@"\n'
    if target.exists() or target.is_symlink():
        if target.is_symlink() or target.read_text() != content:
            raise ValueError("IWANTTOGOHOME already exists with different contents; choose another bin directory")
    else:
        with target.open("x") as stream:stream.write(content)
        target.chmod(0o755)
    # Append one exact PATH entry, keeping every previous shell line intact.
    entry = "export PATH=" + shlex.quote(str(bin_dir)) + ':"$PATH"'
    shell_config.parent.mkdir(parents=True, exist_ok=True)
    previous = shell_config.read_text() if shell_config.exists() else ""
    if entry not in previous.splitlines():
        with shell_config.open("a") as stream:
            stream.write(("\n" if previous and not previous.endswith("\n") else "") +
                         "\n# something-finder command\n" + entry + "\n")
    return target, entry


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bin-dir", default=str(Path.home() / ".local/bin"))
    parser.add_argument("--shell-config", default=str(Path.home() / ".zshrc"))
    args = parser.parse_args()
    try:target, entry = install(args.bin_dir, args.shell_config)
    except (OSError, ValueError) as exc:raise SystemExit(str(exc)) from None
    print("Installed:", target)
    print("Open a new terminal, or run this PATH command in the current shell:")
    print(entry)
    print("Then: IWANTTOGOHOME [build|login|run|resume|status|doctor|stop]")


if __name__ == "__main__":main()
