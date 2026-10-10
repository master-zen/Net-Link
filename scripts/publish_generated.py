from __future__ import annotations

import argparse
import os
import subprocess
import time
from pathlib import Path


def execute(*command, check=True):
    result = subprocess.run(command, text=True, check=False)
    if check and result.returncode != 0:
        raise RuntimeError(f"Command failed: {' '.join(command)}")
    return result.returncode


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("message")
    parser.add_argument("paths", nargs="+")
    args = parser.parse_args()

    if os.getenv("GITHUB_REF_NAME") != "main":
        raise RuntimeError("Publication is only permitted on main")

    for name in args.paths:
        path = Path(name)
        if path.is_absolute() or ".." in path.parts or not path.exists():
            raise RuntimeError(f"Invalid output path: {name}")

    execute("git", "add", "--", *args.paths)
    if execute("git", "diff", "--cached", "--quiet", check=False) == 0:
        return

    execute("git", "config", "user.name", "github-actions[bot]")
    execute("git", "config", "user.email", "41898282+github-actions[bot]@users.noreply.github.com")
    execute("git", "commit", "-m", args.message)

    for attempt in range(1, 9):
        execute("git", "fetch", "origin", "main")
        if execute("git", "rebase", "origin/main", check=False) != 0:
            execute("git", "rebase", "--abort", check=False)
            raise RuntimeError("Rebase conflict: publication stopped without overwriting changes")
        if execute("git", "push", "origin", "HEAD:main", check=False) == 0:
            return
        if attempt < 8:
            time.sleep(min(3 * attempt, 18))

    raise RuntimeError("Publication failed after eight non-force push attempts")


if __name__ == "__main__":
    main()
