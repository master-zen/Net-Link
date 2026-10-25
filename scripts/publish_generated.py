from __future__ import annotations

"""Publish exactly the validated outputs of this run without rebasing generated files.

Rebasing two generated timestamp manifests creates conflicts. Instead, fetch
current main, ensure newer scripts/sources have not superseded this build, stage
only this workflow's outputs on top of current main and push without force.
"""

import argparse
import json
import os
import subprocess
import time
from pathlib import Path


def execute(*command, check=True, capture=False):
    result = subprocess.run(command, text=True, check=False,
                            capture_output=capture)
    if check and result.returncode != 0:
        raise RuntimeError(f"Command failed: {' '.join(command)}: {(result.stderr or '')[-500:]}")
    return result.stdout.strip() if capture else result.returncode


def read_remote_json(path):
    value = execute("git", "show", f"origin/main:{path}", check=False, capture=True)
    if not value:
        return None
    return json.loads(value)


def guarded_inputs(paths):
    guarded = ["scripts/fetch_rule_sources.py", "scripts/validate_generated.py",
               "scripts/publish_generated.py"]
    if "data/reports/china_download_manifest.json" in paths:
        guarded += [
            ".github/workflows/merge-china-domain.yml",
            "scripts/build_china_domain.py", "scripts/audit_rule_coverage.py",
            "data/sources/ChinaDomainList_URLs.txt",
            "data/sources/ChinaSupplement_URLs.txt",
            "data/sources/ChinaForeignDomain_URLs.txt",
            "data/sources/ChinaForeignIP_URLs.txt",
            "data/allowlists/ChinaForeignDomains.list",
            "data/allowlists/ChinaForeignIPs.list",
        ]
    elif "data/reports/ad_download_manifest.json" in paths:
        guarded += [
            ".github/workflows/merge-ad-sets.yml",
            "scripts/build_ad_sets.py",
            "data/sources/AdBlockList_URLs.txt",
            "data/sources/AdAllowList_URLs.txt",
            "data/sources/AdExceptionList_URLs.txt",
            "data/allowlists/AdblockCriticalAllow.list",
        ]
    elif "Trackers/Trackers.txt" in paths:
        guarded += [
            ".github/workflows/merge-trackers.yml",
            "scripts/build_trackers.py",
            "data/sources/TrackersList_URLs.txt",
        ]
    elif "Surge/Icon.json" in paths:
        guarded += [
            ".github/workflows/merge-surge-icons.yml",
            "scripts/build_icon_json.py",
            "Surge/Icon/",
        ]
    elif "Surge/Module/StartUpAds.sgmodule" in paths:
        guarded += [
            ".github/workflows/update-moyu-startup.yml",
            "Surge/Module/.generator/build.py",
            "Surge/Module/runtime/body-rewrite.js",
        ]
    elif "Surge/Module/Adblock4limbo.sgmodule" in paths:
        guarded += [
            ".github/workflows/update-adblock4limbo.yml",
            "Surge/Module/.generator/update-adblock4limbo.py",
        ]
    return guarded


def guard_against_old_build(paths):
    guarded = guarded_inputs(paths)
    changed = execute(
        "git", "diff", "--name-only", os.environ.get("GITHUB_SHA", "HEAD"),
        "origin/main", "--", *guarded,
        check=False, capture=True,
    )
    if changed:
        raise RuntimeError("This build used superseded generator/source configuration; "
                           "newer main requires a fresh download/build: " + changed[:300])
    for profile in ("china", "ad"):
        local_name = f"data/reports/{profile}_download_manifest.json"
        if local_name not in paths:
            continue
        local = json.loads(Path(local_name).read_text(encoding="utf-8"))
        remote = read_remote_json(local_name)
        if remote and remote.get("epoch_seconds", 0) > local.get("epoch_seconds", 0):
            raise RuntimeError(
                f"Refusing stale {profile} build: remote main has a newer upstream snapshot"
            )


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("message")
    parser.add_argument("paths", nargs="+")
    args = parser.parse_args()

    if os.getenv("GITHUB_REF_NAME") != "main":
        raise RuntimeError("Publication is only permitted on main")

    paths = args.paths
    for name in paths:
        path = Path(name)
        if path.is_absolute() or ".." in path.parts or not path.exists():
            raise RuntimeError(f"Invalid output path: {name}")

    execute("git", "config", "user.name", "github-actions[bot]")
    execute("git", "config", "user.email",
            "41898282+github-actions[bot]@users.noreply.github.com")

    for attempt in range(1, 9):
        execute("git", "fetch", "origin", "main")
        guard_against_old_build(paths)
        # Uncommitted generated files remain in the working tree. Reset HEAD
        # and index to latest origin/main, *not* the working tree; then stage
        # only the allowed published paths. This avoids generated-file rebase
        # conflicts and never overwrites unrelated workflow output.
        execute("git", "reset", "--mixed", "origin/main")
        execute("git", "add", "-A", "--", *paths)
        if execute("git", "diff", "--cached", "--quiet", check=False) == 0:
            print("[PUBLISH] outputs unchanged (content hashes identical)")
            return
        execute("git", "commit", "-m", args.message)
        if execute("git", "push", "origin", "HEAD:main", check=False) == 0:
            print("[PUBLISH] pushed validated outputs to latest main")
            return
        if attempt < 8:
            print(f"[PUBLISH] main advanced, retrying cleanly ({attempt}/8)")
            time.sleep(min(2 * attempt, 12))

    raise RuntimeError("Publication failed after eight non-force push attempts")


if __name__ == "__main__":
    main()
