from __future__ import annotations

import argparse
import json
import subprocess
from pathlib import Path


PROFILES = {
    "ad": [
        ("Surge/Rules/AdblockSet.list", "list", 120000, 0.60),
        ("Clash/Rules/AdblockSet.yaml", "yaml", 120000, 0.60),
    ],
    "china": [
        ("Surge/Rules/ChinaDomain.list", "list", 25000, 0.55),
        ("Clash/Rules/ChinaDomain.yaml", "yaml", 25000, 0.55),
    ],
    "trackers": [
        ("Surge/Rules/Trackers.list", "list", 600, 0.50),
        ("Clash/Rules/Trackers.yaml", "yaml", 600, 0.50),
        ("Trackers/Trackers.txt", "list", 900, 0.50),
    ],
    "icons": [
        ("Surge/Icon.json", "icons", 250, 0.70),
    ],
    "moyu": [
        ("Surge/Module/StartUpAds.sgmodule", "module", 100, 0.55),
    ],
    "adblock": [
        ("Surge/Module/Adblock4limbo.sgmodule", "module", 80, 0.70),
        ("Surge/Module/runtime/Adblock4limbo.js", "text", 100, 0.60),
        ("Surge/Module/runtime/Adblock4limbo.user.js", "text", 1500, 0.60),
    ],
}


def count_records(content, kind):
    if kind == "icons":
        payload = json.loads(content)
        icons = payload.get("icons")
        if not isinstance(icons, list):
            raise RuntimeError("Invalid icon JSON")
        names = [item["name"] for item in icons]
        if len(names) != len(set(names)):
            raise RuntimeError("Duplicate icon names")
        if any(
            not item.get("url", "").startswith(
                "https://raw.githubusercontent.com/master-zen/Net-Link/main/Surge/Icon/"
            )
            for item in icons
        ):
            raise RuntimeError("Unexpected icon URL")
        return len(icons)

    if kind == "yaml":
        if not content.startswith("payload:\n"):
            raise RuntimeError("Invalid Clash payload")
        return sum(line.startswith("  - ") for line in content.splitlines())

    if kind in ("module", "text"):
        if kind == "module" and not content.startswith("#!name="):
            raise RuntimeError("Invalid Surge module")
        return sum(bool(line.strip()) for line in content.splitlines())

    return sum(
        bool(line.strip()) and not line.lstrip().startswith(("#", ";"))
        for line in content.splitlines()
    )


def previous_content(path):
    result = subprocess.run(
        ["git", "show", f"HEAD:{path}"],
        capture_output=True,
        check=False,
    )
    if result.returncode != 0:
        return None
    return result.stdout.decode("utf-8")


def validate_profile(profile):
    counts = {}
    for name, kind, minimum, ratio in PROFILES[profile]:
        content = Path(name).read_text(encoding="utf-8")
        current = count_records(content, kind)
        if current < minimum:
            raise RuntimeError(f"Insufficient output: {name}: {current} < {minimum}")
        prior = previous_content(name)
        if prior is not None:
            previous = count_records(prior, kind)
            if previous and current < previous * ratio:
                raise RuntimeError(
                    f"Unexpected output shrinkage: {name}: {previous} -> {current}"
                )
        counts[name] = current

    if profile in ("ad", "china", "trackers"):
        surge = next(n for n in counts if n.startswith("Surge/Rules/"))
        clash = next(n for n in counts if n.startswith("Clash/Rules/"))
        if counts[surge] != counts[clash]:
            raise RuntimeError("Surge and Clash rule counts differ")

    if profile == "adblock":
        module = Path("Surge/Module/Adblock4limbo.sgmodule").read_text(encoding="utf-8")
        loader = Path("Surge/Module/runtime/Adblock4limbo.js").read_text(encoding="utf-8")
        user = Path("Surge/Module/runtime/Adblock4limbo.user.js").read_text(encoding="utf-8")
        if (
            "Adblock4limbo Ads Only" not in module
            or "script-path=https://limbopro.com/Adguard/Adblock4limbo.js" in module
            or "fc_JS_URL" in loader
            or "elementBlocker.user.js" in loader
            or "function daohang_build()" in user
            or "floating-warning-box" in user
        ):
            raise RuntimeError("Unexpected Adblock4limbo dependency")

    for name, count in counts.items():
        print(f"{name}: {count}")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("profile", choices=PROFILES)
    args = parser.parse_args()
    validate_profile(args.profile)


if __name__ == "__main__":
    main()
