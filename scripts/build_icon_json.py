#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import json
import os
from pathlib import Path
from urllib.parse import quote

ICON_DIR = Path("Surge/Icon")
OUTPUT_FILE = Path("Surge/Icon.json")
JSON_NAME = "Icon ZEN"


def build_raw_url(repo: str, branch: str, relative_path: str) -> str:
    encoded_parts = [quote(part, safe="") for part in relative_path.split("/")]
    encoded_path = "/".join(encoded_parts)
    return f"https://raw.githubusercontent.com/{repo}/{branch}/{encoded_path}"


def main() -> int:
    repo = os.environ.get("GITHUB_REPOSITORY", "").strip()
    branch = os.environ.get("GITHUB_REF_NAME", "").strip()

    if not repo:
        raise RuntimeError("Missing GITHUB_REPOSITORY")
    if not branch:
        raise RuntimeError("Missing GITHUB_REF_NAME")

    ICON_DIR.mkdir(parents=True, exist_ok=True)
    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)

    icons: list[dict[str, str]] = []

    png_files = sorted(
        [p for p in ICON_DIR.rglob("*.png") if p.is_file()],
        key=lambda p: p.as_posix().casefold(),
    )

    for png in png_files:
        relative_path = png.as_posix()
        icon_name = png.stem
        icon_url = build_raw_url(repo, branch, relative_path)

        icons.append(
            {
                "name": icon_name,
                "url": icon_url,
            }
        )

    data = {
        "name": JSON_NAME,
        "icons": icons,
    }

    json_text = json.dumps(data, ensure_ascii=False, indent=2)
    OUTPUT_FILE.write_text(json_text + "\n", encoding="utf-8")

    print(f"Generated {OUTPUT_FILE} with {len(icons)} icons.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
