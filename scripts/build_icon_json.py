#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import json
import sys
from pathlib import Path
from urllib.parse import quote

ROOT = Path(__file__).resolve().parents[1]
ICON_DIR = ROOT / "Surge/Icon"
OUTPUT_FILE = ROOT / "Surge/Icon.json"
OUTPUT_NAME = "Icon ZEN"
RAW_BASE_URL = "https://raw.githubusercontent.com/master-zen/Net-Link/main/Surge/Icon/"
ALLOWED_EXTENSIONS = {".png", ".jpg", ".jpeg", ".webp", ".gif", ".svg"}


def list_icon_files(icon_dir: Path) -> list[Path]:
    files = [
        path
        for path in icon_dir.iterdir()
        if path.is_file() and path.suffix.lower() in ALLOWED_EXTENSIONS
    ]
    return sorted(files, key=lambda item: item.name.casefold())


def build_icon_payload(icon_files: list[Path]) -> dict[str, object]:
    icons = [
        {
            "name": icon_file.stem,
            "url": f"{RAW_BASE_URL}{quote(icon_file.name)}",
        }
        for icon_file in icon_files
    ]
    return {
        "name": OUTPUT_NAME,
        "icons": icons,
    }


def main() -> int:
    if not ICON_DIR.exists() or not ICON_DIR.is_dir():
        print(f"[ERROR] icon directory not found: {ICON_DIR}", file=sys.stderr)
        return 1

    icon_files = list_icon_files(ICON_DIR)
    if not icon_files:
        print(f"[ERROR] no icon files found in {ICON_DIR}", file=sys.stderr)
        return 1

    payload = build_icon_payload(icon_files)
    content = json.dumps(payload, ensure_ascii=False, indent=2) + "\n"
    OUTPUT_FILE.write_text(content, encoding="utf-8")

    print(f"[DONE] {OUTPUT_FILE.relative_to(ROOT)}: {len(icon_files)} icons")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
