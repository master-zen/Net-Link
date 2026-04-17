#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPTS_DIR = ROOT / "scripts"

PIPELINE = [
    ("Discover module candidates", SCRIPTS_DIR / "discover_module_candidates.py"),
    ("Discover allowlist candidates", SCRIPTS_DIR / "discover_allowlist_candidates.py"),
    ("Fetch and normalize modules", SCRIPTS_DIR / "fetch_and_normalize_modules.py"),
    ("Fetch and cache ad-block inputs", SCRIPTS_DIR / "fetch_and_cache_adblock_inputs.py"),
    ("Scan JS security", SCRIPTS_DIR / "scan_js_security.py"),
    ("Build staged Ad_Block outputs", SCRIPTS_DIR / "build_ad_block_outputs.py"),
    ("Validate and publish Ad_Block outputs", SCRIPTS_DIR / "validate_ad_block_outputs.py"),
]


def run_step(title: str, script: Path) -> None:
    print(f"==> {title}", flush=True)
    subprocess.run([sys.executable, str(script)], cwd=ROOT, check=True)


def main() -> int:
    for title, script in PIPELINE:
        run_step(title, script)
    print("Ad_Block pipeline completed successfully.", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
