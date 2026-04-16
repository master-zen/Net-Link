#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Compatibility entry point for the Ad_Block pipeline.

Historically this script produced only ``Surge/Rules/Ad_Block.list`` from a
small hard-coded source set. The canonical workflow now lives in
``scripts/run_ad_block_pipeline.py`` and produces the final staged, validated
Ad_Block outputs for Surge.

This wrapper is kept so older local commands do not silently run stale logic.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
PIPELINE = ROOT / "scripts" / "run_ad_block_pipeline.py"


def main() -> int:
    print("build_ad_block.py is a compatibility wrapper.")
    print(f"Delegating to {PIPELINE.relative_to(ROOT)}")
    subprocess.run([sys.executable, str(PIPELINE)], cwd=ROOT, check=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
