#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

from lib_rules import (
    BUILD_DIR,
    NORMALIZED_MODULES_JSON,
    SCAN_REPORTS_DIR,
    SECURITY_SUMMARY_JSON,
    ensure_project_dirs,
    request_text,
    save_json,
    sha256_text,
)

SCRIPTS_CACHE_DIR = SCAN_REPORTS_DIR / "scripts_cache"
SEMGREP_RULES_FILE = SCAN_REPORTS_DIR / "semgrep_rules.yml"
SEMGREP_OUTPUT_FILE = SCAN_REPORTS_DIR / "semgrep_output.json"
CLAMAV_OUTPUT_FILE = SCAN_REPORTS_DIR / "clamav_output.txt"
JSXRAY_OUTPUT_FILE = SCAN_REPORTS_DIR / "js_xray_output.txt"

SEMGREP_RULES = """rules:
  - id: js-eval
    languages: [javascript, typescript]
    severity: ERROR
    message: "Use of eval() is high-risk in downloaded module scripts"
    pattern: eval(...)

  - id: js-new-function
    languages: [javascript, typescript]
    severity: ERROR
    message: "Use of new Function() is high-risk in downloaded module scripts"
    pattern: new Function(...)

  - id: js-cookie-read
    languages: [javascript, typescript]
    severity: WARNING
    message: "Reads document.cookie"
    pattern: document.cookie

  - id: js-localstorage-read
    languages: [javascript, typescript]
    severity: WARNING
    message: "Reads localStorage"
    pattern: localStorage

  - id: js-xhr
    languages: [javascript, typescript]
    severity: WARNING
    message: "Uses XMLHttpRequest"
    pattern: new XMLHttpRequest(...)

  - id: js-fetch
    languages: [javascript, typescript]
    severity: WARNING
    message: "Uses fetch()"
    pattern: fetch(...)
"""


def load_modules() -> list[dict]:
    if not NORMALIZED_MODULES_JSON.exists():
        return []
    data = json.loads(NORMALIZED_MODULES_JSON.read_text(encoding="utf-8"))
    return data.get("modules", [])


def download_scripts(modules: list[dict]) -> tuple[list[dict], dict[str, list[str]]]:
    SCRIPTS_CACHE_DIR.mkdir(parents=True, exist_ok=True)

    downloaded: list[dict] = []
    script_to_modules: dict[str, list[str]] = {}

    for module in modules:
        module_id = module["module_id"]
        for item in module.get("scripts", []):
            script_url = (item.get("script_url") or "").strip()
            if not script_url.startswith(("http://", "https://")):
                continue

            try:
                script_text = request_text(script_url)
            except Exception:
                continue

            script_hash = sha256_text(script_text)
            script_file = SCRIPTS_CACHE_DIR / f"{script_hash}.js"

            if not script_file.exists():
                script_file.write_text(script_text, encoding="utf-8")

            downloaded.append(
                {
                    "module_id": module_id,
                    "script_url": script_url,
                    "script_hash": script_hash,
                    "file": str(script_file),
                }
            )
            script_to_modules.setdefault(script_hash, []).append(module_id)

    return downloaded, script_to_modules


def run_clamav() -> dict:
    if shutil.which("clamscan") is None:
        return {"available": False, "infected_files": []}

    cmd = ["clamscan", "-r", str(SCRIPTS_CACHE_DIR)]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    output = (proc.stdout or "") + "\n" + (proc.stderr or "")
    CLAMAV_OUTPUT_FILE.write_text(output, encoding="utf-8")

    infected = []
    for line in output.splitlines():
        if line.endswith("FOUND"):
            path = line.split(":", 1)[0].strip()
            infected.append(path)

    return {
        "available": True,
        "infected_files": infected,
        "returncode": proc.returncode,
    }


def run_semgrep() -> dict:
    if shutil.which("semgrep") is None:
        return {"available": False, "results": []}

    SEMGREP_RULES_FILE.write_text(SEMGREP_RULES, encoding="utf-8")

    cmd = [
        "semgrep",
        "scan",
        "--quiet",
        "--json",
        "--config",
        str(SEMGREP_RULES_FILE),
        str(SCRIPTS_CACHE_DIR),
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    output = proc.stdout or "{}"
    SEMGREP_OUTPUT_FILE.write_text(output, encoding="utf-8")

    try:
        data = json.loads(output)
    except Exception:
        data = {"results": []}

    return {
        "available": True,
        "results": data.get("results", []),
        "returncode": proc.returncode,
    }


def run_js_xray() -> dict:
    candidates = [
        ["js-x-ray", "scan", str(SCRIPTS_CACHE_DIR)],
        ["js-x-ray", str(SCRIPTS_CACHE_DIR)],
        ["npx", "@nodesecure/js-x-ray", "scan", str(SCRIPTS_CACHE_DIR)],
        ["npx", "@nodesecure/js-x-ray", str(SCRIPTS_CACHE_DIR)],
    ]

    for cmd in candidates:
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True)
        except Exception:
            continue

        # even if command exits non-zero, keep output for inspection
        output = (proc.stdout or "") + "\n" + (proc.stderr or "")
        if output.strip():
            JSXRAY_OUTPUT_FILE.write_text(output, encoding="utf-8")
            return {
                "available": True,
                "command": cmd,
                "returncode": proc.returncode,
                "raw_output_file": str(JSXRAY_OUTPUT_FILE),
            }

    return {"available": False}


def heuristic_scan_script(path: Path) -> dict:
    text = path.read_text(encoding="utf-8", errors="ignore")

    patterns = {
        "eval(": 4,
        "new Function(": 4,
        "document.cookie": 3,
        "localStorage": 2,
        "sessionStorage": 2,
        "navigator.sendBeacon": 3,
        "XMLHttpRequest": 2,
        "fetch(": 1,
        "WebSocket(": 2,
        "atob(": 1,
        "btoa(": 1,
    }

    hits: list[str] = []
    score = 0

    for needle, weight in patterns.items():
        if needle in text:
            hits.append(needle)
            score += weight

    return {"score": score, "hits": hits}


def main() -> int:
    ensure_project_dirs()
    SCAN_REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    SCRIPTS_CACHE_DIR.mkdir(parents=True, exist_ok=True)

    modules = load_modules()
    downloaded, script_to_modules = download_scripts(modules)

    clamav = run_clamav()
    semgrep = run_semgrep()
    js_xray = run_js_xray()

    suspicious_hashes: set[str] = set()
    suspicious_reasons: dict[str, list[str]] = {}

    infected_files = set(clamav.get("infected_files", []))
    for item in downloaded:
        if item["file"] in infected_files:
            suspicious_hashes.add(item["script_hash"])
            suspicious_reasons.setdefault(item["script_hash"], []).append("clamav")

    semgrep_results = semgrep.get("results", [])
    for result in semgrep_results:
        path = result.get("path", "")
        severity = (result.get("extra", {}) or {}).get("severity", "")
        if severity not in {"ERROR", "WARNING"}:
            continue

        for item in downloaded:
            if item["file"] == path:
                suspicious_reasons.setdefault(item["script_hash"], []).append(
                    f"semgrep:{result.get('check_id','unknown')}"
                )
                if severity == "ERROR":
                    suspicious_hashes.add(item["script_hash"])

    for item in downloaded:
        report = heuristic_scan_script(Path(item["file"]))
        if report["score"] >= 5:
            suspicious_hashes.add(item["script_hash"])
            suspicious_reasons.setdefault(item["script_hash"], []).append(
                "heuristic:" + "|".join(report["hits"])
            )

    suspicious_modules = set()
    for script_hash in suspicious_hashes:
        for module_id in script_to_modules.get(script_hash, []):
            suspicious_modules.add(module_id)

    summary = {
        "scanned_script_count": len(downloaded),
        "tool_status": {
            "clamav": clamav,
            "semgrep": {"available": semgrep.get("available", False), "result_count": len(semgrep_results)},
            "js_xray": js_xray,
        },
        "suspicious_script_hashes": sorted(suspicious_hashes),
        "suspicious_modules": sorted(suspicious_modules),
        "suspicious_reasons": suspicious_reasons,
        "downloaded_scripts": downloaded,
    }

    save_json(SECURITY_SUMMARY_JSON, summary)
    print(f"Wrote {SECURITY_SUMMARY_JSON}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
