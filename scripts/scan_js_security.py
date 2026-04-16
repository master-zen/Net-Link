#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import json
import os
import shutil
import subprocess
import time
import base64
from pathlib import Path

import requests

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

ROOT = Path(__file__).resolve().parent.parent
SCRIPTS_CACHE_DIR = SCAN_REPORTS_DIR / "scripts_cache"
CONVERTED_SCRIPTS_DIR = ROOT / "Surge" / "Scripts" / "Converted"
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


def path_for_report(path: str | Path) -> str:
    try:
        return str(Path(path).resolve().relative_to(ROOT))
    except Exception:
        return str(path)


def parse_github_remote(url: str) -> tuple[str, str] | None:
    text = url.strip()
    if not text:
        return None

    if text.startswith("git@github.com:"):
        path = text.split(":", 1)[1]
    elif text.startswith("https://github.com/"):
        path = text.split("https://github.com/", 1)[1]
    else:
        return None

    path = path.removesuffix(".git").strip("/")
    parts = [part for part in path.split("/") if part]
    if len(parts) < 2:
        return None
    return parts[0], parts[1]


def current_repo_raw_base() -> str | None:
    repo = os.environ.get("GITHUB_REPOSITORY", "").strip()
    branch = os.environ.get("GITHUB_REF_NAME", "").strip()

    if repo and "/" in repo:
        if not branch:
            branch = "main"
        return f"https://raw.githubusercontent.com/{repo}/{branch}"

    try:
        remote = subprocess.run(
            ["git", "config", "--get", "remote.origin.url"],
            capture_output=True,
            text=True,
            check=False,
        ).stdout.strip()
    except Exception:
        remote = ""

    parsed = parse_github_remote(remote)
    if not parsed:
        return None

    owner, repo_name = parsed
    if not branch:
        try:
            branch = subprocess.run(
                ["git", "rev-parse", "--abbrev-ref", "HEAD"],
                capture_output=True,
                text=True,
                check=False,
            ).stdout.strip()
        except Exception:
            branch = ""

    if not branch or branch == "HEAD":
        branch = "main"

    return f"https://raw.githubusercontent.com/{owner}/{repo_name}/{branch}"


def script_needs_compatibility_shim(text: str) -> bool:
    # Already multi-platform or already converted.
    if "__net_link_compat__" in text or "__script_hub_compat__" in text:
        return False
    if "$httpClient" in text and "$task" in text:
        return False

    qx_only_markers = (
        "$task.fetch",
        "$prefs.valueForKey",
        "$prefs.setValueForKey",
        "$notify(",
    )
    return any(marker in text for marker in qx_only_markers)


def surge_compat_prefix(source_url: str) -> str:
    return f"""// Net-Link Surge compatibility shim
// Source: {source_url}
;(() => {{
  const __net_link_compat__ = true;
  const __isSurgeLike = typeof $httpClient !== "undefined";
  if (!__isSurgeLike) return;

  if (typeof $task === "undefined") {{
    globalThis.$task = {{
      fetch(options) {{
        return new Promise((resolve, reject) => {{
          const request = typeof options === "string" ? {{ url: options }} : {{ ...(options || {{}}) }};
          const method = String(request.method || "GET").toUpperCase();
          const sender = method === "POST" ? $httpClient.post : $httpClient.get;
          sender(request, (error, response, data) => {{
            if (error && !response) {{
              reject({{ error }});
              return;
            }}
            const result = response || {{}};
            result.body = data;
            resolve(result);
          }});
        }});
      }},
    }};
  }}

  if (typeof $prefs === "undefined" && typeof $persistentStore !== "undefined") {{
    globalThis.$prefs = {{
      valueForKey(key) {{
        return $persistentStore.read(key);
      }},
      setValueForKey(value, key) {{
        return $persistentStore.write(value, key);
      }},
      removeValueForKey(key) {{
        return $persistentStore.write("", key);
      }},
    }};
  }}

  if (typeof $notify === "undefined" && typeof $notification !== "undefined") {{
    globalThis.$notify = (title = "", subtitle = "", detail = "", url) => {{
      const extra = url ? {{ url }} : undefined;
      $notification.post(title, subtitle, detail, extra);
    }};
  }}

  if (typeof $request !== "undefined" && $request && $request.headers) {{
    const lowered = Object.fromEntries(Object.entries($request.headers).map(([k, v]) => [String(k).toLowerCase(), v]));
    $request.headers = new Proxy(lowered, {{
      get(target, prop, receiver) {{
        return Reflect.get(target, String(prop).toLowerCase(), receiver);
      }},
      set(target, prop, value, receiver) {{
        return Reflect.set(target, String(prop).toLowerCase(), value, receiver);
      }},
    }});
  }}

  if (typeof $response !== "undefined" && $response && $response.headers) {{
    const lowered = Object.fromEntries(Object.entries($response.headers).map(([k, v]) => [String(k).toLowerCase(), v]));
    $response.headers = new Proxy(lowered, {{
      get(target, prop, receiver) {{
        return Reflect.get(target, String(prop).toLowerCase(), receiver);
      }},
      set(target, prop, value, receiver) {{
        return Reflect.set(target, String(prop).toLowerCase(), value, receiver);
      }},
    }});
  }}
}})();
"""


def apply_compatibility_conversion(script_text: str, script_url: str) -> tuple[str, bool]:
    if not script_needs_compatibility_shim(script_text):
        return script_text, False
    return surge_compat_prefix(script_url) + "\n" + script_text, True


def reset_converted_scripts_dir() -> None:
    CONVERTED_SCRIPTS_DIR.mkdir(parents=True, exist_ok=True)
    for child in CONVERTED_SCRIPTS_DIR.iterdir():
        if child.name.casefold() == "readme.md":
            continue
        if child.is_dir():
            shutil.rmtree(child, ignore_errors=True)
        else:
            child.unlink(missing_ok=True)


def sanitize_failed_downloads(failed: list[dict]) -> list[dict]:
    sanitized: list[dict] = []
    for item in failed:
        sanitized.append(
            {
                "script_url": item["script_url"],
                "module_ids": sorted(set(item.get("module_ids", []))),
                "error": item.get("error", ""),
            }
        )
    return sanitized


def download_scripts(modules: list[dict]) -> tuple[list[dict], dict[str, list[str]], list[dict]]:
    SCRIPTS_CACHE_DIR.mkdir(parents=True, exist_ok=True)
    reset_converted_scripts_dir()
    repo_raw_base = current_repo_raw_base()

    downloaded: list[dict] = []
    downloaded_by_url: dict[str, dict] = {}
    failed_by_url: dict[str, dict] = {}
    script_to_modules: dict[str, list[str]] = {}

    for module in modules:
        module_id = module["module_id"]
        for item in module.get("scripts", []):
            script_url = (item.get("script_url") or "").strip()
            if not script_url.startswith(("http://", "https://")):
                continue

            existing = downloaded_by_url.get(script_url)
            if existing is not None:
                script_to_modules.setdefault(existing["script_hash"], []).append(module_id)
                continue

            failed_existing = failed_by_url.get(script_url)
            if failed_existing is not None:
                failed_existing.setdefault("module_ids", []).append(module_id)
                continue

            try:
                script_text = request_text(script_url)
            except Exception as exc:
                failed_by_url[script_url] = {
                    "script_url": script_url,
                    "module_ids": [module_id],
                    "error": f"{type(exc).__name__}: {exc}",
                }
                continue

            original_hash = sha256_text(script_text)
            original_file = SCRIPTS_CACHE_DIR / f"{original_hash}.js"

            if not original_file.exists():
                original_file.write_text(script_text, encoding="utf-8")

            converted_text, conversion_applied = apply_compatibility_conversion(script_text, script_url)
            script_hash = sha256_text(converted_text)
            script_file = SCRIPTS_CACHE_DIR / f"{script_hash}.js"

            if not script_file.exists():
                script_file.write_text(converted_text, encoding="utf-8")

            converted_relative_path = ""
            converted_url = ""
            if conversion_applied:
                converted_relative_path = f"Surge/Scripts/Converted/{original_hash}.js"
                converted_file = ROOT / converted_relative_path
                converted_file.parent.mkdir(parents=True, exist_ok=True)
                converted_file.write_text(converted_text, encoding="utf-8")
                if repo_raw_base:
                    converted_url = f"{repo_raw_base}/{converted_relative_path}"

            record = {
                "module_id": module_id,
                "script_url": script_url,
                "original_hash": original_hash,
                "script_hash": script_hash,
                "original_file": str(original_file),
                "file": str(script_file),
                "conversion_applied": conversion_applied,
                "converted_relative_path": converted_relative_path,
                "converted_url": converted_url,
            }
            downloaded.append(record)
            downloaded_by_url[script_url] = record
            script_to_modules.setdefault(script_hash, []).append(module_id)

    return downloaded, script_to_modules, list(failed_by_url.values())


def run_clamav() -> dict:
    if shutil.which("clamscan") is None:
        return {"available": False, "infected_files": []}

    cmd = ["clamscan", "-r"]
    database_dir = os.environ.get("CLAMAV_DB_DIR", "").strip()
    if database_dir:
        cmd.extend(["--database", database_dir])
    cmd.append(str(SCRIPTS_CACHE_DIR))
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


def vt_get_json(endpoint: str, api_key: str) -> dict | None:
    resp = requests.get(
        f"https://www.virustotal.com/api/v3/{endpoint}",
        headers={"x-apikey": api_key},
        timeout=30,
    )
    if resp.status_code == 404:
        return None
    resp.raise_for_status()
    return resp.json()


def vt_url_id(url: str) -> str:
    return base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")


def run_virustotal(downloaded: list[dict]) -> dict:
    api_key = os.environ.get("VT_API_KEY", "").strip()
    if not api_key:
        return {"available": False, "reason": "VT_API_KEY not set", "results": []}

    max_lookups = max(1, min(int(os.environ.get("VT_MAX_LOOKUPS", "8")), 32))
    results: list[dict] = []
    seen_hashes: set[str] = set()

    for item in downloaded:
        script_hash = item["script_hash"]
        if script_hash in seen_hashes:
            continue
        seen_hashes.add(script_hash)
        if len(results) >= max_lookups:
            break

        file_report = None
        url_report = None
        errors: list[str] = []

        try:
            file_report = vt_get_json(f"files/{script_hash}", api_key)
        except Exception as exc:
            errors.append(f"file:{exc}")

        try:
            url_report = vt_get_json(f"urls/{vt_url_id(item['script_url'])}", api_key)
        except Exception as exc:
            errors.append(f"url:{exc}")

        results.append(
            {
                "script_hash": script_hash,
                "script_url": item["script_url"],
                "file_report": file_report,
                "url_report": url_report,
                "errors": errors,
            }
        )
        time.sleep(16)

    return {
        "available": True,
        "looked_up": len(results),
        "max_lookups": max_lookups,
        "results": results,
    }


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


def sanitize_js_xray_status(js_xray: dict) -> dict:
    if not js_xray:
        return {}
    sanitized = dict(js_xray)
    raw_output_file = sanitized.get("raw_output_file")
    if raw_output_file:
        sanitized["raw_output_file"] = path_for_report(raw_output_file)
    command = sanitized.get("command")
    if isinstance(command, list):
        sanitized["command"] = [path_for_report(part) if "/" in str(part) else part for part in command]
    return sanitized


def sanitize_clamav_status(clamav: dict) -> dict:
    if not clamav:
        return {}
    sanitized = dict(clamav)
    infected_files = sanitized.get("infected_files", [])
    sanitized["infected_files"] = [path_for_report(path) for path in infected_files]
    return sanitized


def sanitize_downloaded_scripts(downloaded: list[dict]) -> list[dict]:
    sanitized: list[dict] = []
    for item in downloaded:
        sanitized.append(
            {
                "script_url": item["script_url"],
                "original_hash": item["original_hash"],
                "script_hash": item["script_hash"],
                "original_file": path_for_report(item["original_file"]),
                "file": path_for_report(item["file"]),
                "conversion_applied": item["conversion_applied"],
                "converted_relative_path": item["converted_relative_path"],
                "converted_url": item["converted_url"],
            }
        )
    return sanitized


def main() -> int:
    ensure_project_dirs()
    SCAN_REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    shutil.rmtree(SCRIPTS_CACHE_DIR, ignore_errors=True)
    SCRIPTS_CACHE_DIR.mkdir(parents=True, exist_ok=True)
    for stale_report in (SEMGREP_OUTPUT_FILE, CLAMAV_OUTPUT_FILE, JSXRAY_OUTPUT_FILE):
        try:
            stale_report.unlink()
        except FileNotFoundError:
            pass
    try:
        SEMGREP_RULES_FILE.unlink()
    except FileNotFoundError:
        pass

    modules = load_modules()
    downloaded, script_to_modules, failed_downloads = download_scripts(modules)

    clamav = run_clamav()
    semgrep = run_semgrep()
    js_xray = run_js_xray()
    virustotal = run_virustotal(downloaded)

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

    for result in virustotal.get("results", []):
        script_hash = result["script_hash"]
        for report_type in ("file_report", "url_report"):
            report = result.get(report_type) or {}
            attrs = ((report.get("data") or {}).get("attributes") or {})
            stats = attrs.get("last_analysis_stats") or {}
            malicious = int(stats.get("malicious", 0) or 0)
            suspicious = int(stats.get("suspicious", 0) or 0)
            if malicious > 0 or suspicious > 0:
                suspicious_hashes.add(script_hash)
                suspicious_reasons.setdefault(script_hash, []).append(
                    f"virustotal:{report_type}:malicious={malicious}:suspicious={suspicious}"
                )

    suspicious_modules = set()
    for script_hash in suspicious_hashes:
        for module_id in script_to_modules.get(script_hash, []):
            suspicious_modules.add(module_id)

    summary = {
        "scanned_script_count": len(downloaded),
        "compatibility_converted_count": sum(1 for item in downloaded if item.get("conversion_applied")),
        "tool_status": {
            "clamav": sanitize_clamav_status(clamav),
            "semgrep": {"available": semgrep.get("available", False), "result_count": len(semgrep_results)},
            "js_xray": sanitize_js_xray_status(js_xray),
            "virustotal": {
                "available": virustotal.get("available", False),
                "looked_up": virustotal.get("looked_up", 0),
                "max_lookups": virustotal.get("max_lookups", 0),
                "reason": virustotal.get("reason", ""),
            },
        },
        "suspicious_script_hashes": sorted(suspicious_hashes),
        "suspicious_modules": sorted(suspicious_modules),
        "suspicious_reasons": suspicious_reasons,
        "downloaded_scripts": sanitize_downloaded_scripts(downloaded),
        "failed_script_download_count": len(failed_downloads),
        "failed_script_downloads": sanitize_failed_downloads(failed_downloads),
        "virustotal_results": virustotal.get("results", []),
    }

    save_json(SECURITY_SUMMARY_JSON, summary)
    print(f"Wrote {SECURITY_SUMMARY_JSON}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
