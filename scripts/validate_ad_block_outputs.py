#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import json
import re
import shutil
from pathlib import Path

from build_ad_block_outputs import (
    load_allowlist_hosts_from_remote,
    load_local_allowlist_hosts,
    load_local_allowlist_regexes,
    parse_script_line,
    semantic_script_key,
    validate_final_module_text,
)
from lib_rules import (
    AD_BLOCK_LIST,
    AD_BLOCK_MODULE,
    BUILD_DIR,
    SECURITY_SUMMARY_JSON,
    STAGED_AD_BLOCK_LIST,
    STAGED_AD_BLOCK_MODULE,
    expand_hosts_with_parents,
    line_matches_any_regex,
    line_mentions_allowlisted_host,
    normalize_rule_line,
    rule_matches_allowlist,
    save_json,
)

VALIDATION_REPORT = BUILD_DIR / "scan_reports" / "output_validation.json"
SECTION_RE = re.compile(r"^\[(.+?)\]$")


def load_allowlist_context() -> tuple[set[str], list[re.Pattern[str]]]:
    allow_hosts = load_allowlist_hosts_from_remote()
    allow_hosts |= load_local_allowlist_hosts()
    allow_hosts = expand_hosts_with_parents(allow_hosts)
    allow_regexes = load_local_allowlist_regexes()
    return allow_hosts, allow_regexes


def line_hits_allowlist(line: str, allow_hosts: set[str], allow_regexes: list[re.Pattern[str]]) -> bool:
    return (
        rule_matches_allowlist(line, allow_hosts)
        or line_mentions_allowlisted_host(line, allow_hosts)
        or line_matches_any_regex(line, allow_regexes)
    )


def parse_mitm_hostname_items(line: str) -> list[str]:
    s = line.strip()
    if not s.lower().startswith("hostname ="):
        return []

    tail = s.split("=", 1)[1].strip()
    if tail.lower().startswith("%append%"):
        tail = tail[len("%append%"):].strip()
    return [item.strip() for item in tail.split(",") if item.strip()]


def validate_rule_list(allow_hosts: set[str], allow_regexes: list[re.Pattern[str]]) -> tuple[list[str], dict]:
    issues: list[str] = []
    lines = [line.strip() for line in STAGED_AD_BLOCK_LIST.read_text(encoding="utf-8").splitlines() if line.strip()]

    seen: set[str] = set()
    normalized_lines: list[str] = []
    for idx, line in enumerate(lines, start=1):
        norm = normalize_rule_line(line, strip_policy=True)
        if not norm:
            issues.append(f"Ad_Block.list:{idx}: invalid rule syntax: {line}")
            continue
        normalized_lines.append(norm)
        if line != norm:
            issues.append(f"Ad_Block.list:{idx}: rule not normalized: {line}")
        if norm in seen:
            issues.append(f"Ad_Block.list:{idx}: duplicate rule: {norm}")
        if line_hits_allowlist(norm, allow_hosts, allow_regexes):
            issues.append(f"Ad_Block.list:{idx}: allowlisted rule leaked: {norm}")
        seen.add(norm)

    summary = {
        "rule_count": len(lines),
        "unique_rule_count": len(seen),
    }
    return issues, summary


def collect_module_sections(text: str) -> dict[str, int]:
    counts: dict[str, int] = {}
    current = ""
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        match = SECTION_RE.match(line)
        if match:
            current = match.group(1)
            counts.setdefault(current, 0)
            continue
        if current:
            counts[current] += 1
    return counts


def collect_module_section_lines(text: str) -> dict[str, list[tuple[int, str]]]:
    sections: dict[str, list[tuple[int, str]]] = {}
    current = ""
    for lineno, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()
        if not line:
            continue
        match = SECTION_RE.match(line)
        if match:
            current = match.group(1)
            sections.setdefault(current, [])
            continue
        if current:
            sections.setdefault(current, []).append((lineno, line))
    return sections


def reachable_script_urls_from_security(security: dict) -> set[str]:
    urls: set[str] = set()
    for item in security.get("downloaded_scripts", []):
        script_url = (item.get("script_url") or "").strip()
        if script_url:
            urls.add(script_url)
        converted_url = (item.get("converted_url") or "").strip()
        if converted_url:
            urls.add(converted_url)
    return urls


def validate_module(
    allow_hosts: set[str],
    allow_regexes: list[re.Pattern[str]],
    security: dict,
) -> tuple[list[str], dict]:
    issues: list[str] = []
    text = STAGED_AD_BLOCK_MODULE.read_text(encoding="utf-8")
    ok, reason = validate_final_module_text(text)
    if not ok:
        issues.append(f"Ad_Block.sgmodule invalid: {reason}")

    if "[Rule]" in text:
        issues.append("Ad_Block.sgmodule must not contain [Rule] section")

    sections = collect_module_sections(text)
    section_lines = collect_module_section_lines(text)
    reachable_script_urls = reachable_script_urls_from_security(security)

    for lineno, line in section_lines.get("MITM", []):
        items = parse_mitm_hostname_items(line)
        for item in items:
            host = item.lstrip("-").lstrip("*.").strip(".").lower()
            if not host:
                continue
            if any(host == allow or host.endswith("." + allow) for allow in allow_hosts):
                issues.append(f"Ad_Block.sgmodule:{lineno}: allowlisted MITM host leaked: {item}")

    for section in ("URL Rewrite", "Header Rewrite", "Body Rewrite", "Script", "Host"):
        for lineno, line in section_lines.get(section, []):
            if line_hits_allowlist(line, allow_hosts, allow_regexes):
                issues.append(f"Ad_Block.sgmodule:{lineno}: allowlisted line leaked in [{section}]: {line}")

    seen_script_keys: dict[tuple[str, ...], tuple[int, str]] = {}
    for lineno, line in section_lines.get("Script", []):
        parsed = parse_script_line(line)
        if parsed:
            _, fields = parsed
            script_path = fields.get("script-path", "").strip()
            if script_path.startswith(("http://", "https://")) and script_path not in reachable_script_urls:
                issues.append(
                    f"Ad_Block.sgmodule:{lineno}: script-path was not reachable in current scan: {script_path}"
                )

        key = semantic_script_key(line)
        if not key:
            continue
        if key in seen_script_keys:
            prev_lineno, prev_line = seen_script_keys[key]
            issues.append(
                "Ad_Block.sgmodule:"
                f"{lineno}: semantic duplicate script with line {prev_lineno}: {line} || {prev_line}"
            )
        else:
            seen_script_keys[key] = (lineno, line)

    summary = {
        "module_size_bytes": len(text.encode("utf-8")),
        "sections": sections,
    }
    return issues, summary


def validate_security_summary() -> tuple[list[str], dict, dict]:
    issues: list[str] = []
    if not SECURITY_SUMMARY_JSON.exists():
        issues.append(f"Missing security summary: {SECURITY_SUMMARY_JSON}")
        return issues, {}, {}

    data = json.loads(SECURITY_SUMMARY_JSON.read_text(encoding="utf-8"))
    tool_status = data.get("tool_status", {})

    available_scanners = [
        name for name, status in tool_status.items()
        if isinstance(status, dict) and status.get("available")
    ]
    if not available_scanners:
        issues.append("No security scanner was available for this run")

    return (
        issues,
        {
            "available_scanners": available_scanners,
            "scanned_script_count": data.get("scanned_script_count", 0),
            "failed_script_download_count": data.get("failed_script_download_count", 0),
            "compatibility_converted_count": data.get("compatibility_converted_count", 0),
            "suspicious_module_count": len(data.get("suspicious_modules", [])),
            "suspicious_script_hash_count": len(data.get("suspicious_script_hashes", [])),
        },
        data,
    )


def main() -> int:
    issues: list[str] = []
    summary: dict[str, object] = {}
    allow_hosts, allow_regexes = load_allowlist_context()
    security_issues, security_summary, security_data = validate_security_summary()
    issues.extend(security_issues)
    summary["security"] = security_summary

    if not STAGED_AD_BLOCK_LIST.exists():
        issues.append(f"Missing staged output: {STAGED_AD_BLOCK_LIST}")
    else:
        list_issues, list_summary = validate_rule_list(allow_hosts, allow_regexes)
        issues.extend(list_issues)
        summary["ad_block_list"] = list_summary

    if not STAGED_AD_BLOCK_MODULE.exists():
        issues.append(f"Missing staged output: {STAGED_AD_BLOCK_MODULE}")
    else:
        module_issues, module_summary = validate_module(allow_hosts, allow_regexes, security_data)
        issues.extend(module_issues)
        summary["ad_block_module"] = module_summary

    report = {
        "ok": not issues,
        "issues": issues,
        "summary": summary,
    }
    save_json(VALIDATION_REPORT, report)

    if issues:
        print(json.dumps(report, ensure_ascii=False, indent=2))
        return 1

    AD_BLOCK_LIST.parent.mkdir(parents=True, exist_ok=True)
    AD_BLOCK_MODULE.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(STAGED_AD_BLOCK_LIST, AD_BLOCK_LIST)
    shutil.copyfile(STAGED_AD_BLOCK_MODULE, AD_BLOCK_MODULE)

    print(f"Wrote {VALIDATION_REPORT}")
    print(f"Published {AD_BLOCK_LIST}")
    print(f"Published {AD_BLOCK_MODULE}")
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
