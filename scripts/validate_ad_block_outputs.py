#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import json
import re
import shutil
from pathlib import Path

from lib_rules import (
    AD_BLOCK_LIST,
    AD_BLOCK_MODULE,
    BUILD_DIR,
    REJECTED_RULES_TXT,
    STAGED_AD_BLOCK_LIST,
    STAGED_AD_BLOCK_MODULE,
    WHITELIST_HOSTS_TXT,
    ensure_project_dirs,
    write_text,
)

STANDARD_MODULE_STATIC_HEADER_LINES = [
    "#!name=Ad Block",
    "#!desc=Auto-merged, normalized, deduplicated and security-scanned ad blocking module for Surge",
    "#!author=master-zen",
    "#!icon=https://raw.githubusercontent.com/master-zen/Net-Link/refs/heads/main/Surge/Icon/Strategy_ADVertising.png",
    "#!category=AD Block",
    "#!openUrl=https://apps.apple.com/us/app/surge-5/id1442620678",
    "#!tag=AD Block",
    "#!homepage=https://github.com/master-zen/Net-Link/",
]

VALIDATION_REPORT = BUILD_DIR / "ad_block_validation_report.json"
ARGUMENT_CATALOG_JSON = BUILD_DIR / "scan_reports" / "ad_block_arguments_catalog.json"
SECURITY_SUMMARY_JSON = BUILD_DIR / "scan_reports" / "security_summary.json"
HEADER_DATE_RE = re.compile(r"^#!date=\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$")
VALID_SECTION_HEADERS = {
    "[MITM]",
    "[URL Rewrite]",
    "[Header Rewrite]",
    "[Body Rewrite]",
    "[Script]",
    "[Host]",
}


def load_json(path: Path, default):
    if not path.exists():
        return default
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return default



def validate_list_file(path: Path) -> tuple[list[str], dict]:
    issues: list[str] = []
    if not path.exists():
        return [f"missing file: {path}"], {"line_count": 0}

    text = path.read_text(encoding="utf-8")
    lines = text.splitlines()
    if not lines:
        issues.append("ad block list is empty")

    non_empty = [line.strip() for line in lines if line.strip()]
    unique_non_empty = set(non_empty)
    if len(non_empty) != len(unique_non_empty):
        issues.append("ad block list contains duplicate non-empty lines")

    summary = {
        "line_count": len(lines),
        "non_empty_line_count": len(non_empty),
        "unique_non_empty_line_count": len(unique_non_empty),
    }
    return issues, summary



def validate_module_file(path: Path) -> tuple[list[str], dict]:
    issues: list[str] = []
    if not path.exists():
        return [f"missing file: {path}"], {"line_count": 0}

    text = path.read_text(encoding="utf-8")
    if not text.strip():
        return ["ad block module is empty"], {"line_count": 0}

    lines = text.splitlines()
    non_empty = [line.strip() for line in lines if line.strip()]

    metadata_lines: list[str] = []
    sections: list[str] = []
    metadata_phase = True

    for raw in lines:
        s = raw.strip()
        if not s:
            continue
        if s.startswith("#!"):
            if not metadata_phase:
                issues.append(f"metadata appears after section start: {s}")
            metadata_lines.append(s)
            continue
        metadata_phase = False
        if s.startswith("[") and s.endswith("]"):
            sections.append(s)

    expected_prefix = STANDARD_MODULE_STATIC_HEADER_LINES
    if metadata_lines[: len(expected_prefix)] != expected_prefix:
        issues.append("module static header does not match expected header")

    date_line = None
    arguments_line = None
    arguments_desc_line = None
    for line in metadata_lines:
        if line.startswith("#!date="):
            date_line = line
        elif line.startswith("#!arguments="):
            arguments_line = line
        elif line.startswith("#!arguments-desc="):
            arguments_desc_line = line

    if not date_line or not HEADER_DATE_RE.match(date_line):
        issues.append("missing or invalid #!date header")
    if arguments_line is None:
        issues.append("missing #!arguments header")
    if arguments_desc_line is None:
        issues.append("missing #!arguments-desc header")

    invalid_sections = [s for s in sections if s not in VALID_SECTION_HEADERS]
    if invalid_sections:
        issues.append(f"invalid section headers: {', '.join(invalid_sections)}")

    if "{{{" in text or "}}}" in text:
        issues.append("module contains unresolved template placeholders")

    summary = {
        "line_count": len(lines),
        "metadata_line_count": len(metadata_lines),
        "section_count": len(sections),
        "sections": sections,
    }
    return issues, summary



def publish_staged_outputs() -> None:
    AD_BLOCK_LIST.parent.mkdir(parents=True, exist_ok=True)
    AD_BLOCK_MODULE.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(STAGED_AD_BLOCK_LIST, AD_BLOCK_LIST)
    shutil.copyfile(STAGED_AD_BLOCK_MODULE, AD_BLOCK_MODULE)



def main() -> int:
    ensure_project_dirs()

    issues: list[str] = []

    list_issues, list_summary = validate_list_file(STAGED_AD_BLOCK_LIST)
    module_issues, module_summary = validate_module_file(STAGED_AD_BLOCK_MODULE)
    issues.extend(list_issues)
    issues.extend(module_issues)

    rejected_count = 0
    if REJECTED_RULES_TXT.exists():
        rejected_count = len([x for x in REJECTED_RULES_TXT.read_text(encoding="utf-8").splitlines() if x.strip()])

    whitelist_count = 0
    if WHITELIST_HOSTS_TXT.exists():
        whitelist_count = len([x for x in WHITELIST_HOSTS_TXT.read_text(encoding="utf-8").splitlines() if x.strip()])

    argument_catalog = load_json(ARGUMENT_CATALOG_JSON, [])
    security_summary = load_json(SECURITY_SUMMARY_JSON, {})

    report = {
        "ok": not issues,
        "issues": issues,
        "list_summary": list_summary,
        "module_summary": module_summary,
        "rejected_rule_count": rejected_count,
        "whitelist_host_count": whitelist_count,
        "argument_catalog_count": len(argument_catalog) if isinstance(argument_catalog, list) else 0,
        "security_summary_present": bool(security_summary),
        "staged_list": str(STAGED_AD_BLOCK_LIST),
        "staged_module": str(STAGED_AD_BLOCK_MODULE),
        "final_list": str(AD_BLOCK_LIST),
        "final_module": str(AD_BLOCK_MODULE),
    }

    write_text(VALIDATION_REPORT, json.dumps(report, ensure_ascii=False, indent=2) + "\n")

    if issues:
        print(json.dumps(report, ensure_ascii=False, indent=2))
        return 1

    publish_staged_outputs()
    print(f"Wrote {VALIDATION_REPORT}")
    print(f"Published {AD_BLOCK_LIST}")
    print(f"Published {AD_BLOCK_MODULE}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
