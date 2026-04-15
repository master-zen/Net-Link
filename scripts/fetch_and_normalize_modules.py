#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import re
from pathlib import Path
from urllib.parse import urlparse

from lib_rules import (
    DISCOVERED_MODULE_URLS,
    NORMALIZED_MODULES_JSON,
    dedupe_sorted,
    ensure_project_dirs,
    extract_reject_rule_from_module_rule,
    is_comment_or_empty,
    normalize_rule_line,
    request_text,
    save_json,
    stable_module_id,
    strip_no_resolve_and_trailing_commas,
)

SECTION_ALIASES = {
    "mitm": "mitm",
    "rule": "rule",
    "rules": "rule",
    "urlrewrite": "url_rewrite",
    "rewrite": "url_rewrite",
    "rewritelocal": "url_rewrite",
    "headerrewrite": "header_rewrite",
    "bodyrewrite": "body_rewrite",
    "script": "script",
    "scriptlocal": "script",
    "host": "host",
    "maplocal": "host",
}


def canonical_section_name(raw: str) -> str | None:
    name = raw.strip().strip("[]").lower().replace(" ", "").replace("_", "").replace("-", "")
    return SECTION_ALIASES.get(name)


def has_unresolved_template(text: str) -> bool:
    s = text.strip()
    return "{{{" in s or "}}}" in s


def strip_module_operator_tokens(text: str) -> str:

    return re.sub(r"(?i)%\s*(APPEND|INSERT|REPLACE)\s*%", "", text).strip()


def is_obviously_broken_line(text: str) -> bool:
    s = text.strip().lower()
    if not s:
        return True
    if has_unresolved_template(s):
        return True
    if s.startswith("ttp-request") or s.startswith("ttp-response"):
        return True
    return False


def parse_metadata(lines: list[str]) -> dict[str, str]:
    meta: dict[str, str] = {}
    for line in lines:
        s = line.strip()
        if s.startswith("#!") and "=" in s:
            key, value = s[2:].split("=", 1)
            meta[key.strip().lower()] = value.strip()
    return meta


def split_sections(text: str) -> tuple[dict[str, list[str]], dict[str, str]]:
    sections: dict[str, list[str]] = {
        "mitm": [],
        "rule": [],
        "url_rewrite": [],
        "header_rewrite": [],
        "body_rewrite": [],
        "script": [],
        "host": [],
    }

    lines = text.splitlines()
    metadata = parse_metadata(lines)

    current: str | None = None
    for raw in lines:
        line = raw.rstrip()
        stripped = line.strip()

        if stripped.startswith("#!"):
            continue

        if stripped.startswith("[") and stripped.endswith("]"):
            current = canonical_section_name(stripped)
            continue

        if current is None:
            continue

        sections[current].append(line)

    return sections, metadata


def normalize_mitm_line(line: str) -> list[str]:
    if is_comment_or_empty(line):
        return []

    s = line.strip()
    if is_obviously_broken_line(s):
        return []

    if s.lower().startswith("hostname") and "=" in s:
        s = s.split("=", 1)[1].strip()

    s = strip_module_operator_tokens(s)

    parts = [p.strip().lower().lstrip(".") for p in s.split(",") if p.strip()]
    hosts: list[str] = []

    for part in parts:
        part = strip_module_operator_tokens(part)
        if not part:
            continue

        if "%" in part:
            continue

        if " " in part:
            tokens = [t.strip().lower().lstrip(".") for t in part.split() if t.strip()]
            for token in tokens:
                if token and "%" not in token and ("." in token or "*" in token):
                    hosts.append(token)
            continue

        if "." not in part and "*" not in part:
            continue

        hosts.append(part)

    return hosts


def normalize_rewrite_line(line: str) -> str | None:
    if is_comment_or_empty(line):
        return None

    s = strip_no_resolve_and_trailing_commas(line.strip())
    if not s or is_obviously_broken_line(s):
        return None

    # QX-style: ^https://... url reject
    if " url " in s:
        left, right = s.split(" url ", 1)
        action = right.strip().lower()

        if action.startswith("reject"):
            result = f"{left.strip()} - reject"
            if is_obviously_broken_line(result):
                return None
            return result

        return None

    return s


def extract_script_path(line: str) -> str | None:
    s = line.strip()
    marker = "script-path="
    if marker in s:
        tail = s.split(marker, 1)[1].strip()
        return tail.split(",", 1)[0].strip()

    # QX-style:
    # ^https://example url script-response-body https://xx.js
    if " url script-" in s:
        parts = s.split()
        if parts and parts[-1].startswith(("http://", "https://")):
            return parts[-1].strip()

    return None


def normalize_script_line(line: str) -> dict | None:
    if is_comment_or_empty(line):
        return None

    s = strip_no_resolve_and_trailing_commas(line.strip())
    if not s or is_obviously_broken_line(s):
        return None

    script_url = extract_script_path(s)

    # QX-style -> Surge
    if " url script-" in s:
        parts = s.split()
        if len(parts) >= 4:
            pattern = parts[0].strip()
            kind = parts[2].strip().lower()
            script_url = parts[3].strip()

            mapping = {
                "script-response-body": ("http-response-body", True),
                "script-request-body": ("http-request-body", True),
                "script-response-header": ("http-response-header", False),
                "script-request-header": ("http-request-header", False),
            }

            if kind in mapping and script_url.startswith(("http://", "https://")):
                surge_type, requires_body = mapping[kind]
                line = f"type={surge_type},pattern={pattern},script-path={script_url}"
                if requires_body:
                    line += ",requires-body=1"
                return {
                    "line": line,
                    "script_url": script_url,
                }

    # Surge 风格脚本：至少要有 type/pattern/script-path
    lower = s.lower()
    if "script-path=" in lower and "pattern=" in lower and "type=" in lower:
        return {
            "line": s,
            "script_url": script_url,
        }

    return None


def load_url_list(path: Path) -> list[str]:
    if not path.exists():
        return []
    return [line.strip() for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def module_name_from_url(url: str) -> str:
    path = urlparse(url).path
    return Path(path).stem


def main() -> int:
    ensure_project_dirs()

    urls = load_url_list(DISCOVERED_MODULE_URLS)
    modules: list[dict] = []

    for url in urls:
        try:
            text = request_text(url)
        except Exception:
            continue

        sections, metadata = split_sections(text)

        module = {
            "module_id": stable_module_id(url),
            "source_url": url,
            "module_name": metadata.get("name") or module_name_from_url(url),
            "metadata": metadata,
            "mitm_hosts": [],
            "rules": [],
            "url_rewrite": [],
            "header_rewrite": [],
            "body_rewrite": [],
            "scripts": [],
            "host": [],
            "notes": [],
        }

        mitm_hosts: list[str] = []
        rules: list[str] = []
        url_rewrite: list[str] = []
        header_rewrite: list[str] = []
        body_rewrite: list[str] = []
        scripts: list[dict] = []
        host_lines: list[str] = []

        for line in sections["mitm"]:
            mitm_hosts.extend(normalize_mitm_line(line))

        for line in sections["rule"]:
            norm = normalize_rule_line(line, strip_policy=False)
            if norm:
                rules.append(norm)

        for line in sections["url_rewrite"]:
            norm = normalize_rewrite_line(line)
            if norm:
                url_rewrite.append(norm)

        for line in sections["header_rewrite"]:
            norm = strip_no_resolve_and_trailing_commas(line.strip())
            if not norm or is_comment_or_empty(norm) or is_obviously_broken_line(norm):
                continue
            header_rewrite.append(norm)

        for line in sections["body_rewrite"]:
            norm = strip_no_resolve_and_trailing_commas(line.strip())
            if not norm or is_comment_or_empty(norm) or is_obviously_broken_line(norm):
                continue
            body_rewrite.append(norm)

        for line in sections["script"]:
            norm = normalize_script_line(line)
            if norm:
                scripts.append(norm)

        for line in sections["host"]:
            norm = strip_no_resolve_and_trailing_commas(line.strip())
            if not norm or is_comment_or_empty(norm) or is_obviously_broken_line(norm):
                continue
            host_lines.append(norm)

        module["mitm_hosts"] = dedupe_sorted(mitm_hosts)
        module["rules"] = dedupe_sorted(rules)
        module["url_rewrite"] = dedupe_sorted(url_rewrite)
        module["header_rewrite"] = dedupe_sorted(header_rewrite)
        module["body_rewrite"] = dedupe_sorted(body_rewrite)
        module["scripts"] = sorted(
            {f'{item["line"]}\u0000{item.get("script_url","")}': item for item in scripts}.values(),
            key=lambda x: x["line"].casefold(),
        )
        module["host"] = dedupe_sorted(host_lines)

        extracted = [extract_reject_rule_from_module_rule(r) for r in module["rules"]]
        extracted = [r for r in extracted if r]
        if extracted:
            module["notes"].append(f"extractable_reject_rules={len(extracted)}")

        modules.append(module)

    save_json(
        NORMALIZED_MODULES_JSON,
        {
            "generated_from": str(DISCOVERED_MODULE_URLS),
            "module_count": len(modules),
            "modules": modules,
        },
    )

    print(f"Wrote {NORMALIZED_MODULES_JSON} with {len(modules)} modules.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
