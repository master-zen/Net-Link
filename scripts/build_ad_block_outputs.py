#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

from datetime import datetime, timezone
import json
import ipaddress
import re
from pathlib import Path

from lib_rules import (
    BUILD_DIR,
    DATA_ALLOWLISTS_DIR,
    NORMALIZED_MODULES_JSON,
    REJECTED_RULES_TXT,
    SECURITY_SUMMARY_JSON,
    STAGED_AD_BLOCK_LIST,
    STAGED_AD_BLOCK_MODULE,
    WHITELIST_HOSTS_TXT,
    dedupe_sorted,
    ensure_project_dirs,
    expand_hosts_with_parents,
    extract_reject_rule_from_module_rule,
    is_comment_or_empty,
    line_matches_any_regex,
    line_mentions_allowlisted_host,
    normalized_rule_matches_allowlist,
    parse_allowlist_host_line,
    read_lines,
    safe_compile_regexes,
    write_lines,
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

CACHE_DIR = BUILD_DIR / "cache"
CACHED_ALLOWLIST_HOSTS_JSON = CACHE_DIR / "allowlist_hosts.json"
CACHED_LEGACY_RULES_JSON = CACHE_DIR / "legacy_rules.json"
ARGUMENT_CATALOG_JSON = BUILD_DIR / "scan_reports" / "ad_block_arguments_catalog.json"
HEADER_DATE_RE = re.compile(r"^#!date=\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$")

VALID_SECTION_HEADERS = {
    "[MITM]",
    "[URL Rewrite]",
    "[Header Rewrite]",
    "[Body Rewrite]",
    "[Script]",
    "[Host]",
}

HEADER_ACTION_RE = re.compile(
    r"^(http-request|http-response)\s+\S+\s+"
    r"(header-add|header-del|header-replace|header-replace-regex)\b",
    re.IGNORECASE,
)
BODY_REWRITE_RE = re.compile(
    r"^(http-request|http-response|http-request-jq|http-response-jq)\s+\S+",
    re.IGNORECASE,
)
SCRIPT_FIELD_SPLIT_RE = re.compile(r",\s*(?=[a-z-]+=)", re.IGNORECASE)
HOST_MAPPING_RE = re.compile(
    r"""^(
        DOMAIN-SET:[^=\s]+|
        RULE-SET:[^=\s]+|
        [*A-Za-z0-9._?-]+
    )\s*=\s*(
        server:[^=\s]+|
        [*A-Za-z0-9._:-]+
    )$""",
    re.IGNORECASE | re.VERBOSE,
)


def load_json(path: Path, default):
    if not path.exists():
        return default
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return default


def load_modules() -> list[dict]:
    data = load_json(NORMALIZED_MODULES_JSON, {})
    return data.get("modules", []) if isinstance(data, dict) else []


def load_security_summary() -> dict:
    data = load_json(SECURITY_SUMMARY_JSON, {})
    return data if isinstance(data, dict) else {}


def load_cached_allowlist_hosts() -> set[str]:
    data = load_json(CACHED_ALLOWLIST_HOSTS_JSON, [])
    if not isinstance(data, list):
        return set()
    return {str(x).strip().lower() for x in data if str(x).strip()}


def load_cached_legacy_rules() -> set[str]:
    data = load_json(CACHED_LEGACY_RULES_JSON, [])
    if not isinstance(data, list):
        return set()
    return {str(x).strip() for x in data if str(x).strip()}


def build_converted_script_url_map(security: dict) -> dict[str, str]:
    mapping: dict[str, str] = {}
    for item in security.get("downloaded_scripts", []):
        source_url = (item.get("script_url") or "").strip()
        converted_url = (item.get("converted_url") or "").strip()
        if source_url and converted_url:
            mapping[source_url] = converted_url
    return mapping


def build_reachable_script_urls(security: dict) -> set[str]:
    reachable: set[str] = set()
    for item in security.get("downloaded_scripts", []):
        script_url = (item.get("script_url") or "").strip()
        if script_url:
            reachable.add(script_url)
        converted_url = (item.get("converted_url") or "").strip()
        if converted_url:
            reachable.add(converted_url)
    return reachable


def load_local_allowlist_hosts() -> set[str]:
    hosts: set[str] = set()
    for line in read_lines(DATA_ALLOWLISTS_DIR / "hosts.txt"):
        host = parse_allowlist_host_line(line)
        if host:
            hosts.add(host)
    return hosts


def load_local_allowlist_regexes():
    return safe_compile_regexes(read_lines(DATA_ALLOWLISTS_DIR / "url_regex.txt"))


def load_local_module_ids() -> set[str]:
    ids = set()
    for line in read_lines(DATA_ALLOWLISTS_DIR / "module_ids.txt"):
        s = line.strip()
        if not s or s.startswith(("#", ";", "//")):
            continue
        ids.add(s)
    return ids


def module_is_excluded(module: dict, module_ids: set[str]) -> bool:
    module_id = module.get("module_id", "")
    module_name = (module.get("module_name") or "").strip()
    source_url = (module.get("source_url") or "").strip()
    return module_id in module_ids or module_name in module_ids or source_url in module_ids


def filter_line_by_whitelist(line: str, allow_hosts: set[str], regexes) -> bool:
    if line_mentions_allowlisted_host(line, allow_hosts):
        return True
    if line_matches_any_regex(line, regexes):
        return True
    return False


def is_ip_literal(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def looks_like_regex_residue(value: str) -> bool:
    lower = value.lower()
    bad_substrings = ["a-z", "0-9", "_-", "[", "]", "(", ")", "{", "}", "|", "\\"]
    return any(x in lower for x in bad_substrings)


def unwrap_quoted_token(value: str) -> str:
    s = value.strip()
    if len(s) >= 2 and s[0] == s[-1] and s[0] in {'"', "'"}:
        return s[1:-1]
    return s


def has_domain_like_letters(value: str) -> bool:
    return any(ch.isalpha() for ch in value)


def sanitize_mitm_host(host: str) -> str | None:
    s = host.strip().lower().lstrip(".")
    if not s or is_comment_or_empty(s) or "%" in s or "{{{" in s or "}}}" in s or " " in s:
        return None
    if s in {"<ip-address>", "<ipv4-address>", "<ipv6-address>"}:
        return s
    prefix = ""
    if s.startswith("-"):
        prefix = "-"
        s = s[1:].strip()
        if not s:
            return None
    host_part = s
    port_part = ""
    if ":" in s:
        maybe_host, maybe_port = s.rsplit(":", 1)
        if maybe_port.isdigit():
            host_part = maybe_host
            port_part = ":" + maybe_port
    if is_ip_literal(host_part) or looks_like_regex_residue(host_part):
        return None
    if not has_domain_like_letters(host_part.replace("*", "").replace("?", "")):
        return None
    if not re.fullmatch(r"[*?a-z0-9._-]+", host_part):
        return None
    if "." not in host_part and "*" not in host_part and "?" not in host_part:
        return None
    return prefix + host_part + port_part


def sanitize_url_rewrite_line(line: str) -> str | None:
    s = line.strip()
    if not s or is_comment_or_empty(s) or "{{{" in s or "}}}" in s:
        return None
    lower = s.lower()
    banned_tokens = [
        "reject-dict",
        "reject-200",
        "response-body-json-jq",
        "response-body-json-del",
        "response-body-replace-regex",
        "jq-path=",
    ]
    if any(token in lower for token in banned_tokens):
        return None
    parts = s.split()
    if len(parts) < 3:
        return None
    rewrite_type = parts[-1].lower()
    if rewrite_type not in {"header", "302", "reject"}:
        return None
    pattern = unwrap_quoted_token(parts[0])
    replacement = unwrap_quoted_token(" ".join(parts[1:-1]).strip())
    if not pattern or not replacement:
        return None
    return f"{pattern} {replacement} {rewrite_type}"


def sanitize_header_line(line: str) -> str | None:
    s = line.strip()
    if not s or is_comment_or_empty(s) or "{{{" in s or "}}}" in s:
        return None
    return s if HEADER_ACTION_RE.match(s) else None


def sanitize_body_line(line: str) -> str | None:
    s = line.strip()
    if not s or is_comment_or_empty(s) or "{{{" in s or "}}}" in s:
        return None
    lower = s.lower()
    banned_tokens = ["response-body-json-del", "response-body-replace-regex", "jq-path="]
    if any(token in lower for token in banned_tokens):
        return None
    return s if BODY_REWRITE_RE.match(s) else None


def sanitize_script_line(line: str) -> str | None:
    s = line.strip()
    if not s or is_comment_or_empty(s) or "{{{" in s or "}}}" in s or "=" not in s:
        return None
    name, rhs = s.split("=", 1)
    name = name.strip()
    rhs = rhs.strip()
    if not name or any(ch in name for ch in "[]"):
        return None
    lower = rhs.lower()
    if "type=" not in lower or "pattern=" not in lower or "script-path=" not in lower:
        return None
    return f"{name} = {rhs}"


def sanitize_host_mapping_line(line: str) -> str | None:
    s = line.strip()
    if not s or is_comment_or_empty(s) or "{{{" in s or "}}}" in s:
        return None
    if "data=" in s.lower() or "data-type=" in s.lower() or "status-code=" in s.lower():
        return None
    return s if HOST_MAPPING_RE.match(s) else None


def split_argument_items(raw: str) -> list[str]:
    text = raw.strip()
    if not text:
        return []
    items: list[str] = []
    current: list[str] = []
    quote = ""
    for ch in text:
        if quote:
            current.append(ch)
            if ch == quote:
                quote = ""
            continue
        if ch in {'"', "'"}:
            quote = ch
            current.append(ch)
            continue
        if ch in {",", "，"}:
            item = "".join(current).strip()
            if item:
                items.append(item)
            current = []
            continue
        current.append(ch)
    tail = "".join(current).strip()
    if tail:
        items.append(tail)
    return items


def collect_module_argument_items(module: dict) -> list[str]:
    metadata = module.get("metadata") or {}
    raw = str(metadata.get("arguments") or "").strip()
    items: list[str] = []
    for item in split_argument_items(raw):
        item = item.strip()
        if not item:
            continue
        if "=" in item:
            items.append(item)
            continue
        if ":" in item:
            key, value = item.split(":", 1)
            key = key.strip()
            value = value.strip()
            if key:
                items.append(f"{key}={value}")
            continue
        items.append(item)
    return items


def collect_module_argument_desc(module: dict) -> str:
    metadata = module.get("metadata") or {}
    return str(metadata.get("arguments-desc") or "").strip()


def parse_argument_item(raw: str) -> tuple[str, str] | None:
    s = raw.strip()
    if not s or "=" not in s:
        return None
    key, value = s.split("=", 1)
    key = key.strip()
    value = value.strip()
    if not key:
        return None
    return key, value


def normalize_group_title(text: str) -> str:
    s = str(text or "").strip() or "Unnamed Module"
    s = re.sub(r"\s+", " ", s)
    return s.replace("&", "／").replace("=", "－")


def escape_header_value(text: str) -> str:
    return text.replace("\\", "\\\\").replace("\r\n", "\n").replace("\r", "\n").replace("\n", "\\n")


def make_unique_group_marker(module_name: str, used_markers: set[str]) -> str:
    base = normalize_group_title(module_name)
    candidate = f"【{base}】↓"
    if candidate not in used_markers:
        used_markers.add(candidate)
        return f"{candidate}=--"
    index = 2
    while True:
        candidate = f"【{base} {index}】↓"
        if candidate not in used_markers:
            used_markers.add(candidate)
            return f"{candidate}=--"
        index += 1


def build_argument_bundle(module_argument_blocks: list[dict]) -> tuple[list[str], str, list[dict[str, object]]]:
    used_markers: set[str] = set()
    global_used_keys: set[str] = set()
    header_items: list[str] = []
    desc_lines: list[str] = []
    catalog: list[dict[str, object]] = []
    section_index = 1

    for block in module_argument_blocks:
        module_name = str(block["module_name"])
        module_id = str(block["module_id"])
        source_url = str(block["source_url"])
        original_items: list[str] = list(block["arguments"])
        module_desc = str(block["arguments_desc"] or "").strip()

        kept_items: list[str] = []
        skipped_conflicts: list[str] = []
        skipped_invalid: list[str] = []
        skipped_duplicate_keys_in_module: list[str] = []
        seen_keys_in_module: set[str] = set()

        for raw in original_items:
            parsed = parse_argument_item(raw)
            if not parsed:
                skipped_invalid.append(raw)
                continue
            key, value = parsed
            normalized_raw = f"{key}={value}"
            if key in seen_keys_in_module:
                skipped_duplicate_keys_in_module.append(normalized_raw)
                continue
            seen_keys_in_module.add(key)
            if key in global_used_keys:
                skipped_conflicts.append(normalized_raw)
                continue
            global_used_keys.add(key)
            kept_items.append(normalized_raw)

        group_marker = ""
        if kept_items:
            group_marker = make_unique_group_marker(module_name, used_markers)
            header_items.append(group_marker)
            header_items.extend(kept_items)

            desc_lines.append(f"{section_index}️⃣ {normalize_group_title(module_name)}")
            desc_lines.append("")
            for item in kept_items:
                desc_lines.append(f"• {normalize_group_title(module_name)}：{item}")
            if module_desc:
                desc_lines.append("")
                desc_lines.append("说明：")
                desc_lines.extend(module_desc.replace("\r\n", "\n").replace("\r", "\n").split("\n"))
            if skipped_conflicts:
                desc_lines.append("")
                desc_lines.append("已跳过冲突参数：")
                for item in skipped_conflicts:
                    desc_lines.append(f"- {item}")
            if skipped_duplicate_keys_in_module:
                desc_lines.append("")
                desc_lines.append("已跳过模块内重复参数：")
                for item in skipped_duplicate_keys_in_module:
                    desc_lines.append(f"- {item}")
            if skipped_invalid:
                desc_lines.append("")
                desc_lines.append("已跳过无效参数：")
                for item in skipped_invalid:
                    desc_lines.append(f"- {item}")
            desc_lines.append("")
            section_index += 1

        catalog.append(
            {
                "module_name": module_name,
                "module_id": module_id,
                "source_url": source_url,
                "group_marker": group_marker,
                "original_arguments": original_items,
                "kept_arguments": kept_items,
                "arguments_desc": module_desc,
                "skipped_conflicting_arguments": skipped_conflicts,
                "skipped_invalid_arguments": skipped_invalid,
                "skipped_duplicate_keys_in_module": skipped_duplicate_keys_in_module,
            }
        )

    if not desc_lines:
        desc_lines = ["No module arguments were kept."]

    arguments_desc_text = "\n".join(desc_lines).rstrip()
    return header_items, arguments_desc_text, catalog


def build_standard_module_header(arguments_text: str, arguments_desc_text: str) -> str:
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    lines = list(STANDARD_MODULE_STATIC_HEADER_LINES)
    lines.append(f"#!date={timestamp}")
    lines.append(f"#!arguments={arguments_text}")
    lines.append(f"#!arguments-desc={escape_header_value(arguments_desc_text)}")
    return "\n".join(lines)


def parse_script_line(line: str) -> tuple[str, dict[str, str]] | None:
    s = sanitize_script_line(line)
    if not s or "=" not in s:
        return None
    name, rhs = s.split("=", 1)
    name = name.strip()
    rhs = rhs.strip()
    fields: dict[str, str] = {}
    for part in SCRIPT_FIELD_SPLIT_RE.split(rhs):
        if "=" not in part:
            continue
        key, value = part.split("=", 1)
        fields[key.strip().lower()] = value.strip()
    if not {"type", "pattern", "script-path"} <= set(fields):
        return None
    return name, fields


def replace_script_path(line: str, new_url: str) -> str:
    if not new_url:
        return line
    return re.sub(r"(script-path=)([^,]+)", lambda m: m.group(1) + new_url, line, count=1)


def normalize_script_field_value(key: str, value: str) -> str:
    normalized = unwrap_quoted_token(value.strip())
    lower_key = key.lower()
    if lower_key == "type":
        return normalized.lower()
    if lower_key in {"requires-body", "binary-body-mode"}:
        lowered = normalized.lower()
        if lowered in {"1", "true", "yes"}:
            return "1"
        if lowered in {"0", "false", "no"}:
            return "0"
    return normalized


def semantic_script_key(line: str) -> tuple[str, ...] | None:
    parsed = parse_script_line(line)
    if not parsed:
        return None
    _, fields = parsed
    relevant = ("type", "pattern", "script-path", "argument", "requires-body", "binary-body-mode")
    return tuple(normalize_script_field_value(key, fields.get(key, "")) for key in relevant)


def build_module_text(
    arguments_text: str,
    arguments_desc_text: str,
    mitm_hosts: set[str],
    url_rewrite: set[str],
    header_rewrite: set[str],
    body_rewrite: set[str],
    scripts: set[str],
    host_lines: set[str],
) -> str:
    lines: list[str] = [build_standard_module_header(arguments_text, arguments_desc_text), ""]

    clean_mitm_hosts = [
        h for h in (sanitize_mitm_host(x) for x in sorted(mitm_hosts, key=lambda s: s.casefold())) if h
    ]
    if clean_mitm_hosts:
        lines.append("[MITM]")
        lines.append("hostname = %append% " + ", ".join(clean_mitm_hosts))
        lines.append("")

    clean_url_rewrite = [
        s for s in (sanitize_url_rewrite_line(x) for x in sorted(url_rewrite, key=lambda s: s.casefold())) if s
    ]
    if clean_url_rewrite:
        lines.append("[URL Rewrite]")
        lines.extend(clean_url_rewrite)
        lines.append("")

    clean_header_rewrite = [
        s for s in (sanitize_header_line(x) for x in sorted(header_rewrite, key=lambda s: s.casefold())) if s
    ]
    if clean_header_rewrite:
        lines.append("[Header Rewrite]")
        lines.extend(clean_header_rewrite)
        lines.append("")

    clean_body_rewrite = [
        s for s in (sanitize_body_line(x) for x in sorted(body_rewrite, key=lambda s: s.casefold())) if s
    ]
    if clean_body_rewrite:
        lines.append("[Body Rewrite]")
        lines.extend(clean_body_rewrite)
        lines.append("")

    clean_scripts = [
        s for s in (sanitize_script_line(x) for x in sorted(scripts, key=lambda s: s.casefold())) if s
    ]
    if clean_scripts:
        lines.append("[Script]")
        lines.extend(clean_scripts)
        lines.append("")

    clean_host_lines = [
        s for s in (sanitize_host_mapping_line(x) for x in sorted(host_lines, key=lambda s: s.casefold())) if s
    ]
    if clean_host_lines:
        lines.append("[Host]")
        lines.extend(clean_host_lines)
        lines.append("")

    while lines and not lines[-1].strip():
        lines.pop()

    return "\n".join(lines) + "\n"


def validate_final_module_text(text: str) -> tuple[bool, str]:
    lines = text.splitlines()
    if not lines:
        return False, "empty file"
    metadata_lines: list[str] = []
    for raw in lines:
        s = raw.strip()
        if not s:
            continue
        if s.startswith("[") and s.endswith("]"):
            break
        if s.startswith("#!"):
            metadata_lines.append(s)
            continue
        return False, f"content appears before metadata or section: {s[:120]}"
    if not metadata_lines:
        return False, "missing metadata header"
    expected_metadata_count = len(STANDARD_MODULE_STATIC_HEADER_LINES) + 3
    if len(metadata_lines) != expected_metadata_count:
        return False, f"unexpected metadata header length: {len(metadata_lines)}"
    if metadata_lines[: len(STANDARD_MODULE_STATIC_HEADER_LINES)] != STANDARD_MODULE_STATIC_HEADER_LINES:
        return False, "metadata header does not match required standard header"
    date_line = metadata_lines[len(STANDARD_MODULE_STATIC_HEADER_LINES)]
    if not HEADER_DATE_RE.match(date_line):
        return False, f"invalid standard date header: {date_line}"
    arguments_line = metadata_lines[len(STANDARD_MODULE_STATIC_HEADER_LINES) + 1]
    if not arguments_line.startswith("#!arguments="):
        return False, f"missing standard arguments header: {arguments_line}"
    arguments_desc_line = metadata_lines[len(STANDARD_MODULE_STATIC_HEADER_LINES) + 2]
    if not arguments_desc_line.startswith("#!arguments-desc="):
        return False, f"missing standard arguments-desc header: {arguments_desc_line}"
    if "{{{" in text or "}}}" in text:
        return False, "contains unresolved template placeholders"
    current_section = None
    seen_any_section = False
    metadata_phase = True
    for raw in lines:
        s = raw.strip()
        if not s:
            continue
        if s.startswith("#!"):
            if not metadata_phase:
                return False, f"metadata appears after sections: {s}"
            continue
        metadata_phase = False
        if s.startswith("[") and s.endswith("]"):
            if s not in VALID_SECTION_HEADERS:
                return False, f"invalid section header: {s}"
            current_section = s
            seen_any_section = True
            continue
        if current_section is None:
            return False, f"content appears before any section: {s[:120]}"
        if current_section == "[MITM]":
            if not s.lower().startswith("hostname ="):
                return False, f"invalid MITM line: {s}"
        elif current_section == "[URL Rewrite]":
            if not sanitize_url_rewrite_line(s):
                return False, f"invalid URL Rewrite line: {s}"
        elif current_section == "[Header Rewrite]":
            if not sanitize_header_line(s):
                return False, f"invalid Header Rewrite line: {s}"
        elif current_section == "[Body Rewrite]":
            if not sanitize_body_line(s):
                return False, f"invalid Body Rewrite line: {s}"
        elif current_section == "[Script]":
            if not sanitize_script_line(s):
                return False, f"invalid Script line: {s}"
        elif current_section == "[Host]":
            if not sanitize_host_mapping_line(s):
                return False, f"invalid Host line: {s}"
    if not seen_any_section:
        return False, "no valid sections found"
    return True, "ok"


def main() -> int:
    ensure_project_dirs()
    BUILD_DIR.mkdir(parents=True, exist_ok=True)

    modules = load_modules()
    security = load_security_summary()

    suspicious_modules = set(security.get("suspicious_modules", []))
    suspicious_hashes = set(security.get("suspicious_script_hashes", []))
    converted_script_urls = build_converted_script_url_map(security)
    reachable_script_urls = build_reachable_script_urls(security)
    suspicious_script_urls = {
        item.get("script_url", "")
        for item in security.get("downloaded_scripts", [])
        if item.get("script_hash") in suspicious_hashes
    }

    allow_hosts = load_cached_allowlist_hosts()
    allow_hosts |= load_local_allowlist_hosts()
    allow_hosts = expand_hosts_with_parents(allow_hosts)
    allow_hosts = set(dedupe_sorted(allow_hosts))
    write_lines(WHITELIST_HOSTS_TXT, sorted(allow_hosts, key=lambda s: s.casefold()))

    allow_regexes = load_local_allowlist_regexes()
    allow_module_ids = load_local_module_ids()

    merged_rules: set[str] = set(load_cached_legacy_rules())
    rejected_log: list[str] = []

    mitm_hosts: set[str] = set()
    url_rewrite: set[str] = set()
    header_rewrite: set[str] = set()
    body_rewrite: set[str] = set()
    script_lines_by_key: dict[tuple[str, ...] | str, str] = {}
    host_lines: set[str] = set()
    module_argument_blocks: list[dict[str, object]] = []

    for module in modules:
        module_id = module.get("module_id", "")
        source_url = module.get("source_url", "")
        module_name = module.get("module_name", "")
        module_argument_candidates = collect_module_argument_items(module)
        module_argument_desc = collect_module_argument_desc(module)
        module_contributed_to_final_module = False

        if module_is_excluded(module, allow_module_ids):
            rejected_log.append(f"module_excluded_by_module_ids\t{module_id}\t{module_name}\t{source_url}")
            continue

        if module_id in suspicious_modules:
            rejected_log.append(f"module_excluded_by_security\t{module_id}\t{module_name}\t{source_url}")
            continue

        for rule in module.get("rules", []):
            reject_rule = extract_reject_rule_from_module_rule(rule)
            if not reject_rule:
                continue
            if normalized_rule_matches_allowlist(reject_rule, allow_hosts):
                rejected_log.append(f"rule_removed_by_allowlist\t{reject_rule}\t{module_id}\t{source_url}")
                continue
            merged_rules.add(reject_rule)

        for host in module.get("mitm_hosts", []):
            host = sanitize_mitm_host(host or "")
            if not host:
                continue
            host_plain = host.lstrip("-")
            if any(host_plain == h or host_plain.endswith("." + h) for h in allow_hosts):
                rejected_log.append(f"mitm_removed_by_allowlist\t{host}\t{module_id}\t{source_url}")
                continue
            mitm_hosts.add(host)
            module_contributed_to_final_module = True

        for line in module.get("url_rewrite", []):
            s = sanitize_url_rewrite_line(line)
            if not s:
                continue
            if filter_line_by_whitelist(s, allow_hosts, allow_regexes):
                rejected_log.append(f"url_rewrite_removed_by_allowlist\t{s}\t{module_id}\t{source_url}")
                continue
            url_rewrite.add(s)
            module_contributed_to_final_module = True

        for line in module.get("header_rewrite", []):
            s = sanitize_header_line(line)
            if not s:
                continue
            if filter_line_by_whitelist(s, allow_hosts, allow_regexes):
                rejected_log.append(f"header_rewrite_removed_by_allowlist\t{s}\t{module_id}\t{source_url}")
                continue
            header_rewrite.add(s)
            module_contributed_to_final_module = True

        for line in module.get("body_rewrite", []):
            s = sanitize_body_line(line)
            if not s:
                continue
            if filter_line_by_whitelist(s, allow_hosts, allow_regexes):
                rejected_log.append(f"body_rewrite_removed_by_allowlist\t{s}\t{module_id}\t{source_url}")
                continue
            body_rewrite.add(s)
            module_contributed_to_final_module = True

        for item in module.get("scripts", []):
            line = sanitize_script_line(item.get("line") or "")
            script_url = (item.get("script_url") or "").strip()
            if not line:
                continue
            if script_url.startswith(("http://", "https://")) and script_url not in reachable_script_urls:
                rejected_log.append(f"script_removed_unreachable\t{script_url}\t{module_id}\t{source_url}")
                continue
            if script_url and script_url in suspicious_script_urls:
                rejected_log.append(f"script_removed_by_security\t{script_url}\t{module_id}\t{source_url}")
                continue
            if filter_line_by_whitelist(line, allow_hosts, allow_regexes):
                rejected_log.append(f"script_removed_by_allowlist\t{line}\t{module_id}\t{source_url}")
                continue
            if script_url in converted_script_urls:
                line = replace_script_path(line, converted_script_urls[script_url])
            key = semantic_script_key(line) or line
            existing = script_lines_by_key.get(key)
            if existing is None or line.casefold() < existing.casefold():
                script_lines_by_key[key] = line
                module_contributed_to_final_module = True

        for line in module.get("host", []):
            s = sanitize_host_mapping_line(line)
            if not s:
                continue
            if filter_line_by_whitelist(s, allow_hosts, allow_regexes):
                rejected_log.append(f"host_removed_by_allowlist\t{s}\t{module_id}\t{source_url}")
                continue
            host_lines.add(s)
            module_contributed_to_final_module = True

        if module_contributed_to_final_module and module_argument_candidates:
            module_argument_blocks.append(
                {
                    "module_name": module_name,
                    "module_id": module_id,
                    "source_url": source_url,
                    "arguments": module_argument_candidates,
                    "arguments_desc": module_argument_desc,
                }
            )

    final_rules = [
        r
        for r in dedupe_sorted(merged_rules)
        if not normalized_rule_matches_allowlist(r, allow_hosts)
        and not line_mentions_allowlisted_host(r, allow_hosts)
        and not line_matches_any_regex(r, allow_regexes)
    ]
    write_lines(STAGED_AD_BLOCK_LIST, final_rules)

    module_argument_items, arguments_desc_text, argument_catalog = build_argument_bundle(module_argument_blocks)
    write_text(ARGUMENT_CATALOG_JSON, json.dumps(argument_catalog, ensure_ascii=False, indent=2) + "\n")

    arguments_text = "&".join(module_argument_items)
    module_text = build_module_text(
        arguments_text=arguments_text,
        arguments_desc_text=arguments_desc_text,
        mitm_hosts=mitm_hosts,
        url_rewrite=url_rewrite,
        header_rewrite=header_rewrite,
        body_rewrite=body_rewrite,
        scripts=set(script_lines_by_key.values()),
        host_lines=host_lines,
    )

    ok, reason = validate_final_module_text(module_text)
    if not ok:
        raise RuntimeError(f"Generated invalid Surge module: {reason}")

    write_text(STAGED_AD_BLOCK_MODULE, module_text)
    write_lines(REJECTED_RULES_TXT, rejected_log)

    print(f"Loaded {len(load_cached_legacy_rules())} cached legacy raw rules.", flush=True)
    print(f"Wrote {STAGED_AD_BLOCK_LIST} with {len(final_rules)} rules.", flush=True)
    print(f"Wrote {STAGED_AD_BLOCK_MODULE}", flush=True)
    print(f"Wrote {ARGUMENT_CATALOG_JSON} with {len(argument_catalog)} module argument blocks.", flush=True)
    print(f"Wrote {REJECTED_RULES_TXT} with {len(rejected_log)} entries.", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
