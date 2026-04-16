#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

from datetime import datetime, timezone
import ipaddress
import json
import re

from lib_rules import (
    AD_BLOCK_LIST,
    AD_BLOCK_MODULE,
    BUILD_DIR,
    DATA_ALLOWLISTS_DIR,
    DISCOVERED_ALLOWLIST_URLS,
    NORMALIZED_MODULES_JSON,
    NORMALIZED_RULES_JSON,
    REJECTED_RULES_TXT,
    SECURITY_SUMMARY_JSON,
    STAGED_AD_BLOCK_LIST,
    STAGED_AD_BLOCK_MODULE,
    WHITELIST_HOSTS_TXT,
    dedupe_sorted,
    ensure_project_dirs,
    extract_reject_rule_from_module_rule,
    expand_hosts_with_parents,
    is_comment_or_empty,
    line_matches_any_regex,
    line_mentions_allowlisted_host,
    normalized_rule_matches_allowlist,
    parse_allowlist_host_line,
    read_lines,
    request_text,
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


def load_modules() -> list[dict]:
    if not NORMALIZED_MODULES_JSON.exists():
        return []
    data = json.loads(NORMALIZED_MODULES_JSON.read_text(encoding="utf-8"))
    return data.get("modules", [])


def load_rule_sources() -> list[dict]:
    if not NORMALIZED_RULES_JSON.exists():
        return []
    data = json.loads(NORMALIZED_RULES_JSON.read_text(encoding="utf-8"))
    return data.get("sources", [])


def load_security_summary() -> dict:
    if not SECURITY_SUMMARY_JSON.exists():
        return {}
    return json.loads(SECURITY_SUMMARY_JSON.read_text(encoding="utf-8"))


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


def load_allowlist_hosts_from_remote() -> set[str]:
    hosts: set[str] = set()

    for url in read_lines(DISCOVERED_ALLOWLIST_URLS):
        url = url.strip()
        if not url or url.startswith("#"):
            continue

        try:
            text = request_text(url)
        except Exception:
            continue

        for line in text.splitlines():
            host = parse_allowlist_host_line(line)
            if host:
                hosts.add(host)

    return hosts


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

    return (
        module_id in module_ids
        or module_name in module_ids
        or source_url in module_ids
    )


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
    bad_substrings = [
        "a-z",
        "0-9",
        "_-",
        "[",
        "]",
        "(",
        ")",
        "{",
        "}",
        "|",
        "\\",
    ]
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
    if not s:
        return None
    if is_comment_or_empty(s):
        return None
    if "%" in s or "{{{" in s or "}}}" in s:
        return None
    if " " in s:
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

    if is_ip_literal(host_part):
        return None
    if looks_like_regex_residue(host_part):
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
    if not s:
        return None
    if is_comment_or_empty(s):
        return None
    if "{{{" in s or "}}}" in s:
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
    if not s:
        return None
    if is_comment_or_empty(s):
        return None
    if "{{{" in s or "}}}" in s:
        return None
    return s if HEADER_ACTION_RE.match(s) else None


def sanitize_body_line(line: str) -> str | None:
    s = line.strip()
    if not s:
        return None
    if is_comment_or_empty(s):
        return None
    if "{{{" in s or "}}}" in s:
        return None

    lower = s.lower()
    banned_tokens = [
        "response-body-json-del",
        "response-body-replace-regex",
        "jq-path=",
    ]
    if any(token in lower for token in banned_tokens):
        return None

    return s if BODY_REWRITE_RE.match(s) else None


def sanitize_script_line(line: str) -> str | None:
    s = line.strip()
    if not s:
        return None
    if is_comment_or_empty(s):
        return None
    if "{{{" in s or "}}}" in s:
        return None

    if "=" not in s:
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
    if not s:
        return None
    if is_comment_or_empty(s):
        return None
    if "{{{" in s or "}}}" in s:
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


def build_standard_module_header(arguments_text: str) -> str:
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    lines = list(STANDARD_MODULE_STATIC_HEADER_LINES)
    lines.append(f"#!date={timestamp}")
    lines.append(f"#!arguments={arguments_text}")
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
    relevant = (
        "type",
        "pattern",
        "script-path",
        "argument",
        "requires-body",
        "binary-body-mode",
    )
    return tuple(normalize_script_field_value(key, fields.get(key, "")) for key in relevant)


def build_module_text(
    arguments_text: str,
    mitm_hosts: set[str],
    url_rewrite: set[str],
    header_rewrite: set[str],
    body_rewrite: set[str],
    scripts: set[str],
    host_lines: set[str],
) -> str:
    lines: list[str] = [build_standard_module_header(arguments_text), ""]

    clean_mitm_hosts = [
        h for h in (sanitize_mitm_host(x) for x in sorted(mitm_hosts, key=lambda s: s.casefold()))
        if h
    ]

    if clean_mitm_hosts:
        lines.append("[MITM]")
        # use lowercase %append% for consistency and compatibility
        lines.append("hostname = %append% " + ", ".join(clean_mitm_hosts))
        lines.append("")

    clean_url_rewrite = [
        s for s in (sanitize_url_rewrite_line(x) for x in sorted(url_rewrite, key=lambda s: s.casefold()))
        if s
    ]
    if clean_url_rewrite:
        lines.append("[URL Rewrite]")
        lines.extend(clean_url_rewrite)
        lines.append("")

    clean_header_rewrite = [
        s for s in (sanitize_header_line(x) for x in sorted(header_rewrite, key=lambda s: s.casefold()))
        if s
    ]
    if clean_header_rewrite:
        lines.append("[Header Rewrite]")
        lines.extend(clean_header_rewrite)
        lines.append("")

    clean_body_rewrite = [
        s for s in (sanitize_body_line(x) for x in sorted(body_rewrite, key=lambda s: s.casefold()))
        if s
    ]
    if clean_body_rewrite:
        lines.append("[Body Rewrite]")
        lines.extend(clean_body_rewrite)
        lines.append("")

    clean_scripts = [
        s for s in (sanitize_script_line(x) for x in sorted(scripts, key=lambda s: s.casefold()))
        if s
    ]
    if clean_scripts:
        lines.append("[Script]")
        lines.extend(clean_scripts)
        lines.append("")

    clean_host_lines = [
        s for s in (sanitize_host_mapping_line(x) for x in sorted(host_lines, key=lambda s: s.casefold()))
        if s
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

    expected_metadata_count = len(STANDARD_MODULE_STATIC_HEADER_LINES) + 2
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
            # allow either "hostname = %append% ..." or "hostname = ..."
            if not s.lower().startswith("hostname ="):
                return False, f"invalid MITM line: {s}"
            tail = s.split("=", 1)[1].strip()
            # remove optional %append% token (case-insensitive)
            if tail.lower().startswith("%append%"):
                tail = tail[len("%append%"):].strip()
            # tail now should be a comma-separated list of hosts
            host_items = [x.strip() for x in tail.split(",") if x.strip()]
            if not host_items:
                return False, f"invalid MITM hostname list: {s}"
            for item in host_items:
                if not sanitize_mitm_host(item):
                    return False, f"invalid MITM hostname item: {item}"

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
    rule_sources = load_rule_sources()
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

    allow_hosts = load_allowlist_hosts_from_remote()
    allow_hosts |= load_local_allowlist_hosts()
    allow_hosts = expand_hosts_with_parents(allow_hosts)
    allow_hosts = set(dedupe_sorted(allow_hosts))
    write_lines(WHITELIST_HOSTS_TXT, sorted(allow_hosts, key=lambda s: s.casefold()))

    allow_regexes = load_local_allowlist_regexes()
    allow_module_ids = load_local_module_ids()

    merged_rules: set[str] = set()
    rejected_log: list[str] = []

    mitm_hosts: set[str] = set()
    url_rewrite: set[str] = set()
    header_rewrite: set[str] = set()
    body_rewrite: set[str] = set()
    script_lines_by_key: dict[tuple[str, ...] | str, str] = {}
    host_lines: set[str] = set()
    module_argument_items: list[str] = []
    seen_argument_items: set[str] = set()
    argument_catalog: list[dict[str, object]] = []

    for source in rule_sources:
        source_url = source.get("source_url", "")
        source_name = source.get("source_name", "")
        for normalized_rule in source.get("rules", []):
            if not normalized_rule:
                continue

            if normalized_rule_matches_allowlist(normalized_rule, allow_hosts):
                rejected_log.append(
                    f"raw_rule_removed_by_allowlist\t{normalized_rule}\t{source_name}\t{source_url}"
                )
                continue

            merged_rules.add(normalized_rule)

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

        # 从模块 [Rule] 抽 REJECT / REJECT-TINYGIF 到 Ad_Block.list
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
            kept_items: list[str] = []
            for argument_item in module_argument_candidates:
                if argument_item in seen_argument_items:
                    continue
                seen_argument_items.add(argument_item)
                module_argument_items.append(argument_item)
                kept_items.append(argument_item)

            if kept_items:
                argument_catalog.append(
                    {
                        "module_name": module_name,
                        "module_id": module_id,
                        "source_url": source_url,
                        "arguments": kept_items,
                        "arguments_desc": module_argument_desc,
                    }
                )

    # Ad_Block.list：仅由当前发现到的规则源与模块 REJECT 规则构建，避免历史脏数据永久残留
    final_rules = [
        r
        for r in dedupe_sorted(merged_rules)
        if not normalized_rule_matches_allowlist(r, allow_hosts)
        and not line_mentions_allowlisted_host(r, allow_hosts)
        and not line_matches_any_regex(r, allow_regexes)
    ]
    write_lines(STAGED_AD_BLOCK_LIST, final_rules)
    write_text(ARGUMENT_CATALOG_JSON, json.dumps(argument_catalog, ensure_ascii=False, indent=2) + "\n")

    # Ad_Block.sgmodule：只输出 Surge 官方白名单语法
    arguments_text = "&".join(module_argument_items)
    module_text = build_module_text(
        arguments_text=arguments_text,
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

    print(f"Wrote {STAGED_AD_BLOCK_LIST} with {len(final_rules)} rules.")
    print(f"Wrote {STAGED_AD_BLOCK_MODULE}")
    print(f"Wrote {REJECTED_RULES_TXT} with {len(rejected_log)} entries.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
