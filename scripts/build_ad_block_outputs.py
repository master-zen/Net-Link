#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import json
import re

from lib_rules import (
    AD_BLOCK_LIST,
    AD_BLOCK_MODULE,
    BUILD_DIR,
    DATA_ALLOWLISTS_DIR,
    DISCOVERED_ALLOWLIST_URLS,
    NORMALIZED_MODULES_JSON,
    REJECTED_RULES_TXT,
    SECURITY_SUMMARY_JSON,
    WHITELIST_HOSTS_TXT,
    dedupe_sorted,
    ensure_project_dirs,
    extract_reject_rule_from_module_rule,
    line_matches_any_regex,
    line_mentions_allowlisted_host,
    normalize_rule_line,
    parse_allowlist_host_line,
    read_lines,
    request_text,
    rule_matches_allowlist,
    safe_compile_regexes,
    write_lines,
    write_text,
)

MODULE_HEADER = """#!name=Ad Block
#!desc=Auto-merged, normalized, deduplicated and security-scanned ad blocking module for Surge
#!system=iOS
#!requirement=CORE_VERSION>=20
"""

VALID_SECTION_HEADERS = {
    "[MITM]",
    "[URL Rewrite]",
    "[Header Rewrite]",
    "[Body Rewrite]",
    "[Script]",
    "[Host]",
}

URL_REWRITE_RE = re.compile(r"^\^.+\s+.+\s+(header|302|reject)$", re.IGNORECASE)
HEADER_ACTION_RE = re.compile(
    r"^(http-request|http-response)\s+.+\s+(header-add|header-del|header-replace|header-replace-regex)\s+.+$",
    re.IGNORECASE,
)
BODY_REWRITE_RE = re.compile(
    r"^(http-request|http-response|http-request-jq|http-response-jq)\s+.+$",
    re.IGNORECASE,
)
HOST_MAPPING_RE = re.compile(
    r"""^(
        (DOMAIN-SET:[^=\s]+)|
        (RULE-SET:[^=\s]+)|
        ([*A-Za-z0-9._-]+)
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


def load_security_summary() -> dict:
    if not SECURITY_SUMMARY_JSON.exists():
        return {}
    return json.loads(SECURITY_SUMMARY_JSON.read_text(encoding="utf-8"))


def load_existing_rules() -> set[str]:
    rules: set[str] = set()
    for line in read_lines(AD_BLOCK_LIST):
        norm = normalize_rule_line(line, strip_policy=True)
        if norm:
            rules.add(norm)
    return rules


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


def sanitize_mitm_host(host: str) -> str | None:
    s = host.strip().lower().lstrip(".")
    if not s:
        return None
    if "%" in s or "{{{" in s or "}}}" in s:
        return None
    if " " in s:
        return None
    if "." not in s and "*" not in s:
        return None
    return s


def sanitize_url_rewrite_line(line: str) -> str | None:
    s = line.strip()
    if not s:
        return None
    if "{{{" in s or "}}}" in s:
        return None
    if any(token in s.lower() for token in ["reject-dict", "reject-200", "response-body-json-", "jq-path="]):
        return None
    return s if URL_REWRITE_RE.match(s) else None


def sanitize_header_line(line: str) -> str | None:
    s = line.strip()
    if not s:
        return None
    if "{{{" in s or "}}}" in s:
        return None
    return s if HEADER_ACTION_RE.match(s) else None


def sanitize_body_line(line: str) -> str | None:
    s = line.strip()
    if not s:
        return None
    if "{{{" in s or "}}}" in s:
        return None
    if any(token in s.lower() for token in ["response-body-json-del", "response-body-replace-regex", "jq-path="]):
        return None
    return s if BODY_REWRITE_RE.match(s) else None


def sanitize_script_line(line: str) -> str | None:
    s = line.strip()
    if not s:
        return None
    if "{{{" in s or "}}}" in s:
        return None
    lower = s.lower()
    if "type=" not in lower or "pattern=" not in lower or "script-path=" not in lower:
        return None
    return s


def sanitize_host_mapping_line(line: str) -> str | None:
    s = line.strip()
    if not s:
        return None
    if "{{{" in s or "}}}" in s:
        return None
    # data=/data-type=/status-code= 属于 Map Local，不属于 Host
    if "data=" in s.lower() or "data-type=" in s.lower() or "status-code=" in s.lower():
        return None
    return s if HOST_MAPPING_RE.match(s) else None


def build_module_text(
    mitm_hosts: set[str],
    url_rewrite: set[str],
    header_rewrite: set[str],
    body_rewrite: set[str],
    scripts: set[str],
    host_lines: set[str],
) -> str:
    lines: list[str] = [MODULE_HEADER.strip(), ""]

    clean_mitm_hosts = [
        h for h in (sanitize_mitm_host(x) for x in sorted(mitm_hosts, key=lambda s: s.casefold()))
        if h
    ]

    if clean_mitm_hosts:
        lines.append("[MITM]")
        lines.append("hostname = %APPEND% " + ", ".join(clean_mitm_hosts))
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

    first_nonempty = None
    for line in lines:
        s = line.strip()
        if s:
            first_nonempty = s
            break

    if first_nonempty is None:
        return False, "empty file"

    if not first_nonempty.startswith("#!name="):
        return False, "first non-empty line is not #!name="

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
            if not s.lower().startswith("hostname = %append% "):
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
    suspicious_script_urls = {
        item.get("script_url", "")
        for item in security.get("downloaded_scripts", [])
        if item.get("script_hash") in suspicious_hashes
    }

    allow_hosts = load_allowlist_hosts_from_remote()
    allow_hosts |= load_local_allowlist_hosts()
    allow_hosts = set(dedupe_sorted(allow_hosts))
    write_lines(WHITELIST_HOSTS_TXT, sorted(allow_hosts, key=lambda s: s.casefold()))

    allow_regexes = load_local_allowlist_regexes()
    allow_module_ids = load_local_module_ids()

    merged_rules = load_existing_rules()
    rejected_log: list[str] = []

    mitm_hosts: set[str] = set()
    url_rewrite: set[str] = set()
    header_rewrite: set[str] = set()
    body_rewrite: set[str] = set()
    script_lines: set[str] = set()
    host_lines: set[str] = set()

    for module in modules:
        module_id = module.get("module_id", "")
        source_url = module.get("source_url", "")
        module_name = module.get("module_name", "")

        if module_is_excluded(module, allow_module_ids):
            rejected_log.append(f"module_excluded_by_module_ids\t{module_id}\t{module_name}\t{source_url}")
            continue

        if module_id in suspicious_modules:
            rejected_log.append(f"module_excluded_by_security\t{module_id}\t{module_name}\t{source_url}")
            continue

        # 模块内 [Rule] 的 REJECT / REJECT-TINYGIF 抽到 Ad_Block.list
        for rule in module.get("rules", []):
            reject_rule = extract_reject_rule_from_module_rule(rule)
            if not reject_rule:
                continue

            if rule_matches_allowlist(reject_rule, allow_hosts):
                rejected_log.append(f"rule_removed_by_allowlist\t{reject_rule}\t{module_id}\t{source_url}")
                continue

            merged_rules.add(reject_rule)

        for host in module.get("mitm_hosts", []):
            host = sanitize_mitm_host(host or "")
            if not host:
                continue
            if host in allow_hosts or any(h == host or h.endswith("." + host) for h in allow_hosts):
                rejected_log.append(f"mitm_removed_by_allowlist\t{host}\t{module_id}\t{source_url}")
                continue
            mitm_hosts.add(host)

        for line in module.get("url_rewrite", []):
            s = sanitize_url_rewrite_line(line)
            if not s:
                continue
            if filter_line_by_whitelist(s, allow_hosts, allow_regexes):
                rejected_log.append(f"url_rewrite_removed_by_allowlist\t{s}\t{module_id}\t{source_url}")
                continue
            url_rewrite.add(s)

        for line in module.get("header_rewrite", []):
            s = sanitize_header_line(line)
            if not s:
                continue
            if filter_line_by_whitelist(s, allow_hosts, allow_regexes):
                rejected_log.append(f"header_rewrite_removed_by_allowlist\t{s}\t{module_id}\t{source_url}")
                continue
            header_rewrite.add(s)

        for line in module.get("body_rewrite", []):
            s = sanitize_body_line(line)
            if not s:
                continue
            if filter_line_by_whitelist(s, allow_hosts, allow_regexes):
                rejected_log.append(f"body_rewrite_removed_by_allowlist\t{s}\t{module_id}\t{source_url}")
                continue
            body_rewrite.add(s)

        for item in module.get("scripts", []):
            line = sanitize_script_line(item.get("line") or "")
            script_url = (item.get("script_url") or "").strip()

            if not line:
                continue

            if script_url and script_url in suspicious_script_urls:
                rejected_log.append(f"script_removed_by_security\t{script_url}\t{module_id}\t{source_url}")
                continue

            if filter_line_by_whitelist(line, allow_hosts, allow_regexes):
                rejected_log.append(f"script_removed_by_allowlist\t{line}\t{module_id}\t{source_url}")
                continue

            script_lines.add(line)

        for line in module.get("host", []):
            s = sanitize_host_mapping_line(line)
            if not s:
                continue
            if filter_line_by_whitelist(s, allow_hosts, allow_regexes):
                rejected_log.append(f"host_removed_by_allowlist\t{s}\t{module_id}\t{source_url}")
                continue
            host_lines.add(s)

    # Ad_Block.list：合并旧文件和本次新增，不覆盖
    final_rules = [r for r in dedupe_sorted(merged_rules) if not rule_matches_allowlist(r, allow_hosts)]
    write_lines(AD_BLOCK_LIST, final_rules)

    # 最终模块：只输出 Surge 官方白名单语法
    module_text = build_module_text(
        mitm_hosts=mitm_hosts,
        url_rewrite=url_rewrite,
        header_rewrite=header_rewrite,
        body_rewrite=body_rewrite,
        scripts=script_lines,
        host_lines=host_lines,
    )

    ok, reason = validate_final_module_text(module_text)
    if not ok:
        raise RuntimeError(f"Generated invalid Surge module: {reason}")

    write_text(AD_BLOCK_MODULE, module_text)
    write_lines(REJECTED_RULES_TXT, rejected_log)

    print(f"Wrote {AD_BLOCK_LIST} with {len(final_rules)} rules.")
    print(f"Wrote {AD_BLOCK_MODULE}")
    print(f"Wrote {REJECTED_RULES_TXT} with {len(rejected_log)} entries.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
