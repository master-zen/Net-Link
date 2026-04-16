#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import os
import ipaddress
import re
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from urllib.parse import urlparse

from lib_rules import (
    DISCOVERED_MODULE_URLS,
    NORMALIZED_MODULES_JSON,
    dedupe_sorted,
    ensure_project_dirs,
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
    "maplocal": None,   # 严格模式：Map Local / Mock 不并入最终模块
    "mock": None,
}

SURGE_SCRIPT_TYPE_MAP = {
    "script-response-body": ("http-response-body", True),
    "script-request-body": ("http-request-body", True),
    "script-response-header": ("http-response-header", False),
    "script-request-header": ("http-request-header", False),
}

BAD_TEMPLATE_RE = re.compile(r"\{\{\{.*?\}\}\}")
MODULE_OPERATOR_RE = re.compile(r"(?i)%\s*(APPEND|INSERT|REPLACE)\s*%")
HEADER_ACTION_RE = re.compile(
    r"^(http-request|http-response)\s+\S+\s+"
    r"(header-add|header-del|header-replace|header-replace-regex)\b",
    re.IGNORECASE,
)
BODY_REWRITE_RE = re.compile(
    r"^(http-request|http-response|http-request-jq|http-response-jq)\s+\S+",
    re.IGNORECASE,
)
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


def read_url_list(path: Path) -> list[str]:
    if not path.exists():
        return []
    return [line.strip() for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def canonical_section_name(raw: str) -> str | None:
    name = raw.strip().strip("[]").lower().replace(" ", "").replace("_", "").replace("-", "")
    return SECTION_ALIASES.get(name)


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
            # 不在合法 section 里的内容，一律丢弃
            continue

        sections[current].append(line)

    return sections, metadata


def has_unresolved_template(text: str) -> bool:
    return bool(BAD_TEMPLATE_RE.search(text))


def strip_module_operator_tokens(text: str) -> str:
    return MODULE_OPERATOR_RE.sub("", text).strip()


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


def normalize_hostlist_item(value: str) -> str | None:
    item = value.strip().lower().lstrip(".")
    item = strip_module_operator_tokens(item)

    if not item:
        return None
    if "{{{" in item or "}}}" in item:
        return None
    if " " in item:
        return None

    # 允许 Surge Host List 的 IP 占位符，但不允许把真实 IP 当 hostname 项
    if item in {"<ip-address>", "<ipv4-address>", "<ipv6-address>"}:
        return item

    # 允许负向排除
    prefix = ""
    if item.startswith("-"):
        prefix = "-"
        item = item[1:].strip()
        if not item:
            return None

    # 允许端口后缀
    host_part = item
    port_part = ""
    if ":" in item:
        maybe_host, maybe_port = item.rsplit(":", 1)
        if maybe_port.isdigit():
            host_part = maybe_host
            port_part = ":" + maybe_port

    if is_ip_literal(host_part):
        return None

    if looks_like_regex_residue(host_part):
        return None

    # Host List is for hostnames plus wildcards, not raw IP patterns like 1.2.3.*
    if not has_domain_like_letters(host_part.replace("*", "").replace("?", "")):
        return None

    # Host List 允许 * ? 通配
    if not re.fullmatch(r"[*?a-z0-9._-]+", host_part):
        return None

    if "." not in host_part and "*" not in host_part and "?" not in host_part:
        return None

    return prefix + host_part + port_part


def is_obviously_broken_line(text: str) -> bool:
    s = text.strip()
    lower = s.lower()

    if not s:
        return True
    if is_comment_or_empty(s):
        return True
    if has_unresolved_template(s):
        return True
    if lower.startswith("ttp-request") or lower.startswith("ttp-response"):
        return True
    if "jq-path=" in lower:
        return True

    return False


def normalize_mitm_line(line: str) -> list[str]:
    s = strip_no_resolve_and_trailing_commas(line.strip())
    if not s or is_obviously_broken_line(s):
        return []

    if s.lower().startswith("hostname") and "=" in s:
        s = s.split("=", 1)[1].strip()

    s = strip_module_operator_tokens(s)

    results: list[str] = []
    for part in [p.strip() for p in s.split(",") if p.strip()]:
        norm = normalize_hostlist_item(part)
        if norm:
            results.append(norm)

    return results


def normalize_url_rewrite_line(line: str) -> str | None:
    s = strip_no_resolve_and_trailing_commas(line.strip())
    if not s or is_obviously_broken_line(s):
        return None

    lower = s.lower()

    # 这些都不是 Surge 最终 URL Rewrite 语法
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

    # QX: ^... url reject  -> Surge: ^... _ reject
    if " url " in s:
        left, right = s.split(" url ", 1)
        action = right.strip().lower()
        if action.startswith("reject"):
            s = f"{left.strip()} _ reject"
        else:
            return None

    # 统一 reject 为 `_ reject`
    if re.search(r"\s(?:_|-)?\s*reject(?:-\w+)?$", lower):
        left = re.sub(r"\s(?:_|-)?\s*reject(?:-\w+)?$", "", s, flags=re.IGNORECASE).strip()
        s = f"{left} _ reject"

    parts = s.split()
    if len(parts) < 3:
        return None

    rewrite_type = parts[-1].lower()
    if rewrite_type not in {"header", "302", "reject"}:
        return None

    pattern = unwrap_quoted_token(parts[0])
    if not pattern:
        return None

    replacement = unwrap_quoted_token(" ".join(parts[1:-1]).strip())
    if not replacement:
        return None

    return f"{pattern} {replacement} {rewrite_type}"


def extract_script_path(line: str) -> str | None:
    s = line.strip()
    marker = "script-path="
    if marker in s:
        tail = s.split(marker, 1)[1].strip()
        return tail.split(",", 1)[0].strip()

    if " url script-" in s:
        parts = s.split()
        if parts and parts[-1].startswith(("http://", "https://")):
            return parts[-1].strip()

    return None


def normalize_script_line(line: str) -> dict | None:
    s = strip_no_resolve_and_trailing_commas(line.strip())
    if not s or is_obviously_broken_line(s):
        return None

    script_url = extract_script_path(s)

    # QX -> Surge
    if " url script-" in s:
        parts = s.split()
        if len(parts) >= 4:
            pattern = parts[0].strip()
            kind = parts[2].strip().lower()
            script_url = parts[3].strip()

            if kind in SURGE_SCRIPT_TYPE_MAP and script_url.startswith(("http://", "https://")):
                surge_type, requires_body = SURGE_SCRIPT_TYPE_MAP[kind]
                line_out = f"type={surge_type},pattern={pattern},script-path={script_url}"
                if requires_body:
                    line_out += ",requires-body=1"
                return {
                    "line": line_out,
                    "script_url": script_url,
                }

    lower = s.lower()
    if "=" in s:
        name, rhs = s.split("=", 1)
        name = name.strip()
        rhs = rhs.strip()
    else:
        name = ""
        rhs = s

    lower_rhs = rhs.lower()
    if name and "type=" in lower_rhs and "pattern=" in lower_rhs and "script-path=" in lower_rhs:
        return {
            "line": f"{name} = {rhs}",
            "script_url": script_url,
        }

    return None


def normalize_header_line(line: str) -> str | None:
    s = strip_no_resolve_and_trailing_commas(line.strip())
    if not s or is_obviously_broken_line(s):
        return None

    if HEADER_ACTION_RE.match(s):
        return s

    return None


def normalize_body_line(line: str) -> str | None:
    s = strip_no_resolve_and_trailing_commas(line.strip())
    if not s or is_obviously_broken_line(s):
        return None

    lower = s.lower()

    # Surge 原生语法
    if BODY_REWRITE_RE.match(s):
        return s

    # 严格可确认的 QX -> Surge JQ 转换
    if " response-body-json-jq " in s:
        try:
            pattern, jq_expr = s.split(" response-body-json-jq ", 1)
            pattern = pattern.strip()
            jq_expr = jq_expr.strip()

            if "jq-path=" in jq_expr.lower():
                return None

            if pattern and jq_expr:
                candidate = f"http-response-jq {pattern} {jq_expr}"
                if BODY_REWRITE_RE.match(candidate):
                    return candidate
        except Exception:
            return None

    # 以下不做猜测转换
    banned_tokens = [
        "response-body-json-del",
        "response-body-replace-regex",
        "jq-path=",
    ]
    if any(token in lower for token in banned_tokens):
        return None

    return None


def normalize_host_line(line: str) -> str | None:
    s = strip_no_resolve_and_trailing_commas(line.strip())
    if not s or is_obviously_broken_line(s):
        return None

    # [Host] 只允许 Local DNS Mapping，绝不允许 Mock(Map Local) 语法混入
    if "data=" in s.lower() or "data-type=" in s.lower() or "status-code=" in s.lower():
        return None
    if HOST_MAPPING_RE.match(s):
        return s
    return None


def module_name_from_url(url: str) -> str:
    path = urlparse(url).path
    return Path(path).stem


def normalize_module_from_url(url: str) -> dict:
    result = {
        "source_url": url,
        "module": None,
        "skip_reason": "",
    }

    try:
        text = request_text(url)
    except Exception as exc:
        result["skip_reason"] = f"fetch_failed:{type(exc).__name__}"
        return result

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
        norm = normalize_url_rewrite_line(line)
        if norm:
            url_rewrite.append(norm)

    for line in sections["header_rewrite"]:
        norm = normalize_header_line(line)
        if norm:
            header_rewrite.append(norm)

    for line in sections["body_rewrite"]:
        norm = normalize_body_line(line)
        if norm:
            body_rewrite.append(norm)

    for line in sections["script"]:
        norm = normalize_script_line(line)
        if norm:
            scripts.append(norm)

    for line in sections["host"]:
        norm = normalize_host_line(line)
        if norm:
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

    if not any(
        [
            module["mitm_hosts"],
            module["rules"],
            module["url_rewrite"],
            module["header_rewrite"],
            module["body_rewrite"],
            module["scripts"],
            module["host"],
        ]
    ):
        result["skip_reason"] = "no_supported_sections"
        return result

    result["module"] = module
    return result


def main() -> int:
    ensure_project_dirs()

    urls = read_url_list(DISCOVERED_MODULE_URLS)
    max_workers = max(4, min(16, (os.cpu_count() or 4) * 2))
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        outcomes = list(executor.map(normalize_module_from_url, urls))

    modules = [item["module"] for item in outcomes if item.get("module")]
    skipped_sources = [
        {
            "source_url": item["source_url"],
            "skip_reason": item["skip_reason"],
        }
        for item in outcomes
        if not item.get("module")
    ]

    save_json(
        NORMALIZED_MODULES_JSON,
        {
            "generated_from": str(DISCOVERED_MODULE_URLS),
            "module_count": len(modules),
            "skipped_source_count": len(skipped_sources),
            "skipped_sources": skipped_sources,
            "modules": modules,
        },
    )

    print(
        f"Wrote {NORMALIZED_MODULES_JSON} with {len(modules)} modules "
        f"and {len(skipped_sources)} skipped sources."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
