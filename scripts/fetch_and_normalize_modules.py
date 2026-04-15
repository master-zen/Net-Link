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

SURGE_SCRIPT_TYPE_MAP = {
    "script-response-body": ("http-response-body", True),
    "script-request-body": ("http-request-body", True),
    "script-response-header": ("http-response-header", False),
    "script-request-header": ("http-request-header", False),
}

BAD_TEMPLATE_RE = re.compile(r"\{\{\{.*?\}\}\}")
MODULE_OPERATOR_RE = re.compile(r"(?i)%\s*(APPEND|INSERT|REPLACE)\s*%")
HOST_LIKE_RE = re.compile(r"^[*.-]*[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)+$")


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
            # 严格模式：不在合法 section 里的行一律丢弃
            continue

        sections[current].append(line)

    return sections, metadata


def has_unresolved_template(text: str) -> bool:
    return bool(BAD_TEMPLATE_RE.search(text))


def strip_module_operator_tokens(text: str) -> str:
    return MODULE_OPERATOR_RE.sub("", text).strip()


def is_obviously_broken_line(text: str) -> bool:
    s = text.strip()
    lower = s.lower()
    if not s:
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

    hosts: list[str] = []
    for part in [p.strip().lower().lstrip(".") for p in s.split(",") if p.strip()]:
        part = strip_module_operator_tokens(part)

        if not part:
            continue
        if "%" in part:
            continue
        if "{{{" in part or "}}}" in part:
            continue
        if " " in part:
            continue
        if not HOST_LIKE_RE.match(part):
            continue

        hosts.append(part)

    return hosts


def is_supported_surge_url_rewrite(line: str) -> bool:
    # Surge 文档允许的 URL Rewrite 三类：header / 302 / reject
    s = line.strip()
    if not s.startswith("^"):
        return False

    lower = s.lower()

    if re.search(r"\sheader$", lower):
        return True
    if re.search(r"\s302$", lower):
        return True
    if re.search(r"\s(?:_|-)?\s*reject(?:-\w+)?$", lower):
        # 这里只接受最终会进一步规整为 _ reject 的行
        return True

    return False


def normalize_rewrite_line(line: str) -> str | None:
    s = strip_no_resolve_and_trailing_commas(line.strip())
    if not s or is_obviously_broken_line(s):
        return None

    lower = s.lower()

    # 明确丢弃非 Surge 最终语法
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

    # QX-style reject: ^https://... url reject
    if " url " in s:
        left, right = s.split(" url ", 1)
        action = right.strip().lower()
        if action.startswith("reject"):
            return f"{left.strip()} _ reject"
        return None

    if not is_supported_surge_url_rewrite(s):
        return None

    # 统一 reject 的写法成 "_ reject"
    if re.search(r"\s(?:-|_)?\s*reject(?:-\w+)?$", lower):
        rule = re.sub(r"\s(?:-|_)?\s*reject(?:-\w+)?$", "", s, flags=re.IGNORECASE).strip()
        return f"{rule} _ reject"

    return s


def extract_script_path(line: str) -> str | None:
    s = line.strip()
    marker = "script-path="
    if marker in s:
        tail = s.split(marker, 1)[1].strip()
        return tail.split(",", 1)[0].strip()

    # QX style: ^... url script-response-body https://xx.js
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

    # QX → Surge
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

    # Surge style: 必须同时有 type / pattern / script-path
    lower = s.lower()
    if "type=" in lower and "pattern=" in lower and "script-path=" in lower:
        return {
            "line": s,
            "script_url": script_url,
        }

    return None


def normalize_header_line(line: str) -> str | None:
    s = strip_no_resolve_and_trailing_commas(line.strip())
    if not s or is_obviously_broken_line(s):
        return None

    lower = s.lower()

    # 只保留 Surge Header Rewrite 文档定义动作
    valid_actions = ("header-add", "header-del", "header-replace", "header-replace-regex")
    if (lower.startswith("http-request ") or lower.startswith("http-response ")) and any(
        f" {action} " in lower for action in valid_actions
    ):
        return s

    return None


def normalize_body_line(line: str) -> str | None:
    s = strip_no_resolve_and_trailing_commas(line.strip())
    if not s or is_obviously_broken_line(s):
        return None

    lower = s.lower()

    # 先支持 Surge 官方 Body Rewrite 基础语法
    if lower.startswith("http-request ") or lower.startswith("http-response "):
        return s

    # 有些来源是 QX 风格的 response-body-json-jq / response-body-json-del
    # 这里只做“严格且明确”的可转换：
    # 1. response-body-json-jq '<jq表达式>'  -> http-response-jq
    # 2. response-body-json-del <path>      -> 丢弃（不猜）
    if " response-body-json-jq " in s:
        try:
            pattern, jq_expr = s.split(" response-body-json-jq ", 1)
            pattern = pattern.strip()
            jq_expr = jq_expr.strip()

            # Surge 文档没有 jq-path= 这种参数，必须是内联 jq 表达式
            if "jq-path=" in jq_expr.lower():
                return None

            if pattern.startswith("^") and jq_expr:
                return f"http-response-jq {pattern} {jq_expr}"
        except Exception:
            return None

    # response-body-json-del / response-body-replace-regex 这种不做不安全猜测
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
    if "=" not in s:
        return None
    return s


def module_name_from_url(url: str) -> str:
    path = urlparse(url).path
    return Path(path).stem


def main() -> int:
    ensure_project_dirs()

    urls = read_url_list(DISCOVERED_MODULE_URLS)
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

        # 全空模块直接丢
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
            continue

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
