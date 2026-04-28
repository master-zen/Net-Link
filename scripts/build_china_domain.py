#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import re
import ssl
import sys
import time
import ipaddress
from pathlib import Path
from typing import Iterable
from urllib.parse import urlparse, urlunparse
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parents[1]
SOURCE_URLS_FILE = ROOT / "data/sources/ChinaDomainList_URLs.txt"
OUTPUT_FILE = ROOT / "Surge/Rules/ChinaDomain.list"

RULE_TYPES = {"DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD"}
COMMENT_PREFIXES = ("#", ";", "//", "!", "[")
DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9-]{2,63}$"
)
HOSTS_LINE_RE = re.compile(r"^(?:0\.0\.0\.0|127\.0\.0\.1|::1|::)\s+([^\s#;]+)")


def fetch_text(url: str, timeout: int = 30, retries: int = 3, max_bytes: int = 20_000_000) -> str:
    last_error: Exception | None = None
    for attempt in range(1, retries + 1):
        try:
            req = Request(
                url,
                headers={
                    "User-Agent": "Mozilla/5.0 (Net-Link china-domain builder)",
                    "Accept": "text/plain, */*",
                },
            )
            context = ssl.create_default_context()
            with urlopen(req, timeout=timeout, context=context) as resp:
                chunks: list[bytes] = []
                total = 0
                while True:
                    chunk = resp.read(65536)
                    if not chunk:
                        break
                    total += len(chunk)
                    if total > max_bytes:
                        raise RuntimeError(f"payload too large: {total} bytes")
                    chunks.append(chunk)

                charset = resp.headers.get_content_charset() or "utf-8"
                return b"".join(chunks).decode(charset, errors="replace")
        except Exception as exc:  # noqa: BLE001
            last_error = exc
            if attempt < retries:
                time.sleep(2 * attempt)
    raise RuntimeError(f"Failed to fetch {url}: {last_error}") from last_error


def unique_sorted(items: Iterable[str]) -> list[str]:
    return sorted(set(items), key=lambda s: s.casefold())


def normalize_source_url(raw_url: str) -> str | None:
    candidate = raw_url.strip().strip("<>()[]{}\"'`.,\\")
    if not candidate:
        return None

    parsed = urlparse(candidate)
    if parsed.scheme.lower() not in {"http", "https"}:
        return None

    host = (parsed.netloc or "").lower()
    path = parsed.path or ""

    if host == "github.com":
        parts = [p for p in path.split("/") if p]
        if len(parts) >= 5 and parts[2] == "blob":
            owner, repo = parts[0], parts[1]
            rest = "/".join(parts[3:])
            host = "raw.githubusercontent.com"
            path = f"/{owner}/{repo}/{rest}"
        elif len(parts) >= 5 and parts[2] == "raw":
            owner, repo = parts[0], parts[1]
            rest = "/".join(parts[3:])
            host = "raw.githubusercontent.com"
            path = f"/{owner}/{repo}/{rest}"

    normalized = urlunparse((parsed.scheme.lower(), host, path, "", parsed.query, ""))
    reparsed = urlparse(normalized)
    if reparsed.scheme.lower() not in {"http", "https"}:
        return None
    if not reparsed.netloc:
        return None
    return normalized


def read_source_urls(path: Path) -> list[str]:
    if not path.exists():
        return []

    urls: list[str] = []
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        url = normalize_source_url(line)
        if url:
            urls.append(url)
    return unique_sorted(urls)


def is_comment_or_empty(line: str) -> bool:
    stripped = line.strip().lstrip("\ufeff")
    if not stripped:
        return True
    return stripped.startswith(COMMENT_PREFIXES)


def strip_inline_comment(line: str) -> str:
    value = line.strip().lstrip("\ufeff")
    if not value:
        return ""
    if " #" in value:
        value = value.split(" #", 1)[0].rstrip()
    if " ;" in value:
        value = value.split(" ;", 1)[0].rstrip()
    return value.strip()


def normalize_domain_token(raw: str) -> str | None:
    token = raw.strip().lower()
    if not token:
        return None

    if token.startswith("*."):
        token = token[2:]
    if token.startswith("."):
        token = token[1:]

    token = token.strip(".")
    token = token.split("/", 1)[0]
    token = token.split("^", 1)[0]
    token = token.split("$", 1)[0]

    if not token:
        return None
    if ":" in token:
        return None
    try:
        ipaddress.ip_address(token)
        return None
    except ValueError:
        pass

    labels = token.split(".")
    if labels and labels[-1].isdigit():
        return None
    if DOMAIN_RE.match(token):
        return token
    return None


def normalize_rule(head: str, value: str) -> str | None:
    upper_head = head.upper()
    if upper_head not in RULE_TYPES:
        return None

    if upper_head == "DOMAIN-KEYWORD":
        keyword = value.strip().lower()
        if not keyword:
            return None
        return f"{upper_head},{keyword}"

    domain = normalize_domain_token(value)
    if not domain:
        return None
    return f"{upper_head},{domain}"


def parse_adblock_domain(line: str) -> str | None:
    value = line.strip()
    if not value:
        return None

    if value.startswith("@@"):
        value = value[2:].strip()
    value = value.removeprefix("||")
    value = value.removeprefix("|")

    domain = normalize_domain_token(value)
    if not domain:
        return None
    return f"DOMAIN-SUFFIX,{domain}"


def normalize_line(raw_line: str) -> str | None:
    if is_comment_or_empty(raw_line):
        return None

    line = raw_line.strip().lstrip("\ufeff")
    if line.startswith("- "):
        line = line[2:].strip()

    line = strip_inline_comment(line)
    if not line:
        return None

    line = re.sub(r"(?i),\s*no-resolve\b", "", line).strip()
    while line.endswith(","):
        line = line[:-1].rstrip()
    if not line:
        return None

    if line.lower().startswith("payload:"):
        return None

    if line.startswith("||") or line.startswith("|") or line.startswith("@@||"):
        return parse_adblock_domain(line)

    if "," in line:
        parts = [p.strip() for p in line.split(",")]
        if len(parts) >= 2:
            return normalize_rule(parts[0], parts[1])
        return None

    hosts_match = HOSTS_LINE_RE.match(line)
    if hosts_match:
        domain = normalize_domain_token(hosts_match.group(1))
        if domain:
            return f"DOMAIN,{domain}"
        return None

    if line.startswith("*.") or line.startswith("."):
        domain = normalize_domain_token(line)
        if domain:
            return f"DOMAIN-SUFFIX,{domain}"
        return None

    domain = normalize_domain_token(line)
    if domain:
        return f"DOMAIN,{domain}"
    return None


def rule_sort_key(rule: str) -> tuple[int, str, str]:
    head, _, tail = rule.partition(",")
    order = {
        "DOMAIN": 1,
        "DOMAIN-SUFFIX": 2,
        "DOMAIN-KEYWORD": 3,
    }
    return (order.get(head.upper(), 99), head.upper(), tail.casefold())


def is_ip_only_source(url: str) -> bool:
    lower = url.lower()
    hints = ("chinaasn", "chinaips", "cncidr", "geoip", "ip-cidr")
    return any(hint in lower for hint in hints)


def main() -> int:
    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)

    source_urls = read_source_urls(SOURCE_URLS_FILE)
    if not source_urls:
        print(f"[ERROR] no source urls in {SOURCE_URLS_FILE}", file=sys.stderr)
        return 1

    print(f"[INFO] source urls: {len(source_urls)}")

    all_rules: list[str] = []
    ok_sources = 0
    for source in source_urls:
        try:
            text = fetch_text(source)
            count_before = len(all_rules)
            for raw_line in text.splitlines():
                rule = normalize_line(raw_line)
                if rule:
                    all_rules.append(rule)
            parsed_for_source = len(all_rules) - count_before
            if parsed_for_source > 0:
                ok_sources += 1
            else:
                if is_ip_only_source(source):
                    print(f"[INFO] skipped IP-only source: {source}")
                else:
                    print(f"[WARN] no domain rules parsed: {source}", file=sys.stderr)
        except Exception as exc:  # noqa: BLE001
            print(f"[WARN] fetch failed: {source} -> {exc}", file=sys.stderr)

    if ok_sources == 0:
        print("[ERROR] all sources failed or parsed zero rules", file=sys.stderr)
        return 1

    merged_rules = sorted(set(all_rules), key=rule_sort_key)
    if not merged_rules:
        print("[ERROR] no rules generated", file=sys.stderr)
        return 1

    OUTPUT_FILE.write_text("\n".join(merged_rules) + "\n", encoding="utf-8")
    print(f"[DONE] {OUTPUT_FILE.relative_to(ROOT)}: {len(merged_rules)} lines")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
