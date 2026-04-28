#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import ipaddress
import ssl
import sys
import time
from pathlib import Path
from typing import Iterable
from urllib.parse import urlparse, urlunparse
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parents[1]
SOURCE_URLS_FILE = ROOT / "data/sources/TrackersList_URLs.txt"
OUTPUT_SURGE = ROOT / "Surge/Rules/Trackers.list"
OUTPUT_TRACKERS_RAW = ROOT / "Trackers/Trackers.txt"
OUTPUT_CLASH = ROOT / "Clash/Rules/Trackers.yaml"

ALLOWED_SCHEMES = {"udp", "http", "https", "ws", "wss"}


def fetch_text(url: str, timeout: int = 30, retries: int = 3, max_bytes: int = 24_000_000) -> str:
    last_error: Exception | None = None
    for attempt in range(1, retries + 1):
        try:
            req = Request(
                url,
                headers={
                    "User-Agent": "Mozilla/5.0 (Net-Link trackers builder)",
                    "Accept": "text/plain,text/html,*/*",
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


def yaml_quote(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def write_clash_ruleset(path: Path, rules: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    lines = ["payload:"]
    lines.extend(f"  - {yaml_quote(rule)}" for rule in rules)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def read_source_urls(path: Path) -> list[str]:
    if not path.exists():
        return []

    urls: list[str] = []
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        urls.append(line)
    return unique_sorted(urls)


def split_candidates(text: str) -> list[str]:
    items: list[str] = []
    for raw_line in text.splitlines():
        line = raw_line.strip().lstrip("\ufeff")
        if not line:
            continue
        if line.startswith(("#", ";", "//", "!")):
            continue
        for part in line.split():
            token = part.strip().strip("<>()[]{}\"'`.,")
            if not token:
                continue
            items.append(token)
    return items


def normalize_tracker_url(url: str) -> str | None:
    raw = url.strip()
    if not raw:
        return None

    try:
        parsed = urlparse(raw)
    except Exception:
        return None

    scheme = parsed.scheme.lower()
    if scheme not in ALLOWED_SCHEMES:
        return None
    if not parsed.hostname:
        return None

    host = parsed.hostname.lower()
    if ":" in host and not host.startswith("["):
        host_for_netloc = f"[{host}]"
    else:
        host_for_netloc = host

    port = parsed.port
    netloc = f"{host_for_netloc}:{port}" if port is not None else host_for_netloc
    path = parsed.path or ""
    query = parsed.query or ""

    return urlunparse((scheme, netloc, path, "", query, ""))


def tracker_url_sort_key(url: str) -> tuple[int, str]:
    scheme_order = {"udp": 1, "http": 2, "https": 3, "ws": 4, "wss": 5}
    parsed = urlparse(url)
    return (scheme_order.get(parsed.scheme.lower(), 99), url.casefold())


def tracker_url_to_surge_rule(url: str) -> str | None:
    parsed = urlparse(url)
    host = parsed.hostname
    if not host:
        return None
    host = host.lower()

    try:
        ip = ipaddress.ip_address(host)
        if isinstance(ip, ipaddress.IPv6Address):
            return f"IP-CIDR6,{ip.compressed}/128,no-resolve"
        return f"IP-CIDR,{ip.compressed}/32,no-resolve"
    except ValueError:
        return f"DOMAIN,{host}"


def surge_rule_sort_key(rule: str) -> tuple[int, str]:
    head, _, tail = rule.partition(",")
    order = {"DOMAIN": 1, "IP-CIDR": 2, "IP-CIDR6": 3}
    return (order.get(head.upper(), 99), tail.casefold())


def ensure_parent_dirs() -> None:
    OUTPUT_SURGE.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT_TRACKERS_RAW.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT_CLASH.parent.mkdir(parents=True, exist_ok=True)


def main() -> int:
    ensure_parent_dirs()

    source_urls = read_source_urls(SOURCE_URLS_FILE)
    if not source_urls:
        print(f"[ERROR] no source urls in {SOURCE_URLS_FILE}", file=sys.stderr)
        return 1

    print(f"[INFO] source urls: {len(source_urls)}")

    all_urls: list[str] = []
    ok_sources = 0
    for src in source_urls:
        try:
            text = fetch_text(src)
            candidates = split_candidates(text)
            normalized = [norm for item in candidates if (norm := normalize_tracker_url(item))]
            if normalized:
                ok_sources += 1
            all_urls.extend(normalized)
        except Exception as exc:  # noqa: BLE001
            print(f"[WARN] fetch failed: {src} -> {exc}", file=sys.stderr)

    if ok_sources == 0:
        print("[ERROR] all sources failed", file=sys.stderr)
        return 1

    merged_urls = sorted(set(all_urls), key=tracker_url_sort_key)
    if not merged_urls:
        print("[ERROR] no valid tracker URLs merged", file=sys.stderr)
        return 1

    surge_rules = sorted(
        {rule for url in merged_urls if (rule := tracker_url_to_surge_rule(url)) is not None},
        key=surge_rule_sort_key,
    )

    if not surge_rules:
        print("[ERROR] no Surge rules generated", file=sys.stderr)
        return 1

    raw_content = "\n".join(merged_urls) + "\n"
    surge_content = "\n".join(surge_rules) + "\n"

    OUTPUT_TRACKERS_RAW.write_text(raw_content, encoding="utf-8")
    OUTPUT_SURGE.write_text(surge_content, encoding="utf-8")
    write_clash_ruleset(OUTPUT_CLASH, surge_rules)

    print(f"[DONE] {OUTPUT_TRACKERS_RAW.relative_to(ROOT)}: {len(merged_urls)} lines")
    print(f"[DONE] {OUTPUT_SURGE.relative_to(ROOT)}: {len(surge_rules)} lines")
    print(f"[DONE] {OUTPUT_CLASH.relative_to(ROOT)}: {len(surge_rules)} lines")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
