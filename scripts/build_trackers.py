#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import ipaddress
import json
import ssl
import sys
import time
from pathlib import Path
from typing import Iterable
from urllib.parse import urlparse, urlunparse
from urllib.request import Request, urlopen

SOURCES = [
    "https://git.ustc.edu.cn/cwzsquare/trackerslist/-/raw/master/trackers_all.txt",
    "https://raw.githubusercontent.com/ngosang/trackerslist/master/trackers_all.txt",
    "https://raw.githubusercontent.com/adysec/tracker/main/trackers_all.txt",
    "https://cf.trackerslist.com/all.txt",
]

OUTPUT_RAW = Path("Trackers/Merge-List/Trackers.txt")
OUTPUT_SURGE = Path("Surge/Rules/Trackers.list")
OUTPUT_STATUS = Path("sources_status.json")


def fetch_text(url: str, timeout: int = 30, retries: int = 3) -> str:
    last_error = None

    for attempt in range(1, retries + 1):
        try:
            req = Request(
                url,
                headers={
                    "User-Agent": "Mozilla/5.0 (GitHub Actions tracker merger)",
                    "Accept": "text/plain, */*",
                },
            )
            context = ssl.create_default_context()
            with urlopen(req, timeout=timeout, context=context) as resp:
                charset = resp.headers.get_content_charset() or "utf-8"
                return resp.read().decode(charset, errors="replace")
        except Exception as exc:
            last_error = exc
            if attempt < retries:
                time.sleep(2 * attempt)

    raise RuntimeError(f"Failed to fetch {url}: {last_error}") from last_error


def split_candidates(text: str) -> list[str]:
    items: list[str] = []
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        if line.startswith("#"):
            continue

        for part in line.split():
            part = part.strip()
            if not part or part.startswith("#"):
                continue
            items.append(part)

    return items


def normalize_tracker_url(url: str) -> str | None:
    url = url.strip()
    if not url:
        return None

    try:
        parsed = urlparse(url)
    except Exception:
        return None

    if parsed.scheme.lower() not in {"udp", "http", "https", "ws", "wss"}:
        return None

    if not parsed.hostname:
        return None

    scheme = parsed.scheme.lower()
    hostname = parsed.hostname.lower()

    if ":" in hostname and not hostname.startswith("["):
        host_for_netloc = f"[{hostname}]"
    else:
        host_for_netloc = hostname

    port = parsed.port
    if port is not None:
        netloc = f"{host_for_netloc}:{port}"
    else:
        netloc = host_for_netloc

    path = parsed.path or ""
    query = parsed.query or ""

    normalized = urlunparse((scheme, netloc, path, "", query, ""))
    return normalized


def unique_sorted(items: Iterable[str]) -> list[str]:
    return sorted(set(items), key=lambda s: (s.split("://", 1)[0], s))


def tracker_url_to_surge_rule(url: str) -> str | None:
    parsed = urlparse(url)
    host = parsed.hostname
    if not host:
        return None

    host = host.lower()

    try:
        ip = ipaddress.ip_address(host)
        if isinstance(ip, ipaddress.IPv4Address):
            return f"IP-CIDR,{ip.compressed}/32,no-resolve"
        return f"IP-CIDR6,{ip.compressed}/128,no-resolve"
    except ValueError:
        return f"DOMAIN,{host}"


def ensure_parent_dirs() -> None:
    OUTPUT_RAW.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT_SURGE.parent.mkdir(parents=True, exist_ok=True)


def main() -> int:
    ensure_parent_dirs()

    status: dict[str, dict[str, str | int | bool]] = {}
    all_urls: list[str] = []

    for src in SOURCES:
        try:
            text = fetch_text(src)
            candidates = split_candidates(text)

            normalized: list[str] = []
            for item in candidates:
                norm = normalize_tracker_url(item)
                if norm:
                    normalized.append(norm)

            all_urls.extend(normalized)

            status[src] = {
                "ok": True,
                "count_after_normalize": len(normalized),
            }
        except Exception as exc:
            status[src] = {
                "ok": False,
                "error": str(exc),
            }

    merged_urls = unique_sorted(all_urls)

    surge_rules = unique_sorted(
        rule for url in merged_urls
        if (rule := tracker_url_to_surge_rule(url)) is not None
    )

    OUTPUT_RAW.write_text("\n".join(merged_urls) + "\n", encoding="utf-8")
    OUTPUT_SURGE.write_text("\n".join(surge_rules) + "\n", encoding="utf-8")
    OUTPUT_STATUS.write_text(
        json.dumps(
            {
                "generated_at_unix": int(time.time()),
                "sources": status,
                "merged_url_count": len(merged_urls),
                "surge_rule_count": len(surge_rules),
            },
            ensure_ascii=False,
            indent=2,
        ) + "\n",
        encoding="utf-8",
    )

    print(f"{OUTPUT_RAW}: {len(merged_urls)} lines")
    print(f"{OUTPUT_SURGE}: {len(surge_rules)} lines")

    if not any(info.get("ok") for info in status.values()):
        print("All sources failed.", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
