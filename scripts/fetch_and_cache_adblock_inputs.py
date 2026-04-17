#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import json
import time
from pathlib import Path

from build_ad_block import (
    load_legacy_sources,
    fetch_text as legacy_fetch_text,
    normalize_line as legacy_normalize_line,
)
from lib_rules import (
    BUILD_DIR,
    DISCOVERED_ALLOWLIST_URLS,
    ensure_project_dirs,
    parse_allowlist_host_line,
    read_lines,
    request_text,
    write_text,
)

CACHE_DIR = BUILD_DIR / "cache"
CACHED_ALLOWLIST_HOSTS_JSON = CACHE_DIR / "allowlist_hosts.json"
CACHED_ALLOWLIST_FETCH_REPORT_JSON = CACHE_DIR / "allowlist_fetch_report.json"
CACHED_LEGACY_RULES_JSON = CACHE_DIR / "legacy_rules.json"
CACHED_LEGACY_FETCH_REPORT_JSON = CACHE_DIR / "legacy_fetch_report.json"

ALLOWLIST_TIMEOUT = 12
LEGACY_FETCH_TIMEOUT = 12


def ensure_cache_dirs() -> None:
    ensure_project_dirs()
    CACHE_DIR.mkdir(parents=True, exist_ok=True)


def write_json(path: Path, data) -> None:
    write_text(path, json.dumps(data, ensure_ascii=False, indent=2) + "\n")


def load_allowlist_hosts_from_remote() -> tuple[list[str], list[dict]]:
    hosts: set[str] = set()
    report: list[dict] = []

    for idx, url in enumerate(read_lines(DISCOVERED_ALLOWLIST_URLS), start=1):
        url = url.strip()
        if not url or url.startswith("#"):
            continue

        print(f"[allowlist {idx}] fetching: {url}", flush=True)
        started = time.time()

        try:
            text = request_text(url, timeout=ALLOWLIST_TIMEOUT)
            source_count = 0
            for line in text.splitlines():
                host = parse_allowlist_host_line(line)
                if host:
                    hosts.add(host)
                    source_count += 1
            elapsed = round(time.time() - started, 2)
            report.append(
                {
                    "url": url,
                    "ok": True,
                    "host_count": source_count,
                    "elapsed_seconds": elapsed,
                }
            )
            print(f"[allowlist {idx}] ok: {source_count} hosts in {elapsed}s", flush=True)
        except Exception as exc:
            elapsed = round(time.time() - started, 2)
            report.append(
                {
                    "url": url,
                    "ok": False,
                    "error": f"{type(exc).__name__}: {exc}",
                    "elapsed_seconds": elapsed,
                }
            )
            print(f"[allowlist {idx}] failed in {elapsed}s: {type(exc).__name__}: {exc}", flush=True)

    return sorted(hosts, key=str.casefold), report


def load_legacy_rules() -> tuple[list[str], list[dict]]:
    rules: set[str] = set()
    report: list[dict] = []
    sources = load_legacy_sources()

    for idx, source_url in enumerate(sources, start=1):
        print(f"[legacy {idx}] fetching: {source_url}", flush=True)
        started = time.time()

        try:
            text = legacy_fetch_text(source_url, timeout=LEGACY_FETCH_TIMEOUT, retries=2)
            source_count = 0
            for raw_line in text.splitlines():
                normalized_rule = legacy_normalize_line(raw_line)
                if normalized_rule:
                    rules.add(normalized_rule)
                    source_count += 1
            elapsed = round(time.time() - started, 2)
            report.append(
                {
                    "url": source_url,
                    "ok": True,
                    "rule_count": source_count,
                    "elapsed_seconds": elapsed,
                }
            )
            print(f"[legacy {idx}] ok: {source_count} rules in {elapsed}s", flush=True)
        except Exception as exc:
            elapsed = round(time.time() - started, 2)
            report.append(
                {
                    "url": source_url,
                    "ok": False,
                    "error": f"{type(exc).__name__}: {exc}",
                    "elapsed_seconds": elapsed,
                }
            )
            print(f"[legacy {idx}] failed in {elapsed}s: {type(exc).__name__}: {exc}", flush=True)

    return sorted(rules, key=str.casefold), report


def main() -> int:
    ensure_cache_dirs()

    allow_hosts, allow_report = load_allowlist_hosts_from_remote()
    write_json(CACHED_ALLOWLIST_HOSTS_JSON, allow_hosts)
    write_json(CACHED_ALLOWLIST_FETCH_REPORT_JSON, allow_report)
    print(f"Wrote {CACHED_ALLOWLIST_HOSTS_JSON} with {len(allow_hosts)} hosts.", flush=True)

    legacy_rules, legacy_report = load_legacy_rules()
    write_json(CACHED_LEGACY_RULES_JSON, legacy_rules)
    write_json(CACHED_LEGACY_FETCH_REPORT_JSON, legacy_report)
    print(f"Wrote {CACHED_LEGACY_RULES_JSON} with {len(legacy_rules)} rules.", flush=True)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
