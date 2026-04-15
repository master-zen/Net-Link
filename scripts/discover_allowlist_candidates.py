#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import os

from lib_rules import (
    DATA_SOURCES_DIR,
    DISCOVERED_ALLOWLIST_URLS,
    dedupe_sorted,
    ensure_project_dirs,
    github_blob_html_to_raw,
    read_seed_urls,
    request_json,
    write_lines,
)

ALLOWLIST_FILE_HINTS = {
    "allowlist",
    "whitelist",
    "exceptionrules",
    "exceptions",
    "referral-sites",
}


def discover_from_github_search(gh_token: str | None) -> list[str]:
    if not gh_token:
        return []

    queries = [
        'filename:exceptionrules.txt',
        'filename:allowlist.txt',
        'filename:whitelist.txt',
        '"referral-sites" extension:txt',
    ]

    urls: list[str] = []

    for query in queries:
        api = f"https://api.github.com/search/code?q={query}&per_page=50"
        try:
            data = request_json(api, token=gh_token)
        except Exception:
            continue

        for item in data.get("items", []):
            html_url = item.get("html_url", "")
            raw = github_blob_html_to_raw(html_url)
            if raw:
                lower = raw.lower()
                if any(hint in lower for hint in ALLOWLIST_FILE_HINTS):
                    urls.append(raw)

    return urls


def main() -> int:
    ensure_project_dirs()

    gh_token = os.environ.get("GH_TOKEN", "").strip() or None
    seed_urls = read_seed_urls(DATA_SOURCES_DIR / "ad_allowlist_seed_urls.txt")

    discovered = list(seed_urls)
    discovered.extend(discover_from_github_search(gh_token))

    final_urls = dedupe_sorted(discovered)
    write_lines(DISCOVERED_ALLOWLIST_URLS, final_urls)

    print(f"Wrote {DISCOVERED_ALLOWLIST_URLS} with {len(final_urls)} URLs.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
