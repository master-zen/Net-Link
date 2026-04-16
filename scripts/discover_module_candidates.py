#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import os
import re
from pathlib import Path

from lib_rules import (
    BUILD_DIR,
    DATA_SOURCES_DIR,
    DISCOVERED_MODULE_URLS,
    dedupe_sorted,
    ensure_project_dirs,
    github_blob_html_to_raw,
    github_get_default_branch,
    github_list_repo_tree,
    github_raw_url,
    parse_github_repo_url,
    read_seed_urls,
    request_json,
    write_lines,
)

EXTENSIONS = {".sgmodule", ".module", ".plugin"}

PATH_HINTS = {
    "surge/",
    "loon/",
    "quantumult",
    "quantumultx",
    "rewrite/",
    "plugin/",
    "module/",
    "script/",
    "ruleset/",
}

TOKEN_HINTS = {
    "ad",
    "ads",
    "adblock",
    "advertising",
    "antiad",
    "startup",
    "splash",
    "blockads",
    "httpdns",
    "hijack",
    "reject",
    "mitm",
    "zhihuads",
}

CHINESE_HINTS = {
    "去广告",
    "广告",
    "开屏",
    "拦截",
    "屏蔽",
    "过滤",
}

NEGATIVE_TOKENS = {
    "adobe",
    "upgrade",
    "redirect",
    "safredirect",
    "saferedirect",
    "getcookie",
    "cookie",
    "debug",
    "sample",
    "demo",
}

TOKEN_RE = re.compile(r"[A-Z]+(?=[A-Z][a-z]|[0-9]|$)|[A-Z]?[a-z]+|[0-9]+|[\u4e00-\u9fff]+")


def tokenize_path(path: str) -> set[str]:
    tokens: set[str] = set()
    for chunk in re.split(r"[^A-Za-z0-9\u4e00-\u9fff]+", path):
        if not chunk:
            continue
        for token in TOKEN_RE.findall(chunk):
            normalized = token.lower()
            if normalized:
                tokens.add(normalized)
    return tokens


def looks_like_module_path(path: str) -> bool:
    lower = path.lower()
    if not any(lower.endswith(ext) for ext in EXTENSIONS):
        return False

    if not any(hint in lower for hint in PATH_HINTS):
        return False

    tokens = tokenize_path(path)
    if tokens & NEGATIVE_TOKENS:
        return False

    if any(hint in lower for hint in CHINESE_HINTS):
        return True

    return bool(tokens & TOKEN_HINTS)


def discover_from_repo(repo_url: str, gh_token: str | None) -> list[str]:
    parsed = parse_github_repo_url(repo_url)
    if not parsed:
        return []

    owner, repo = parsed
    branch = github_get_default_branch(owner, repo, token=gh_token)
    tree = github_list_repo_tree(owner, repo, branch, token=gh_token)

    urls: list[str] = []
    for item in tree:
        if item.get("type") != "blob":
            continue
        path = item.get("path", "")
        if not path or not looks_like_module_path(path):
            continue
        urls.append(github_raw_url(owner, repo, branch, path))
    return urls


def discover_from_github_search(gh_token: str | None) -> list[str]:
    if not gh_token:
        return []

    queries = [
        "extension:sgmodule adblock",
        "extension:sgmodule 去广告",
        "extension:module blockAds",
        "extension:plugin 去广告",
        "extension:snippet adblock",
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
                urls.append(raw)

    return urls


def main() -> int:
    ensure_project_dirs()
    BUILD_DIR.mkdir(parents=True, exist_ok=True)

    gh_token = os.environ.get("GH_TOKEN", "").strip() or None

    seed_urls = read_seed_urls(DATA_SOURCES_DIR / "ad_module_seed_urls.txt")
    repo_seed_urls = read_seed_urls(DATA_SOURCES_DIR / "repo_seed_urls.txt")

    discovered: list[str] = []
    discovered.extend(seed_urls)

    for repo_url in repo_seed_urls:
        try:
            discovered.extend(discover_from_repo(repo_url, gh_token))
        except Exception:
            continue

    discovered.extend(discover_from_github_search(gh_token))

    final_urls = dedupe_sorted(discovered)
    write_lines(DISCOVERED_MODULE_URLS, final_urls)

    print(f"Wrote {DISCOVERED_MODULE_URLS} with {len(final_urls)} URLs.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
