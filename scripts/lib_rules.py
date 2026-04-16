#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import re
from pathlib import Path
from typing import Iterable
from urllib.parse import quote, urlparse
from urllib.request import Request, urlopen


ROOT = Path(__file__).resolve().parent.parent

DATA_DIR = ROOT / "data"
DATA_SOURCES_DIR = DATA_DIR / "sources"
DATA_ALLOWLISTS_DIR = DATA_DIR / "allowlists"

BUILD_DIR = ROOT / "build"
SCAN_REPORTS_DIR = BUILD_DIR / "scan_reports"

SURGE_RULES_DIR = ROOT / "Surge" / "Rules"
SURGE_MODULE_DIR = ROOT / "Surge" / "Module"

DISCOVERED_MODULE_URLS = BUILD_DIR / "discovered_module_urls.txt"
DISCOVERED_ALLOWLIST_URLS = BUILD_DIR / "discovered_allowlist_urls.txt"
NORMALIZED_MODULES_JSON = BUILD_DIR / "normalized_modules.json"

WHITELIST_HOSTS_TXT = BUILD_DIR / "whitelist_hosts.txt"
REJECTED_RULES_TXT = BUILD_DIR / "rejected_rules.txt"
SECURITY_SUMMARY_JSON = SCAN_REPORTS_DIR / "security_summary.json"

AD_BLOCK_LIST = SURGE_RULES_DIR / "Ad_Block.list"
AD_BLOCK_MODULE = SURGE_MODULE_DIR / "Ad_Block.sgmodule"

STAGING_DIR = BUILD_DIR / "staging"
STAGED_AD_BLOCK_LIST = STAGING_DIR / "Ad_Block.list"
STAGED_AD_BLOCK_MODULE = STAGING_DIR / "Ad_Block.sgmodule"

URL_RE = re.compile(r"https?://[^\s<>'\"）)]+", re.IGNORECASE)
DOMAIN_RE = re.compile(r"^(?:\*\.)?(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,63}$")
DOMAIN_TOKEN_RE = re.compile(r"(?:\*\.)?(?:[a-z0-9-]+\.)+[a-z]{2,63}", re.IGNORECASE)

RULE_TYPES = {
    "DOMAIN",
    "DOMAIN-SUFFIX",
    "DOMAIN-KEYWORD",
    "IP-CIDR",
    "IP-CIDR6",
    "IP-ASN",
    "URL-REGEX",
    "PROCESS-NAME",
    "USER-AGENT",
    "PROTOCOL",
    "DEST-PORT",
    "SRC-IP",
    "IN-PORT",
    "AND",
    "OR",
    "NOT",
}

MODULE_RULE_POLICIES = {"DIRECT", "REJECT", "REJECT-TINYGIF"}
COMMENT_PREFIXES = ("#", ";", "//", "!")


def ensure_project_dirs() -> None:
    for p in [
        DATA_SOURCES_DIR,
        DATA_ALLOWLISTS_DIR,
        BUILD_DIR,
        SCAN_REPORTS_DIR,
        SURGE_RULES_DIR,
        SURGE_MODULE_DIR,
    ]:
        p.mkdir(parents=True, exist_ok=True)


def read_text(path: Path, default: str = "") -> str:
    if not path.exists():
        return default
    return path.read_text(encoding="utf-8")


def write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def read_lines(path: Path) -> list[str]:
    if not path.exists():
        return []
    return path.read_text(encoding="utf-8").splitlines()


def write_lines(path: Path, lines: Iterable[str]) -> None:
    cleaned = [str(x).rstrip() for x in lines if str(x).strip()]
    write_text(path, "\n".join(cleaned) + ("\n" if cleaned else ""))


def dedupe_sorted(items: Iterable[str]) -> list[str]:
    return sorted(set(i for i in items if i and str(i).strip()), key=lambda s: s.casefold())


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", errors="ignore")).hexdigest()


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def stable_module_id(source_url: str) -> str:
    return hashlib.sha1(source_url.encode("utf-8", errors="ignore")).hexdigest()[:16]


def is_comment_or_empty(line: str) -> bool:
    s = line.strip().lstrip("\ufeff")
    return not s or any(s.startswith(prefix) for prefix in COMMENT_PREFIXES)


def strip_no_resolve_and_trailing_commas(line: str) -> str:
    line = re.sub(r"(?i),\s*no-resolve\b", "", line).strip()
    while line.endswith(","):
        line = line[:-1].rstrip()
    return line


def extract_urls_from_text(text: str) -> list[str]:
    urls = []
    for match in URL_RE.findall(text):
        url = match.strip().rstrip(".,;:)]〗）")
        while url and ord(url[-1]) > 127:
            url = url[:-1]
        if url:
            urls.append(url)
    return urls


def read_seed_urls(path: Path) -> list[str]:
    urls: list[str] = []
    for line in read_lines(path):
        urls.extend(extract_urls_from_text(line))
    return dedupe_sorted(urls)


def github_headers(token: str | None = None) -> dict[str, str]:
    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "Net-Link-AdBlock-Automation",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def _read_url_bytes(url: str, headers: dict[str, str] | None = None, timeout: int = 30) -> tuple[bytes, str]:
    req = Request(url, headers=headers or {})
    with urlopen(req, timeout=timeout) as resp:
        data = resp.read()
        charset = resp.headers.get_content_charset() or "utf-8"
    return data, charset


def request_text(url: str, timeout: int = 30) -> str:
    data, charset = _read_url_bytes(
        url,
        headers={"User-Agent": "Net-Link-AdBlock-Automation"},
        timeout=timeout,
    )
    return data.decode(charset, errors="replace")


def request_json(url: str, token: str | None = None, timeout: int = 30) -> dict:
    data, charset = _read_url_bytes(
        url,
        headers=github_headers(token),
        timeout=timeout,
    )
    text = data.decode(charset, errors="replace")
    return json.loads(text)


def parse_github_repo_url(url: str) -> tuple[str, str] | None:
    parsed = urlparse(url)
    if parsed.netloc.lower() != "github.com":
        return None
    parts = [p for p in parsed.path.strip("/").split("/") if p]
    if len(parts) < 2:
        return None
    return parts[0], parts[1]


def github_blob_html_to_raw(html_url: str) -> str | None:
    parsed = urlparse(html_url)
    if parsed.netloc.lower() != "github.com":
        return None
    parts = [p for p in parsed.path.strip("/").split("/") if p]
    if len(parts) < 5 or parts[2] != "blob":
        return None
    owner, repo, _, branch = parts[:4]
    path = "/".join(parts[4:])
    return f"https://raw.githubusercontent.com/{owner}/{repo}/{branch}/{path}"


def github_get_default_branch(owner: str, repo: str, token: str | None = None) -> str:
    info = request_json(f"https://api.github.com/repos/{owner}/{repo}", token=token)
    return info.get("default_branch", "main")


def github_list_repo_tree(owner: str, repo: str, branch: str, token: str | None = None) -> list[dict]:
    data = request_json(
        f"https://api.github.com/repos/{owner}/{repo}/git/trees/{branch}?recursive=1",
        token=token,
    )
    return data.get("tree", [])


def github_raw_url(owner: str, repo: str, branch: str, path: str) -> str:
    encoded_parts = [quote(part, safe="") for part in path.split("/")]
    encoded_path = "/".join(encoded_parts)
    return f"https://raw.githubusercontent.com/{owner}/{repo}/{branch}/{encoded_path}"


def normalize_ip_or_network_value(value: str) -> tuple[str, str] | None:
    value = value.strip().strip("[]")
    if not value:
        return None

    try:
        network = ipaddress.ip_network(value, strict=False)
        if isinstance(network, ipaddress.IPv6Network):
            return "IP-CIDR6", network.compressed
        return "IP-CIDR", network.compressed
    except ValueError:
        return None


def normalize_rule_line(line: str, strip_policy: bool = False) -> str | None:
    if is_comment_or_empty(line):
        return None

    line = strip_no_resolve_and_trailing_commas(line)
    if not line or "," not in line:
        return None

    parts = [p.strip() for p in line.split(",")]
    if not parts or not parts[0]:
        return None

    head = parts[0].upper()
    if head not in RULE_TYPES:
        return None

    if len(parts) < 2 or not parts[1]:
        return None

    value = parts[1].strip()
    extras = [p.strip() for p in parts[2:] if p.strip()]

    if extras:
        last = extras[-1].upper()
        if last in MODULE_RULE_POLICIES:
            if strip_policy:
                extras = extras[:-1]
            else:
                extras[-1] = last

    if head in {"DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD"}:
        raw_value = value.lstrip(".") if head == "DOMAIN-SUFFIX" else value

        ip_norm = normalize_ip_or_network_value(raw_value)
        if ip_norm:
            head, value = ip_norm
            extras = [e for e in extras if e.lower() != "no-resolve"]
            result = ",".join([head, value, *extras]).strip()
            return strip_no_resolve_and_trailing_commas(result)

        value = raw_value.lower()
        result = ",".join([head, value, *extras]).strip()
        return strip_no_resolve_and_trailing_commas(result)

    if head in {"IP-CIDR", "IP-CIDR6"}:
        ip_norm = normalize_ip_or_network_value(value)
        if not ip_norm:
            return None
        head, value = ip_norm
        extras = [e for e in extras if e.lower() != "no-resolve"]
        result = ",".join([head, value, *extras]).strip()
        return strip_no_resolve_and_trailing_commas(result)

    result = ",".join([head, value, *extras]).strip()
    return strip_no_resolve_and_trailing_commas(result)


def extract_reject_rule_from_module_rule(line: str) -> str | None:
    norm = normalize_rule_line(line, strip_policy=False)
    if not norm:
        return None

    parts = [p.strip() for p in norm.split(",") if p.strip()]
    if len(parts) < 3:
        return None
    if parts[-1].upper() not in {"REJECT", "REJECT-TINYGIF"}:
        return None

    return normalize_rule_line(norm, strip_policy=True)


def parse_allowlist_host_line(line: str) -> str | None:
    s = line.strip().lstrip("\ufeff")
    if not s or s.startswith(("#", ";", "//", "!")):
        return None

    # ABP exception: @@||example.com^
    if s.startswith("@@"):
        abp = parse_abp_exception_to_host(s)
        if abp:
            return abp

    # hosts file line
    m = re.match(r"^(?:0\.0\.0\.0|127\.0\.0\.1|::1)\s+([^\s#]+)", s)
    if m:
        host = m.group(1).strip().lower().lstrip(".")
        if DOMAIN_RE.match(host):
            return host

    # plain domain
    host = s.split()[0].strip().lower().lstrip(".")
    if DOMAIN_RE.match(host):
        return host

    return None


def parse_abp_exception_to_host(line: str) -> str | None:
    s = line.strip()
    if not s.startswith("@@"):
        return None

    # @@||example.com^
    if s.startswith("@@||"):
        tail = s[4:]
        host = re.split(r"[\^/$]", tail, maxsplit=1)[0].strip().lower().lstrip(".")
        if DOMAIN_RE.match(host):
            return host

    # @@|https://example.com/path
    if s.startswith("@@|http://") or s.startswith("@@|https://"):
        url = s[3:]
        try:
            host = (urlparse(url).hostname or "").strip().lower().lstrip(".")
            if DOMAIN_RE.match(host):
                return host
        except Exception:
            return None

    return None


def host_or_parent_matches(host: str, allow_hosts: set[str]) -> bool:
    value = host.strip().lower().lstrip(".")
    if not value:
        return False

    if value in allow_hosts:
        return True

    labels = value.split(".")
    for idx in range(1, len(labels) - 1):
        parent = ".".join(labels[idx:])
        if parent in allow_hosts:
            return True

    return False


def normalized_rule_matches_allowlist(norm: str, allow_hosts: set[str]) -> bool:
    if not norm:
        return False

    parts = [p.strip() for p in norm.split(",") if p.strip()]
    if len(parts) < 2:
        return False

    head, value = parts[0].upper(), parts[1].lower()

    if head == "DOMAIN":
        return host_or_parent_matches(value, allow_hosts)
    if head == "DOMAIN-SUFFIX":
        return host_or_parent_matches(value, allow_hosts)
    if head == "DOMAIN-KEYWORD":
        return any(value in host for host in allow_hosts)

    return False


def rule_matches_allowlist(rule: str, allow_hosts: set[str]) -> bool:
    norm = normalize_rule_line(rule, strip_policy=True)
    if not norm:
        return False
    return normalized_rule_matches_allowlist(norm, allow_hosts)


def line_mentions_allowlisted_host(line: str, allow_hosts: set[str]) -> bool:
    normalized = (
        line.lower()
        .replace(r"\.", ".")
        .replace(r"\/", "/")
        .replace(",", " ")
        .replace("=", " ")
    )

    for token in DOMAIN_TOKEN_RE.findall(normalized):
        host = token.lstrip("*.").strip(".")
        if not host:
            continue
        if host_or_parent_matches(host, allow_hosts):
            return True

    return False


def line_matches_any_regex(line: str, regex_list: list[re.Pattern[str]]) -> bool:
    return any(r.search(line) for r in regex_list)


def safe_compile_regexes(lines: Iterable[str]) -> list[re.Pattern[str]]:
    regexes: list[re.Pattern[str]] = []
    for line in lines:
        s = line.strip()
        if not s or s.startswith(("#", ";", "//")):
            continue
        try:
            regexes.append(re.compile(s))
        except re.error:
            continue
    return regexes


def expand_hosts_with_parents(hosts: Iterable[str]) -> set[str]:
    expanded: set[str] = set()
    for host in hosts:
        s = host.strip().lower().lstrip(".")
        if not s:
            continue
        labels = s.split(".")
        for idx in range(0, max(len(labels) - 1, 1)):
            expanded.add(".".join(labels[idx:]))
    return expanded


def slugify(text: str) -> str:
    text = re.sub(r"[^A-Za-z0-9._-]+", "-", text.strip())
    return text.strip("-") or "item"


def save_json(path: Path, data: object) -> None:
    write_text(path, json.dumps(data, ensure_ascii=False, indent=2) + "\n")
