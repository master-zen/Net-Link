#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import argparse
import ipaddress
import re
import ssl
import sys
import time
from pathlib import Path
from typing import Iterable
from urllib.parse import urlparse, urlunparse
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parents[1]

BLOCK_SOURCES_FILE = ROOT / "data/sources/AdBlockList_URLs.txt"
ALLOW_SOURCES_FILE = ROOT / "data/sources/AdAllowList_URLs.txt"
SEED_SOURCES_FILE = ROOT / "data/sources/AdRepoSeed_URLs.txt"

OUTPUT_BLOCK = ROOT / "Surge/Rules/AdblockSet.list"
OUTPUT_CLASH = ROOT / "Clash/Rules/AdblockSet.yaml"

WEB_DISCOVERY_SEEDS = [
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/README.md",
    "https://raw.githubusercontent.com/ppfeufer/adguard-filter-list/master/README.md",
]

WEB_DISCOVERY_CANDIDATES_BLOCK = [
    "https://raw.githubusercontent.com/easylist/easylist/master/easylist/easylist_adservers.txt",
    "https://raw.githubusercontent.com/easylist/easylist/master/easyprivacy/easyprivacy_trackingservers.txt",
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/pro.txt",
]

WEB_DISCOVERY_CANDIDATES_ALLOW = [
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/whitelist-referral-native.txt",
]

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

POLICY_TOKENS = {
    "DIRECT",
    "REJECT",
    "REJECT-DROP",
    "REJECT-NO-DROP",
    "REJECT-TINYGIF",
    "PROXY",
    "FINAL",
    "DONE",
}

BINARY_EXTENSIONS = {
    ".7z",
    ".bmp",
    ".doc",
    ".docx",
    ".exe",
    ".gif",
    ".gz",
    ".ico",
    ".jar",
    ".jpeg",
    ".jpg",
    ".mp3",
    ".mp4",
    ".pdf",
    ".png",
    ".rar",
    ".svg",
    ".tar",
    ".tgz",
    ".webp",
    ".xz",
    ".zip",
}

TRUSTED_DISCOVERY_HOSTS = {
    "raw.githubusercontent.com",
    "easylist-downloads.adblockplus.org",
    "ruleset.skk.moe",
    "anti-ad.net",
}

ALLOW_HINTS = ("allow", "whitelist", "exception", "unbreak", "referral")
BLOCK_HINTS = (
    "ad",
    "ads",
    "reject",
    "anti",
    "track",
    "privacy",
    "hijack",
    "malware",
    "block",
)
RELEVANCE_HINTS = (
    "ad",
    "ads",
    "adblock",
    "allow",
    "whitelist",
    "reject",
    "privacy",
    "tracking",
    "hijack",
)

COMMENT_PREFIXES = ("#", ";", "//", "! ", "!\t")
DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9-]{2,63}$")
URL_RE = re.compile(r"https?://[^\s<>\]\[\"'`]+", re.IGNORECASE)


def fetch_text(url: str, timeout: int = 30, retries: int = 3, max_bytes: int = 20_000_000) -> str:
    last_error: Exception | None = None
    for attempt in range(1, retries + 1):
        try:
            request = Request(
                url,
                headers={
                    "User-Agent": "Mozilla/5.0 (Net-Link ad sets builder)",
                    "Accept": "text/plain,text/html,*/*",
                },
            )
            context = ssl.create_default_context()
            with urlopen(request, timeout=timeout, context=context) as response:
                chunks: list[bytes] = []
                total = 0
                while True:
                    chunk = response.read(65536)
                    if not chunk:
                        break
                    total += len(chunk)
                    if total > max_bytes:
                        raise RuntimeError(f"payload too large: {total} bytes")
                    chunks.append(chunk)

                charset = response.headers.get_content_charset() or "utf-8"
                return b"".join(chunks).decode(charset, errors="replace")
        except Exception as exc:  # noqa: BLE001
            last_error = exc
            if attempt < retries:
                time.sleep(2 * attempt)

    raise RuntimeError(f"Failed to fetch {url}: {last_error}") from last_error


def ensure_parent_dirs() -> None:
    OUTPUT_BLOCK.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT_CLASH.parent.mkdir(parents=True, exist_ok=True)


def is_comment_or_empty(line: str) -> bool:
    line = line.strip().lstrip("\ufeff")
    if not line:
        return True
    if line.startswith(COMMENT_PREFIXES):
        return True
    return False


def strip_inline_comment(line: str) -> str:
    value = line.strip().lstrip("\ufeff")
    if not value:
        return ""

    if " #" in value:
        value = value.split(" #", 1)[0].rstrip()
    if " ;" in value:
        value = value.split(" ;", 1)[0].rstrip()

    return value.strip()


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
    elif host == "cdn.jsdelivr.net":
        parts = [p for p in path.split("/") if p]
        if len(parts) >= 4 and parts[0] == "gh":
            owner = parts[1]
            repo_ref = parts[2]
            if "@" in repo_ref:
                repo, ref = repo_ref.split("@", 1)
                rest = "/".join(parts[3:])
                ref_norm = "main" if ref == "latest" else ref
                host = "raw.githubusercontent.com"
                path = f"/{owner}/{repo}/{ref_norm}/{rest}"

    normalized = urlunparse((parsed.scheme.lower(), host, path, "", parsed.query, ""))
    reparsed = urlparse(normalized)
    if reparsed.scheme.lower() not in {"http", "https"}:
        return None
    if not reparsed.netloc:
        return None

    return normalized


def looks_like_rule_source_url(url: str) -> bool:
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"}:
        return False

    lower_path = parsed.path.lower()

    for bad in ("/issues", "/pull/", "/pulls", "/releases", "/actions", "/commits"):
        if bad in lower_path:
            return False

    extension = Path(lower_path).suffix
    if extension and extension in BINARY_EXTENSIONS:
        return False

    if "raw.githubusercontent.com" in parsed.netloc:
        return True

    if extension in {".txt", ".list", ".conf", ".rules", ".sgmodule"}:
        return True

    if any(token in lower_path for token in ("/rule", "/rules", "adblock", "allow", "whitelist", "blacklist")):
        if lower_path.endswith(".md"):
            return False
        return True

    return False


def unique_sorted(items: Iterable[str]) -> list[str]:
    return sorted(set(items), key=lambda item: item.casefold())


def is_trusted_discovery_host(url: str) -> bool:
    host = (urlparse(url).netloc or "").lower()
    host = host.split(":", 1)[0]
    return host in TRUSTED_DISCOVERY_HOSTS


def read_source_urls(path: Path) -> list[str]:
    if not path.exists():
        return []

    urls: list[str] = []
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        norm = normalize_source_url(line)
        if norm:
            urls.append(norm)

    return unique_sorted(urls)


def write_source_urls(path: Path, urls: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    content = "\n".join(unique_sorted(urls)).strip()
    path.write_text((content + "\n") if content else "", encoding="utf-8")


def parse_adblock_domain(candidate: str) -> str | None:
    token = candidate.strip().lower()
    if not token:
        return None

    token = token.removeprefix("~")
    token = token.removeprefix("||")
    token = token.removeprefix("|")

    if token.startswith("http://") or token.startswith("https://"):
        parsed = urlparse(token)
        token = parsed.hostname or ""

    token = token.split("^", 1)[0]
    token = token.split("/", 1)[0]
    token = token.split("*", 1)[0]
    token = token.strip(".")

    if token.startswith("www."):
        token = token[4:]

    if not token:
        return None

    try:
        ip = ipaddress.ip_address(token)
        if isinstance(ip, ipaddress.IPv6Address):
            return f"IP-CIDR6,{ip.compressed}/128"
        return f"IP-CIDR,{ip.compressed}/32"
    except ValueError:
        pass

    if DOMAIN_RE.match(token):
        return f"DOMAIN-SUFFIX,{token}"

    return None


def normalize_ip_or_network(value: str) -> tuple[str, str] | None:
    raw = value.strip().strip("[]")
    if not raw:
        return None

    try:
        network = ipaddress.ip_network(raw, strict=False)
        if isinstance(network, ipaddress.IPv6Network):
            return ("IP-CIDR6", network.compressed)
        return ("IP-CIDR", network.compressed)
    except ValueError:
        return None


def normalize_domain(host: str) -> str | None:
    token = host.strip().lower().strip(".")
    if token.startswith("*."):
        token = token[2:]
    if not token:
        return None
    if DOMAIN_RE.match(token):
        return token
    return None


def normalize_rule_line(raw_line: str, default_bucket: str) -> tuple[str, str] | None:
    line = strip_inline_comment(raw_line)
    if not line:
        return None

    bucket = default_bucket

    # Adblock exception and blocking syntax.
    if line.startswith("@@"):
        bucket = "allow"
        line = line[2:].strip()

    if "#@#" in line or "##" in line:
        return None

    if line.startswith("||") or line.startswith("|"):
        normalized = parse_adblock_domain(line.split("$", 1)[0])
        if normalized:
            return (normalized, bucket)
        return None

    # Surge-like rule with explicit type.
    if "," in line:
        parts = [part.strip() for part in line.split(",") if part.strip()]
        if len(parts) >= 2:
            head = parts[0].upper()
            value = parts[1]

            if head in RULE_TYPES:
                if head in {"DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD"}:
                    domain = normalize_domain(value.lstrip(".") if head == "DOMAIN-SUFFIX" else value)
                    if not domain:
                        ip_norm = normalize_ip_or_network(value)
                        if not ip_norm:
                            return None
                        return (f"{ip_norm[0]},{ip_norm[1]}", bucket)

                    normalized_value = domain if head in {"DOMAIN", "DOMAIN-SUFFIX"} else value.lower()
                    return (f"{head},{normalized_value}", bucket)

                if head in {"IP-CIDR", "IP-CIDR6"}:
                    ip_norm = normalize_ip_or_network(value)
                    if not ip_norm:
                        return None

                    extras = [token.lower() for token in parts[2:] if token.upper() not in POLICY_TOKENS]
                    if extras:
                        return (f"{ip_norm[0]},{ip_norm[1]},{','.join(extras)}", bucket)
                    return (f"{ip_norm[0]},{ip_norm[1]}", bucket)

                extras = [token for token in parts[2:] if token.upper() not in POLICY_TOKENS]
                if extras:
                    return (f"{head},{value},{','.join(extras)}", bucket)
                return (f"{head},{value}", bucket)

    hosts_match = re.match(r"^(?:0\.0\.0\.0|127\.0\.0\.1|::1)\s+([^\s#;]+)", line)
    if hosts_match:
        domain = normalize_domain(hosts_match.group(1))
        if domain:
            return (f"DOMAIN,{domain}", bucket)
        return None

    dnsmasq_match = re.match(r"^address=/([^/]+)/", line, flags=re.IGNORECASE)
    if dnsmasq_match:
        domain = normalize_domain(dnsmasq_match.group(1))
        if domain:
            return (f"DOMAIN-SUFFIX,{domain}", bucket)
        return None

    ip_norm = normalize_ip_or_network(line)
    if ip_norm:
        return (f"{ip_norm[0]},{ip_norm[1]}", bucket)

    domain = normalize_domain(line)
    if domain:
        if default_bucket == "allow":
            return (f"DOMAIN,{domain}", "allow")
        return (f"DOMAIN,{domain}", bucket)

    return None


def tokenize_line(raw_line: str) -> list[str]:
    line = raw_line.strip().lstrip("\ufeff")
    if not line:
        return []

    if line.startswith(COMMENT_PREFIXES):
        return []

    # Handle one-line domain packs (e.g. many domains separated by spaces).
    if "," not in line and "\t" not in line and line.count(" ") >= 2 and "http" not in line.lower():
        tokens = [token.strip() for token in line.split() if token.strip()]
        valid = 0
        for token in tokens:
            if normalize_domain(token.strip(".")) or normalize_ip_or_network(token):
                valid += 1
        if valid >= max(2, len(tokens) // 2):
            return tokens

    return [line]


def parse_rules_from_text(text: str, default_bucket: str) -> tuple[set[str], set[str], int]:
    block_rules: set[str] = set()
    allow_rules: set[str] = set()
    parsed_lines = 0

    for raw_line in text.splitlines():
        if raw_line.lstrip().startswith("|"):
            # Skip markdown table rows to avoid treating docs as list sources.
            continue
        entries = tokenize_line(raw_line)
        if not entries:
            continue

        for entry in entries:
            parsed = normalize_rule_line(entry, default_bucket)
            if not parsed:
                continue

            rule, bucket = parsed
            if bucket == "allow":
                allow_rules.add(rule)
            else:
                block_rules.add(rule)
            parsed_lines += 1

    return block_rules, allow_rules, parsed_lines


def score_candidate_url(url: str) -> int:
    lower = url.lower()
    score = 0

    if "raw.githubusercontent.com" in lower:
        score += 4

    if any(keyword in lower for keyword in ("adblock", "blacklist", "whitelist", "allow", "reject", "rules")):
        score += 4

    if lower.endswith((".txt", ".list", ".conf", ".md")):
        score += 2

    if "/blob/" in lower or "/tree/" in lower:
        score -= 2

    return score


def has_relevance_hint(url: str) -> bool:
    lower = url.lower()
    tokens = {token for token in re.split(r"[^a-z0-9]+", lower) if token}
    return any(token in tokens for token in RELEVANCE_HINTS)


def is_oversized_candidate_url(url: str) -> bool:
    lower = url.lower()
    skip_patterns = (
        "/adblock/dga",
        "/adblock/nrd",
        "/adblock/tif",
        "/adblock/ultimate",
        "/adblock/pro.plus",
    )
    return any(pattern in lower for pattern in skip_patterns)


def classify_by_url(url: str) -> str:
    lower = url.lower()
    tokens = {token for token in re.split(r"[^a-z0-9]+", lower) if token}

    allow_tokens = {"allow", "allowlist", "whitelist", "exception", "exceptions", "unbreak", "referral"}
    block_tokens = {"ad", "ads", "adblock", "reject", "anti", "tracking", "privacy", "hijacking", "block", "blacklist"}

    if tokens & allow_tokens:
        return "allow"
    if tokens & block_tokens:
        return "block"

    allow_hits = sum(1 for token in ALLOW_HINTS if token in lower)
    block_hits = sum(1 for token in BLOCK_HINTS if token in lower)
    if allow_hits > block_hits:
        return "allow"
    if block_hits > allow_hits:
        return "block"
    return "unknown"


def extract_urls_from_seed_text(text: str) -> list[str]:
    discovered: list[str] = []
    for matched in URL_RE.findall(text):
        normalized = normalize_source_url(matched)
        if not normalized:
            continue
        if not looks_like_rule_source_url(normalized):
            continue
        discovered.append(normalized)

    return discovered


def discover_new_sources(
    seed_urls: list[str],
    known_block_sources: list[str],
    known_allow_sources: list[str],
    candidate_cap: int,
) -> tuple[list[str], list[str]]:
    known = set(known_block_sources) | set(known_allow_sources)
    raw_candidates: list[str] = []

    for seed in seed_urls:
        try:
            text = fetch_text(seed, max_bytes=3_000_000)
            raw_candidates.extend(extract_urls_from_seed_text(text))
        except Exception as exc:  # noqa: BLE001
            print(f"[WARN] seed fetch failed: {seed} -> {exc}", file=sys.stderr)

    raw_candidates.extend(WEB_DISCOVERY_CANDIDATES_BLOCK)
    raw_candidates.extend(WEB_DISCOVERY_CANDIDATES_ALLOW)

    deduped = unique_sorted(raw_candidates)
    deduped = [url for url in deduped if url not in known]
    prioritized = sorted(deduped, key=score_candidate_url, reverse=True)[:candidate_cap]

    new_block: list[str] = []
    new_allow: list[str] = []

    for candidate in prioritized:
        if not is_trusted_discovery_host(candidate):
            continue
        if is_oversized_candidate_url(candidate):
            continue
        if not has_relevance_hint(candidate):
            continue
        bucket_guess = classify_by_url(candidate)

        try:
            text = fetch_text(candidate, max_bytes=5_000_000)
        except Exception as exc:  # noqa: BLE001
            print(f"[WARN] candidate fetch failed: {candidate} -> {exc}", file=sys.stderr)
            continue

        block_rules, allow_rules, parsed_count = parse_rules_from_text(text, "block")
        if parsed_count < 10:
            continue

        if bucket_guess == "allow":
            if len(allow_rules) == 0 and len(block_rules) > 0:
                # e.g. plain-domain allowlist resources without @@ syntax
                if len(block_rules) <= 30000:
                    new_allow.append(candidate)
            else:
                new_allow.append(candidate)
            continue

        if bucket_guess == "block":
            new_block.append(candidate)
            continue

        # Unknown: infer by parsed result balance.
        if len(allow_rules) >= max(20, len(block_rules) // 2):
            new_allow.append(candidate)
        else:
            new_block.append(candidate)

    return unique_sorted(new_block), unique_sorted(new_allow)


def rule_type_sort_key(rule: str) -> tuple[int, str, str]:
    head, _, tail = rule.partition(",")
    order = {
        "DOMAIN": 1,
        "DOMAIN-SUFFIX": 2,
        "DOMAIN-KEYWORD": 3,
        "IP-CIDR": 4,
        "IP-CIDR6": 5,
        "IP-ASN": 6,
        "URL-REGEX": 7,
        "PROCESS-NAME": 8,
        "USER-AGENT": 9,
        "PROTOCOL": 10,
        "DEST-PORT": 11,
        "SRC-IP": 12,
        "IN-PORT": 13,
        "AND": 14,
        "OR": 15,
        "NOT": 16,
    }
    return (order.get(head.upper(), 99), head.upper(), tail.casefold())


def merge_rules_from_sources(source_urls: list[str], default_bucket: str) -> tuple[list[str], list[str]]:
    all_rules: list[str] = []
    warnings: list[str] = []

    for source in source_urls:
        try:
            text = fetch_text(source)
            block_rules, allow_rules, parsed = parse_rules_from_text(text, default_bucket)
            if parsed == 0:
                warnings.append(f"No rules parsed: {source}")
                continue

            if default_bucket == "allow":
                all_rules.extend(allow_rules or block_rules)
            else:
                all_rules.extend(block_rules)
        except Exception as exc:  # noqa: BLE001
            warnings.append(f"Fetch failed: {source} -> {exc}")

    merged = sorted(set(all_rules), key=rule_type_sort_key)
    return merged, warnings


def subtract_allow_rules(block_rules: list[str], allow_rules: list[str]) -> list[str]:
    allow_set = set(allow_rules)
    if not allow_set:
        return list(block_rules)

    # Build equivalent-domain removals for common rule variants.
    eq_domain_pairs: set[tuple[str, str]] = set()
    for rule in allow_set:
        head, sep, value = rule.partition(",")
        if not sep or not value:
            continue
        head = head.upper()
        value = value.strip()
        if head == "DOMAIN":
            eq_domain_pairs.add(("DOMAIN-SUFFIX", value))
        elif head == "DOMAIN-SUFFIX":
            eq_domain_pairs.add(("DOMAIN", value))

    filtered: list[str] = []
    for rule in block_rules:
        if rule in allow_set:
            continue
        head, sep, value = rule.partition(",")
        if sep and (head.upper(), value.strip()) in eq_domain_pairs:
            continue
        filtered.append(rule)

    return filtered


def write_ruleset(path: Path, rules: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    content = "\n".join(rules).strip()
    path.write_text((content + "\n") if content else "", encoding="utf-8")


def yaml_quote(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def write_clash_ruleset(path: Path, rules: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    lines = ["payload:"]
    lines.extend(f"  - {yaml_quote(rule)}" for rule in rules)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Build Surge AdblockSet by subtracting merged allow rules from merged block rules.",
    )
    parser.add_argument(
        "--candidate-cap",
        type=int,
        default=180,
        help="Maximum number of discovered candidate URLs to validate per run.",
    )
    parser.add_argument(
        "--no-discovery",
        action="store_true",
        help="Skip seed discovery and only merge from existing source URL files.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    ensure_parent_dirs()

    block_sources = read_source_urls(BLOCK_SOURCES_FILE)
    allow_sources = read_source_urls(ALLOW_SOURCES_FILE)
    seed_sources = read_source_urls(SEED_SOURCES_FILE)

    if not block_sources:
        print(f"[ERROR] no block sources in {BLOCK_SOURCES_FILE}", file=sys.stderr)
        return 1
    if not allow_sources:
        print(f"[ERROR] no allow sources in {ALLOW_SOURCES_FILE}", file=sys.stderr)
        return 1

    print(f"[INFO] block sources: {len(block_sources)}")
    print(f"[INFO] allow sources: {len(allow_sources)}")

    if not args.no_discovery:
        discovery_seeds = unique_sorted(seed_sources + WEB_DISCOVERY_SEEDS)
        new_block_sources, new_allow_sources = discover_new_sources(
            seed_urls=discovery_seeds,
            known_block_sources=block_sources,
            known_allow_sources=allow_sources,
            candidate_cap=max(10, args.candidate_cap),
        )

        if new_block_sources:
            print(f"[DISCOVERY] new block sources: {len(new_block_sources)}")
            block_sources = unique_sorted(block_sources + new_block_sources)
            write_source_urls(BLOCK_SOURCES_FILE, block_sources)

        if new_allow_sources:
            print(f"[DISCOVERY] new allow sources: {len(new_allow_sources)}")
            allow_sources = unique_sorted(allow_sources + new_allow_sources)
            write_source_urls(ALLOW_SOURCES_FILE, allow_sources)

    block_rules, block_warnings = merge_rules_from_sources(block_sources, default_bucket="block")
    allow_rules, allow_warnings = merge_rules_from_sources(allow_sources, default_bucket="allow")

    if block_warnings:
        for warning in block_warnings:
            print(f"[WARN] {warning}", file=sys.stderr)
    if allow_warnings:
        for warning in allow_warnings:
            print(f"[WARN] {warning}", file=sys.stderr)

    if not block_rules:
        print("[ERROR] no rules generated for AdblockSet.list", file=sys.stderr)
        return 1

    filtered_block_rules = subtract_allow_rules(block_rules, allow_rules)
    if not filtered_block_rules:
        print("[ERROR] AdblockSet.list became empty after allow subtraction", file=sys.stderr)
        return 1

    write_ruleset(OUTPUT_BLOCK, filtered_block_rules)
    write_clash_ruleset(OUTPUT_CLASH, filtered_block_rules)

    print(f"[DONE] {OUTPUT_BLOCK.relative_to(ROOT)}: {len(filtered_block_rules)} lines")
    print(f"[DONE] {OUTPUT_CLASH.relative_to(ROOT)}: {len(filtered_block_rules)} lines")
    print(
        "[DONE] subtraction summary: "
        f"block={len(block_rules)}, allow={len(allow_rules)}, "
        f"removed={len(block_rules) - len(filtered_block_rules)}"
    )
    print(f"[DONE] {BLOCK_SOURCES_FILE.relative_to(ROOT)}: {len(block_sources)} URLs")
    print(f"[DONE] {ALLOW_SOURCES_FILE.relative_to(ROOT)}: {len(allow_sources)} URLs")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
