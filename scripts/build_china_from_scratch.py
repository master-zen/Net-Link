#!/usr/bin/env python3
from __future__ import annotations

import asyncio
import hashlib
import ipaddress
import json
import os
import re
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import dns.message
import dns.rcode
import dns.rdatatype
import httpx

ROOT = Path(__file__).resolve().parents[1]
SOURCE_LIST_PATH = ROOT / "data" / "sources" / "ChinaDomain.txt"
TEMP_DIR = ROOT / "data" / "temporary"
COLLECTION_PATH = TEMP_DIR / "ChinaDomainCollection.txt"
DNS_RESULTS_PATH = TEMP_DIR / "ChinaDomainDNSresults.txt"
DNS_TIDY_PATH = TEMP_DIR / "ChinaDomainDNSTidy.txt"
TIDY_PATH = TEMP_DIR / "ChinaDomainTidy.txt"
OUTPUT_PATH = ROOT / "Surge" / "Rules" / "China.list"

FORCE_DNS_REFRESH = os.getenv("FORCE_DNS_REFRESH", "0") == "1"
MAX_DOMAIN_CONCURRENCY = int(os.getenv("CHINA_DOMAIN_MAX_CONCURRENCY", "96"))
REQUEST_TIMEOUT = float(os.getenv("CHINA_DOMAIN_REQUEST_TIMEOUT", "4.5"))
SUCCESS_CACHE_HOURS = int(os.getenv("CHINA_DOMAIN_SUCCESS_CACHE_HOURS", "720"))
FAILURE_CACHE_HOURS = int(os.getenv("CHINA_DOMAIN_FAILURE_CACHE_HOURS", "72"))
DNS_FOLLOW_CNAME_DEPTH = 6
DNS_WRITE_EVERY = 200

CN_DOH_RESOLVERS = [
    "https://doh.pub/dns-query",
    "https://dns.alidns.com/dns-query",
    "https://doh.360.cn/dns-query",
    "https://223.5.5.5/dns-query",
    "https://223.6.6.6/dns-query",
]

GLOBAL_DOH_RESOLVERS = [
    "https://dns.google/dns-query",
    "https://cloudflare-dns.com/dns-query",
    "https://dns.quad9.net/dns-query",
    "https://doh.opendns.com/dns-query",
    "https://dns.sb/dns-query",
]

QUERYABLE_RULE_TYPES = {"DOMAIN", "DOMAIN-SUFFIX"}
PASS_THROUGH_RULE_TYPES = {
    "DOMAIN-KEYWORD",
    "DOMAIN-WILDCARD",
    "IP-CIDR",
    "IP-CIDR6",
    "IP-ASN",
    "USER-AGENT",
    "URL-REGEX",
    "DEST-PORT",
    "SRC-IP",
    "IN-PORT",
    "PROCESS-NAME",
    "AND",
    "OR",
    "NOT",
    "SUBNET",
    "PROTOCOL",
    "DEVICE-NAME",
    "RULE-SET",
}

RULE_TYPE_ORDER = {
    "DOMAIN": 10,
    "DOMAIN-SUFFIX": 20,
    "DOMAIN-KEYWORD": 30,
    "DOMAIN-WILDCARD": 40,
    "URL-REGEX": 45,
    "USER-AGENT": 46,
    "PROCESS-NAME": 47,
    "DEST-PORT": 48,
    "SRC-IP": 49,
    "IN-PORT": 50,
    "SUBNET": 51,
    "PROTOCOL": 52,
    "IP-CIDR": 60,
    "IP-CIDR6": 70,
    "IP-ASN": 80,
    "RULE-SET": 90,
}

DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$",
    re.IGNORECASE,
)


@dataclass
class ParsedCollection:
    passthrough_rules: set[str]
    query_rule_lines_by_domain: dict[str, set[str]]


@dataclass
class ResolverResult:
    status: str
    answers: list[str]
    resolver: str
    cname_chain: list[str]
    rcode: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "answers": self.answers,
            "resolver": self.resolver,
            "cname_chain": self.cname_chain,
            "rcode": self.rcode,
        }


@dataclass
class CacheEntry:
    domain: str
    cn: dict[str, Any]
    global_: dict[str, Any]
    verdict: str
    checked_at: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "domain": self.domain,
            "cn": self.cn,
            "global": self.global_,
            "verdict": self.verdict,
            "checked_at": self.checked_at,
        }


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def ensure_dirs() -> None:
    TEMP_DIR.mkdir(parents=True, exist_ok=True)
    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)


def write_lines(path: Path, lines: list[str]) -> None:
    normalized = "\n".join(lines).rstrip()
    path.write_text((normalized + "\n") if normalized else "", encoding="utf-8")


def stable_unique(lines: list[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for raw in lines:
        line = raw.strip()
        if not line:
            continue
        if line in seen:
            continue
        seen.add(line)
        out.append(line)
    return out


def load_source_urls() -> list[str]:
    content = SOURCE_LIST_PATH.read_text(encoding="utf-8")
    urls = stable_unique(re.split(r"\s+", content.strip()))
    return [url for url in urls if url]


def fetch_source_lines(urls: list[str]) -> list[str]:
    merged: list[str] = []
    with httpx.Client(follow_redirects=True, timeout=30.0) as client:
        for url in urls:
            response = client.get(url)
            response.raise_for_status()
            text = response.text.replace("\r\n", "\n").replace("\r", "\n")
            merged.extend(line.strip() for line in text.split("\n") if line.strip())
    return merged


def normalize_domain(value: str) -> str:
    return value.strip().rstrip(".").lower()


def is_domain(value: str) -> bool:
    value = normalize_domain(value)
    if "://" in value:
        return False
    return bool(DOMAIN_RE.fullmatch(value))


def parse_ip_network(value: str) -> tuple[str, str] | None:
    value = value.strip()
    if not value:
        return None
    try:
        network = ipaddress.ip_network(value, strict=False)
    except ValueError:
        return None
    if isinstance(network, ipaddress.IPv4Network):
        return ("IP-CIDR", network.with_prefixlen)
    return ("IP-CIDR6", network.with_prefixlen)


def normalize_rule_line(keyword: str, payload: str, extras: list[str]) -> str | None:
    keyword = keyword.strip().upper()
    payload = payload.strip()
    extras = [item.strip() for item in extras if item.strip()]
    if not payload:
        return None

    if keyword in {"DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD", "DOMAIN-WILDCARD"}:
        payload = normalize_domain(payload)
    elif keyword in {"IP-CIDR", "IP-CIDR6"}:
        parsed = parse_ip_network(payload)
        if not parsed:
            return None
        keyword, payload = parsed
    elif keyword == "IP-ASN":
        payload = payload.upper()

    return ",".join([keyword, payload, *extras])


def classify_collection(lines: list[str]) -> ParsedCollection:
    passthrough_rules: set[str] = set()
    query_rule_lines_by_domain: dict[str, set[str]] = defaultdict(set)

    for raw in lines:
        line = raw.strip()
        if not line or line.startswith("#") or line.startswith("//"):
            continue

        if "," not in line:
            parsed_ip = parse_ip_network(line)
            if parsed_ip:
                passthrough_rules.add(f"{parsed_ip[0]},{parsed_ip[1]}")
                continue

            if is_domain(line):
                domain = normalize_domain(line)
                query_rule_lines_by_domain[domain].add(f"DOMAIN-SUFFIX,{domain}")
            continue

        parts = [part.strip() for part in line.split(",")]
        keyword = parts[0].upper()
        payload = parts[1] if len(parts) > 1 else ""
        extras = parts[2:] if len(parts) > 2 else []

        if keyword in QUERYABLE_RULE_TYPES and is_domain(payload):
            domain = normalize_domain(payload)
            normalized = normalize_rule_line(keyword, domain, extras)
            if normalized:
                query_rule_lines_by_domain[domain].add(normalized)
            continue

        if keyword in PASS_THROUGH_RULE_TYPES or keyword in {"IP-CIDR", "IP-CIDR6", "IP-ASN"}:
            normalized = normalize_rule_line(keyword, payload, extras)
            if normalized:
                passthrough_rules.add(normalized)
            continue

        parsed_ip = parse_ip_network(line)
        if parsed_ip:
            passthrough_rules.add(f"{parsed_ip[0]},{parsed_ip[1]}")

    return ParsedCollection(
        passthrough_rules=passthrough_rules,
        query_rule_lines_by_domain=query_rule_lines_by_domain,
    )


def load_dns_cache() -> dict[str, CacheEntry]:
    if not DNS_RESULTS_PATH.exists():
        return {}

    cache: dict[str, CacheEntry] = {}
    for raw in DNS_RESULTS_PATH.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line:
            continue
        try:
            payload = json.loads(line)
        except json.JSONDecodeError:
            continue
        domain = payload.get("domain")
        if not domain:
            continue
        cache[domain] = CacheEntry(
            domain=domain,
            cn=payload.get("cn", {}),
            global_=payload.get("global", {}),
            verdict=payload.get("verdict", "drop"),
            checked_at=payload.get("checked_at", "1970-01-01T00:00:00+00:00"),
        )
    return cache


def save_dns_cache(cache: dict[str, CacheEntry]) -> None:
    lines = [json.dumps(cache[domain].to_dict(), ensure_ascii=False, sort_keys=True) for domain in sorted(cache)]
    write_lines(DNS_RESULTS_PATH, lines)


def cache_is_fresh(entry: CacheEntry) -> bool:
    if FORCE_DNS_REFRESH:
        return False
    try:
        checked_at = datetime.fromisoformat(entry.checked_at)
    except ValueError:
        return False

    success = entry.verdict == "match"
    max_age = timedelta(hours=SUCCESS_CACHE_HOURS if success else FAILURE_CACHE_HOURS)
    return datetime.now(timezone.utc) - checked_at < max_age


def resolver_rotation(resolvers: list[str], domain: str) -> list[str]:
    if not resolvers:
        return []
    digest = hashlib.sha256(domain.encode("utf-8")).digest()
    index = int.from_bytes(digest[:2], "big") % len(resolvers)
    return resolvers[index:] + resolvers[:index]


def extract_a_and_cname(response: dns.message.Message) -> tuple[list[str], list[str]]:
    answers: set[str] = set()
    cname_chain: list[str] = []
    for rrset in response.answer:
        if rrset.rdtype == dns.rdatatype.CNAME:
            for item in rrset.items:
                cname_chain.append(normalize_domain(item.target.to_text()))
        elif rrset.rdtype == dns.rdatatype.A:
            for item in rrset.items:
                answers.add(item.address)
    return sorted(answers), cname_chain


async def doh_query_wire(
    client: httpx.AsyncClient,
    endpoint: str,
    name: str,
) -> dns.message.Message:
    query = dns.message.make_query(name, dns.rdatatype.A)
    response = await client.post(
        endpoint,
        content=query.to_wire(),
        headers={
            "accept": "application/dns-message",
            "content-type": "application/dns-message",
        },
        timeout=REQUEST_TIMEOUT,
    )
    response.raise_for_status()
    return dns.message.from_wire(response.content)


async def resolve_a_via_doh(
    client: httpx.AsyncClient,
    endpoint: str,
    domain: str,
    depth: int = 0,
) -> ResolverResult:
    try:
        message = await doh_query_wire(client, endpoint, domain)
    except asyncio.CancelledError:
        raise
    except Exception:
        return ResolverResult(
            status="request_error",
            answers=[],
            resolver=endpoint,
            cname_chain=[],
            rcode="REQUEST_ERROR",
        )

    rcode_text = dns.rcode.to_text(message.rcode())
    if message.rcode() != dns.rcode.NOERROR:
        return ResolverResult(
            status=rcode_text.lower(),
            answers=[],
            resolver=endpoint,
            cname_chain=[],
            rcode=rcode_text,
        )

    answers, cname_chain = extract_a_and_cname(message)
    if answers:
        return ResolverResult(
            status="ok",
            answers=answers,
            resolver=endpoint,
            cname_chain=cname_chain,
            rcode=rcode_text,
        )

    if cname_chain and depth < DNS_FOLLOW_CNAME_DEPTH:
        target = cname_chain[-1]
        followed = await resolve_a_via_doh(client, endpoint, target, depth + 1)
        return ResolverResult(
            status=followed.status,
            answers=followed.answers,
            resolver=endpoint,
            cname_chain=cname_chain + followed.cname_chain,
            rcode=followed.rcode,
        )

    return ResolverResult(
        status="no_a",
        answers=[],
        resolver=endpoint,
        cname_chain=cname_chain,
        rcode=rcode_text,
    )


async def race_resolver_group(
    client: httpx.AsyncClient,
    domain: str,
    resolvers: list[str],
) -> ResolverResult:
    ordered = resolver_rotation(resolvers, domain)
    tasks = [asyncio.create_task(resolve_a_via_doh(client, endpoint, domain)) for endpoint in ordered]
    failures: list[ResolverResult] = []

    try:
        for future in asyncio.as_completed(tasks):
            result = await future
            if result.status == "ok" and result.answers:
                for task in tasks:
                    if not task.done():
                        task.cancel()
                await asyncio.gather(*tasks, return_exceptions=True)
                return result
            failures.append(result)
    finally:
        for task in tasks:
            if not task.done():
                task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)

    if failures:
        return failures[0]

    return ResolverResult(
        status="request_error",
        answers=[],
        resolver="",
        cname_chain=[],
        rcode="REQUEST_ERROR",
    )


async def resolve_domain(
    client: httpx.AsyncClient,
    domain: str,
) -> CacheEntry:
    cn_task = asyncio.create_task(race_resolver_group(client, domain, CN_DOH_RESOLVERS))
    global_task = asyncio.create_task(race_resolver_group(client, domain, GLOBAL_DOH_RESOLVERS))
    cn_result, global_result = await asyncio.gather(cn_task, global_task)

    verdict = (
        "match"
        if cn_result.status == "ok"
        and global_result.status == "ok"
        and cn_result.answers == global_result.answers
        else "drop"
    )

    return CacheEntry(
        domain=domain,
        cn=cn_result.to_dict(),
        global_=global_result.to_dict(),
        verdict=verdict,
        checked_at=utc_now_iso(),
    )


async def refresh_dns_cache(domains: list[str], cache: dict[str, CacheEntry]) -> dict[str, CacheEntry]:
    domains_to_query = [domain for domain in domains if domain not in cache or not cache_is_fresh(cache[domain])]
    if not domains_to_query:
        return cache

    limits = httpx.Limits(max_keepalive_connections=64, max_connections=256)
    semaphore = asyncio.Semaphore(MAX_DOMAIN_CONCURRENCY)
    updated_count = 0

    async with httpx.AsyncClient(http2=True, limits=limits, follow_redirects=True) as client:
        async def worker(domain: str) -> tuple[str, CacheEntry]:
            async with semaphore:
                entry = await resolve_domain(client, domain)
                return domain, entry

        tasks = [asyncio.create_task(worker(domain)) for domain in domains_to_query]
        for future in asyncio.as_completed(tasks):
            domain, entry = await future
            cache[domain] = entry
            updated_count += 1
            if updated_count % DNS_WRITE_EVERY == 0:
                save_dns_cache(cache)

    save_dns_cache(cache)
    return cache


def build_dns_tidy(cache: dict[str, CacheEntry], domains: list[str]) -> list[str]:
    tidy: list[str] = []
    for domain in domains:
        entry = cache.get(domain)
        if not entry:
            continue
        if entry.verdict == "match":
            tidy.append(domain)
    return sorted(set(tidy))


def sort_rule_lines(lines: set[str]) -> list[str]:
    def sort_key(line: str) -> tuple[int, str, str]:
        parts = [item.strip() for item in line.split(",")]
        keyword = parts[0].upper() if parts else ""
        payload = parts[1].lower() if len(parts) > 1 else ""
        return (RULE_TYPE_ORDER.get(keyword, 999), payload, line.lower())

    return sorted(lines, key=sort_key)


def main() -> int:
    ensure_dirs()

    source_urls = load_source_urls()
    merged_lines = fetch_source_lines(source_urls)
    write_lines(COLLECTION_PATH, merged_lines)

    deduped_collection = stable_unique(merged_lines)
    write_lines(COLLECTION_PATH, deduped_collection)

    parsed = classify_collection(deduped_collection)
    query_domains = sorted(parsed.query_rule_lines_by_domain)

    cache = load_dns_cache()
    cache = asyncio.run(refresh_dns_cache(query_domains, cache))

    dns_tidy_domains = build_dns_tidy(cache, query_domains)
    write_lines(DNS_TIDY_PATH, dns_tidy_domains)

    tidy_lines = sort_rule_lines(parsed.passthrough_rules) + dns_tidy_domains
    tidy_lines = stable_unique(tidy_lines)
    write_lines(TIDY_PATH, tidy_lines)

    final_rules: set[str] = set(parsed.passthrough_rules)
    for domain in dns_tidy_domains:
        final_rules.update(parsed.query_rule_lines_by_domain.get(domain, set()))

    final_sorted = sort_rule_lines(final_rules)
    write_lines(OUTPUT_PATH, final_sorted)

    save_dns_cache(cache)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
