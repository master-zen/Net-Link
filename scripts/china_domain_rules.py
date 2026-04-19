#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import json
import os
import re
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path

import dns.exception
import dns.message
import dns.query
import dns.rdatatype

ROOT = Path(__file__).resolve().parent.parent
SOURCE_FILE = ROOT / "data" / "sources" / "ChinaDomain.txt"
TEMP_DIR = ROOT / "data" / "temporary"
OUTPUT_FILE = ROOT / "Surge" / "Rules" / "China.list"

COLLECTION_FILE = TEMP_DIR / "ChinaDomainCollection.txt"
TIDY_FILE = TEMP_DIR / "ChinaDomainTidy.txt"
DNS_CACHE_FILE = TEMP_DIR / "ChinaDomainDNSresults.txt"
DNS_TIDY_FILE = TEMP_DIR / "ChinaDomainDNSTidy.txt"

FORCE_DNS_REFRESH = os.getenv("FORCE_DNS_REFRESH", "0") == "1"
MAX_CONCURRENCY = max(4, min(32, int(os.getenv("CHINA_DOMAIN_MAX_CONCURRENCY", "24"))))
REQUEST_TIMEOUT = max(1.0, min(8.0, float(os.getenv("CHINA_DOMAIN_REQUEST_TIMEOUT", "3.5"))))
SUCCESS_CACHE_HOURS = max(24, int(os.getenv("CHINA_DOMAIN_SUCCESS_CACHE_HOURS", "720")))
FAILURE_CACHE_HOURS = max(12, int(os.getenv("CHINA_DOMAIN_FAILURE_CACHE_HOURS", "72")))

# 只把明显高风险的海外基础设施域交给 DNS 复核。
SUSPICIOUS_TOKENS = {
    "akamaized.net", "akamaiedge.net", "edgekey.net", "edgesuite.net",
    "fastly.net", "fastlylb.net", "cloudfront.net", "amazonaws.com",
    "trafficmanager.net", "azureedge.net", "azurefd.net", "github.io",
    "githubusercontent.com", "workers.dev", "pages.dev", "vercel.app",
    "netlify.app", "cdn77.org", "b-cdn.net", "cachefly.net", "linodeobjects.com",
    "digitaloceanspaces.com", "wasabisys.com", "herokuapp.com", "firebaseapp.com",
    "appspot.com", "onrender.com", "fly.dev", "cloudflare.net", "cloudflare.com",
    "cf-ipfs.com", "ipfs.io",
}
SUSPICIOUS_PREFIXES = ("cdn.", "img.", "static.", "assets.", "media.", "edge.", "cache.")
SAMPLE_PREFIXES = ("", "www", "m", "api", "img", "cdn", "static", "passport")

CHINA_DOH = [
    "https://doh.pub/dns-query",
    "https://dns.alidns.com/dns-query",
    "https://sm2.doh.pub/dns-query",
]

GLOBAL_DOH = [
    "https://1.1.1.1/dns-query",
    "https://1.0.0.1/dns-query",
    "https://dns.google/dns-query",
    "https://dns.quad9.net/dns-query",
]

COMMENT_PREFIXES = ("#", ";", "//")
NO_RESOLVE_RE = re.compile(r"(?i),\s*no-resolve\b")
DOMAIN_RE = re.compile(r"^(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$", re.I)


@dataclass(frozen=True)
class Rule:
    kind: str
    value: str

    def render(self) -> str:
        return f"{self.kind},{self.value}"


def ensure_dirs() -> None:
    TEMP_DIR.mkdir(parents=True, exist_ok=True)
    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)


def clean_line(line: str) -> str:
    s = line.strip().lstrip("\ufeff")
    if not s or any(s.startswith(p) for p in COMMENT_PREFIXES):
        return ""
    s = NO_RESOLVE_RE.sub("", s).strip()
    while s.endswith(","):
        s = s[:-1].rstrip()
    return s


def normalize_rule(line: str) -> Rule | None:
    s = clean_line(line)
    if not s:
        return None

    parts = [p.strip() for p in s.split(",") if p.strip()]
    if not parts:
        return None

    if len(parts) >= 2:
        kind = parts[0].upper()
        value = parts[1]
        if kind in {"DOMAIN", "DOMAIN-SUFFIX", "IP-CIDR", "IP-CIDR6", "IP-ASN"}:
            return Rule(kind, value)
        if kind == "HOST":
            return Rule("DOMAIN", value)

    if DOMAIN_RE.match(s):
        return Rule("DOMAIN-SUFFIX", s.lower())

    return None


def load_rules() -> list[Rule]:
    raw_lines = SOURCE_FILE.read_text(encoding="utf-8", errors="replace").splitlines()
    rules: list[Rule] = []
    for line in raw_lines:
        rule = normalize_rule(line)
        if rule:
            rules.append(rule)
    return rules


def write_lines(path: Path, lines) -> None:
    text = "\n".join(lines)
    if text:
        text += "\n"
    path.write_text(text, encoding="utf-8")


def is_suspicious_domain(value: str) -> bool:
    v = value.lower().lstrip(".")
    if any(v == token or v.endswith("." + token) for token in SUSPICIOUS_TOKENS):
        return True
    if v.startswith(SUSPICIOUS_PREFIXES):
        return True
    return False


def sample_hosts_for_suffix(suffix: str) -> list[str]:
    suffix = suffix.lower().lstrip(".")
    hosts = []
    for prefix in SAMPLE_PREFIXES:
        if prefix:
            hosts.append(f"{prefix}.{suffix}")
        else:
            hosts.append(suffix)
    seen = set()
    out = []
    for host in hosts:
        if host not in seen:
            seen.add(host)
            out.append(host)
    return out


def rule_to_probe_hosts(rule: Rule) -> list[str]:
    if rule.kind == "DOMAIN":
        return [rule.value.lower().lstrip(".")]
    if rule.kind == "DOMAIN-SUFFIX":
        return sample_hosts_for_suffix(rule.value)
    return []


def should_probe(rule: Rule) -> bool:
    return rule.kind in {"DOMAIN", "DOMAIN-SUFFIX"} and is_suspicious_domain(rule.value)


def load_cache() -> dict:
    if not DNS_CACHE_FILE.exists():
        return {}
    cache = {}
    for line in DNS_CACHE_FILE.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            item = json.loads(line)
            if isinstance(item, dict) and "host" in item:
                cache[item["host"]] = item
        except Exception:
            continue
    return cache


def save_cache(cache: dict) -> None:
    lines = [json.dumps(cache[host], ensure_ascii=False, sort_keys=True) for host in sorted(cache)]
    write_lines(DNS_CACHE_FILE, lines)


def cache_valid(item: dict) -> bool:
    if FORCE_DNS_REFRESH:
        return False
    ts = float(item.get("timestamp", 0))
    status = item.get("status", "error")
    age_hours = (time.time() - ts) / 3600.0
    ttl = SUCCESS_CACHE_HOURS if status == "ok" else FAILURE_CACHE_HOURS
    return age_hours <= ttl


def doh_query(url: str, host: str, timeout: float) -> dict:
    queries = [
        dns.message.make_query(host, dns.rdatatype.A),
        dns.message.make_query(host, dns.rdatatype.AAAA),
    ]
    ips = set()
    cnames = set()

    for query in queries:
        response = dns.query.https(query, url, timeout=timeout)
        for rrset in response.answer:
            if rrset.rdtype == dns.rdatatype.CNAME:
                for item in rrset:
                    cnames.add(str(item.target).rstrip(".").lower())
            elif rrset.rdtype in (dns.rdatatype.A, dns.rdatatype.AAAA):
                for item in rrset:
                    ips.add(item.address)

    return {"ips": sorted(ips), "cnames": sorted(cnames)}


def resolve_group(urls: list[str], host: str, timeout: float) -> dict:
    errors = []
    for url in urls:
        try:
            result = doh_query(url, host, timeout)
            if result["ips"] or result["cnames"]:
                return {"status": "ok", "resolver": url, **result}
            errors.append(f"{url}: empty")
        except dns.exception.DNSException as exc:
            errors.append(f"{url}: {type(exc).__name__}: {exc}")
        except Exception as exc:
            errors.append(f"{url}: {type(exc).__name__}: {exc}")
    return {"status": "error", "resolver": "", "ips": [], "cnames": [], "errors": errors[:5]}


def probe_host(host: str, cache: dict) -> dict:
    cached = cache.get(host)
    if cached and cache_valid(cached):
        return cached

    started = time.time()
    with ThreadPoolExecutor(max_workers=2) as executor:
        future_cn = executor.submit(resolve_group, CHINA_DOH, host, REQUEST_TIMEOUT)
        future_global = executor.submit(resolve_group, GLOBAL_DOH, host, REQUEST_TIMEOUT)
        cn = future_cn.result()
        global_ = future_global.result()

    status = "keep"
    reason = "default_keep"

    if cn["status"] == "ok" and global_["status"] == "ok":
        if cn["ips"] != global_["ips"] or cn["cnames"] != global_["cnames"]:
            status = "drop"
            reason = "cn_global_diverged"
        elif cn["ips"] or cn["cnames"]:
            status = "keep"
            reason = "same_answer_keep"
        else:
            status = "keep"
            reason = "both_empty_keep"
    elif cn["status"] == "ok" and global_["status"] != "ok":
        status = "keep"
        reason = "cn_only_keep"
    elif cn["status"] != "ok" and global_["status"] == "ok":
        status = "keep"
        reason = "global_only_keep"
    else:
        status = "keep"
        reason = "both_failed_keep"

    item = {
        "host": host,
        "status": status,
        "reason": reason,
        "timestamp": time.time(),
        "elapsed_seconds": round(time.time() - started, 3),
        "cn": cn,
        "global": global_,
    }
    cache[host] = item
    return item


def main() -> int:
    ensure_dirs()
    rules = load_rules()

    collection = sorted({rule.render() for rule in rules})
    write_lines(COLLECTION_FILE, collection)

    ip_and_asn_rules = sorted(
        {rule.render() for rule in rules if rule.kind in {"IP-CIDR", "IP-CIDR6", "IP-ASN"}}
    )
    domain_rules = [rule for rule in rules if rule.kind in {"DOMAIN", "DOMAIN-SUFFIX"}]

    non_suspicious_rules = {rule.render() for rule in domain_rules if not should_probe(rule)}
    suspicious_rules = [rule for rule in domain_rules if should_probe(rule)]

    tidy_lines = sorted(non_suspicious_rules | {rule.render() for rule in suspicious_rules} | set(ip_and_asn_rules))
    write_lines(TIDY_FILE, tidy_lines)

    cache = load_cache()

    host_to_rules: dict[str, set[str]] = {}
    for rule in suspicious_rules:
        for host in rule_to_probe_hosts(rule):
            host_to_rules.setdefault(host, set()).add(rule.render())

    hosts = sorted(host_to_rules)
    print(f"[china-domain] total rules: {len(rules)}", flush=True)
    print(f"[china-domain] suspicious rules: {len(suspicious_rules)}", flush=True)
    print(f"[china-domain] probe hosts: {len(hosts)}", flush=True)
    print(f"[china-domain] max concurrency: {MAX_CONCURRENCY}", flush=True)

    dns_results = []
    if hosts:
        with ThreadPoolExecutor(max_workers=MAX_CONCURRENCY) as executor:
            futures = {executor.submit(probe_host, host, cache): host for host in hosts}
            total = len(futures)
            done = 0
            for future in as_completed(futures):
                done += 1
                dns_results.append(future.result())
                if done % 100 == 0 or done == total:
                    print(f"[china-domain] processed {done}/{total}", flush=True)

    save_cache(cache)

    drop_rules = set()
    dns_tidy_lines = []
    for result in sorted(dns_results, key=lambda item: item["host"]):
        host = result["host"]
        related_rules = sorted(host_to_rules.get(host, set()))
        dns_tidy_lines.append(
            json.dumps(
                {
                    "host": host,
                    "status": result["status"],
                    "reason": result["reason"],
                    "rules": related_rules,
                    "cn": result["cn"],
                    "global": result["global"],
                },
                ensure_ascii=False,
                sort_keys=True,
            )
        )
        if result["status"] == "drop":
            drop_rules.update(related_rules)

    write_lines(DNS_TIDY_FILE, dns_tidy_lines)

    final_rules = sorted(
        non_suspicious_rules
        | {rule.render() for rule in suspicious_rules if rule.render() not in drop_rules}
        | set(ip_and_asn_rules)
    )
    write_lines(OUTPUT_FILE, final_rules)

    print(f"[china-domain] drop rules: {len(drop_rules)}", flush=True)
    print(f"[china-domain] final rules: {len(final_rules)}", flush=True)
    print(f"[china-domain] wrote: {OUTPUT_FILE}", flush=True)
    print(f"[china-domain] wrote: {COLLECTION_FILE}", flush=True)
    print(f"[china-domain] wrote: {TIDY_FILE}", flush=True)
    print(f"[china-domain] wrote: {DNS_CACHE_FILE}", flush=True)
    print(f"[china-domain] wrote: {DNS_TIDY_FILE}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
