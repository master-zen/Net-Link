from pathlib import Path

content = r'''#!/usr/bin/env python3
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
import dns.flags
import dns.message
import dns.query
import dns.rdatatype
import httpx

ROOT = Path(__file__).resolve().parent.parent

# 这里放的是“规则源 URL 池”，不是规则本体
SOURCE_POOL_FILE = ROOT / "data" / "sources" / "ChinaDomain.txt"

TEMP_DIR = ROOT / "data" / "temporary"
OUTPUT_FILE = ROOT / "Surge" / "Rules" / "China.list"

COLLECTION_FILE = TEMP_DIR / "ChinaDomainCollection.txt"
TIDY_FILE = TEMP_DIR / "ChinaDomainTidy.txt"
DNS_CACHE_FILE = TEMP_DIR / "ChinaDomainDNSresults.txt"
DNS_TIDY_FILE = TEMP_DIR / "ChinaDomainDNSTidy.txt"
FETCH_REPORT_FILE = TEMP_DIR / "ChinaDomainFetchReport.json"

FORCE_DNS_REFRESH = os.getenv("FORCE_DNS_REFRESH", "0") == "1"
MAX_CONCURRENCY = max(4, min(32, int(os.getenv("CHINA_DOMAIN_MAX_CONCURRENCY", "24"))))
REQUEST_TIMEOUT = max(1.0, min(8.0, float(os.getenv("CHINA_DOMAIN_REQUEST_TIMEOUT", "3.5"))))
SOURCE_FETCH_TIMEOUT = max(5.0, min(30.0, float(os.getenv("CHINA_SOURCE_FETCH_TIMEOUT", "15"))))
SUCCESS_CACHE_HOURS = max(24, int(os.getenv("CHINA_DOMAIN_SUCCESS_CACHE_HOURS", "720")))
FAILURE_CACHE_HOURS = max(12, int(os.getenv("CHINA_DOMAIN_FAILURE_CACHE_HOURS", "72")))
FOLLOW_CNAME_DEPTH = max(0, min(6, int(os.getenv("CHINA_DOMAIN_CNAME_DEPTH", "2"))))

# 直接保留，不进入 DNS 复核
DIRECT_KEEP_SUFFIXES = (
    ".cn",
    ".com.cn",
)

# 原生 DNS over TCP 解析器
CN_DNS_SERVERS = [
    "119.29.29.29",
    "119.28.28.28",
    "223.5.5.5",
    "223.6.6.6",
    "114.114.114.114",
    "114.114.115.115",
    "180.76.76.76",
    "1.2.4.8",
    "210.2.4.8",
]

GLOBAL_DNS_SERVERS = [
    "1.1.1.1",
    "1.0.0.1",
    "8.8.8.8",
    "8.8.4.4",
    "9.9.9.9",
    "149.112.112.112",
    "208.67.222.222",
    "208.67.220.220",
    "64.6.64.6",
    "64.6.65.6",
]

SAMPLE_PREFIXES = ("", "www", "m", "api", "img", "cdn", "static", "passport")

COMMENT_PREFIXES = ("#", ";", "//")
NO_RESOLVE_RE = re.compile(r"(?i),\s*no-resolve\b")
DOMAIN_RE = re.compile(r"^(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$", re.I)
URL_RE = re.compile(r"^https?://", re.I)


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


def load_source_urls() -> list[str]:
    urls: list[str] = []
    seen = set()
    for line in SOURCE_POOL_FILE.read_text(encoding="utf-8", errors="replace").splitlines():
        s = clean_line(line)
        if not s or not URL_RE.match(s):
            continue
        if s not in seen:
            seen.add(s)
            urls.append(s)
    return urls


def fetch_text(client: httpx.Client, url: str) -> str:
    resp = client.get(url, follow_redirects=True, timeout=SOURCE_FETCH_TIMEOUT)
    resp.raise_for_status()
    return resp.text


def fetch_all_sources(urls: list[str]) -> tuple[list[str], list[dict]]:
    fetched_texts: list[str] = []
    report: list[dict] = []

    if not urls:
        return fetched_texts, report

    with httpx.Client(
        http2=True,
        headers={
            "User-Agent": "Net-Link ChinaDomain builder",
            "Accept": "text/plain, */*",
        },
    ) as client:
        for idx, url in enumerate(urls, start=1):
            started = time.time()
            print(f"[fetch] {idx}/{len(urls)} {url}", flush=True)
            try:
                text = fetch_text(client, url)
                fetched_texts.append(text)
                report.append(
                    {
                        "url": url,
                        "ok": True,
                        "elapsed_seconds": round(time.time() - started, 3),
                        "line_count": len(text.splitlines()),
                    }
                )
            except Exception as exc:
                report.append(
                    {
                        "url": url,
                        "ok": False,
                        "elapsed_seconds": round(time.time() - started, 3),
                        "error": f"{type(exc).__name__}: {exc}",
                    }
                )
                print(f"[fetch] failed: {url} -> {type(exc).__name__}: {exc}", flush=True)

    return fetched_texts, report


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


def parse_rules_from_texts(texts: list[str]) -> list[Rule]:
    rules: list[Rule] = []
    for text in texts:
        for line in text.splitlines():
            rule = normalize_rule(line)
            if rule:
                rules.append(rule)
    return rules


def write_lines(path: Path, lines) -> None:
    lines = list(lines)
    path.write_text(("\n".join(lines) + "\n") if lines else "", encoding="utf-8")


def write_json(path: Path, obj) -> None:
    path.write_text(json.dumps(obj, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


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


def should_direct_keep(rule: Rule) -> bool:
    if rule.kind not in {"DOMAIN", "DOMAIN-SUFFIX"}:
        return False
    value = "." + rule.value.lower().lstrip(".")
    return any(value.endswith(sfx) for sfx in DIRECT_KEEP_SUFFIXES)


def tcp_query_once(server: str, host: str, rdtype: int) -> dict:
    message = dns.message.make_query(host, rdtype)
    message.flags |= dns.flags.RD
    response = dns.query.tcp(message, server, timeout=REQUEST_TIMEOUT)

    ips = set()
    cnames = set()

    for rrset in response.answer:
        if rrset.rdtype == dns.rdatatype.CNAME:
            for item in rrset:
                cnames.add(str(item.target).rstrip(".").lower())
        elif rrset.rdtype in (dns.rdatatype.A, dns.rdatatype.AAAA):
            for item in rrset:
                ips.add(item.address)

    return {"ips": sorted(ips), "cnames": sorted(cnames)}


def tcp_query_host(server: str, host: str) -> dict:
    pending = [host]
    seen = set()
    all_ips = set()
    all_cnames = set()
    errors = []

    depth = 0
    while pending and depth <= FOLLOW_CNAME_DEPTH:
        current = pending.pop(0)
        if current in seen:
            continue
        seen.add(current)

        try:
            a_result = tcp_query_once(server, current, dns.rdatatype.A)
            aaaa_result = tcp_query_once(server, current, dns.rdatatype.AAAA)
        except dns.exception.DNSException as exc:
            errors.append(f"{type(exc).__name__}: {exc}")
            break
        except Exception as exc:
            errors.append(f"{type(exc).__name__}: {exc}")
            break

        all_ips.update(a_result["ips"])
        all_ips.update(aaaa_result["ips"])

        new_cnames = set(a_result["cnames"]) | set(aaaa_result["cnames"])
        for cname in new_cnames:
            all_cnames.add(cname)
            if cname not in seen:
                pending.append(cname)

        if all_ips:
            return {
                "status": "ok",
                "resolver": server,
                "ips": sorted(all_ips),
                "cnames": sorted(all_cnames),
            }

        depth += 1

    return {
        "status": "error",
        "resolver": "",
        "ips": [],
        "cnames": sorted(all_cnames),
        "errors": errors[:5],
    }


def resolve_group(servers: list[str], host: str) -> dict:
    errors = []
    for server in servers:
        result = tcp_query_host(server, host)
        if result["status"] == "ok":
            return result
        errors.extend(result.get("errors", []))
    return {"status": "error", "resolver": "", "ips": [], "cnames": [], "errors": errors[:5]}


def probe_host(host: str, cache: dict) -> dict:
    cached = cache.get(host)
    if cached and cache_valid(cached):
        return cached

    started = time.time()
    with ThreadPoolExecutor(max_workers=2) as executor:
        future_cn = executor.submit(resolve_group, CN_DNS_SERVERS, host)
        future_global = executor.submit(resolve_group, GLOBAL_DNS_SERVERS, host)
        cn = future_cn.result()
        global_ = future_global.result()

    # 原则：
    # 1. 默认保留
    # 2. 只有中外两组都成功且答案明确分裂，才剔除
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

    source_urls = load_source_urls()
    print(f"[china-domain] source urls: {len(source_urls)}", flush=True)

    texts, fetch_report = fetch_all_sources(source_urls)
    write_json(FETCH_REPORT_FILE, fetch_report)

    rules = parse_rules_from_texts(texts)

    collection = sorted({rule.render() for rule in rules})
    write_lines(COLLECTION_FILE, collection)

    ip_and_asn_rules = sorted(
        {rule.render() for rule in rules if rule.kind in {"IP-CIDR", "IP-CIDR6", "IP-ASN"}}
    )
    domain_rules = [rule for rule in rules if rule.kind in {"DOMAIN", "DOMAIN-SUFFIX"}]

    direct_keep_rules = {rule.render() for rule in domain_rules if should_direct_keep(rule)}
    probe_rules = [rule for rule in domain_rules if rule.render() not in direct_keep_rules]

    tidy_lines = sorted(direct_keep_rules | {rule.render() for rule in probe_rules} | set(ip_and_asn_rules))
    write_lines(TIDY_FILE, tidy_lines)

    cache = load_cache()

    host_to_rules: dict[str, set[str]] = {}
    for rule in probe_rules:
        for host in rule_to_probe_hosts(rule):
            host_to_rules.setdefault(host, set()).add(rule.render())

    hosts = sorted(host_to_rules)
    print(f"[china-domain] parsed rules: {len(rules)}", flush=True)
    print(f"[china-domain] domain rules: {len(domain_rules)}", flush=True)
    print(f"[china-domain] direct keep rules: {len(direct_keep_rules)}", flush=True)
    print(f"[china-domain] ip/asn rules: {len(ip_and_asn_rules)}", flush=True)
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
        direct_keep_rules
        | {rule.render() for rule in probe_rules if rule.render() not in drop_rules}
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
    print(f"[china-domain] wrote: {FETCH_REPORT_FILE}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
'''
path = Path('/mnt/data/china_domain_rules_tcp_keep.py')
path.write_text(content, encoding='utf-8')
print(path)
