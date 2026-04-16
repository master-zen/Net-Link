#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import ipaddress
import json
import re
import signal
import ssl
import socket
import sys
import time
from functools import lru_cache
from pathlib import Path
from urllib.request import Request, urlopen

from lib_rules import BUILD_DIR, normalize_rule_line

DOMAIN_SOURCES = [
    "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/refs/heads/master/rule/Surge/China/China_Domain.list",
]

IP_SOURCES = [
    "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/refs/heads/master/rule/Surge/ChinaIPs/ChinaIPs_Resolve.list",
    "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/refs/heads/master/rule/Surge/ChinaASN/ChinaASN_Resolve.list",
    "https://raw.githubusercontent.com/Loyalsoldier/surge-rules/release/ruleset/cncidr.txt",
    "https://raw.githubusercontent.com/Hackl0us/GeoIP2-CN/release/CN-ip-cidr.txt",
]

OUTPUT = Path("Surge/Rules/China.list")
VALIDATION_REPORT = BUILD_DIR / "china_validation.json"
COMMENT_PREFIXES = ("#", ";", "//")

DOMAIN_RULE_TYPES = {"DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD"}
IP_RULE_TYPES = {"IP-CIDR", "IP-CIDR6", "IP-ASN"}
NO_RESOLVE_RE = re.compile(r"(?i),\s*no-resolve\b")
SUSPECT_FOREIGN_DOMAIN_RE = re.compile(
    r"(akamai|akamaized|apple|itunes|mzstatic|microsoft|officecdn|google|gstatic|youtube|ytimg|steam|kaspersky|jetbrains|amazon|cloudfront|level3|strava)",
    re.IGNORECASE,
)


def fetch_text(url: str, timeout: int = 30, retries: int = 3) -> str:
    last_error = None
    for attempt in range(1, retries + 1):
        try:
            req = Request(
                url,
                headers={
                    "User-Agent": "Mozilla/5.0 (GitHub Actions china rules merger)",
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


def ensure_parent_dirs() -> None:
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    VALIDATION_REPORT.parent.mkdir(parents=True, exist_ok=True)


def is_comment_or_empty(line: str) -> bool:
    s = line.strip().lstrip("\ufeff")
    return not s or any(s.startswith(prefix) for prefix in COMMENT_PREFIXES)


def normalize_domain_rule(line: str) -> str | None:
    s = line.strip()
    if is_comment_or_empty(s):
        return None
    s = NO_RESOLVE_RE.sub("", s).strip().rstrip(",")
    if not s:
        return None

    normalized = normalize_rule_line(s, strip_policy=True)
    if not normalized:
        if s.startswith("."):
            normalized = normalize_rule_line(f"DOMAIN-SUFFIX,{s[1:]}", strip_policy=True)
        else:
            normalized = normalize_rule_line(f"DOMAIN,{s}", strip_policy=True)
    if not normalized:
        return None

    head = normalized.split(",", 1)[0].upper()
    if head not in DOMAIN_RULE_TYPES:
        return None
    return normalized


def normalize_ip_rule(line: str) -> str | None:
    s = line.strip()
    if is_comment_or_empty(s):
        return None
    s = NO_RESOLVE_RE.sub("", s).strip().rstrip(",")
    if not s:
        return None

    normalized = normalize_rule_line(s, strip_policy=True)
    if not normalized:
        return None

    head = normalized.split(",", 1)[0].upper()
    if head not in IP_RULE_TYPES:
        return None
    return normalized


def unique_sorted(items: set[str]) -> list[str]:
    return sorted(items, key=lambda s: s.casefold())


def build_cn_networks(trusted_ip_rules: set[str]) -> list[ipaddress._BaseNetwork]:
    networks: list[ipaddress._BaseNetwork] = []
    for rule in trusted_ip_rules:
        parts = [p.strip() for p in rule.split(",") if p.strip()]
        if len(parts) < 2:
            continue
        head, value = parts[0].upper(), parts[1]
        if head not in {"IP-CIDR", "IP-CIDR6"}:
            continue
        try:
            networks.append(ipaddress.ip_network(value, strict=False))
        except ValueError:
            continue
    return networks


def ip_is_in_cn_networks(ip_text: str, cn_networks: list[ipaddress._BaseNetwork]) -> bool:
    try:
        ip_obj = ipaddress.ip_address(ip_text)
    except ValueError:
        return False
    return any(ip_obj.version == network.version and ip_obj in network for network in cn_networks)


@lru_cache(maxsize=8192)
def resolve_domain_ips(host: str) -> tuple[str, ...]:
    def _handle_timeout(signum, frame):
        raise TimeoutError

    previous_handler = signal.getsignal(signal.SIGALRM)
    try:
        signal.signal(signal.SIGALRM, _handle_timeout)
        signal.setitimer(signal.ITIMER_REAL, 3)
        infos = socket.getaddrinfo(host, None)
    except (OSError, TimeoutError):
        return ()
    finally:
        try:
            signal.setitimer(signal.ITIMER_REAL, 0)
        except TimeoutError:
            pass
        signal.signal(signal.SIGALRM, previous_handler)
    return tuple(sorted({item[4][0] for item in infos if item and item[4]}))


def extract_domain_host(rule: str) -> str | None:
    parts = [p.strip() for p in rule.split(",") if p.strip()]
    if len(parts) < 2:
        return None
    head, value = parts[0].upper(), parts[1].lower().lstrip(".")
    if head in {"DOMAIN", "DOMAIN-SUFFIX"}:
        return value
    return None


def filter_mainland_domain_rules(
    trusted_domain_rules: set[str],
    cn_networks: list[ipaddress._BaseNetwork],
) -> tuple[set[str], list[dict], list[str]]:
    kept: set[str] = set()
    rejected: list[dict] = []
    unresolved: list[str] = []

    for rule in trusted_domain_rules:
        host = extract_domain_host(rule)
        if not host:
            kept.add(rule)
            continue

        if not SUSPECT_FOREIGN_DOMAIN_RE.search(host):
            kept.add(rule)
            continue

        resolved_ips = resolve_domain_ips(host)
        if not resolved_ips:
            unresolved.append(rule)
            continue

        if any(ip_is_in_cn_networks(ip, cn_networks) for ip in resolved_ips):
            kept.add(rule)
            continue

        rejected.append({"rule": rule, "resolved_ips": list(resolved_ips)})

    return kept, rejected, unresolved


def fetch_and_normalize(sources: list[str], normalizer) -> tuple[set[str], list[dict], list[dict]]:
    merged: set[str] = set()
    source_status: list[dict] = []
    failures: list[dict] = []

    for src in sources:
        try:
            text = fetch_text(src)
            kept: set[str] = set()
            for raw_line in text.splitlines():
                normalized = normalizer(raw_line)
                if normalized:
                    kept.add(normalized)

            merged.update(kept)
            source_status.append(
                {
                    "source_url": src,
                    "ok": True,
                    "normalized_count": len(kept),
                }
            )
        except Exception as exc:
            failures.append({"source_url": src, "error": str(exc)})
            source_status.append(
                {
                    "source_url": src,
                    "ok": False,
                    "error": str(exc),
                }
            )

    return merged, source_status, failures


def validate_final_rules(
    final_rules: list[str],
    trusted_domain_rules: set[str],
    trusted_ip_rules: set[str],
) -> tuple[list[str], dict]:
    issues: list[str] = []
    domain_count = 0
    ip_count = 0
    asn_count = 0

    for idx, rule in enumerate(final_rules, start=1):
        parts = [p.strip() for p in rule.split(",") if p.strip()]
        if len(parts) < 2:
            issues.append(f"China.list:{idx}: malformed rule: {rule}")
            continue

        head = parts[0].upper()
        if head in DOMAIN_RULE_TYPES:
            domain_count += 1
            if rule not in trusted_domain_rules:
                issues.append(f"China.list:{idx}: domain rule not in trusted mainland domain set: {rule}")
        elif head in {"IP-CIDR", "IP-CIDR6"}:
            ip_count += 1
            if rule not in trusted_ip_rules:
                issues.append(f"China.list:{idx}: IP rule not in trusted mainland IP set: {rule}")
        elif head == "IP-ASN":
            asn_count += 1
            if rule not in trusted_ip_rules:
                issues.append(f"China.list:{idx}: ASN rule not in trusted mainland ASN set: {rule}")
        else:
            issues.append(f"China.list:{idx}: unsupported rule type leaked: {rule}")

    summary = {
        "rule_count": len(final_rules),
        "domain_rule_count": domain_count,
        "ip_rule_count": ip_count,
        "asn_rule_count": asn_count,
    }
    return issues, summary


def main() -> int:
    ensure_parent_dirs()

    trusted_domain_rules, domain_status, domain_failures = fetch_and_normalize(DOMAIN_SOURCES, normalize_domain_rule)
    trusted_ip_rules, ip_status, ip_failures = fetch_and_normalize(IP_SOURCES, normalize_ip_rule)
    cn_networks = build_cn_networks(trusted_ip_rules)
    mainland_domain_rules, rejected_domain_rules, unresolved_domain_rules = filter_mainland_domain_rules(
        trusted_domain_rules,
        cn_networks,
    )

    final_rules = unique_sorted(mainland_domain_rules | trusted_ip_rules)
    if not final_rules:
        print("No valid china rules generated.", file=sys.stderr)
        return 1

    issues, summary = validate_final_rules(final_rules, mainland_domain_rules, trusted_ip_rules)
    report = {
        "ok": not issues,
        "generated_at_unix": int(time.time()),
        "summary": summary,
        "sources": {
            "domain_sources": domain_status,
            "ip_sources": ip_status,
        },
        "domain_resolution_filter": {
            "rejected_count": len(rejected_domain_rules),
            "unresolved_count": len(unresolved_domain_rules),
            "rejected_samples": rejected_domain_rules[:50],
            "unresolved_samples": unresolved_domain_rules[:50],
        },
        "failures": {
            "domain_sources": domain_failures,
            "ip_sources": ip_failures,
        },
        "issues": issues,
    }

    VALIDATION_REPORT.write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )

    if issues:
        print(json.dumps(report, ensure_ascii=False, indent=2), file=sys.stderr)
        return 1

    OUTPUT.write_text("\n".join(final_rules) + "\n", encoding="utf-8")
    print(f"{OUTPUT}: {len(final_rules)} lines")
    print(f"{VALIDATION_REPORT}: ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
