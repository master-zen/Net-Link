#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import ipaddress
import re
import ssl
import sys
import time
from pathlib import Path
from typing import Iterable
from urllib.request import Request, urlopen

SOURCES = [
    "https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/BanAD.list",
    "https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/BanProgramAD.list",
    "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/refs/heads/master/rule/Surge/AdGuardSDNSFilter/AdGuardSDNSFilter_All.list",
    "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/refs/heads/master/rule/Surge/Advertising/Advertising.list",
    "https://raw.githubusercontent.com/privacy-protection-tools/anti-AD/refs/heads/master/anti-ad-surge.txt",
    "https://raw.githubusercontent.com/limbopro/Adblock4limbo/refs/heads/main/rule/Surge/Adblock4limbo_surge.list",
    "https://raw.githubusercontent.com/limbopro/Adblock4limbo/refs/heads/main/Surge/rule/Peter_Lowe_adservers_surge.list",
    "https://raw.githubusercontent.com/limbopro/Adblock4limbo/refs/heads/main/rule/Surge/BanAD_surge.list",
    "https://raw.githubusercontent.com/Loyalsoldier/surge-rules/release/ruleset/reject.txt",
    "https://raw.githubusercontent.com/fmz200/wool_scripts/main/Loon/rule/rejectAd.list",
    "https://ruleset.skk.moe/List/non_ip/reject.conf",
    "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/refs/heads/master/rule/Surge/Privacy/Privacy_All.list",
    "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/refs/heads/master/rule/Surge/EasyPrivacy/EasyPrivacy_All.list",
    "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/refs/heads/master/rule/Surge/Hijacking/Hijacking_Resolve.list",
]

OUTPUT = Path("Surge/Rules/Ad_Block.list")

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

DOMAIN_RE = re.compile(r"^(?:\*\.)?(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,63}$")


def fetch_text(url: str, timeout: int = 30, retries: int = 3) -> str:
    last_error = None
    for attempt in range(1, retries + 1):
        try:
            req = Request(
                url,
                headers={
                    "User-Agent": "Mozilla/5.0 (GitHub Actions ad block merger)",
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


def is_comment_or_empty(line: str) -> bool:
    s = line.strip().lstrip("\ufeff")
    return not s or s.startswith("#") or s.startswith(";") or s.startswith("//")


def cleanup_prefix(line: str) -> str:
    line = line.strip().lstrip("\ufeff")
    if line.startswith("- "):
        line = line[2:].strip()
    return line


def strip_trailing_commas(line: str) -> str:
    line = line.strip()
    while line.endswith(","):
        line = line[:-1].rstrip()
    return line

def normalize_ip_or_network_value(value: str) -> tuple[str, str] | None:
    value = value.strip().strip("[]")
    if not value:
        return None

    try:
        network = ipaddress.ip_network(value, strict=False)
        if isinstance(network, ipaddress.IPv6Network):
            return ("IP-CIDR6", network.compressed)
        return ("IP-CIDR", network.compressed)
    except ValueError:
        return None


def normalize_existing_rule(line: str) -> str | None:
    if "," not in line:
        return None

    parts = [p.strip() for p in line.split(",")]
    if not parts:
        return None

    head = parts[0].upper()
    if head not in RULE_TYPES:
        return None

    if len(parts) < 2 or not parts[1]:
        return None

    value = strip_trailing_commas(parts[1].strip())

    if head in {"DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD"}:
        raw_value = value.lstrip(".") if head == "DOMAIN-SUFFIX" else value
        ip_norm = normalize_ip_or_network_value(raw_value)
        if ip_norm:
            new_head, new_value = ip_norm
            return f"{new_head},{new_value}"

        normalized_value = raw_value.lower() if head == "DOMAIN-SUFFIX" else value.lower()
        return f"{head},{normalized_value}"

    if head in {"IP-CIDR", "IP-CIDR6"}:
        ip_norm = normalize_ip_or_network_value(value)
        if not ip_norm:
            return None
        new_head, new_value = ip_norm

        extras = [p.strip().lower() for p in parts[2:] if p.strip()]
        result = ",".join([new_head, new_value, *extras]).strip()
        while result.endswith(","):
            result = result[:-1].rstrip()
        return result

    extras = [p.strip() for p in parts[2:] if p.strip()]
    result = ",".join([head, value, *extras]).strip()
    while result.endswith(","):
        result = result[:-1].rstrip()

    return result or None


def convert_plain_entry(line: str) -> str | None:
    raw = strip_trailing_commas(line.strip())
    if not raw:
        return None

    try:
        network = ipaddress.ip_network(raw, strict=False)
        if isinstance(network, ipaddress.IPv6Network):
            return f"IP-CIDR6,{network.compressed}"
        return f"IP-CIDR,{network.compressed}"
    except ValueError:
        pass

    try:
        ip = ipaddress.ip_address(raw)
        if isinstance(ip, ipaddress.IPv6Address):
            return f"IP-CIDR6,{ip.compressed}/128"
        return f"IP-CIDR,{ip.compressed}/32"
    except ValueError:
        pass

    if raw.startswith("."):
        host = raw[1:].strip().lower()
        if host and DOMAIN_RE.match(host):
            return f"DOMAIN-SUFFIX,{host}"
        return None

    host = raw.lower()
    if DOMAIN_RE.match(host):
        return f"DOMAIN,{host}"

    return None


def normalize_line(line: str) -> str | None:
    line = cleanup_prefix(line)

    if is_comment_or_empty(line):
        return None

    normalized = normalize_existing_rule(line)
    if normalized:
        return normalized

    return convert_plain_entry(line)


def unique_sorted(items: Iterable[str]) -> list[str]:
    return sorted(set(items), key=lambda s: s.casefold())


def main() -> int:
    ensure_parent_dirs()

    all_rules: list[str] = []

    for src in SOURCES:
        try:
            text = fetch_text(src)
            for raw_line in text.splitlines():
                norm = normalize_line(raw_line)
                if norm:
                    all_rules.append(norm)
        except Exception as exc:
            print(f"[WARN] {src} -> {exc}", file=sys.stderr)

    rules = unique_sorted(all_rules)

    if not rules:
        print("No valid ad block rules generated.", file=sys.stderr)
        return 1

    OUTPUT.write_text("\n".join(rules) + "\n", encoding="utf-8")
    print(f"{OUTPUT}: {len(rules)} lines")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
