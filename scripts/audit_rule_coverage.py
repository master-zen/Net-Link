#!/usr/bin/env python3
"""Full-file deterministic audit of published Surge rule sets (no sampling)."""
from __future__ import annotations

import collections
import ipaddress
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RULES = ROOT / "Surge/Rules"
REPORT = ROOT / "data/reports/rule_coverage_audit.json"
TYPES = ("DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD", "IP-CIDR", "IP-CIDR6", "IP-ASN", "GEOIP")
PARTITIONS = {
    "China_Domain.list": {"DOMAIN", "DOMAIN-SUFFIX"},
    "China_IPv4.list": {"IP-CIDR"},
    "China_IPv6.list": {"IP-CIDR6"},
    "China_ASN.list": {"IP-ASN"},
    "China_GEOIP.list": {"GEOIP"},
    "China_Keyword.list": {"DOMAIN-KEYWORD"},
}
CRITICAL = (
    "google.com", "github.com", "openai.com", "youtube.com",
    "stripe.com", "dashboard.stripe.com", "microsoft.com",
    "login.microsoftonline.com", "apple.com", "icloud.com",
    "paypal.com", "cloudflare.com", "cloudfront.net", "amazonaws.com",
    "baidu.com", "qq.com", "wechat.com", "taobao.com",
    "jd.com", "bilibili.com", "alipay.com",
)

def load(name):
    path = RULES / name
    if not path.is_file():
        raise RuntimeError(f"Missing ruleset: {path}")
    rows = [x.strip() for x in path.read_text(encoding="utf-8").splitlines()
            if x.strip() and not x.lstrip().startswith(("#", ";"))]
    return rows

def parse(rows):
    result = collections.defaultdict(set)
    invalid = []
    for number, row in enumerate(rows, 1):
        kind, sep, value = row.partition(",")
        if not sep or not value or kind not in TYPES:
            invalid.append({"line": number, "rule": row})
        else:
            result[kind].add(value)
    return result, invalid

def domain_matches(domain, groups):
    exact = groups["DOMAIN"]
    suffixes = groups["DOMAIN-SUFFIX"]
    keywords = groups["DOMAIN-KEYWORD"]
    suffix_hits = [domain[i:] for i in range(len(domain))
                   if (i == 0 or domain[i - 1] == ".") and domain[i:] in suffixes]
    return (["DOMAIN," + domain] if domain in exact else []) + [
        "DOMAIN-SUFFIX," + x for x in suffix_hits
    ] + ["DOMAIN-KEYWORD," + x for x in sorted(keywords) if x in domain]

def cidr_audit(groups):
    out = {}
    for kind in ("IP-CIDR", "IP-CIDR6"):
        networks, invalid, non_public, mapped = [], [], [], []
        for value in sorted(groups[kind]):
            try:
                net = ipaddress.ip_network(value, strict=False)
                if (net.version == 4) != (kind == "IP-CIDR"):
                    raise ValueError("address family mismatch")
                networks.append(net)
                if not net.network_address.is_global or not net.broadcast_address.is_global:
                    non_public.append(value)
                if net.version == 6 and net.network_address.ipv4_mapped is not None:
                    mapped.append(value)
            except ValueError:
                invalid.append(value)
        collapsed = list(ipaddress.collapse_addresses(networks))
        # Collapsing preserves the exact address union; not a geographic validation.
        out[kind] = {
            "rule_count": len(groups[kind]), "collapsed_prefix_count": len(collapsed),
            "redundant_prefix_count": len(networks) - len(collapsed),
            "unique_address_count": str(sum(net.num_addresses for net in collapsed)),
            "non_public_count": len(non_public), "non_public_examples": non_public[:40],
            "ipv4_mapped_count": len(mapped), "ipv4_mapped_examples": mapped[:40],
            "invalid_count": len(invalid), "invalid_examples": invalid[:40],
        }
    return out

def main():
    china_rows, ad_rows = load("ChinaDomain.list"), load("AdblockSet.list")
    china, china_invalid = parse(china_rows)
    ad, ad_invalid = parse(ad_rows)
    combined = set(china_rows)
    partitions = {}
    all_partition_rows = set()
    for filename, types in PARTITIONS.items():
        rows = load(filename)
        wrong_type = [r for r in rows if r.partition(",")[0] not in types]
        not_in_combined = [r for r in rows if r not in combined]
        partitions[filename] = {
            "count": len(rows), "unique_count": len(set(rows)),
            "wrong_type_count": len(wrong_type),
            "not_in_combined_count": len(not_in_combined),
            "wrong_type_examples": wrong_type[:20],
            "not_in_combined_examples": not_in_combined[:20],
        }
        all_partition_rows.update(rows)
    # CIDR subsets intentionally omit non-public prefixes. Other types should be complete.
    missing_non_ip = sorted(r for r in combined - all_partition_rows
                            if not r.startswith(("IP-CIDR,", "IP-CIDR6,")))
    critical = {}
    for domain in CRITICAL:
        critical[domain] = {
            "china_matches": domain_matches(domain, china),
            "ad_matches": domain_matches(domain, ad),
        }
    keyword_risks = {
        keyword: [d for d in CRITICAL if keyword in d]
        for keyword in sorted(china["DOMAIN-KEYWORD"])
    }
    # Every block domain is checked against every relevant China suffix via label lookup.
    ad_china_overlaps = []
    overlap_count = 0
    for kind in ("DOMAIN", "DOMAIN-SUFFIX"):
        for domain in sorted(ad[kind]):
            if domain_matches(domain, china):
                overlap_count += 1
                if len(ad_china_overlaps) < 100:
                    ad_china_overlaps.append({"ad_rule": kind + "," + domain,
                                              "china_matches": domain_matches(domain, china)[:8]})
    report = {
        "scope": "entire published rule files, not a sample",
        "files": {"ChinaDomain.list": len(china_rows), "AdblockSet.list": len(ad_rows)},
        "unique_rules": {"china": len(combined), "ad": len(set(ad_rows))},
        "duplicates": {"china": len(china_rows) - len(combined),
                       "ad": len(ad_rows) - len(set(ad_rows))},
        "rule_types": {"china": {k: len(china[k]) for k in TYPES},
                       "ad": {k: len(ad[k]) for k in TYPES}},
        "invalid_rows": {"china": len(china_invalid), "ad": len(ad_invalid),
                         "china_examples": china_invalid[:30], "ad_examples": ad_invalid[:30]},
        "partitions": partitions,
        "missing_non_ip_partition_count": len(missing_non_ip),
        "missing_non_ip_partition_examples": missing_non_ip[:50],
        "cidr": cidr_audit(china),
        "critical_domain_tests": critical,
        "china_keywords": sorted(china["DOMAIN-KEYWORD"]),
        "keyword_critical_matches": keyword_risks,
        "ad_china_domain_overlap_count": overlap_count,
        "ad_china_domain_overlap_examples": ad_china_overlaps,
        "limitations": [
            "Geographic coverage percentage requires an independently sourced dated IP/domain reference.",
            "Domain and IP rule matches do not prove actual Surge traffic routing; rule ordering matters.",
            "Overlap examples are capped for report size; all input rows were examined.",
        ],
    }
    REPORT.parent.mkdir(parents=True, exist_ok=True)
    REPORT.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print("AUDIT complete: China", len(china_rows), "Adblock", len(ad_rows),
          "cross-set overlaps", overlap_count)
    print("Report:", REPORT.relative_to(ROOT))

if __name__ == "__main__":
    main()
