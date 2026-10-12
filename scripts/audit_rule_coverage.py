#!/usr/bin/env python3
"""Full-file deterministic audit of published Surge rule sets (no sampling)."""
from __future__ import annotations

import collections
import csv
import ipaddress
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RULES = ROOT / "Surge/Rules"
REPORT = ROOT / "data/reports/rule_coverage_audit.json"
TYPES = ("DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD", "IP-CIDR", "IP-CIDR6", "IP-ASN", "GEOIP")
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
                ad_china_overlaps.append({"ad_rule": kind + "," + domain,
                                          "china_matches": domain_matches(domain, china)})
    overlap_path = REPORT.with_name("rule_coverage_overlaps.csv")
    overlap_path.parent.mkdir(parents=True, exist_ok=True)
    with overlap_path.open("w", encoding="utf-8", newline="") as fp:
        writer = csv.writer(fp)
        writer.writerow(("ad_rule", "china_matching_rules"))
        for item in ad_china_overlaps:
            writer.writerow((item["ad_rule"], ";".join(item["china_matches"])))
    # Classify every overlap by the matching China rule's semantics.
    # These are review categories, NOT verified false positives.
    overlap_categories = collections.Counter()
    broad_suffix_counts = collections.Counter()
    keyword_overlap_counts = collections.Counter()
    for item in ad_china_overlaps:
        matches = item["china_matches"]
        categories = set()
        for match in matches:
            kind, _, value = match.partition(",")
            if kind == "DOMAIN-KEYWORD":
                categories.add("keyword")
                keyword_overlap_counts[value] += 1
            elif kind == "DOMAIN-SUFFIX" and "." not in value:
                categories.add("single_label_suffix")
                broad_suffix_counts[value] += 1
            elif kind == "DOMAIN-SUFFIX":
                categories.add("domain_suffix")
            else:
                categories.add("exact_domain")
        for category in categories:
            overlap_categories[category] += 1
    risky_keywords = {"microsoft", "stripe"}
    # This is an opt-in proposal, never applied to legacy routing.
    keyword_recommendations = {
        keyword: ("manual_review_high_priority" if keyword in risky_keywords
                  else "manual_review")
        for keyword in sorted(china["DOMAIN-KEYWORD"])
    }
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
        "cidr": cidr_audit(china),
        "critical_domain_tests": critical,
        "china_keywords": sorted(china["DOMAIN-KEYWORD"]),
        "keyword_critical_matches": keyword_risks,
        "ad_china_domain_overlap_count": overlap_count,
        "overlap_category_counts_nonexclusive": dict(sorted(overlap_categories.items())),
        "overlap_single_label_suffix_counts": dict(sorted(broad_suffix_counts.items())),
        "overlap_keyword_counts": dict(sorted(keyword_overlap_counts.items())),
        "keyword_review_recommendations": keyword_recommendations,
        "ad_china_domain_overlap_csv": str(overlap_path.relative_to(ROOT)),
        "ad_china_domain_overlap_examples": ad_china_overlaps[:100],
        "limitations": [
            "Geographic coverage percentage requires an independently sourced dated IP/domain reference.",
            "Domain and IP rule matches do not prove actual Surge traffic routing; rule ordering matters.",
            "The JSON shows 100 examples; the companion CSV contains every matching ad rule.",
        ],
    }
    REPORT.parent.mkdir(parents=True, exist_ok=True)
    REPORT.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print("AUDIT complete: China", len(china_rows), "Adblock", len(ad_rows),
          "cross-set overlaps", overlap_count)
    print("Report:", REPORT.relative_to(ROOT))
    print("Full overlap CSV:", overlap_path.relative_to(ROOT))

if __name__ == "__main__":
    main()
