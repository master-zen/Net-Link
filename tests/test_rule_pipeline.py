#!/usr/bin/env python3
"""Pure unit regressions for fail-closed routing and DNS block-list semantics."""
from __future__ import annotations

import ipaddress
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import build_ad_sets as ad
import build_china_domain as china
import fetch_rule_sources as fetch


class RulePipelineRegressionTests(unittest.TestCase):
    def test_explicit_block_in_allow_source_is_not_whitelisted(self):
        block, allow, _ = ad.parse_rules_from_text(
            "||malvertising.example^\n@@||legitimate.example^\n", "allow"
        )
        self.assertIn("DOMAIN-SUFFIX,malvertising.example", block)
        self.assertNotIn("DOMAIN-SUFFIX,malvertising.example", allow)
        self.assertIn("DOMAIN-SUFFIX,legitimate.example", allow)

    def test_official_adguard_dns_host_rules_only(self):
        blocked, allowed, stats = ad.parse_rules_from_text(
            "||advertiser.example^\n"
            "||ads.example^$third-party\n"
            "||metrics.example^$domain=publisher.example\n"
            "||analytics.example^$important\n"
            "||safe.example^|\n"
            "||no-boundary.example\n"
            "||ad*.example^\n"
            "||images.example/banner.png\n"
            "@@||login.example^\n"
            "@@||billing.example^$document\n",
            "block",
        )
        self.assertIn("DOMAIN-SUFFIX,advertiser.example", blocked)
        self.assertIn("DOMAIN-SUFFIX,login.example", allowed)
        self.assertEqual(len(blocked), 1)
        self.assertEqual(len(allowed), 1)
        self.assertGreaterEqual(stats.ignored_scoped_adblock, 6)

    def test_preserves_www_hostnames_instead_of_widening_block(self):
        blocked, allowed, _ = ad.parse_rules_from_text(
            "DOMAIN,www.video.example,REJECT\n"
            "||www.ads.example^\n",
            "block",
        )
        self.assertIn("DOMAIN,www.video.example", blocked)
        self.assertIn("DOMAIN-SUFFIX,www.ads.example", blocked)
        self.assertNotIn("DOMAIN,video.example", blocked)
        self.assertNotIn("DOMAIN-SUFFIX,ads.example", blocked)
        self.assertFalse(allowed)

    def test_adguard_official_unsupported_options_do_not_expand(self):
        for value in (
            "||service.example^$denyallow=auth.example",
            "||service.example^$dnsrewrite=0.0.0.0",
            "||service.example^$client=mobile",
            "||service.example^$~third-party",
            "@@||service.example^$domain=example.com",
        ):
            with self.subTest(rule=value):
                self.assertIsNone(ad.normalize_rule_line(value, "block"))

    def test_explicit_reject_or_hosts_cannot_be_allow(self):
        blocks, allows, _ = ad.parse_rules_from_text(
            "DOMAIN,ads.example,REJECT\n0.0.0.0 spyware.example\n"
            "address=/tracking.example/0.0.0.0\nDOMAIN,login.example,DIRECT\n",
            "allow"
        )
        self.assertIn("DOMAIN,ads.example", blocks)
        self.assertIn("DOMAIN,spyware.example", blocks)
        self.assertIn("DOMAIN-SUFFIX,tracking.example", blocks)
        self.assertIn("DOMAIN,login.example", allows)
        self.assertNotIn("DOMAIN,ads.example", allows)

    def test_safety_allow_removes_broad_reject(self):
        remaining, removed = ad.subtract_allow_rules(
            ["DOMAIN-SUFFIX,example.com", "DOMAIN,ads.other.com"],
            ["DOMAIN,account.example.com"]
        )
        self.assertEqual(removed, 1)
        self.assertEqual(remaining, ["DOMAIN,ads.other.com"])

    def test_ad_semantic_duplicate_elimination(self):
        cleaned = ad.remove_semantically_redundant_domains([
            "DOMAIN-SUFFIX,example.com",
            "DOMAIN,sub.example.com",
            "DOMAIN-SUFFIX,other.sub.example.com",
            "DOMAIN,billing.org",
        ])
        self.assertEqual(cleaned, ["DOMAIN-SUFFIX,example.com", "DOMAIN,billing.org"])

    def test_china_foreign_parent_protection(self):
        self.assertTrue(china.domain_hits_exclusion(
            "microsoftonline.com", "DOMAIN-SUFFIX", set(), {"microsoftonline.com"}))
        self.assertTrue(china.domain_hits_exclusion(
            "auth.microsoftonline.com", "DOMAIN", set(), {"microsoftonline.com"}))
        self.assertFalse(china.domain_hits_exclusion(
            "baidu.com", "DOMAIN-SUFFIX", set(), {"microsoftonline.com"}))

    def test_china_ip_subtract_maintains_exact_coverage(self):
        kept = china.remove_foreign_ip_overlap(
            [ipaddress.ip_network("8.8.8.0/23")],
            [ipaddress.ip_network("8.8.8.0/24")],
        )
        self.assertEqual(kept, [ipaddress.ip_network("8.8.9.0/24")])

    def test_china_semantic_duplicate_elimination(self):
        rules, removed = china.eliminate_domain_hierarchy_redundancy([
            "DOMAIN-SUFFIX,example.org",
            "DOMAIN,login.example.org",
            "DOMAIN-SUFFIX,sub.example.org",
            "DOMAIN,standalone.org",
        ])
        self.assertEqual(removed, 2)
        self.assertEqual(rules, ["DOMAIN-SUFFIX,example.org", "DOMAIN,standalone.org"])

    def test_download_paths_per_source_are_deterministic(self):
        url = "https://raw.githubusercontent.com/example/rules/main/ads.txt"
        p = fetch.source_path("ad", "block", url)
        self.assertEqual(p, fetch.source_path("ad", "block", url))
        self.assertTrue(p.as_posix().endswith("_ads.txt"))
        self.assertIn("data/ad/upstream/block/", p.as_posix())


if __name__ == "__main__":
    unittest.main()
