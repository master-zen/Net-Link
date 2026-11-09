from __future__ import annotations

import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "Surge/Module/.generator"))
from adblock_safety import harden_module, unsafe_rewrite

class AdblockSafetyTests(unittest.TestCase):
    def test_broad_rewrites_are_excluded(self):
        for line in (
            "https://imasdk.googleapis.com/js/sdkloader/ima3.js - reject",
            r"\/api\/video\/getadsdatalist\? - reject",
            "ad-provider.js - reject",
            "https://help.fanza.cc/* - reject",
            "https://rouman5.com/_next/static/chunks/pages/home-123.js - reject",
        ):
            with self.subTest(line=line):
                self.assertTrue(unsafe_rewrite(line))

    def test_specific_ads_are_retained(self):
        for line in (
            "https://a.realsrv.com/ad-provider.js - reject",
            "https://a.magsrv.com/ad-provider.js - reject",
            r"js\.wpadmngr\.com\/static\/adManager\.js - reject",
            r"^https?:\/\/www\.novel543\.com\/log\/ad\.html - reject",
        ):
            with self.subTest(line=line):
                self.assertFalse(unsafe_rewrite(line))

    def test_published_module_is_hardened(self):
        module = (ROOT / "Surge/Module/Adblock4limbo.sgmodule").read_text(encoding="utf-8")
        self.assertEqual(harden_module(module), module)
        self.assertNotIn("*.cloudfront.net", module)
        self.assertNotIn("header-replace Content-Security-Policy", module)
        self.assertNotIn("imasdk.googleapis.com/js/sdkloader/ima3.js", module)

    def test_user_selectors_do_not_remove_essential_media(self):
        user = (ROOT / "Surge/Module/runtime/Adblock4limbo.user.js").read_text(encoding="utf-8")
        self.assertNotIn('test: "*, div,img', user)
        self.assertNotIn('diyibanzhu: "img,', user)
        self.assertNotIn("hanime1: \".comics-banner-ads,span.scaled-exoclick, iframe,", user)
        self.assertNotIn('javday: "p[style], p > a', user)
        self.assertNotIn("case 'douban':", user)

    def test_loader_leaves_media_and_security_headers_unchanged(self):
        js = r"""
const fs = require('fs');
const vm = require('vm');
const source = fs.readFileSync(process.argv[1], 'utf8');
function run(url, type, body) {
  let result;
  const response = {headers: {'Content-Type': type, 'Content-Security-Policy': "default-src 'self'", 'X-Frame-Options': 'DENY'}, body};
  vm.runInNewContext(source, {$request:{url},$response:response,$done:r=>{result=r},console});
  return result;
}
const mp4 = run('https://www.iyf.tv/movie.mp4', 'video/mp4', 'moviebytes');
if (Object.keys(mp4).length !== 0) throw Error('Media response changed');
const html = run('https://www.baidu.com/search?q=test', 'TEXT/HTML; charset=utf-8', "<html><head data-x='1'></head><body><script>window.open('https://example.com')</script></body></html>");
if (!html.body || !html.body.includes("<head data-x='1'>")) throw Error('Head attributes changed');
if (!html.body.includes("window.open('https://example.com')")) throw Error('window.open changed');
if (!html.body.includes('Adblock4limbo.user.js')) throw Error('Injection missing');
if ('headers' in html) throw Error('HTTP headers changed');
if (html.body.includes('limbopro.com/CSS/')) throw Error('Remote CSS injected');
"""
        result = subprocess.run(
            ["node", "-e", js, str(ROOT / "Surge/Module/runtime/Adblock4limbo.js")],
            text=True, capture_output=True, check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)

if __name__ == "__main__":
    unittest.main()
