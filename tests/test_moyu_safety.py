from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "Surge/Module/.generator"))
from safety import is_protected_mitm_host, should_skip_rewrite


class MoyuFalsePositiveTests(unittest.TestCase):
    def test_functional_apis_are_protected(self):
        patterns = (
            r"^https?:\/\/napi\.ithome\.com\/api\/news\/indexv\d\/iphone",
            r"^https?:\/\/api\.douban\.com\/v2\/movie\/subject",
            r"^https?:\/\/learn\.chaoxing\.com\/apis\/service\/appConfig",
            r"^https?:\/\/api\.dangdang\.com\/mapi\d\/mobile\/init",
            r"^https?:\/\/r\.inews\.qq\.com\/(getBannerAds|getNewsRemoteConfig|getSplash)",
            r"https?:\/\/helper\.2bulu\.com\/(greenPea\/queryTasks|getSplash)",
            r"^https?:\/\/.*zhangyuyidong\.cn\/api\/",
            r"^https?:\/\/[a-z]+\.eastmoney\.com\/infoService\/",
            r"^https?:\/\/ccsp-egmas\.sf-express\.com\/cx-app-base\/base\/app\/appVersion\/detectionUpgrade",
        )
        for pattern in patterns:
            with self.subTest(pattern=pattern):
                self.assertTrue(should_skip_rewrite(pattern))

    def test_additional_business_paths_are_protected(self):
        for pattern in (
            r"^https?:\/\/apps\.api\.ke\.com\/config\/config\/(bootpage|getactivityconfig)",
            r"^https?:\/\/dispatcher\.camera360\.com\/api\/v1\/list$",
            r"^https?:\/\/home\.mi\.com\/cgi-op\/api\/v\d\/recommendation",
            r"^https?:\/\/.*zongheng\.com\/iosapi\/system\/startup",
            r"^https?:\/\/.*flyert.*\/api\/mobile\/index\.php\?module=advis",
        ):
            with self.subTest(pattern=pattern):
                self.assertTrue(should_skip_rewrite(pattern))

    def test_ad_specific_apis_still_work(self):
        for pattern in (
            r"^https?:\/\/ad\.mcloud\.139\.com\/advertapi",
            r"^https?:\/\/api\.ireader\.mobi\/activity\/ad\/openScreen",
            r"^https?:\/\/ftapi\.10jqka\.com\.cn\/futgwapi\/api\/om\/v\d\/ad\/common\/transfer",
            r"^https?:\/\/api\.douban\.com\/v2\/app_ads\/splash",
            r"^https?:\/\/api\.douban\.com\/b.*\/common_ads\?.*",
        ):
            with self.subTest(pattern=pattern):
                self.assertFalse(should_skip_rewrite(pattern))

    def test_mitm_host_guards(self):
        for host in ("napi.ithome.com", "vt1.doubanio.com", "r.inews.qq.com"):
            self.assertTrue(is_protected_mitm_host(host))
        self.assertFalse(is_protected_mitm_host("ad.mcloud.139.com"))
        self.assertFalse(is_protected_mitm_host("api.douban.com"))

    def test_generated_module_has_no_protected_rewrites(self):
        content = (ROOT / "Surge/Module/StartUpAds.sgmodule").read_text(encoding="utf-8")
        self.assertNotIn(r"napi\.ithome", content)
        self.assertIn(r"api\.douban\.com\/v2\/app_ads\/splash", content)
        self.assertIn(r"api\.douban\.com\/b.*\/common_ads\?.*", content)
        self.assertNotIn(r"api\.douban\.com\/v2\/movie", content)
        self.assertNotIn(r"zhangyuyidong\.cn\/api\/", content)
        self.assertNotIn("getNewsRemoteConfig", content)
        self.assertNotIn("queryTasks", content)

    def test_douban_trailer_preservation(self):
        user = (ROOT / "Surge/Module/runtime/Adblock4limbo.user.js").read_text(encoding="utf-8")
        self.assertNotIn('douban: "*{display:none!important}"', user)
        self.assertNotIn("case 'douban':", user)
        allow = (ROOT / "data/allowlists/AdblockCriticalAllow.list").read_text(encoding="utf-8")
        self.assertIn("DOMAIN,vt1.doubanio.com", allow)
        self.assertIn("DOMAIN,erebor.douban.com", allow)
        ads = (ROOT / "Surge/Rules/AdblockSet.list").read_text(encoding="utf-8")
        self.assertNotIn("DOMAIN-SUFFIX,erebor.douban.com", ads)
        self.assertNotIn("DOMAIN,erebor.douban.com", ads)


if __name__ == "__main__":
    unittest.main()
