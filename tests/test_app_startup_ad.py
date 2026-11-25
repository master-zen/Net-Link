from __future__ import annotations
import re
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from build_app_startup_ad import load, pattern, render, OUTPUT

class StartupADTests(unittest.TestCase):
    def test_generated_output(self):
        self.assertEqual(OUTPUT.read_text(encoding="utf-8"), render(load()))

    def test_protected_requests(self):
        patterns = [re.compile(pattern(e)) for e in load()["entries"]]
        for url in (
            "https://napi.ithome.com/api/news/indexv1/iphone",
            "https://api.douban.com/v2/movie/subject",
            "https://api.douban.com/b1/common_ads?x=1",
            "https://erebor.douban.com/movie/trailer.mp4",
            "https://vt1.doubanio.com/video.m3u8",
            "https://restapi.amap.com/v3/geocode/regeo",
            "https://tiebac.baidu.com/c/f/ad/getFeedAd",
            "https://app.bilibili.com/x/v2/feed/index",
            "https://app.bilibili.com/x/v2/splash/listOther",
            "https://api.m.jd.com/client.action?functionId=startup",
            "https://api.m.jd.com/client.action?functionId=home_launchConfig",
            "https://api.mcd.cn/bff/portal/richpop",
            "https://api.cloud.189.cn/guns/img/recommendedPosition",
            "https://api.internetofcity.cn/api/resource/anon/popups/getList",
            "https://edith.xiaohongshu.com/api/sns/v2/system_service/config",
            "https://switch.jumpvg.com/jump/recommend/ad_conf",
            "https://l.yimg.com/resource",
            "https://fc.yahoo.com/",
            "https://service.cmp.oath.com/",
            "https://oneapp-api.faw-vw.com/content/booth/getBoothList/v1?showPositionCode=VWAPP_ICE_CAR_ZHIHU_COLLEGE",
            "https://pan.baidu.com/buy/ad/conf?type=normal",
            "https://m5.amap.com/ws/c3frontend/af-launch/page/main",
            "https://guide-acs.m.taobao.com/gw/mtop.taobao.cloudvideo.video.query",
            "https://security.wechat.com/",
            "https://wxa.wxs.qq.com/",
        ):
            with self.subTest(url=url):
                self.assertFalse(any(p.match(url) for p in patterns))

    def test_script_only_shared_interface(self):
        data = load()
        for entry in data["entries"]:
            if entry["host"] == "wmapi.meituan.com" and "loadInfo" in entry["path"]:
                self.assertEqual(entry["action"], "meituan")
            if entry["host"] == "api.m.jd.com":
                self.assertEqual(entry["query"], "functionId=start")
                self.assertEqual(entry["action"], "jd")

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
