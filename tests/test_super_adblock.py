import sys
import unittest
from pathlib import Path

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"scripts"))
import super_adblock as s

class SuperAdBlockTests(unittest.TestCase):
    def test_sources(self):
        self.assertEqual(len(s.sources()),64)

    def test_url_rewrite(self):
        protected=s.protected_domains()
        self.assertIsNotNone(s.url_candidate(r"^https?:\/\/api\.example\.com\/ads",protected))
        for pattern in (r"(?i)\b\/ad\/",r"^https?:\/\/.*\/ads",r"^https?:\/\/napi\.ithome\.com\/api\/ads",r"^https?:\/\/restapi\.amap\.com\/ads",r"^https?:\/\/api\.douban\.com\/v2\/movie\/ads",r"^https?:\/\/api\.example\.com\/login\/ads"):
            self.assertIsNone(s.url_candidate(pattern,protected))
        self.assertIsNotNone(s.url_candidate(r"^https?:\/\/api\.douban\.com\/v2\/app_ads\/splash",protected))

    def test_protected_domains(self):
        for host in ("napi.ithome.com","vt1.doubanio.com","erebor.douban.com","restapi.amap.com","l.yimg.com"):
            self.assertTrue(s.blocked_domain("DOMAIN",host,s.protected_domains(),set()))
        self.assertTrue(s.blocked_domain("DOMAIN-SUFFIX","douban.com",s.protected_domains(),set()))
        self.assertTrue(s.blocked_domain("DOMAIN-SUFFIX","ad.example.com",set(),{("DOMAIN","login.ad.example.com")}))

    def test_new_sources_and_regex_scope(self):
        self.assertEqual(s.family("https://raw.githubusercontent.com/Maasea/sgmodule/master/a"),"unverified-lineage")
        self.assertEqual(s.family("https://raw.githubusercontent.com/master-zen/Net-Link/main/a"),"unverified-lineage")
        protected=s.protected_domains()
        for pattern in (r"^https://api\.example\.com/ads|.*",r"^https://api\.example\.com/ads/.*",r"^https://api\.example\.com/ads(foo|bar)",r"^https://foo\.tipatipa\.xyz/ads"):
            self.assertIsNone(s.url_candidate(pattern,protected))
        pattern,host=s.url_candidate(r"^https://api\.example\.com/ads",protected)
        self.assertEqual(host,"api.example.com")
        self.assertIsNotNone(s.re.match(pattern,"https://api.example.com/ads?x=1"))
        self.assertIsNone(s.re.match(pattern,"https://api.example.com/adservice"))
        self.assertEqual(s.parse_rewrite("map local",r'^https://api\.example\.com/ads status-code=200 data-type=text data=""'),(r"^https://api\.example\.com/ads","reject-200"))

    def test_actions(self):
        p=r"^https?:\/\/api\.example\.com\/ads"
        self.assertEqual(s.parse_rewrite("rewrite",p+" reject-dict"),(p,"reject-dict"))
        self.assertEqual(s.parse_rewrite("url rewrite",p+" - reject"),(p,"reject"))
        self.assertEqual(s.parse_rewrite("map local",p+" "+s.MAP["reject-array"]),(p,"reject-array"))
        self.assertIsNone(s.parse_rewrite("rewrite",p+" 302 https://evil.example"))
        self.assertIsNone(s.parse_rewrite("rewrite",p+" script-path=https://evil.example/a.js"))

    def test_script_parser(self):
        import super_adblock_scripts as sec
        u="https://raw.githubusercontent.com/a/b/main/ads.js"
        p=r"^https://api\.example\.com/ads"
        line=f"ads = type=http-response,pattern={p},requires-body=true,script-path={u}"
        self.assertEqual(sec.discover("[Script]\n"+line),{u})
        self.assertEqual(sec.declaration(line),(p,u))
        self.assertIsNone(sec.declaration(line+",binary-body-mode=true"))
        self.assertIsNone(sec.declaration(line.replace("http-response","http-request")))

    def test_download_validation(self):
        for raw in (b"<html>"+b"x"*100,b"\x00"*100,b"invalid"*100):
            with self.assertRaises(ValueError):
                s.decode(raw)
        with self.assertRaises(ValueError):
            s.safe_url("https://evil.example/file")

if __name__=="__main__":
    unittest.main()
