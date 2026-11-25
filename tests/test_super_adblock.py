import sys
import unittest
import json
import os
import tempfile
from unittest.mock import patch
from pathlib import Path

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"scripts"))
import super_adblock as s

class SuperAdBlockTests(unittest.TestCase):
    def test_sources(self):
        self.assertEqual(len(s.sources()),97)

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

    def test_review_build_never_publishes_partial_input(self):
        import super_adblock_scripts as sec
        urls=s.sources()[:2]
        raw=("[Rule]\n"+"\n".join(f"DOMAIN,ads.test{i}.com,REJECT" for i in range(60))+"\n").encode()
        with tempfile.TemporaryDirectory() as tmp:
            work=Path(tmp)
            (work/"upstream").mkdir()
            entries=[]
            for i,u in enumerate(urls,1):
                path=f"{i:02d}-{s.urlsplit(u).path.rsplit('/',1)[-1]}"
                e={"url":u,"family":s.family(u),"file":path}
                if i==1:
                    e.update(bytes=len(raw),sha256=s.digest(raw))
                    (work/"upstream"/path).write_bytes(raw)
                else:
                    e["error"]="HTTP 403"
                entries.append(e)
            s.dump(work/"manifest.json",{"run_id":os.getenv("GITHUB_RUN_ID","local"),"run_attempt":os.getenv("GITHUB_RUN_ATTEMPT","1"),"sources":entries,"failed":1})
            s.dump(work/"script-audit.json",{"module_manifest_sha256":sec.sha((work/"manifest.json").read_bytes()),"antivirus_ready":False,"references":0,"entries":[]})
            with patch.object(s,"sources",return_value=urls):
                report=s.build(work,review=True)
                self.assertEqual(report["output"]["rules"],60)
                self.assertEqual(report["failed"],1)
                self.assertTrue(s.validate(work,review=True)["review_only"])
                self.assertFalse((work/"SuperAdBlock.sgmodule").exists())
                with self.assertRaises(ValueError):
                    s.build(work)
                self.assertFalse(s.approved(work))

    def test_download_validation(self):
        for raw in (b"<html>"+b"x"*100,b"\x00"*100,b"invalid"*100):
            with self.assertRaises(ValueError):
                s.decode(raw)
        with self.assertRaises(ValueError):
            s.safe_url("https://evil.example/file")

if __name__=="__main__":
    unittest.main()
