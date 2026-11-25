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
        self.assertEqual(len(s.sources()),428)

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
                self.assertEqual(report["provenance_count"],60)
                self.assertEqual(report["rule_provenance"][0]["origins"][0]["source"],urls[0])
                self.assertEqual(report["failed"],1)
                self.assertTrue(s.validate(work,review=True)["review_only"])
                self.assertFalse((work/"SuperAdBlock.sgmodule").exists())
                with self.assertRaises(ValueError):
                    s.build(work)
                self.assertFalse(s.approved(work))

    def test_batch_antivirus(self):
        import super_adblock_scripts as sec
        with tempfile.TemporaryDirectory() as tmp:
            folder=Path(tmp)
            hashes=["a"*64,"b"*64,"c"*64]
            output=f"{folder/hashes[0]}.js: OK\n{folder/hashes[1]}.js: Test.Signature FOUND\n"
            with patch.object(sec.subprocess,"run",return_value=sec.subprocess.CompletedProcess([],1,stdout=output)):
                result=sec.batch_scan(folder,hashes,True)
            self.assertEqual([result[h] for h in hashes],["no-signature-hit","detected","scan-error"])

    def test_source_canonicalization(self):
        a="https://raw.githubusercontent.com/QingRex/LoonKissSurge/main/Surge/可莉.sgmodule"
        b="https://raw.githubusercontent.com/QingRex/LoonKissSurge/refs/heads/main/Surge/%E5%8F%AF%E8%8E%89.sgmodule"
        self.assertEqual(s.canonical_url(a),s.canonical_url(b))
        for u in ("https://raw.githubusercontent.com/a/b/main/../x","https://raw.githubusercontent.com/a/b/main/%2Fx","https://raw.githubusercontent.com/a/b/main/x?token=x"):
            with self.assertRaises(ValueError):
                s.safe_url(u)

    def test_overlapping_actions(self):
        protected=s.protected_domains()
        a,h=s.url_candidate(r"^https?://api\.example\.com/ads",protected)
        b,_=s.url_candidate(r"^https://api\.example\.com/ads/list",protected)
        c,_=s.url_candidate(r"^https://api\.example\.com/advertisement",protected)
        self.assertTrue(s.scopes_overlap(a,b))
        self.assertFalse(s.scopes_overlap(a,c))
        self.assertEqual(s.rewrite_conflicts({a:{"reject"},b:{"reject-dict"},c:{"reject"}},{a:h,b:h,c:h}),{a,b})
        self.assertIsNone(s.url_candidate(r"^https://api\.example\.com/ads/%6cogin",protected))
        p,_=s.url_candidate(r"^https?://api\.douban\.com/v2/app_ads/splash",protected)
        self.assertIsNone(s.re.match(p,"https://api.douban.com/v2/app_ads/splashback"))
        self.assertIsNotNone(s.re.match(p,"https://api.douban.com/v2/app_ads/splash?x=1"))

    def test_map_local_content_type(self):
        pattern=r"^https://api\.example\.com/ads"
        self.assertEqual(s.parse_rewrite("map local",pattern+' data-type=text data="{}" status-code=200 header="Content-Type:application/json"'),(pattern,"reject-dict"))

    def test_safe_body_rewrite(self):
        p=r"^https://mag1\.sdgun\.net/mag/circle/v4/show/showView"
        candidate=s.parse_body(f"http-response-jq {p} 'del(.ads,.data.adInfo)'",s.protected_domains())
        self.assertIsNotNone(candidate)
        pattern,host,paths=candidate
        self.assertEqual(paths,{("ads",),("data","adInfo")})
        self.assertIsNone(s.re.match(pattern,"https://mag1.sdgun.net/mag/circle/v4/show/showViewExtra"))
        self.assertIsNotNone(s.re.match(pattern,"https://mag1.sdgun.net/mag/circle/v4/show/showView?x=1"))
        self.assertEqual(s.parse_body(f"http-response-jq {p} 'delpaths([[\"ads\"]])'",set())[2],{("ads",)})
        for expr in ("del(.data)","del(.user.ads)","del(.ads)|empty","delpaths([[\"data\",0]])","walk(del(.ads))"):
            self.assertIsNone(s.parse_body(f"http-response-jq {p} '{expr}'",set()))
        self.assertIsNone(s.parse_body(r"http-response-jq ^https://restapi\.amap\.com/v1/ads 'del(.ads)'",s.protected_domains()))

    def test_script_endpoint_policy(self):
        import super_adblock_scripts as sec
        self.assertEqual(sec.script_endpoint("https://raw.perzikkop.com/Scripts/MiniPrograms/T3.js"),"https://raw.perzikkop.com/Scripts/MiniPrograms/T3.js")
        self.assertEqual(sec.script_endpoint("https://gist.githubusercontent.com/blackmatrix7/f5f780d0f56b319b6ad9848fd080bb18/raw/zheye.min.js"),"https://gist.githubusercontent.com/blackmatrix7/f5f780d0f56b319b6ad9848fd080bb18/raw/zheye.min.js")
        for u in ("https://evil.example/script.js","https://raw.perzikkop.com/other/a.js","https://release-assets.githubusercontent.com/github-production-release-asset/a?x=1","https://github.com/a/b/releases/download/v1/a.js"):
            with self.assertRaises(ValueError):
                sec.script_endpoint(u)
        self.assertEqual(sec.script_endpoint("https://github.com/Biliverse/ADBlock/releases/download/v0.6.24/response.bundle.js"),"https://github.com/Biliverse/ADBlock/releases/download/v0.6.24/response.bundle.js")

    def test_reference_inventory(self):
        refs=s.reference_only()
        self.assertEqual(len(refs),43)
        self.assertEqual(sum(e["alternative"] is None for e in refs),2)
        self.assertTrue(set(s.sources()).isdisjoint(e["url"] for e in refs))
        self.assertTrue(all(e["alternative"] is None or e["alternative"] in s.sources() for e in refs))

    def test_discovery_selection(self):
        import super_adblock_discover as discover
        paths=["Surge/Example去广告.sgmodule","Surge/Beta/Example去广告.beta.sgmodule","Surge/Official/Example去广告.sgmodule","Surge/Example签到.sgmodule"]
        tree={"truncated":False,"tree":[{"path":p,"type":"blob"} for p in paths]}
        self.assertEqual(discover.candidates(tree),set(paths[:3]))
        with self.assertRaises(ValueError):
            discover.candidates({"truncated":True,"tree":[]})

    def test_array_filter_parser(self):
        p=r"^https://mag1\.sdgun\.net/mag/info/v2/channel/infoListByCatId"
        line=f"http-response-jq {p} '.list |= map(select(._type != \"pic_ad\"))'"
        a=s.parse_array_filter(line,s.protected_domains())
        self.assertIsNotNone(a)
        self.assertEqual(a[2],(("list",),"_type",'"pic_ad"'))
        for expr in ('.list |= map(select(.type != "article"))','.list |= map(select(.id != 1))','.list |= map(select(.type != "ad")) | empty','.users |= map(select(.type != "ad"))'):
            self.assertIsNone(s.parse_array_filter(f"http-response-jq {p} '{expr}'",set()))

    def test_quality_regression_gate(self):
        import super_adblock_quality as q
        policy=json.loads(q.POLICY.read_bytes())
        output=dict(policy["baseline"]["output"])
        audit={"output":output,"review_only":False,"failed":0,"sources":428,"downloaded":428}
        manifest={"failed":0,"downloaded":428}
        script={"references":1,"antivirus_ready":True,"entries":[]}
        self.assertTrue(q.evaluate(audit,manifest,script,policy)["passed"])
        output["rules"]=1
        self.assertIn("total-rule-loss",q.evaluate(audit,manifest,script,policy)["reasons"])
        output["mitm_hosts"]=1000
        self.assertIn("mitm-growth",q.evaluate(audit,manifest,script,policy)["reasons"])

    def test_cross_module_conflict(self):
        import super_adblock_cross as c
        candidate=list(c.rows("[Rule]\nDOMAIN,ads.example.com,REJECT\n[URL Rewrite]\n^https://api\\.example\\.com/ads _ reject\n","candidate"))
        existing=list(c.rows("[Rule]\nDOMAIN-SUFFIX,example.com,DIRECT\n[Map Local]\n^https://api\\.example\\.com/ads data-type=text data=\"\" status-code=200\n","existing"))
        r=c.compare(candidate,existing)
        self.assertEqual(r["counts"]["non-reject-domain-conflict"],2)
        self.assertEqual(r["counts"]["exact-url-overlap"],1)
        self.assertNotIn("pattern",r["examples"][0]["candidate"])

    def test_host_case_canonicalization(self):
        a=s.url_candidate(r"^https://API\.example\.com/ads",set())
        b=s.url_candidate(r"^https://api\.example\.com/ads",set())
        self.assertEqual(a,b)

    def test_quality_hash_churn(self):
        import super_adblock_quality as q
        policy=json.loads(q.POLICY.read_bytes())
        out=dict(policy["baseline"]["output"])
        audit={"output":out,"review_only":False,"failed":0,"sources":428,"downloaded":428,"rule_provenance":[{"rule_sha256":str(i)} for i in range(sum(out[k] for k in q.RULES))],"provenance_count":sum(out[k] for k in q.RULES)}
        manifest={"failed":0,"downloaded":428}
        script={"references":0,"antivirus_ready":True,"entries":[]}
        prior={"output":out,"rule_hashes":[str(i+1000) for i in range(100)]}
        result=q.evaluate(audit,manifest,script,policy,prior,{"counts":{"non-reject-domain-conflict":1}})
        self.assertIn("rule-hash-churn",result["reasons"])
        self.assertIn("cross-module-functional-conflict",result["reasons"])

    def test_compiled_script_plan(self):
        import super_adblock_scripts as sec
        url="https://raw.githubusercontent.com/a/b/main/ads.js"
        with tempfile.TemporaryDirectory() as tmp:
            work=Path(tmp)
            plan={"deletes":[["ads"]],"filters":[]}
            s.dump(work/"script-audit.json",{"entries":[{"url":url,"ast":{"plan":plan}}]})
            self.assertEqual(sec.plans(work,{url:"a"*64}),{url:plan})
            self.assertEqual(sec.plans(work,{}),{})

    def test_download_validation(self):
        for raw in (b"<html>"+b"x"*100,b"\x00"*100,b"invalid"*100):
            with self.assertRaises(ValueError):
                s.decode(raw)
        with self.assertRaises(ValueError):
            s.safe_url("https://evil.example/file")

if __name__=="__main__":
    unittest.main()
