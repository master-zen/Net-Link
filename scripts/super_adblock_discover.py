from __future__ import annotations

import json
import os
import re
import sys
from pathlib import Path
from urllib.request import Request, build_opener, HTTPRedirectHandler
from urllib.parse import urlsplit
from super_adblock import sources, canonical_url, reference_only, dump

REPO="QingRex/LoonKissSurge"
BASE="https://api.github.com/repos/"
RAW="https://raw.githubusercontent.com/"+REPO+"/main/"
OFFICIAL=re.compile(r"去广告|广告联盟|BiliADBlock|Youtube \(Music\) Enhance",re.I)

class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self,req,fp,code,msg,headers,newurl):
        raise ValueError("Unexpected GitHub API redirect")

def api(path):
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(?:/git/trees/main\?recursive=1)?",path):
        raise ValueError("Invalid repository API path")
    headers={"User-Agent":"Net-Link-SuperAdBlock/1.0","Accept":"application/vnd.github+json","X-GitHub-Api-Version":"2022-11-28"}
    token=os.getenv("SUPER_ADBLOCK_DISCOVERY_TOKEN")
    if token:
        headers["Authorization"]="Bearer "+token
    with build_opener(NoRedirect()).open(Request(BASE+path,headers=headers),timeout=30) as response:
        if urlsplit(response.geturl()).hostname!="api.github.com":
            raise ValueError("Unexpected GitHub API endpoint")
        data=response.read(16*1024*1024+1)
    if len(data)>16*1024*1024:
        raise ValueError("Oversize GitHub response")
    return json.loads(data)

def candidates(tree):
    if tree.get("truncated") or not isinstance(tree.get("tree"),list):
        raise ValueError("Incomplete tree")
    paths=set()
    for e in tree["tree"]:
        path=e["path"]
        if e["type"]!="blob" or not path.endswith(".sgmodule"):
            continue
        if re.fullmatch(r"Surge/[^/]+去广告\.sgmodule",path) or re.fullmatch(r"Surge/Beta/(?:[^/]+去广告|可莉广告过滤器)\.beta\.sgmodule",path) or (path.startswith("Surge/Official/") and OFFICIAL.search(path)):
            paths.add(path)
    return paths

def run(work):
    active=sources()
    tracked={canonical_url(u) for u in active}
    try:
        tree=api(REPO+"/git/trees/main?recursive=1")
        new=[RAW+p for p in sorted(candidates(tree)) if canonical_url(RAW+p) not in tracked]
    except Exception as exc:
        dump(work/"discovery.json",{"status":"failed","reason":type(exc).__name__,"http_status":getattr(exc,"code",None),"candidate_count":None,"redistribution_permission_inferred":False})
        raise SystemExit("Upstream discovery failed")
    repos=sorted({"/".join(urlsplit(u).path.strip("/").split("/")[:2]) for u in active if urlsplit(u).hostname=="raw.githubusercontent.com"})
    licenses={}
    for repo in repos:
        try:
            meta=api(repo)
            license=meta.get("license") or {}
            licenses[repo]={"spdx_id":license.get("spdx_id"),"license_url":license.get("url"),"repository_url":meta.get("html_url"),"default_branch":meta.get("default_branch"),"archived":meta.get("archived"),"permission_confirmed":False}
        except Exception as exc:
            licenses[repo]={"error":type(exc).__name__,"permission_confirmed":False}
    report={"status":"complete","upstream_tree_sha":tree.get("sha"),"active_sources":len(active),"reference_only":len(reference_only()),"new_candidates":new,"candidate_count":len(new),"repository_license_metadata":licenses,"redistribution_permission_inferred":False}
    dump(work/"discovery.json",report)
    print(json.dumps({"new_candidates":len(new),"repositories":len(licenses),"metadata_failures":sum("error" in v for v in licenses.values())}))

if __name__=="__main__":
    run(Path(sys.argv[1]))
