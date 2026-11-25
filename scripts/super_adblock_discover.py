from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from urllib.request import Request, urlopen
from urllib.parse import urlsplit
from super_adblock import sources, canonical_url, reference_only, dump

REPO="QingRex/LoonKissSurge"
BASE="https://api.github.com/repos/"
RAW="https://raw.githubusercontent.com/"+REPO+"/main/"
OFFICIAL=re.compile(r"去广告|广告联盟|BiliADBlock|Youtube \(Music\) Enhance",re.I)

def api(path):
    with urlopen(Request(BASE+path,headers={"User-Agent":"Net-Link-SuperAdBlock/1.0","Accept":"application/vnd.github+json"}),timeout=30) as response:
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
    tree=api(REPO+"/git/trees/main?recursive=1")
    new=[RAW+p for p in sorted(candidates(tree)) if canonical_url(RAW+p) not in tracked]
    repos=sorted({"/".join(urlsplit(u).path.strip("/").split("/")[:2]) for u in active if urlsplit(u).hostname=="raw.githubusercontent.com"})
    licenses={}
    for repo in repos:
        try:
            meta=api(repo)
            license=meta.get("license") or {}
            licenses[repo]={"spdx_id":license.get("spdx_id"),"license_url":license.get("url"),"repository_url":meta.get("html_url"),"default_branch":meta.get("default_branch"),"archived":meta.get("archived"),"permission_confirmed":False}
        except Exception as exc:
            licenses[repo]={"error":type(exc).__name__,"permission_confirmed":False}
    report={"upstream_tree_sha":tree.get("sha"),"active_sources":len(active),"reference_only":len(reference_only()),"new_candidates":new,"candidate_count":len(new),"repository_license_metadata":licenses,"redistribution_permission_inferred":False}
    dump(work/"discovery.json",report)
    print(json.dumps({"new_candidates":len(new),"repositories":len(licenses),"metadata_failures":sum("error" in v for v in licenses.values())}))

if __name__=="__main__":
    run(Path(sys.argv[1]))
