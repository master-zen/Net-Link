from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import re
import shutil
import sys
import time
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from urllib.parse import quote, urlsplit, urlunsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "data/sources/SuperAdBlock_URLs.txt"
APPROVAL = ROOT / "data/sources/SuperAdBlock_publication.json"
ALLOW = ROOT / "data/allowlists/AdblockCriticalAllow.list"
sys.path.insert(0, str(ROOT / "Surge/Module/.generator"))
from safety import should_skip_rewrite, is_protected_mitm_host

MAX_BYTES = 8 * 1024 * 1024
HOSTS = {"raw.githubusercontent.com", "kelee.one"}
DOMAIN = re.compile(r"(?=.{4,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?$")
AD_LABEL = re.compile(r"^(?:ads?|adapi|adservice|adserver|adnetwork|adtrack|adtracking|adstat|adtech|adcdn|admob|admarket|adshow|adview|adconfig|adlog|adreport|adrequest|ad-splash|advert(?:ising|isement|iser)?|doubleclick|pangolin|pangle|appsflyer|applovin|adnxs|inmobi|ironsrc|vungle|sigmob|tradplus|ad-scope|dsp|rtb)(?:[-0-9].*)?$", re.I)
AD_PATH = re.compile(r"(?:^|[/_.-])(?:ads?|app_ads|advert(?:isement|ising|ise)?|ad(?:server|service|info|list|config|banner|splash|union|realTime|request|report)|get(?:ads?|adinfo|adlist|advertisement|splashads)|common_ads|splash(?:_ad|ad|_ads|ads))(?:$|[/_.?\\(\[\-])", re.I)
SENSITIVE = re.compile(r"(?:^|[/_.?&=-])(?:auth|oauth|login|logout|passport|account|payment|pay|checkout|wallet|bank|security|verify|captcha|register|purchase|order|booking|ticket|location|locate|navigation|route|search|feed|recommendation|profile|message|notification|config|init|update|upgrade|video|playback|trailer|stream|download|upload|media)(?:$|[/_.?&=\\(\[\-])", re.I)
EXTRA_PROTECTED = {"ad.12306.cn","testflight.apple.com","mp.weixin.qq.com","spclient.wg.spotify.com","mobilepaas.abchina.com.cn","ump.sz.creditcard.ecitic.com","creditcardapp.bankcomm.com","creditcardapp.bankcomm.cn","zjmbank.js96008.com","smsrebuild1.mail.10086.cn","fuwu.nhsa.gov.cn","client.app.coc.10086.cn","api.futunn.com","gab.122.gov.cn","security.wechat.com","weixin110.qq.com","wxa.wxs.qq.com"}
DOUBAN = {r"^https?://api\.douban\.com/v2/app_ads/splash",r"^https?://api\.douban\.com/b.*/common_ads\?.*"}
PUBLIC_SUFFIX = {"com.cn","net.cn","org.cn","gov.cn","co.uk","org.uk","com.au","co.jp","com.hk","com.tw","co.kr","com.sg","github.io","pages.dev","cloudfront.net","aliyuncs.com","amazonaws.com","azurewebsites.net","appspot.com","workers.dev"}
MAP = {
    "reject-200": 'data-type=text data="" status-code=200',
    "reject-img": "data-type=tiny-gif status-code=200",
    "reject-dict": 'data-type=text data="{}" header="Content-Type:application/json;charset=utf-8" status-code=200',
    "reject-array": 'data-type=text data="[]" header="Content-Type:application/json;charset=utf-8" status-code=200',
}

def digest(data):
    return hashlib.sha256(data).hexdigest()

def dump(path, obj):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")

def sources():
    result = [x.strip() for x in SOURCE.read_text(encoding="utf-8").splitlines() if x.strip()]
    if len(result) != 49 or len(set(result)) != len(result):
        raise ValueError("Invalid source inventory")
    return result

def safe_url(url):
    u = urlsplit(url)
    if u.scheme != "https" or u.hostname not in HOSTS or u.username or u.password or u.port or u.fragment:
        raise ValueError("Unapproved source endpoint")
    return urlunsplit((u.scheme, u.netloc, quote(u.path, safe="/%"), u.query, ""))

class Redirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return super().redirect_request(req, fp, code, msg, headers, safe_url(newurl))

def family(url):
    if "QingRex/" in url or "kelee.one/" in url:
        return "kelee"
    if "AWAvenue-Ads-Rule/" in url:
        return "awavenue"
    return "blackmatrix7"

def decode(data):
    if not 80 <= len(data) <= MAX_BYTES:
        raise ValueError("Invalid snapshot size")
    text = data.decode("utf-8-sig")
    if "\x00" in text or any(ord(c) < 32 and c not in "\t\r\n" for c in text):
        raise ValueError("Unexpected binary or control content")
    if not re.search(r"(?im)^\s*\[(?:rule|rewrite|url rewrite|script|mitm|map local|body rewrite)\]\s*$", text):
        raise ValueError("Missing module sections")
    if re.search(r"(?i)^\s*(?:<!doctype|<html)", text):
        raise ValueError("HTML response")
    return text

def download_one(index_url, base):
    index, url = index_url
    path = f"{index:02d}-{urlsplit(url).path.rsplit('/',1)[-1]}"
    for attempt in range(3):
        try:
            with build_opener(Redirect()).open(Request(safe_url(url), headers={"User-Agent":"Net-Link-SuperAdBlock/1.0","Accept":"text/plain,*/*"}), timeout=40) as response:
                if response.status != 200:
                    raise ValueError("Unexpected HTTP status")
                safe_url(response.geturl())
                raw = response.read(MAX_BYTES + 1)
            decode(raw)
            (base / path).write_bytes(raw)
            return {"url":url,"family":family(url),"file":path,"bytes":len(raw),"sha256":digest(raw)}
        except Exception:
            if attempt == 2:
                raise RuntimeError(f"Source {index} download or validation failed") from None
            time.sleep(2 ** attempt)

def fetch(work):
    if work.exists():
        raise ValueError("Workspace already exists")
    base = work / "upstream"
    base.mkdir(parents=True)
    with ThreadPoolExecutor(max_workers=6) as pool:
        entries = list(pool.map(lambda pair: download_one(pair,base), enumerate(sources(),1)))
    dump(work / "manifest.json", {"run_id":os.getenv("GITHUB_RUN_ID","local"),"run_attempt":os.getenv("GITHUB_RUN_ATTEMPT","1"),"epoch_seconds":int(time.time()),"sources":entries})

def snapshots(work):
    manifest = json.loads((work / "manifest.json").read_text(encoding="utf-8"))
    if manifest["run_id"] != os.getenv("GITHUB_RUN_ID","local") or manifest["run_attempt"] != os.getenv("GITHUB_RUN_ATTEMPT","1"):
        raise ValueError("Stale manifest")
    if [x["url"] for x in manifest["sources"]] != sources():
        raise ValueError("Incomplete manifest")
    for i, entry in enumerate(manifest["sources"],1):
        expected = f"{i:02d}-{urlsplit(entry['url']).path.rsplit('/',1)[-1]}"
        if entry["file"] != expected or entry["family"] != family(entry["url"]):
            raise ValueError("Invalid manifest path or source family")
        raw = (work / "upstream" / expected).read_bytes()
        if len(raw) != entry["bytes"] or digest(raw) != entry["sha256"]:
            raise ValueError("Snapshot integrity failure")
        yield entry, decode(raw)

def parse_csv(line):
    try:
        return [x.strip() for x in next(csv.reader([line],skipinitialspace=True,strict=True))]
    except (csv.Error, StopIteration):
        return []

def normalize_domain(value):
    value = value.lower().rstrip(".")
    return value if DOMAIN.fullmatch(value) and value not in PUBLIC_SUFFIX and not value.endswith((".local",".localhost",".internal",".test",".invalid",".example")) else None

def protected_domains():
    result = set(EXTRA_PROTECTED)
    for line in ALLOW.read_text(encoding="utf-8").splitlines():
        fields = parse_csv(line)
        if len(fields) >= 2 and fields[0] in {"DOMAIN","DOMAIN-SUFFIX"}:
            result.add(fields[1].lower())
    return result

def matches_domain(host, base, suffix=False):
    return host == base or (suffix and host.endswith("." + base))

def blocked_domain(kind, domain, protected, upstream_allow):
    if is_protected_mitm_host(domain):
        return True
    if any(matches_domain(domain,x,True) or matches_domain(x,domain,kind=="DOMAIN-SUFFIX") for x in protected):
        return True
    return any(matches_domain(domain,x,k=="DOMAIN-SUFFIX") or matches_domain(x,domain,kind=="DOMAIN-SUFFIX") for k,x in upstream_allow)

def normalize_pattern(pattern):
    if len(pattern) > 512 or any(c.isspace() or ord(c)<32 for c in pattern):
        return None
    pattern = pattern.replace(r"\/","/").replace(r"\:",":")
    if not pattern.startswith(("^https?://","^https://","^http://")):
        return None
    try:
        re.compile(pattern)
    except re.error:
        return None
    return pattern

def url_candidate(pattern, protected):
    pattern = normalize_pattern(pattern)
    if not pattern:
        return None
    match = re.match(r"^\^https?\??://([a-zA-Z0-9-]+(?:\\\.[a-zA-Z0-9-]+)+)(/.*)$",pattern)
    if not match:
        return None
    host = normalize_domain(match.group(1).replace(r"\.","."))
    path = match.group(2)
    if not host or is_protected_mitm_host(host):
        return None
    if pattern in DOUBAN:
        return pattern,host
    if any(matches_domain(host,x,True) for x in protected):
        return None
    if should_skip_rewrite(pattern) or SENSITIVE.search(path) or not AD_PATH.search(path):
        return None
    if re.search(r"\\[1-9]|\(\?|\([^)]*[+*][^)]*\)[+*{]|\.\*[+*]|\{[0-9]{4,}",path):
        return None
    if re.search(r"\.(?:mp4|m3u8|mov|m4s|ts)(?:$|\\|\?)",path,re.I):
        return None
    if re.search(r"(?i)(?:login|password|oauth|payment|checkout|location|trailer|playurl)",path):
        return None
    return pattern,host

def parse_rewrite(section, line):
    if section == "url rewrite":
        match = re.fullmatch(r'(?:"([^"]+)"|(\S+))\s+[-_]\s+reject',line,re.I)
        if match:
            return (match.group(1) or match.group(2)),"reject"
    if section == "rewrite":
        match = re.fullmatch(r"(\S+)\s+(?:url\s+)?(reject(?:-200|-img|-dict|-array)?)",line,re.I)
        if match:
            return match.group(1),match.group(2).lower()
        match = re.fullmatch(r"request\s+if\s+\$\{url\}\s*~=\s*/((?:\\.|[^/])*)/\s+then\s+(reject|reject_img|reject_dict|reject_array)\(200\)",line)
        if match:
            return match.group(1),{"reject":"reject-200","reject_img":"reject-img","reject_dict":"reject-dict","reject_array":"reject-array"}[match.group(2)]
    if section == "map local":
        for action, value in MAP.items():
            if line.endswith(" "+value):
                return line[:-len(value)-1].strip('"'),action
    return None

def build(work):
    protected = protected_domains()
    domain_hits = defaultdict(set)
    url_hits = defaultdict(set)
    url_hosts = {}
    upstream_allow = set()
    counts = Counter()
    quarantine = Counter()
    for entry, text in snapshots(work):
        section = ""
        for original in text.splitlines():
            line = original.strip()
            if not line or line.startswith(("#",";","//")):
                continue
            if re.fullmatch(r"\[[^\]]+\]",line):
                section = line[1:-1].lower()
                continue
            counts[section] += 1
            if section == "rule":
                fields = parse_csv(line)
                if len(fields) < 3:
                    quarantine["invalid-rule"] += 1
                    continue
                kind = {"HOST":"DOMAIN","HOST-SUFFIX":"DOMAIN-SUFFIX"}.get(fields[0].upper(),fields[0].upper())
                policy = fields[2].upper()
                if kind in {"DOMAIN","DOMAIN-SUFFIX"}:
                    domain = normalize_domain(fields[1])
                    if not domain or any(x.lower() not in {"extended-matching","pre-matching"} for x in fields[3:]):
                        quarantine["domain-syntax"] += 1
                        continue
                    if policy == "DIRECT":
                        upstream_allow.add((kind,domain))
                        continue
                    if policy != "REJECT":
                        quarantine["domain-policy"] += 1
                        continue
                    domain_hits[(kind,domain)].add(entry["family"])
                    continue
                if kind == "URL-REGEX" and policy == "REJECT" and all(x.lower()=="extended-matching" for x in fields[3:]):
                    candidate = (fields[1],"reject")
                else:
                    quarantine["unsupported-rule"] += 1
                    continue
            elif section in {"rewrite","url rewrite","map local"}:
                candidate = parse_rewrite(section,line)
            else:
                quarantine["excluded-section:"+section] += 1
                continue
            if not candidate:
                quarantine["unsupported-rewrite"] += 1
                continue
            qualified = url_candidate(candidate[0],protected)
            if not qualified:
                quarantine["unsafe-or-ambiguous-url"] += 1
                continue
            pattern,host = qualified
            url_hits[pattern].add(candidate[1])
            url_hosts[pattern] = host

    accepted = set()
    for (kind,domain),families in domain_hits.items():
        if blocked_domain(kind,domain,protected,upstream_allow):
            quarantine["protected-domain"] += 1
            continue
        if not any(AD_LABEL.fullmatch(label) for label in domain.split(".")[:-1]):
            quarantine["ambiguous-domain"] += 1
            continue
        if kind == "DOMAIN-SUFFIX" and (len(families)<2 or domain in PUBLIC_SUFFIX):
            quarantine["unconfirmed-suffix"] += 1
            continue
        accepted.add((kind,domain))
    suffixes = {domain for kind,domain in accepted if kind=="DOMAIN-SUFFIX"}
    domains = sorted((kind,domain) for kind,domain in accepted if not any(matches_domain(domain,suffix,True) and (kind!="DOMAIN-SUFFIX" or domain!=suffix) for suffix in suffixes))
    rules = [f"{kind},{domain},REJECT" for kind,domain in domains]
    rewrite, maps, hosts = [], [], set()
    for pattern,actions in sorted(url_hits.items()):
        host = url_hosts[pattern]
        if len(actions) != 1:
            quarantine["conflicting-rewrite"] += 1
            continue
        if any(matches_domain(host,domain,kind=="DOMAIN-SUFFIX") for kind,domain in domains):
            quarantine["covered-by-domain"] += 1
            continue
        if any(matches_domain(host,x,k=="DOMAIN-SUFFIX") for k,x in upstream_allow):
            quarantine["upstream-allowed-url"] += 1
            continue
        action = next(iter(actions))
        if action == "reject":
            rewrite.append(f'{pattern} - reject')
        else:
            maps.append(f'{pattern} {MAP[action]}')
        if not pattern.startswith("^http://"):
            hosts.add(host)
    sections = [("Rule",rules),("URL Rewrite",rewrite),("Map Local",maps),("MITM",["hostname = %APPEND% "+",".join(sorted(hosts))] if hosts else [])]
    output = ["#!name=SuperAdBlock","#!desc=Conservative merged ad-blocking module; source and safety audit in Net-Link","#!category=Advertising"]
    for section,lines in sections:
        if lines:
            output.extend(["",f"[{section}]",*lines])
    module = "\n".join(output)+"\n"
    if len(rules)+len(rewrite)+len(maps)<50:
        raise ValueError("Insufficient safe rules")
    (work/"SuperAdBlock.sgmodule").write_text(module,encoding="utf-8")
    report = {"sources":49,"input_sections":dict(counts),"quarantine":dict(quarantine),"output":{"rules":len(rules),"url_rewrite":len(rewrite),"map_local":len(maps),"mitm_hosts":len(hosts),"sha256":digest(module.encode())}}
    dump(work/"audit.json",report)
    return report

def validate(work):
    data = (work/"SuperAdBlock.sgmodule").read_bytes()
    audit = (work/"audit.json").read_bytes()
    build(work)
    if data != (work/"SuperAdBlock.sgmodule").read_bytes() or audit != (work/"audit.json").read_bytes():
        raise ValueError("Non-reproducible output")
    if b"[Script]" in data or b"[General]" in data or b"script-path=" in data:
        raise ValueError("Executable or global config")
    return json.loads(audit)

def approved():
    config = json.loads(APPROVAL.read_text(encoding="utf-8"))
    approved_urls = {x["url"] for x in config.get("sources",[]) if x.get("redistribution") is True and x.get("evidence") and x.get("license")}
    return config.get("enabled") is True and approved_urls == set(sources()) and bool(config.get("combined_license_review"))

def stage(work):
    if not approved():
        raise ValueError("Public redistribution not approved")
    validate(work)
    target = ROOT/"data/super-adblock/upstream"
    target.mkdir(parents=True,exist_ok=True)
    for path in target.iterdir():
        if path.is_file():
            path.unlink()
    for path in (work/"upstream").iterdir():
        shutil.copyfile(path,target/path.name)
    for name,dest in [("manifest.json","data/reports/super_adblock_download_manifest.json"),("audit.json","data/reports/super_adblock_audit.json"),("SuperAdBlock.sgmodule","Surge/Module/SuperAdBlock.sgmodule")]:
        shutil.copyfile(work/name,ROOT/dest)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("action",choices=["fetch","build","validate","stage","approved"])
    parser.add_argument("work",type=Path)
    args = parser.parse_args()
    if args.action=="approved":
        print("true" if approved() else "false")
    elif args.action=="fetch":
        fetch(args.work)
    elif args.action=="build":
        build(args.work)
    elif args.action=="validate":
        print(json.dumps(validate(args.work)["output"],sort_keys=True))
    else:
        stage(args.work)

if __name__=="__main__":
    main()
