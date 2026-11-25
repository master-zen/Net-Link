from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import re
import shutil
import shlex
import fnmatch
import super_adblock_scripts as sec
import sys
import time
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from urllib.parse import quote, unquote, urlsplit, urlunsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener
from urllib.error import HTTPError, URLError

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "data/sources/SuperAdBlock_URLs.txt"
APPROVAL = ROOT / "data/sources/SuperAdBlock_publication.json"
ALLOW = ROOT / "data/allowlists/AdblockCriticalAllow.list"
sys.path.insert(0, str(ROOT / "Surge/Module/.generator"))
from safety import should_skip_rewrite, is_protected_mitm_host, PROTECTED_MITM_HOSTS

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
    if not result or len({canonical_url(u) for u in result}) != len(result):
        raise ValueError("Invalid source inventory")
    return result

def safe_url(url):
    u = urlsplit(url)
    if u.scheme != "https" or u.hostname not in HOSTS or u.username or u.password or u.port or u.fragment:
        raise ValueError("Unapproved source endpoint")
    path=unquote(u.path,errors="strict")
    if not path.startswith("/") or "\\" in path or any(ord(c)<32 or ord(c)==127 for c in path) or any(p in {"",".",".."} for p in path[1:].split("/")) or re.search(r"%2f|%5c|%25",u.path,re.I):
        raise ValueError("Unsafe source path")
    if u.query:
        raise ValueError("Source query not permitted")
    return urlunsplit((u.scheme, u.hostname, quote(path, safe="/"), "", ""))

def canonical_url(url):
    endpoint=safe_url(url)
    if urlsplit(endpoint).hostname=="raw.githubusercontent.com":
        endpoint=endpoint.replace("/refs/heads/","/",1)
    return endpoint

class Redirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return super().redirect_request(req, fp, code, msg, headers, safe_url(newurl))

def family(url):
    u=urlsplit(safe_url(url))
    owner,repo,*_=u.path.strip("/").split("/")
    identity=(owner.lower(),repo.lower())
    if u.hostname=="kelee.one" or identity==("qingrex","loonkisssurge"):
        return "kelee"
    if identity==("tg-twilight","awavenue-ads-rule"):
        return "awavenue"
    if identity==("blackmatrix7","ios_rule_script"):
        return "blackmatrix7"
    if identity in {("amlabort","my_clash"),("maasea","sgmodule"),("master-zen","net-link"),("fmz200","wool_scripts"),("app2smile","rules")}:
        return "unverified-lineage"
    raise ValueError("Unknown source family")

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
        except Exception as exc:
            permanent=isinstance(exc,ValueError) or isinstance(exc,HTTPError) and exc.code not in {408,425,429,500,502,503,504}
            if attempt == 2 or permanent:
                reason = (f"HTTP {exc.code}" if isinstance(exc, HTTPError) else
                          type(exc.reason).__name__ if isinstance(exc, URLError) else
                          str(exc) if isinstance(exc, ValueError) else type(exc).__name__)
                return {"url":url,"family":family(url),"file":path,"error":reason[:180]}
            time.sleep(2 ** attempt)

def fetch(work):
    if work.exists():
        raise ValueError("Workspace already exists")
    base = work / "upstream"
    base.mkdir(parents=True)
    with ThreadPoolExecutor(max_workers=10) as pool:
        entries = list(pool.map(lambda pair: download_one(pair,base), enumerate(sources(),1)))
    failures = [x for x in entries if "error" in x]
    dump(work / "manifest.json", {"run_id":os.getenv("GITHUB_RUN_ID","local"),"run_attempt":os.getenv("GITHUB_RUN_ATTEMPT","1"),"epoch_seconds":int(time.time()),"sources":entries,"downloaded":len(entries)-len(failures),"failed":len(failures)})


def snapshots(work, review=False):
    manifest = json.loads((work / "manifest.json").read_text(encoding="utf-8"))
    if manifest["run_id"] != os.getenv("GITHUB_RUN_ID","local") or manifest["run_attempt"] != os.getenv("GITHUB_RUN_ATTEMPT","1"):
        raise ValueError("Stale manifest")
    failures=sum("error" in e for e in manifest["sources"])
    if manifest.get("failed")!=failures or ("downloaded" in manifest and manifest["downloaded"]!=len(manifest["sources"])-failures):
        raise ValueError("Inconsistent manifest counts")
    if (failures and not review) or [x["url"] for x in manifest["sources"]] != sources():
        raise ValueError("Incomplete manifest")
    for i, entry in enumerate(manifest["sources"],1):
        expected = f"{i:02d}-{urlsplit(entry['url']).path.rsplit('/',1)[-1]}"
        if entry["file"] != expected or entry["family"] != family(entry["url"]):
            raise ValueError("Invalid manifest path or source family")
        if "error" in entry:
            if review:
                continue
            raise ValueError("Failed snapshot")
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

def protected_mitm(host):
    return is_protected_mitm_host(host) or any(fnmatch.fnmatchcase(host, x) for x in PROTECTED_MITM_HOSTS)

def blocked_domain(kind, domain, protected, upstream_allow):
    if protected_mitm(domain):
        return True
    if kind=="DOMAIN-SUFFIX" and any("*" in h and (h.endswith("."+domain) or h.lstrip("*.")==domain) for h in PROTECTED_MITM_HOSTS):
        return True
    if any(SENSITIVE.search("/"+label+"/") for label in domain.split(".")[:-1]):
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

def url_candidate(pattern, protected, body=False):
    pattern = normalize_pattern(pattern)
    if not pattern:
        return None
    match = re.match(r"^\^https?\??://([a-zA-Z0-9-]+(?:\\\.[a-zA-Z0-9-]+)+)(/.*)$",pattern)
    if not match:
        return None
    host = normalize_domain(match.group(1).replace(r"\.","."))
    path = match.group(2)
    if not host or protected_mitm(host):
        return None
    if pattern in DOUBAN:
        if body:
            return None
        if path=="/v2/app_ads/splash":
            return pattern+r"(?:[/?&]|$)",host
        return r"^https?://api\.douban\.com/b[^?#]*/common_ads\?",host
    if any(matches_domain(host,x,True) for x in protected):
        return None
    if not re.fullmatch(r"(?:[A-Za-z0-9_/=&-]|\\[.?])+\$?", path):
        return None
    if should_skip_rewrite(pattern) or SENSITIVE.search(path) or (not body and not AD_PATH.search(path.rstrip("$"))):
        return None
    if re.search(r"\\[1-9]|\(\?|\([^)]*[+*][^)]*\)[+*{]|\.\*[+*]|\{[0-9]{4,}",path):
        return None
    if re.search(r"\.(?:mp4|m3u8|mov|m4s|ts)(?:$|\\|\?)",path,re.I):
        return None
    if re.search(r"(?i)(?:login|password|oauth|payment|checkout|location|trailer|playurl)",path):
        return None
    if body:
        route=path.removesuffix("$").removesuffix(r"\?")
        if route.count("/")<2 or route.endswith("/") or not re.fullmatch(r"(?:[A-Za-z0-9_/-]|\\.)+",route):
            return None
        if not path.endswith(("$",r"\?")):
            pattern+=r"(?:\?|$)"
    elif not path.endswith(("/", "$", r"\?")):
        pattern += r"(?:[/?&]|$)"
    return pattern,host

def scopes_overlap(left,right):
    def scope(p):
        m=re.match(r"^\^(https\?|https|http)://([^/]+)(/.*)$",p)
        if not m:
            return None
        scheme,host,path=m.groups()
        scheme={"http","https"} if scheme=="https?" else {scheme}
        path=path.removesuffix(r"(?:[/?&]|$)").removesuffix(r"(?:\?|$)").removesuffix("$")
        if not re.fullmatch(r"(?:[A-Za-z0-9_/=&-]|\\[.?])+",path):
            path=None
        else:
            path=path.replace(r"\.","." ).replace(r"\?","?")
        return scheme,host.lower(),path
    a,b=scope(left),scope(right)
    if not a or not b:
        return True
    if not a[0]&b[0] or a[1]!=b[1]:
        return False
    return a[2] is None or b[2] is None or a[2].startswith(b[2]) or b[2].startswith(a[2])

def rewrite_conflicts(hits,hosts):
    groups=defaultdict(list)
    for p in hits:
        groups[hosts[p]].append(p)
    result=set()
    for patterns in groups.values():
        for i,p in enumerate(patterns):
            if len(hits[p])!=1:
                result.add(p)
            for q in patterns[i+1:]:
                if hits[p]!=hits[q] and scopes_overlap(p,q):
                    result.update((p,q))
    return result

AD_JSON_KEYS={"ad","ads","adinfo","adlist","aditems","adpayload","advert","adverts","advertisement","advertisements","advertising","admetadata","adconfig","splashad","splashads","splashadvertisement","promotedads","commentspageads","adbanner","adslots","adslot","adcontent"}
JSON_PARENTS={"data","result","response","payload","body","content","page","detail","info"}
def parse_body(line,protected):
    m=re.fullmatch(r"http-response-jq\s+(\S+)\s+(['\"])(.+)\2",line)
    if not m or len(line)>2048:
        return None
    pattern,_,expression=m.groups()
    qualified=url_candidate(pattern,protected,body=True)
    if not qualified:
        return None
    if expression.startswith("delpaths(") and expression.endswith(")"):
        try:
            paths=json.loads(expression[9:-1])
        except ValueError:
            return None
    elif re.fullmatch(r"del\(\s*\.[A-Za-z_][A-Za-z0-9_.]*(?:\s*,\s*\.[A-Za-z_][A-Za-z0-9_.]*)*\s*\)",expression):
        paths=[p.strip()[1:].split(".") for p in expression[4:-1].split(",")]
    else:
        return None
    if not isinstance(paths,list) or not 1<=len(paths)<=16:
        return None
    for path in paths:
        if not isinstance(path,list) or not 1<=len(path)<=4 or not all(isinstance(k,str) and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*",k) for k in path):
            return None
        if path[-1].lower() not in AD_JSON_KEYS or any(k.lower() not in JSON_PARENTS for k in path[:-1]):
            return None
    return (*qualified,{tuple(p) for p in paths})

def body_expression(paths):
    return ". as $original | try (if type == \"object\" then delpaths("+json.dumps([list(p) for p in sorted(paths)],separators=(",",":"))+") else . end) catch $original"

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
        pattern, sep, raw = line.partition(" ")
        if not sep:
            return None
        try:
            args = shlex.split(raw)
            if len(args) != len({x.split("=",1)[0] for x in args}):
                return None
            args=[x.replace("Content-Type:application/json;charset=utf-8","Content-Type:application/json").replace("Content-Type:application/json; charset=utf-8","Content-Type:application/json") for x in args]
            for action, value in MAP.items():
                reference=[x.replace("Content-Type:application/json;charset=utf-8","Content-Type:application/json") for x in shlex.split(value)]
                if sorted(args) == sorted(reference):
                    return pattern.strip('"'), action
        except ValueError:
            return None
    return None

def build(work, review=False):
    protected = protected_domains()
    domain_hits = defaultdict(set)
    url_hits = defaultdict(set)
    url_hosts = {}
    upstream_allow = set()
    counts = Counter()
    quarantine = Counter()
    source_sections = {}
    cleared = sec.eligible(work, review=review)
    script_hits = defaultdict(set)
    script_origins = defaultdict(set)
    body_hits = defaultdict(set)
    seen_content = set()
    content_sources=defaultdict(list)
    for entry, text in snapshots(work, review=review):
        source_sections[entry["url"]] = Counter()
        if not review and "/QingRex/LoonKissSurge/" in entry["url"] and "/Surge/Beta/" in entry["url"]:
            quarantine["beta-review-only"] += 1
            continue
        fingerprint=entry["sha256"]
        content_sources[fingerprint].append(entry["url"])
        if fingerprint in seen_content:
            quarantine["duplicate-source-content"] += 1
            continue
        seen_content.add(fingerprint)
        section = ""
        for original in text.splitlines():
            line = original.strip()
            if not line or line.startswith(("#",";","//")):
                continue
            if re.fullmatch(r"\[[^\]]+\]",line):
                section = line[1:-1].lower()
                continue
            counts[section] += 1
            source_sections[entry["url"]][section] += 1
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
                    if policy not in {"REJECT","REJECT-DROP","REJECT-TINYGIF","REJECT-NO-DROP"}:
                        upstream_allow.add((kind,domain))
                        quarantine["non-reject-policy-protected"] += 1
                        continue
                    if policy!="REJECT":
                        quarantine["different-reject-semantics"] += 1
                        continue
                    domain_hits[(kind,domain)].add(entry["family"])
                    continue
                if kind == "URL-REGEX" and policy == "REJECT" and all(x.lower()=="extended-matching" for x in fields[3:]):
                    candidate = (fields[1],"reject")
                else:
                    quarantine["unsupported-rule"] += 1
                    continue
            elif section == "body rewrite":
                parsed=parse_body(line,protected)
                if not parsed:
                    quarantine["unsupported-or-unsafe-body-rewrite"] += 1
                    continue
                pattern,host,paths=parsed
                body_hits[pattern].update(paths)
                url_hosts[pattern]=host
                continue
            elif section == "script":
                spec = sec.declaration(line)
                if not spec or spec[1] not in cleared:
                    quarantine["script-not-cleared-or-unsupported"] += 1
                    continue
                pattern,url=spec
                qualified=url_candidate(pattern,protected)
                if not qualified or qualified[1]=="api.douban.com":
                    quarantine["script-functional-risk"] += 1
                    continue
                pattern,host=qualified
                h=cleared[url]
                script_hits[pattern].add(h)
                script_origins[h].add(url)
                url_hosts[pattern]=host
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
        if kind == "DOMAIN-SUFFIX" and (len(families - {"unverified-lineage"}) < 2 or domain in PUBLIC_SUFFIX):
            quarantine["unconfirmed-suffix"] += 1
            continue
        accepted.add((kind,domain))
    suffixes = {domain for kind,domain in accepted if kind=="DOMAIN-SUFFIX"}
    domains = sorted((kind,domain) for kind,domain in accepted if not any(matches_domain(domain,suffix,True) and (kind!="DOMAIN-SUFFIX" or domain!=suffix) for suffix in suffixes))
    rules = [f"{kind},{domain},REJECT" for kind,domain in domains]
    rewrite, maps, hosts = [], [], set()
    conflicts=rewrite_conflicts(url_hits,url_hosts)
    cross=set()
    collections=[url_hits,body_hits,script_hits]
    for i,group in enumerate(collections):
        for other in collections[i+1:]:
            for a in group:
                for b in other:
                    if url_hosts[a]==url_hosts[b] and scopes_overlap(a,b):
                        cross.update((a,b))
    conflicts.update(cross)
    for pattern,actions in sorted(url_hits.items()):
        host = url_hosts[pattern]
        if pattern in conflicts:
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
            rewrite.append(f'{pattern} _ reject')
        else:
            maps.append(f'{pattern} {MAP[action]}')
        if not pattern.startswith("^http://"):
            hosts.add(host)
    bodies=[]
    for pattern,paths in sorted(body_hits.items()):
        host=url_hosts[pattern]
        if pattern in cross or any(matches_domain(host,a,k=="DOMAIN-SUFFIX") for k,a in [*domains,*upstream_allow]):
            quarantine["body-conflict-or-covered"] += 1
            continue
        if len(paths)>16:
            quarantine["body-field-limit"] += 1
            continue
        bodies.append(f"#!REQUIREMENT CORE_VERSION>=6008000 http-response-jq {pattern} '{body_expression(paths)}'")
        if not pattern.startswith("^http://"):
            hosts.add(host)
    scripts, published = [], {}
    for pattern,hashes in sorted(script_hits.items()):
        host=url_hosts[pattern]
        if pattern in cross or len(hashes)!=1 or any(url_hosts[k]==host and scopes_overlap(pattern,k) for k in url_hits) or any(k!=pattern and url_hosts[k]==host and scopes_overlap(pattern,k) for k in script_hits):
            quarantine["script-conflict"] += 1
            continue
        if any(matches_domain(host,domain,kind=="DOMAIN-SUFFIX") for kind,domain in domains) or any(matches_domain(host,a,k=="DOMAIN-SUFFIX") for k,a in upstream_allow):
            quarantine["script-covered-or-allowed"] += 1
            continue
        h=next(iter(hashes))
        name="super-"+digest((pattern+h).encode())[:20]
        scripts.append(f"{name} = type=http-response,pattern={pattern},requires-body=true,max-size=1048576,timeout=5,script-path={sec.PREFIX}{h}.js")
        published[h]=sorted(set(published.get(h,[]))|script_origins[h])
        if not pattern.startswith("^http://"):
            hosts.add(host)
    sections = [("Rule",rules),("URL Rewrite",rewrite),("Map Local",maps),("Body Rewrite",bodies),("Script",scripts),("MITM",["hostname = %APPEND% "+",".join(sorted(hosts))] if hosts else [])]
    output = ["#!name=SuperAdBlock","#!desc=Conservative merged ad-blocking module; source and safety audit in Net-Link","#!category=Advertising"]
    for section,lines in sections:
        if lines:
            output.extend(["",f"[{section}]",*lines])
    module = "\n".join(output)+"\n"
    if len(rules)+len(rewrite)+len(maps)+len(bodies)+len(scripts)<50:
        raise ValueError("Insufficient safe rules")
    (work/("SuperAdBlock.review.sgmodule" if review else "SuperAdBlock.sgmodule")).write_text(module,encoding="utf-8")
    manifest=json.loads((work/"manifest.json").read_text(encoding="utf-8"))
    alternatives=json.loads((ROOT/"data/sources/SuperAdBlock_alternatives.json").read_text(encoding="utf-8"))["alternatives"]
    success={e["url"] for e in manifest["sources"] if "error" not in e}
    report = {"duplicate_content_groups":[v for v in content_sources.values() if len(v)>1],"source_status":{e["url"]:{"family":e["family"],"status":"failed" if "error" in e else "downloaded","beta":"/Surge/Beta/" in e["url"]} for e in manifest["sources"]},"failure_reasons":dict(Counter(e["error"] for e in manifest["sources"] if "error" in e)),"review_only":review,"downloaded":len(success),"failed":len(manifest["sources"])-len(success),"alternative_coverage":sum(a in success and u not in success for u,a in alternatives.items()),"sources":len(sources()),"input_sections":dict(counts),"source_sections":source_sections,"published_scripts":published,"script_audit_sha256":digest((work/"script-audit.json").read_bytes()),"quarantine":dict(quarantine),"output":{"rules":len(rules),"url_rewrite":len(rewrite),"map_local":len(maps),"body_rewrite":len(bodies),"scripts":len(scripts),"mitm_hosts":len(hosts),"sha256":digest(module.encode())}}
    dump(work/("review-audit.json" if review else "audit.json"),report)
    return report

def validate(work, review=False):
    module=work/("SuperAdBlock.review.sgmodule" if review else "SuperAdBlock.sgmodule")
    report=work/("review-audit.json" if review else "audit.json")
    data = module.read_bytes()
    audit = report.read_bytes()
    build(work,review=review)
    if data != module.read_bytes() or audit != report.read_bytes():
        raise ValueError("Non-reproducible output")
    if b"[General]" in data:
        raise ValueError("Global config")
    for line in data.decode().splitlines():
        if "script-path=" in line:
            ref=line.split("script-path=",1)[1]
            if not ref.startswith(sec.PREFIX) or not re.fullmatch(r"[0-9a-f]{64}\.js",ref[len(sec.PREFIX):]):
                raise ValueError("Unpinned script")
    return json.loads(audit)

def approved(work=None):
    config = json.loads(APPROVAL.read_text(encoding="utf-8"))
    approved_urls = {x["url"] for x in config.get("sources",[]) if x.get("redistribution") is True and x.get("evidence") and x.get("license")}
    if not (config.get("enabled") is True and approved_urls == set(sources()) and config.get("combined_license_review")):
        return False
    if work is not None:
        if not (work/"audit.json").exists() or not (work/"manifest.json").exists():
            return False
        if json.loads((work/"manifest.json").read_text())["failed"] or json.loads((work/"audit.json").read_text()).get("review_only",True):
            return False
        required={(u,h) for h,urls in json.loads((work/"audit.json").read_text())["published_scripts"].items() for u in urls}
        allowed={(e["url"],e.get("sha256")) for e in config.get("scripts",[]) if e.get("redistribution") is True and e.get("license") and e.get("evidence")}
        return required <= allowed
    return True

def stage(work):
    if not approved(work):
        raise ValueError("Public redistribution not approved")
    validate(work)
    target = ROOT/"data/super-adblock/upstream"
    target.mkdir(parents=True,exist_ok=True)
    for path in target.iterdir():
        if path.is_file():
            path.unlink()
    for entry,_ in snapshots(work):
        path=work/"upstream"/entry["file"]
        shutil.copyfile(path,target/path.name)
    published=json.loads((work/"audit.json").read_text())["published_scripts"]
    runtime=ROOT/sec.RUNTIME
    runtime.mkdir(parents=True,exist_ok=True)
    for h in published:
        raw=(work/"script-snapshots"/(h+".js")).read_bytes()
        target=runtime/(h+".js")
        if digest(raw)!=h or (target.exists() and target.read_bytes()!=raw):
            raise ValueError("Runtime integrity failure")
        target.write_bytes(raw)
    dump(runtime/"manifest.json",published)
    shutil.copyfile(work/"script-audit.json",ROOT/"data/reports/super_adblock_script_audit.json")
    for name,dest in [("manifest.json","data/reports/super_adblock_download_manifest.json"),("audit.json","data/reports/super_adblock_audit.json"),("SuperAdBlock.sgmodule","Surge/Module/SuperAdBlock.sgmodule")]:
        shutil.copyfile(work/name,ROOT/dest)

def verify_release(work):
    work.mkdir(parents=True,exist_ok=False)
    reports=ROOT/"data/reports"
    for name,source in [("manifest.json","super_adblock_download_manifest.json"),("audit.json","super_adblock_audit.json"),("script-audit.json","super_adblock_script_audit.json")]:
        shutil.copyfile(reports/source,work/name)
    shutil.copyfile(ROOT/"Surge/Module/SuperAdBlock.sgmodule",work/"SuperAdBlock.sgmodule")
    shutil.copytree(ROOT/"data/super-adblock/upstream",work/"upstream")
    report=json.loads((work/"audit.json").read_bytes())
    runtime=ROOT/sec.RUNTIME
    (work/"script-snapshots").mkdir()
    for e in json.loads((work/"script-audit.json").read_bytes())["entries"]:
        if e["decision"]!="eligible":
            continue
        h=e["sha256"]
        if not re.fullmatch(r"[a-f0-9]{64}",h):
            raise ValueError("Invalid eligible script hash")
        path=runtime/(h+".js")
        if h in report["published_scripts"]:
            shutil.copyfile(path,work/"script-snapshots"/path.name)
    if not approved(work):
        raise ValueError("Release not approved")
    manifest=json.loads((work/"manifest.json").read_bytes())
    if manifest["run_id"]!=os.getenv("GITHUB_RUN_ID","local") or manifest["run_attempt"]!=os.getenv("GITHUB_RUN_ATTEMPT","1"):
        raise ValueError("Stale release")
    if set(p.name for p in (work/"upstream").iterdir())!={e["file"] for e in manifest["sources"]}:
        raise ValueError("Unexpected released upstream files")
    list(snapshots(work))
    if digest((work/"SuperAdBlock.sgmodule").read_bytes())!=report["output"]["sha256"] or digest((work/"script-audit.json").read_bytes())!=report["script_audit_sha256"]:
        raise ValueError("Release checksum failure")
    refs=set(re.findall(re.escape(sec.PREFIX)+r"([0-9a-f]{64})\.js",(work/"SuperAdBlock.sgmodule").read_text()))
    if refs!=set(report["published_scripts"]):
        raise ValueError("Release script inventory mismatch")
    for h in refs:
        if digest((work/"script-snapshots"/(h+".js")).read_bytes())!=h:
            raise ValueError("Release script checksum failure")
    if json.loads((runtime/"manifest.json").read_bytes())!=report["published_scripts"]:
        raise ValueError("Release runtime manifest mismatch")
    for path in runtime.iterdir():
        if path.name=="manifest.json":
            continue
        if not path.is_file() or not re.fullmatch(r"[a-f0-9]{64}\.js",path.name) or digest(path.read_bytes())!=path.stem:
            raise ValueError("Unexpected or modified runtime file")

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("action",choices=["fetch","build","validate","review","review-validate","stage","approved","verify-release"])
    parser.add_argument("work",type=Path)
    args = parser.parse_args()
    if args.action=="approved":
        print("true" if approved(args.work) else "false")
    elif args.action=="fetch":
        fetch(args.work)
    elif args.action=="build":
        build(args.work)
    elif args.action=="validate":
        print(json.dumps(validate(args.work)["output"],sort_keys=True))
    elif args.action=="review":
        build(args.work,review=True)
    elif args.action=="review-validate":
        print(json.dumps(validate(args.work,review=True)["output"],sort_keys=True))
    elif args.action=="verify-release":
        verify_release(args.work)
    else:
        stage(args.work)

if __name__=="__main__":
    main()
