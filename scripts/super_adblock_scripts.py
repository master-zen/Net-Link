from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from urllib.request import Request, build_opener
from urllib.parse import urlsplit

ROOT=Path(__file__).resolve().parents[1]
RUNTIME="Surge/Scripts/Converted/SuperAdBlock"
PREFIX="https://raw.githubusercontent.com/master-zen/Net-Link/main/"+RUNTIME+"/"
REF=re.compile(r"""https://[^\s,"'<>]+\.js(?:\?[^\s,"'<>]*)?""",re.I)

def sha(data):
    return hashlib.sha256(data).hexdigest()

def discover(text):
    section=""
    result=set()
    for raw in text.splitlines():
        line=raw.strip()
        if not line or line.startswith(("#",";","//")):
            continue
        if re.fullmatch(r"\[[^\]]+\]",line):
            section=line[1:-1].lower()
        elif section=="script":
            result.update(REF.findall(line))
            result.update(re.findall(r"""(?i)\bscript-path\s*=\s*["']?(https://[^\s,"'<>]+)""",line))
    return result

def declaration(line):
    if "{{{" in line or len(line)>2048:
        return None
    _,sep,rest=line.partition("=")
    if sep and re.match(r"\s*type=",rest):
        parts=rest.split(",")
        pattern=None
    else:
        m=re.fullmatch(r"http-response\s+(\S+)\s+(.+)",line)
        if not m:
            return None
        pattern=m.group(1)
        parts=re.split(r",\s*|\s+(?=[\w-]+=)",m.group(2))
    fields={}
    for part in parts:
        key,eq,value=part.strip().partition("=")
        if not eq or key in fields:
            return None
        fields[key]=value.strip()
    if fields.get("type","http-response")!="http-response" or fields.get("requires-body") not in {"1","true"}:
        return None
    if set(fields)-{"type","pattern","script-path","requires-body","timeout","max-size","binary-body-mode","tag","script-update-interval"}:
        return None
    if fields.get("binary-body-mode","false") not in {"0","false"}:
        return None
    pattern=pattern or fields.get("pattern")
    url=fields.get("script-path")
    return (pattern,url) if pattern and url else None

def download(url,folder):
    from super_adblock import safe_url,Redirect
    try:
        endpoint=safe_url(url)
        with build_opener(Redirect()).open(Request(endpoint,headers={"User-Agent":"Net-Link-SuperAdBlock/1.0","Accept":"text/plain,*/*"}),timeout=25) as response:
            safe_url(response.geturl())
            raw=response.read(2*1024*1024+1)
        if not raw or len(raw)>2*1024*1024 or b"\x00" in raw or raw.lstrip().lower().startswith((b"<html",b"<!doctype")):
            raise ValueError("invalid-script")
        raw.decode("utf-8-sig")
        h=sha(raw)
        target=folder/(h+".js")
        try:
            with target.open("xb") as out:
                out.write(raw)
        except FileExistsError:
            pass
        return {"url":url,"sha256":h,"bytes":len(raw),"download":"ok"}
    except Exception as exc:
        return {"url":url,"download":"failed","reason":type(exc).__name__,"http_status":getattr(exc,"code",None)}

def batch_scan(folder,hashes,ready):
    if not ready:
        return dict.fromkeys(hashes,"not-verified")
    if not hashes:
        return {}
    result=dict.fromkeys(hashes,"scan-error")
    try:
        run=subprocess.run(["clamscan","--no-summary","--max-filesize=4M","--max-scansize=8M","--alert-exceeds-max=yes",str(folder)],capture_output=True,text=True,timeout=600)
        if run.returncode not in {0,1}:
            return result
        for line in run.stdout.splitlines():
            path,sep,status=line.rpartition(": ")
            if not sep:
                continue
            h=Path(path).stem
            if h not in result or Path(path).parent.resolve()!=folder.resolve():
                continue
            if status=="OK":
                result[h]="no-signature-hit"
            elif status.endswith(" FOUND"):
                result[h]="detected"
        return result
    except (OSError,subprocess.TimeoutExpired):
        return result

def audit(work,ready):
    from super_adblock import snapshots
    manifest=(work/"manifest.json").read_bytes()
    origins={}
    declaration_counts={}
    for entry,body in snapshots(work,review=True):
        refs=discover(body)
        declaration_counts[entry["url"]]=len(refs)
        for url in refs:
            origins.setdefault(url,[]).append(entry["url"])
    urls=set(origins)
    if len(urls)>1000:
        raise ValueError("Excessive script references")
    folder=work/"script-snapshots"
    folder.mkdir(exist_ok=False)
    with ThreadPoolExecutor(max_workers=8) as pool:
        entries=list(pool.map(lambda u:download(u,folder),sorted(urls)))
    findings={}
    hashes=sorted({e["sha256"] for e in entries if e["download"]=="ok"})
    antivirus=batch_scan(folder,hashes,ready)
    for h in hashes:
        file=folder/(h+".js")
        av=antivirus[h]
        try:
            parsed=subprocess.run(["node",str(ROOT/"scripts/super_adblock_ast.cjs"),str(file)],capture_output=True,text=True,timeout=15,check=True)
            ast=json.loads(parsed.stdout)
        except (OSError,subprocess.SubprocessError,ValueError):
            ast={"eligible":False,"reason":"scanner-error"}
        findings[h]={"antivirus":av,"ast":ast,"decision":"eligible" if av=="no-signature-hit" and ast.get("eligible") is True else "quarantine"}
    for e in entries:
        e["sources"]=sorted(origins[e["url"]])
        e.update(findings[e["sha256"]] if e["download"]=="ok" else {"decision":"download-failed"})
    report={"module_manifest_sha256":sha(manifest),"antivirus_ready":ready,"references":len(entries),"unique_downloaded_scripts":len(hashes),"source_reference_counts":declaration_counts,"entries":entries}
    (work/"script-audit.json").write_text(json.dumps(report,ensure_ascii=False,sort_keys=True,indent=2)+"\n",encoding="utf-8")

def eligible(work, review=False):
    report=json.loads((work/"script-audit.json").read_text(encoding="utf-8"))
    if report["module_manifest_sha256"]!=sha((work/"manifest.json").read_bytes()):
        raise ValueError("Stale script audit")
    if report["references"] and not report["antivirus_ready"]:
        if review:
            return {}
        raise ValueError("Antivirus signatures unavailable")
    if any(e.get("antivirus")=="scan-error" or e.get("ast",{}).get("reason")=="scanner-error" for e in report["entries"]):
        if review:
            return {}
        raise ValueError("Script scan failed")
    if report["references"]!=len(report["entries"]) or len({e["url"] for e in report["entries"]})!=len(report["entries"]):
        raise ValueError("Invalid script reference inventory")
    result={}
    for e in report["entries"]:
        if e["decision"]!="eligible":
            continue
        h=e["sha256"]
        if not re.fullmatch(r"[0-9a-f]{64}",h) or e["antivirus"]!="no-signature-hit" or e["ast"]["eligible"] is not True or sha((work/"script-snapshots"/(h+".js")).read_bytes())!=h:
            raise ValueError("Invalid script audit")
        result[e["url"]]=h
    return result

if __name__=="__main__":
    audit(Path(sys.argv[1]),os.getenv("SUPER_ADBLOCK_ANTIVIRUS_READY")=="true")
