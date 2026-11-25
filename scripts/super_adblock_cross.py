from __future__ import annotations

import json
import re
import sys
from collections import Counter,defaultdict
from pathlib import Path
from super_adblock import ROOT, digest, dump, normalize_pattern, parse_csv, matches_domain, scopes_overlap, url_candidate, protected_domains, blocked_domain

TARGETS=("Surge/Module/StartUpAds.sgmodule","Surge/Module/Adblock4limbo.sgmodule","Surge/Rules/AdblockSet.list")
SECTION={"url rewrite","map local","body rewrite","script","header rewrite","rule"}

def rows(text,source):
    section="rule" if source.endswith(".list") else ""
    for i,original in enumerate(text.splitlines(),1):
        line=original.strip()
        if re.fullmatch(r"\[[^\]]+\]",line):
            section=line[1:-1].lower()
            continue
        if not line or section not in SECTION:
            continue
        if line.startswith("#!REQUIREMENT "):
            line=re.sub(r"^#!REQUIREMENT\s+CORE_VERSION[><=]+\d+\s+","",line)
        elif line.startswith(("#",";","//")):
            continue
        item={"source":source,"line":i,"sha256":digest(original.strip().encode()),"section":section}
        if section=="rule":
            fields=parse_csv(line)
            if len(fields)>=2 and fields[0].upper() in {"DOMAIN","DOMAIN-SUFFIX"}:
                yield {**item,"kind":fields[0].upper(),"host":fields[1].lower().rstrip("."),"action":fields[2].upper() if len(fields)>2 else "REJECT"}
            elif source.endswith(".list") and re.fullmatch(r"[a-zA-Z0-9.-]+",line):
                yield {**item,"kind":"DOMAIN-SUFFIX" if line.startswith(".") else "DOMAIN","host":line.lower().strip("."),"action":"REJECT"}
            else:
                yield {**item,"kind":"unsupported"}
            continue
        if section=="script":
            m=re.search(r"(?:^|,\s*)pattern=([^,]+)",line)
            raw=m.group(1).strip() if m else ""
        elif section in {"body rewrite","header rewrite"}:
            parts=line.split()
            raw=parts[1] if len(parts)>1 else ""
        else:
            raw=line.split()[0]
        pattern=normalize_pattern(raw)
        if not pattern:
            yield {**item,"kind":"unsupported"}
            continue
        host=re.match(r"^\^https?\??://([a-zA-Z0-9-]+(?:\\\.[a-zA-Z0-9-]+)+)(?:/|$)",pattern)
        if not host:
            yield {**item,"kind":"unsupported"}
            continue
        yield {**item,"kind":"url","host":host.group(1).replace(r"\.","." ).lower(),"pattern":pattern}

def compare(candidate,existing):
    domains=defaultdict(list)
    suffixes=defaultdict(list)
    urls=defaultdict(list)
    for row in existing:
        if row["kind"]=="DOMAIN": domains[row["host"]].append(row)
        elif row["kind"]=="DOMAIN-SUFFIX": suffixes[row["host"]].append(row)
        elif row["kind"]=="url": urls[row["host"]].append(row)
    counts=Counter()
    examples=[]
    for row in candidate:
        if row["kind"]=="unsupported": continue
        host=row["host"]
        parts=host.split(".")
        matched=list(domains[host])
        for i in range(len(parts)-1):
            matched.extend(suffixes[".".join(parts[i:])])
        if row["kind"]=="DOMAIN-SUFFIX":
            matched.extend(x for h,items in domains.items() if h.endswith("."+host) for x in items)
            matched.extend(x for h,items in suffixes.items() if h.endswith("."+host) for x in items)
        if row["kind"]=="url":
            matched.extend(x for x in urls[host] if scopes_overlap(row["pattern"],x["pattern"]))
        else:
            matched.extend(urls[host])
            if row["kind"]=="DOMAIN-SUFFIX":
                matched.extend(x for h,items in urls.items() if h.endswith("."+host) for x in items)
        for other in matched:
            if other["kind"] in {"DOMAIN","DOMAIN-SUFFIX"} and other["action"] not in {"REJECT","REJECT-DROP","REJECT-TINYGIF","REJECT-NO-DROP"}:
                category="non-reject-domain-conflict"
            elif row["kind"]==other["kind"]=="url":
                category="exact-url-overlap" if row["pattern"]==other["pattern"] else "possible-url-overlap"
            elif row["kind"]=="url" or other["kind"]=="url":
                category="domain-url-overlap"
            else:
                category="domain-overlap"
            counts[category]+=1
            if len(examples)<500:
                examples.append({"category":category,"candidate":{k:row[k] for k in ("line","sha256","section")},"existing":{k:other[k] for k in ("source","line","sha256","section")}})
    return {"counts":dict(counts),"examples":examples,"examples_capped":sum(counts.values())>len(examples)}

def run(work):
    module=work/"SuperAdBlock.sgmodule"
    candidate=list(rows(module.read_text(),"candidate"))
    existing=[]
    inputs={}
    for path in TARGETS:
        raw=(ROOT/path).read_bytes()
        records=list(rows(raw.decode("utf-8-sig"),path))
        existing.extend(records)
        inputs[path]={"sha256":digest(raw),"records":len(records),"unsupported":sum(r["kind"]=="unsupported" for r in records)}
    report=compare(candidate,existing)
    report.update(inputs=inputs,candidate_records=len(candidate),candidate_unsupported=sum(r["kind"]=="unsupported" for r in candidate),scope="static exact-domain and conservative literal-host URL overlap; unsupported syntax counted, not deemed safe",module_sha256=digest(module.read_bytes()))
    dump(work/"cross-audit.json",report)
    print(json.dumps({"counts":report["counts"],"candidate_records":len(candidate),"candidate_unsupported":report["candidate_unsupported"],"inputs":inputs},sort_keys=True))
    return report

if __name__=="__main__":
    run(Path(sys.argv[1]))
