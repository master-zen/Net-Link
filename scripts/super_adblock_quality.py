from __future__ import annotations

import json
import math
import os
import sys
from pathlib import Path
from super_adblock import ROOT, dump, digest

POLICY=ROOT/"data/sources/SuperAdBlock_quality_policy.json"
HISTORY=ROOT/"data/reports/super_adblock_quality_history.json"
COUNTS=("rules","url_rewrite","map_local","body_rewrite","scripts","mitm_hosts")
RULES=COUNTS[:-1]

def evaluate(audit,manifest,script,policy,previous=None,cross=None):
    out={k:audit["output"][k] for k in COUNTS}
    reasons=[]
    if audit["review_only"] or manifest["failed"] or audit["failed"] or audit["sources"]!=manifest["downloaded"] or audit["downloaded"]!=manifest["downloaded"]:
        reasons.append("incomplete-or-review")
    if script["references"] and not script["antivirus_ready"]:
        reasons.append("antivirus-unavailable")
    if cross and cross.get("counts",{}).get("non-reject-domain-conflict",0):
        reasons.append("cross-module-functional-conflict")
    if "rule_provenance" in audit and audit.get("provenance_count")!=sum(out[k] for k in RULES):
        reasons.append("incomplete-rule-provenance")
    limits=policy["limits"]
    baselines=[policy["baseline"]["output"]]
    if previous:
        baselines.append(previous["output"])
    for base in baselines:
        old=sum(base[k] for k in RULES)
        new=sum(out[k] for k in RULES)
        if new<old*(1-limits["maximum_total_loss_fraction"]):
            reasons.append("total-rule-loss")
        for k in RULES:
            if base[k]-out[k]>=limits["minimum_section_loss_count"] and out[k]<base[k]*(1-limits["maximum_section_loss_fraction"]):
                reasons.append("section-loss:"+k)
        if out["mitm_hosts"]-base["mitm_hosts"]>=limits["minimum_mitm_growth_count"] and out["mitm_hosts"]>base["mitm_hosts"]*(1+limits["maximum_mitm_growth_fraction"]):
            reasons.append("mitm-growth")
    hashes=sorted({p["rule_sha256"] for p in audit.get("rule_provenance",[])})
    host_hashes=sorted(set(audit.get("mitm_host_hashes",[])))
    old_hashes=set(previous.get("rule_hashes",[])) if previous else set()
    old_hosts=set(previous.get("mitm_host_hashes",[])) if previous else set()
    removed=len(old_hashes-set(hashes))
    added=len(set(hashes)-old_hashes)
    if old_hashes and removed>=10 and removed/len(old_hashes)>limits.get("maximum_rule_churn_fraction",0.25):
        reasons.append("rule-hash-churn")
    if old_hosts and len(set(host_hashes)-old_hosts)>=10 and len(set(host_hashes)-old_hosts)/len(old_hosts)>limits.get("maximum_mitm_growth_fraction",0.25):
        reasons.append("mitm-host-churn")
    return {"rule_hashes":hashes,"mitm_host_hashes":host_hashes,"rules_added":added if old_hashes else None,"rules_removed":removed if old_hashes else None,"cross_counts":cross.get("counts",{}) if cross else {},"passed":not reasons,"reasons":sorted(set(reasons)),"output":out,"sources":audit["sources"],"downloaded":manifest["downloaded"],"reference_only":audit.get("reference_only_count",0),"script_references":script["references"],"unique_downloaded_scripts":script.get("unique_downloaded_scripts",0),"script_decisions":{k:sum(e["decision"]==k for e in script["entries"]) for k in sorted({e["decision"] for e in script["entries"]})}}

def load_history():
    return json.loads(HISTORY.read_text()) if HISTORY.exists() else {"schema":1,"runs":[]}

def run(work):
    audit=json.loads((work/"audit.json").read_bytes())
    manifest=json.loads((work/"manifest.json").read_bytes())
    script=json.loads((work/"script-audit.json").read_bytes())
    policy=json.loads(POLICY.read_bytes())
    history=load_history()
    previous=next((r for r in reversed(history["runs"]) if r["passed"]),None)
    cross_path=work/"cross-audit.json"
    cross=json.loads(cross_path.read_bytes())
    if cross["module_sha256"]!=audit["output"]["sha256"]:
        raise ValueError("Stale cross audit")
    result=evaluate(audit,manifest,script,policy,previous,cross)
    result["cross_sha256"]=digest(cross_path.read_bytes())
    regression=json.loads((work/"regression.json").read_bytes())
    if regression["module_sha256"]!=audit["output"]["sha256"] or regression["structure"]!="passed":
        raise ValueError("Stale regression report")
    result["regression_checks"]=regression["jq_preservation_checks"]
    result.update(run_id=manifest["run_id"],run_attempt=manifest["run_attempt"],epoch_seconds=manifest.get("epoch_seconds",0),module_sha256=audit["output"]["sha256"],audit_sha256=digest((work/"audit.json").read_bytes()),policy_sha256=digest(POLICY.read_bytes()))
    dump(work/"quality.json",result)
    print(json.dumps(result,sort_keys=True))
    return result

def record(path):
    data=json.loads(path.read_bytes())
    required={"passed","reasons","output","sources","downloaded","reference_only","script_references","unique_downloaded_scripts","script_decisions","run_id","run_attempt","epoch_seconds","module_sha256","audit_sha256","policy_sha256","cross_sha256","rule_hashes","mitm_host_hashes","rules_added","rules_removed","cross_counts","regression_checks"}
    if set(data)!=required or set(data["output"])!=set(COUNTS) or any(type(v) is not int or v<0 for v in data["output"].values()):
        raise ValueError("Invalid quality record")
    if data["policy_sha256"]!=digest(POLICY.read_bytes()):
        raise ValueError("Stale quality policy")
    if str(data["run_id"])!=os.environ["GITHUB_RUN_ID"] or str(data["run_attempt"])!=os.environ["GITHUB_RUN_ATTEMPT"]:
        raise ValueError("Stale quality record")
    history=load_history()
    runs=history["runs"]
    if runs and data["epoch_seconds"]<runs[-1]["epoch_seconds"]:
        raise ValueError("Older quality run")
    runs=[r for r in runs if (r["run_id"],r["run_attempt"])!=(data["run_id"],data["run_attempt"])]
    runs.append(data)
    history["runs"]=runs[-json.loads(POLICY.read_bytes())["history_limit"]:]
    latest_passing=next((r for r in reversed(history["runs"]) if r["passed"]),None)
    for row in history["runs"]:
        if row is not latest_passing:
            row.pop("rule_hashes",None)
            row.pop("mitm_host_hashes",None)
    dump(HISTORY,history)

if __name__=="__main__":
    if sys.argv[1]=="record":
        record(Path(sys.argv[2]))
    elif not run(Path(sys.argv[2]))["passed"]:
        raise SystemExit("Quality gate blocked")
