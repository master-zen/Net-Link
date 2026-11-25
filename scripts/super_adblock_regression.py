from __future__ import annotations

import argparse
import json
import re
import subprocess
import tempfile
from pathlib import Path
from super_adblock import digest, dump, validate_structure, ROOT

def run_jq(expression,value):
    proc=subprocess.run(["jq","-c",expression],input=json.dumps(value),text=True,capture_output=True,timeout=5,check=True)
    outputs=proc.stdout.splitlines()
    if len(outputs)!=1:
        raise ValueError("JQ must return exactly one response")
    return json.loads(outputs[0])

def checks(work,cli=None):
    path=work/"SuperAdBlock.sgmodule"
    audit=json.loads((work/"audit.json").read_bytes())
    data=path.read_bytes()
    validate_structure(data,audit)
    count=0
    for line in data.decode().splitlines():
        if not line.startswith("#!REQUIREMENT CORE_VERSION>=6008000 http-response-jq "):
            continue
        match=re.fullmatch(r"#!REQUIREMENT CORE_VERSION>=6008000 http-response-jq \S+ '(.+)'",line)
        if not match:
            raise ValueError("Malformed emitted jq")
        expression=match.group(1)
        fixtures=[None,True,7,"untouched",[1,{"user":{"id":42}}],{},{"user":{"id":42},"account":{"name":"keep"},"playback":{"url":"keep"},"data":7},{"data":{"title":"keep","id":42},"list":[{"type":"article","id":1},null,3]}]
        for original in fixtures:
            if run_jq(expression,original)!=original:
                raise ValueError("Non-ad response regression")
            count+=1
    report={"module_sha256":digest(data),"jq_preservation_checks":count,"structure":"passed","surge_cli":"not-run","live_app_traffic":"not-tested"}
    if cli:
        with tempfile.TemporaryDirectory() as tmp:
            lines=["[General]"]
            section=""
            for line in data.decode().splitlines():
                if line.startswith("#!") and not line.startswith("#!REQUIREMENT"):
                    continue
                if line.startswith("["):
                    if section=="[Rule]":
                        lines.append("FINAL,DIRECT")
                    section=line
                if section=="[MITM]":
                    line=line.replace("%APPEND% ","")
                lines.append(line)
            if section=="[Rule]":
                lines.append("FINAL,DIRECT")
            conf=Path(tmp)/"candidate.conf"
            conf.write_text("\n".join(lines)+"\n")
            subprocess.run([str(cli),"--check",str(conf)],check=True,timeout=30)
            report["surge_cli"]="passed"
    dump(work/"regression.json",report)
    print(json.dumps(report,sort_keys=True))

if __name__=="__main__":
    parser=argparse.ArgumentParser()
    parser.add_argument("work",type=Path)
    parser.add_argument("--surge-cli",type=Path)
    args=parser.parse_args()
    checks(args.work,args.surge_cli)
