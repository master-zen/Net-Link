from __future__ import annotations
import argparse
import fnmatch
import hashlib
import json
import re
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "data/sources/AppStartUpADBlacklist.json"
OUTPUT = ROOT / "Surge/Module/AppStartUpADBlacklist.sgmodule"
SCRIPT_URL = "https://raw.githubusercontent.com/master-zen/Net-Link/main/Surge/Module/runtime/app-startup-ad.js"
ACTIONS = {"reject", "empty", "json", "bili", "vg", "jd", "dmall", "family", "dida", "xhs", "meituan"}

def escape(value):
    return re.sub(r"([.\\?*+^$()[\]{}|])", r"\\\1", value)

def pattern(entry):
    host = escape(entry["host"])
    port = ":" + str(entry["port"]) if entry.get("port") else ""
    path = "[0-9]+".join(escape(part) for part in entry["path"].split("{version}"))
    if entry.get("query"):
        tail = r"\?(?:[^#&]*&)*" + escape(entry["query"]) + r"(?:&[^#]*)?$"
    elif entry["match"] == "subtree":
        tail = r"[^?#]*(?:\?[^#]*)?$"
    else:
        tail = r"(?:\?[^#]*)?$"
    return "^" + entry.get("scheme", "https?") + "://" + host + port + path + tail

def load():
    return json.loads(MANIFEST.read_text(encoding="utf-8"))

def render(data):
    if data["name"] != "App Start Up AD Blacklist" or data["schema"] != 1:
        raise ValueError("Invalid manifest")
    ids, patterns, hosts = set(), set(), set()
    sources = {s["id"] for s in data["sources"]}
    sections = {"URL Rewrite": [], "Map Local": [], "Script": []}
    endpoints = []
    for entry in sorted(data["entries"], key=lambda item: item["id"]):
        ident, host, path, action = (entry[k] for k in ("id", "host", "path", "action"))
        if not re.fullmatch(r"[a-z0-9-]+", ident) or ident in ids:
            raise ValueError(f"Duplicate or invalid id: {ident}")
        if not re.fullmatch(r"[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?\.[a-z]{2,}", host) or ".." in host:
            raise ValueError(f"Invalid literal host: {host}")
        if any(fnmatch.fnmatchcase(host, h) for h in data["protected_hosts"]):
            raise ValueError(f"Protected host: {host}")
        if not re.fullmatch(r"/[A-Za-z0-9_./{}-]*", path) or not re.fullmatch(r"[A-Za-z0-9_./-]*", path.replace("{version}", "")):
            raise ValueError(f"Invalid literal path: {path}")
        if entry["match"] not in ("exact", "subtree") or (entry["match"] == "subtree" and (not path.endswith("/") or path == "/")):
            raise ValueError(f"Invalid path boundary: {path}")
        if entry.get("query") and not re.fullmatch(r"[A-Za-z0-9_.-]+=[A-Za-z0-9_.-]+", entry["query"]):
            raise ValueError("Invalid query discriminator")
        if path == "/" and not entry.get("query"):
            raise ValueError("Unbounded root match")
        if not entry["sources"] or not set(entry["sources"]) <= sources or action not in ACTIONS:
            raise ValueError(f"Unknown provenance or action: {ident}")
        if entry.get("scheme", "https?") not in ("http", "https", "https?") or (entry.get("port") and not 1 <= entry["port"] <= 65535):
            raise ValueError("Invalid protocol or port")
        if host == "api.douban.com" and path != "/v2/app_ads/splash":
            raise ValueError("Non-splash Douban route")
        if re.search(r"/(?:feed|recommend|search|login|payment|pay|tracking)(?:/|$)", path, re.I):
            raise ValueError(f"Non-splash route: {path}")
        p = pattern(entry)
        compiled = re.compile(p)
        sample = ("http" if entry.get("scheme") == "http" else "https") + "://" + host + (":" + str(entry["port"]) if entry.get("port") else "") + path.replace("{version}", "7") + ("?" + entry["query"] if entry.get("query") else "")
        if not compiled.fullmatch(sample) or compiled.match(sample.replace(host, host + ".invalid", 1)):
            raise ValueError(f"Boundary test failed: {ident}")
        for previous, previous_sample in endpoints:
            if compiled.match(previous_sample) or previous.match(sample):
                raise ValueError(f"Overlapping endpoints: {ident}")
        endpoints.append((compiled, sample))
        if p in patterns:
            raise ValueError(f"Duplicate pattern: {ident}")
        ids.add(ident)
        patterns.add(p)
        if entry.get("scheme") != "http":
            hosts.add(host + (":" + str(entry["port"]) if entry.get("port") else ""))
        if action == "reject":
            sections["URL Rewrite"].append(p + " _ reject")
        elif action in ("empty", "json"):
            body = "{}" if action == "json" else ""
            header = ' header="Content-Type:application/json"' if action == "json" else ""
            sections["Map Local"].append(f'{p} data-type=text data="{body}" status-code=200{header}')
        else:
            name = "startup_" + ident.replace("-", "_")
            sections["Script"].append(f"{name} = type=http-response,pattern={p},script-path={SCRIPT_URL},requires-body=true,max-size=1048576,timeout=5,argument={action}")
    if not patterns:
        raise ValueError("Empty module")
    lines = ["#!name=App Start Up AD Blacklist", "#!desc=App opening-screen ads and dedicated preload only. Reviewed endpoints; no general ad or tracking interception.", ""]
    for section, rows in sections.items():
        if rows:
            lines.extend(["[" + section + "]", *rows, ""])
    lines.extend(["[MITM]", "hostname = %APPEND% " + ", ".join(sorted(hosts)), ""])
    return "\n".join(lines)

def audit(data, destination):
    results = []
    for source in data["sources"]:
        request = urllib.request.Request(source["url"], headers={"User-Agent": "Net-Link-Startup-Audit"})
        with urllib.request.urlopen(request, timeout=30) as response:
            body = response.read(12_000_001)
        if not body or len(body) > 12_000_000:
            raise ValueError("Invalid upstream size: " + source["id"])
        body.decode("utf-8")
        blob = hashlib.sha1(f"blob {len(body)}\0".encode() + body).hexdigest()
        results.append({"id": source["id"], "url": source["url"], "blob": blob, "reviewed_blob": source["reviewed_blob"], "changed": blob != source["reviewed_blob"], "bytes": len(body)})
    destination.write_text(json.dumps({"review_required": any(r["changed"] for r in results), "sources": results}, indent=2) + "\n", encoding="utf-8")

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--audit", type=Path)
    args = parser.parse_args()
    data = load()
    content = render(data)
    if args.check:
        if OUTPUT.read_text(encoding="utf-8") != content:
            raise ValueError("Generated module differs from reviewed manifest")
    else:
        OUTPUT.write_text(content, encoding="utf-8")
    if args.audit:
        audit(data, args.audit)

if __name__ == "__main__":
    main()
