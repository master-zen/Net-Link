from __future__ import annotations

import argparse
import hashlib
import json
import ipaddress
import subprocess
from pathlib import Path

from fetch_rule_sources import load_manifest


PROFILES = {
    "ad": [
        ("Surge/Rules/AdblockSet.list", "list", 120000, 0.60),
        ("Clash/Rules/AdblockSet.yaml", "yaml", 120000, 0.60),
    ],
    "china": [
        ("Surge/Rules/ChinaDomain.list", "list", 25000, 0.55),
        ("Clash/Rules/ChinaDomain.yaml", "yaml", 25000, 0.55),
    ],
    "trackers": [
        ("Surge/Rules/Trackers.list", "list", 600, 0.50),
        ("Clash/Rules/Trackers.yaml", "yaml", 600, 0.50),
        ("Trackers/Trackers.txt", "list", 900, 0.50),
    ],
    "icons": [
        ("Surge/Icon.json", "icons", 250, 0.70),
    ],
    "moyu": [
        ("Surge/Module/StartUpAds.sgmodule", "module", 100, 0.55),
    ],
    "adblock": [
        ("Surge/Module/Adblock4limbo.sgmodule", "module", 80, 0.70),
        ("Surge/Module/runtime/Adblock4limbo.js", "text", 100, 0.60),
        ("Surge/Module/runtime/Adblock4limbo.user.js", "text", 1500, 0.60),
    ],
}


def count_records(content, kind):
    if kind == "icons":
        payload = json.loads(content)
        icons = payload.get("icons")
        if not isinstance(icons, list):
            raise RuntimeError("Invalid icon JSON")
        names = [item["name"] for item in icons]
        if len(names) != len(set(names)):
            raise RuntimeError("Duplicate icon names")
        if any(
            not item.get("url", "").startswith(
                "https://raw.githubusercontent.com/master-zen/Net-Link/main/Surge/Icon/"
            )
            for item in icons
        ):
            raise RuntimeError("Unexpected icon URL")
        return len(icons)

    if kind == "yaml":
        if not content.startswith("payload:\n"):
            raise RuntimeError("Invalid Clash payload")
        return sum(line.startswith("  - ") for line in content.splitlines())

    if kind in ("module", "text"):
        if kind == "module" and not content.startswith("#!name="):
            raise RuntimeError("Invalid Surge module")
        return sum(bool(line.strip()) for line in content.splitlines())

    return sum(
        bool(line.strip()) and not line.lstrip().startswith(("#", ";"))
        for line in content.splitlines()
    )


def previous_content(path):
    result = subprocess.run(
        ["git", "show", f"HEAD:{path}"],
        capture_output=True,
        check=False,
    )
    if result.returncode != 0:
        return None
    return result.stdout.decode("utf-8")


def validate_profile(profile):
    counts = {}
    for name, kind, minimum, ratio in PROFILES[profile]:
        content = Path(name).read_text(encoding="utf-8")
        current = count_records(content, kind)
        if current < minimum:
            raise RuntimeError(f"Insufficient output: {name}: {current} < {minimum}")
        prior = previous_content(name)
        if prior is not None:
            previous = count_records(prior, kind)
            if previous and current < previous * ratio:
                raise RuntimeError(
                    f"Unexpected output shrinkage: {name}: {previous} -> {current}"
                )
        counts[name] = current

    if profile in ("ad", "china", "trackers"):
        surge = next(n for n in counts if n.startswith("Surge/Rules/"))
        clash = next(n for n in counts if n.startswith("Clash/Rules/"))
        if counts[surge] != counts[clash]:
            raise RuntimeError("Surge and Clash rule counts differ")
        # Counts are insufficient: validate line-for-line equivalence.
        surge_rows = Path(surge).read_text(encoding="utf-8").splitlines()
        clash_rows = Path(clash).read_text(encoding="utf-8").splitlines()
        clash_payload = [
            line[5:-1].replace("''", "'") for line in clash_rows[1:]
            if line.startswith("  - '") and line.endswith("'")
        ]
        if len(clash_payload) != len(surge_rows) or clash_payload != surge_rows:
            raise RuntimeError(f"Surge and Clash rule CONTENT differs: {surge} / {clash}")

    if profile == "china":
        # Independent fetch step must have succeeded in THIS run, and every
        # primary + geographic reference snapshot must still match its hash.
        downloads = load_manifest("china")
        risk = json.loads(Path("data/reports/china_risk_audit.json").read_text(encoding="utf-8"))
        if risk.get("download_run") != downloads.get("github_run_id"):
            raise RuntimeError("China risk audit is not from the current fresh download")
        # Supplementary CN/DIRECT sources must be independently audited before
        # promotion into the sole final ChinaDomain.list. A DIRECT label alone
        # is not admissible geographic evidence.
        supplement = json.loads(
            Path("data/reports/china_supplement_audit.json").read_text(encoding="utf-8")
        )
        expected_supplements = {
            item["url"]: item for item in downloads["sources"]
            if item["bucket"] == "china_supplement"
        }
        audited = supplement.get("sources", [])
        if (not audited
                or supplement.get("download_run") != downloads["github_run_id"]
                or len(audited) != len(expected_supplements)
                or {item["url"] for item in audited} != set(expected_supplements)):
            raise RuntimeError("China supplementary audit is incomplete or belongs to an old build")
        for source in audited:
            downloaded_source = expected_supplements[source["url"]]
            if (source["snapshot_sha256"] != downloaded_source["sha256"]
                    or source["snapshot_path"] != downloaded_source["path"]
                    or source["parsed_candidate_count"] <= 0):
                raise RuntimeError(f"China supplementary source was not parsed correctly: {source['url']}")
        if supplement.get("accepted_unique_rule_count", -1) < 0:
            raise RuntimeError("Invalid China supplementary acceptance total")
        print(f"Audited mainland-only promotion of {len(audited)} supplementary source files")
        # All upstream source payloads must exist and match their recorded SHA-256.
        source_manifest = json.loads(Path("data/reports/china_source_integrity.json").read_text(encoding="utf-8"))
        sources = source_manifest["sources"]
        if (not sources or len(sources) != source_manifest["source_count"]
                or source_manifest["successful_sources"] != len(sources)
                or len({item["url"] for item in sources}) != len(sources)):
            raise RuntimeError("Incomplete or duplicated China upstream source downloads")
        for entry in sources:
            if entry["status"] != "ok" or entry["parsed_rule_count"] <= 0:
                raise RuntimeError(f"Unhealthy China source: {entry['url']}")
            raw_path = Path(entry["raw_path"])
            if not raw_path.as_posix().startswith("data/china/upstream/"):
                raise RuntimeError(f"Unexpected China source path: {raw_path}")
            payload = raw_path.read_bytes()
            if (len(payload) != entry["size_bytes"]
                    or hashlib.sha256(payload).hexdigest() != entry["sha256"]):
                raise RuntimeError(f"China source download SHA-256 mismatch: {entry['url']}")
        # Verify that persisted upstream inputs and both published outputs
        # correspond to this exact build; a passing count alone is insufficient.
        published = source_manifest.get("published_files", {})
        required = ("Surge/Rules/ChinaDomain.list", "Clash/Rules/ChinaDomain.yaml")
        if not source_manifest.get("completed_at_utc"):
            raise RuntimeError("China provenance is missing its build timestamp")
        for name in required:
            if published.get(name) != hashlib.sha256(Path(name).read_bytes()).hexdigest():
                raise RuntimeError(f"China output SHA-256 mismatch: {name}")
        tracked_snapshots = {Path(x["path"]) for x in downloads["sources"]}
        actual_snapshots = set(Path("data/china/upstream").glob("*"))
        if actual_snapshots != tracked_snapshots:
            raise RuntimeError("Stale or missing China raw upstream snapshots")
        print(f"China upstream downloads verified: {len(sources)}")

        rows = [row for row in Path("Surge/Rules/ChinaDomain.list").read_text(
            encoding="utf-8").splitlines() if row.strip()]
        if len(rows) != source_manifest.get("published_rule_count"):
            raise RuntimeError("China output record count differs from source manifest")
        if len(rows) != len(set(rows)):
            raise RuntimeError("Duplicate unified China rules")
        from build_china_domain import domain_hits_exclusion
        excluded_roots = {
            x.strip().lower()
            for x in Path("data/allowlists/ChinaForeignDomains.list").read_text(encoding="utf-8").splitlines()
            if x.strip() and not x.lstrip().startswith("#")
        }
        for row in rows:
            kind, _, domain = row.partition(",")
            if kind not in ("DOMAIN", "DOMAIN-SUFFIX"):
                continue
            # Country-code .cn and explicitly sourced cn.* regional names
            # are not silently discarded by broad foreign-parent exclusions.
            if domain_hits_exclusion(domain, kind, set(), excluded_roots):
                raise RuntimeError(f"China includes a protected non-CN service: {row}")
        allowed = {"DOMAIN", "DOMAIN-SUFFIX", "IP-CIDR", "IP-CIDR6"}
        families = set()
        for row in rows:
            kind, sep, value = row.partition(",")
            if not sep or kind not in allowed or not value:
                raise RuntimeError(f"Unsafe unified China rule: {row}")
            if kind == "DOMAIN-SUFFIX" and "." not in value and value != "cn":
                raise RuntimeError(f"Unapproved broad TLD suffix: {row}")
            if kind in {"IP-CIDR", "IP-CIDR6"}:
                net = ipaddress.ip_network(value, strict=False)
                expected = 4 if kind == "IP-CIDR" else 6
                if (net.version != expected or not net.network_address.is_global
                        or not net.broadcast_address.is_global
                        or (expected == 6 and net.network_address.ipv4_mapped is not None)):
                    raise RuntimeError(f"Unsafe unified China IP: {row}")
                families.add(expected)
        if families != {4, 6}:
            raise RuntimeError("Missing IPv4 or IPv6 in unified China rules")
        if rows.count("DOMAIN-SUFFIX,cn") != 1:
            raise RuntimeError("Missing mandatory .cn country-code suffix coverage")
        suffixes = {row.partition(",")[2] for row in rows if row.startswith("DOMAIN-SUFFIX,")}
        for rule in rows:
            kind, _, domain = rule.partition(",")
            if kind not in {"DOMAIN", "DOMAIN-SUFFIX"}:
                continue
            labels = domain.split(".")
            if (kind == "DOMAIN" and domain in suffixes
                    or any(".".join(labels[i:]) in suffixes for i in range(1, len(labels)))):
                raise RuntimeError(f"Redundant nested China domain entry: {rule}")

        disallowed_ip = [
            ipaddress.ip_network(line.strip(), strict=False)
            for line in Path("data/allowlists/ChinaForeignIPs.list").read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        ]
        for item in downloads["sources"]:
            if item["bucket"] == "foreign_ip" and "telegramcidr" in item["url"]:
                for line in Path(item["path"]).read_text(encoding="utf-8").splitlines():
                    if line.startswith(("IP-CIDR,", "IP-CIDR6,")):
                        disallowed_ip.append(ipaddress.ip_network(line.partition(",")[2].strip(), strict=False))
        for row in rows:
            kind, _, token = row.partition(",")
            if kind not in {"IP-CIDR", "IP-CIDR6"}:
                continue
            network = ipaddress.ip_network(token, strict=False)
            if any(network.version == exclusion.version and network.overlaps(exclusion)
                   for exclusion in disallowed_ip):
                raise RuntimeError(f"China contains a documented foreign/global service IP: {row}")
        print(f"Unified China domain/IP risks and hierarchy verified: {len(rows)}")

    if profile == "ad":
        downloaded = load_manifest("ad")
        report = json.loads(Path("data/reports/ad_build_audit.json").read_text(encoding="utf-8"))
        if (report.get("download_run") != downloaded.get("github_run_id")
                or report.get("input_sources") != len(downloaded["sources"])):
            raise RuntimeError("Adblock build was not based on this run freshly downloaded sources")
        for name in ("Surge/Rules/AdblockSet.list", "Clash/Rules/AdblockSet.yaml"):
            if report.get("output_sha256", {}).get(name) != hashlib.sha256(Path(name).read_bytes()).hexdigest():
                raise RuntimeError(f"Adblock output checksum does not match this run: {name}")
        rules = Path("Surge/Rules/AdblockSet.list").read_text(encoding="utf-8").splitlines()
        if len(rules) != len(set(rules)) or len(rules) != report.get("final_rules"):
            raise RuntimeError("Adblock final file contains duplicates or differs from build report")
        from build_ad_sets import parse_rules_from_text, subtract_allow_rules
        protected, allowed, _ = parse_rules_from_text(
            Path("data/allowlists/AdblockCriticalAllow.list").read_text(encoding="utf-8"), "allow"
        )
        remaining, removed = subtract_allow_rules(rules, sorted(protected | allowed))
        if removed or len(remaining) != len(rules):
            raise RuntimeError(f"Adblock blocks critical service endpoints: {removed} conflicting rules")
        print(f"Adblock fresh source and protection audit verified: {len(rules)} rules")

    if profile == "moyu":
        module = Path("Surge/Module/StartUpAds.sgmodule").read_text(encoding="utf-8")
        metadata = json.loads(Path("Surge/Module/upstream/metadata.json").read_text(encoding="utf-8"))
        sections = {}
        section = ""
        for raw_line in module.splitlines():
            line = raw_line.strip()
            if line.startswith("[") and line.endswith("]"):
                section = line
                sections.setdefault(section, [])
            elif line and not line.startswith("#") and section:
                sections[section].append(line)

        for kind in ("[URL Rewrite]", "[Map Local]", "[Body Rewrite]", "[Rule]", "[Script]"):
            entries = sections.get(kind, [])
            if len(entries) != len(set(entries)):
                raise RuntimeError(f"Duplicate Moyu entries in {kind}")

        checks = {
            "[URL Rewrite]": "url_rewrite",
            "[Map Local]": "map_local",
            "[Body Rewrite]": "body_rewrite",
            "[Rule]": "rules",
            "[Script]": "scripts",
        }
        for kind, key in checks.items():
            if len(sections.get(kind, [])) != metadata[key]:
                raise RuntimeError(f"Moyu output/metadata mismatch: {kind}")

        mitm_rows = sections.get("[MITM]", [])
        if len(mitm_rows) != 1 or not mitm_rows[0].startswith("hostname = %APPEND% "):
            raise RuntimeError("Invalid Moyu MITM host list")
        hosts = [part.strip() for part in mitm_rows[0].split("%APPEND%", 1)[1].split(",")]
        if not hosts or len(hosts) != len(set(hosts)) or len(hosts) != metadata["mitm_hosts"]:
            raise RuntimeError("Invalid or duplicated Moyu MITM hostnames")

        forbidden_hosts = {
            "security.wechat.com", "weixin110.qq.com", "wxa.wxs.qq.com",
            "ad.12306.cn", "spclient.wg.spotify.com",
            "mobilepaas.abchina.com.cn", "ump.sz.creditcard.ecitic.com",
            "creditcardapp.bankcomm.com", "creditcardapp.bankcomm.cn",
            "zjmbank.js96008.com",
            "smsrebuild1.mail.10086.cn",
            "fuwu.nhsa.gov.cn",
            "client.app.coc.10086.cn",
            "api.futunn.com",
            "gab.122.gov.cn",
        }
        if forbidden_hosts.intersection(hosts):
            raise RuntimeError("Moyu contains excluded MITM hosts")
        if any("ad.12306.cn" in item for item in sections.get("[Rule]", [])):
            raise RuntimeError("Moyu changed 12306 routing")
        for name in ("testflight", "mp\\.weixin", "ad\\.12306"):
            if name in module:
                raise RuntimeError(f"Moyu sensitive rewrite still present: {name}")
        if any(name in module for name in (
            "spclient.wg.spotify.com", "mobilepaas", "creditcardapp",
            "zjmbank", "ump\\.sz\\.creditcard",
        )):
            raise RuntimeError("Moyu has unrelated sensitive rewrites")

        import re
        for name in ("[URL Rewrite]", "[Map Local]", "[Body Rewrite]", "[Script]"):
            for line in sections.get(name, []):
                if name == "[Script]":
                    found = re.search(r'pattern=(?:"([^"]+)"|([^,]+)),script-path=', line)
                    if not found:
                        raise RuntimeError("Invalid Moyu Script pattern")
                    pattern = found.group(1) or found.group(2)
                else:
                    fields = line.split()
                    pattern = fields[1] if name == "[Body Rewrite]" else fields[0]
                normalized = pattern.replace(r"\/", "/").replace(r"\.", ".").replace(r"\:", ":")
                normalized = normalized.replace("https?://", "https://")
                matched = re.match(r"^\^?https?://([A-Za-z0-9.-]+):(\d{2,5})/", normalized)
                if matched:
                    host, port = matched.groups()
                    if port != "443" and f"{host}:{port}" not in hosts:
                        raise RuntimeError(f"Moyu missing port-specific MITM: {host}:{port}")

        for item in sections.get("[Body Rewrite]", []):
            if item.startswith(("http-response ", "http-request ")):
                fields = item.split()
                if len(fields) < 4 or len(fields) % 2:
                    raise RuntimeError("Invalid Moyu native body rewrite fields")
                for expression in fields[2:]:
                    if expression.count('"') % 2:
                        raise RuntimeError("Invalid Moyu native body rewrite quotation")

        for section_name in ("[URL Rewrite]", "[Map Local]", "[Script]"):
            for item in sections.get(section_name, []):
                normalized = item.replace(r"\/", "/").replace(r"\.", ".")
                if any(marker in normalized for marker in (
                    "https?://[a-zA-Z0-9_-]+(",
                    "http://[a-zA-Z0-9_-]+(",
                    "api.xiaoyi.com/v5/app/config",
                )):
                    raise RuntimeError("Moyu contains unsafe universal or core config rewrite")

        if metadata["unsupported_rules"] != 0:
            raise RuntimeError("Moyu has unsupported rules")

    if profile == "adblock":
        module = Path("Surge/Module/Adblock4limbo.sgmodule").read_text(encoding="utf-8")
        loader = Path("Surge/Module/runtime/Adblock4limbo.js").read_text(encoding="utf-8")
        user = Path("Surge/Module/runtime/Adblock4limbo.user.js").read_text(encoding="utf-8")
        if (
            "Adblock4limbo Ads Only" not in module
            or "script-path=https://limbopro.com/Adguard/Adblock4limbo.js" in module
            or "fc_JS_URL" in loader
            or "elementBlocker.user.js" in loader
            or "function daohang_build()" in user
            or "floating-warning-box" in user
        ):
            raise RuntimeError("Unexpected Adblock4limbo dependency")

    for name, count in counts.items():
        print(f"{name}: {count}")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("profile", choices=PROFILES)
    args = parser.parse_args()
    validate_profile(args.profile)


if __name__ == "__main__":
    main()
