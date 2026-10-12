from __future__ import annotations

import argparse
import json
import ipaddress
import subprocess
from pathlib import Path


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

    if profile == "china":
        rows = [row for row in Path("Surge/Rules/ChinaDomain.list").read_text(
            encoding="utf-8").splitlines() if row.strip()]
        if len(rows) != len(set(rows)):
            raise RuntimeError("Duplicate unified China rules")
        allowed = {"DOMAIN", "DOMAIN-SUFFIX", "IP-CIDR", "IP-CIDR6"}
        families = set()
        for row in rows:
            kind, sep, value = row.partition(",")
            if not sep or kind not in allowed or not value:
                raise RuntimeError(f"Unsafe unified China rule: {row}")
            if kind == "DOMAIN-SUFFIX" and "." not in value:
                raise RuntimeError(f"Broad TLD suffix: {row}")
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
        print(f"Unified China rules validated: {len(rows)}")

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
