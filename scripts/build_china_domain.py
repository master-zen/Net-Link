#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import os
import re
import ssl
import sys
import time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse, urlunparse
from urllib.request import Request, urlopen

from fetch_rule_sources import load_manifest


ROOT = Path(__file__).resolve().parents[1]

SOURCE_URLS_FILE = ROOT / "data/sources/ChinaDomainList_URLs.txt"
SOURCE_CACHE_DIR = ROOT / "data/china/upstream"
SOURCE_REPORT_FILE = ROOT / "data/reports/china_source_integrity.json"

# 保持原输出路径，避免你现有订阅地址失效。
# 注意：现在这个文件已经不是“纯域名合集”，而是混合规则合集。
OUTPUT_SURGE_FILE = ROOT / "Surge/Rules/ChinaDomain.list"
OUTPUT_CLASH_FILE = ROOT / "Clash/Rules/ChinaDomain.yaml"


ACCEPTED_RULE_TYPES = {
    "DOMAIN",
    "DOMAIN-SUFFIX",
    "DOMAIN-KEYWORD",
    "IP-CIDR",
    "IP-CIDR6",
    "IP-ASN",
    "GEOIP",
}

COMMENT_PREFIXES = ("#", ";", "//", "!", "[")
YAML_LIST_PREFIX_RE = re.compile(r"^\s*-\s*")
HOSTS_LINE_RE = re.compile(r"^(?:0\.0\.0\.0|127\.0\.0\.1|::1|::)\s+([^\s#;]+)")

DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)"
    r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"[a-z0-9-]{2,63}$"
)

SINGLE_LABEL_RE = re.compile(
    r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$"
)


def fetch_text(
    url: str,
    timeout: int = 30,
    retries: int = 3,
    max_bytes: int = 30_000_000,
) -> tuple[str, bytes]:
    last_error: Exception | None = None

    for attempt in range(1, retries + 1):
        try:
            req = Request(
                url,
                headers={
                    "User-Agent": "Mozilla/5.0 (Net-Link China rule builder)",
                    "Accept": "text/plain, */*",
                },
            )

            context = ssl.create_default_context()

            with urlopen(req, timeout=timeout, context=context) as resp:
                chunks: list[bytes] = []
                total = 0

                while True:
                    chunk = resp.read(1024 * 1024)
                    if not chunk:
                        break

                    total += len(chunk)
                    if total > max_bytes:
                        raise RuntimeError(f"payload too large: {total} bytes")

                    chunks.append(chunk)

                charset = resp.headers.get_content_charset() or "utf-8"
                payload = b"".join(chunks)
                return payload.decode(charset, errors="replace"), payload

        except Exception as exc:  # noqa: BLE001
            last_error = exc
            if attempt < retries:
                time.sleep(2 * attempt)

    raise RuntimeError(f"Failed to fetch {url}: {last_error}") from last_error


def normalize_source_url(raw_url: str) -> str | None:
    candidate = raw_url.strip().strip("<>()[]{}\"'`.,\\")
    if not candidate:
        return None

    parsed = urlparse(candidate)
    if parsed.scheme.lower() not in {"http", "https"}:
        return None

    host = (parsed.netloc or "").lower()
    path = parsed.path or ""

    if host == "github.com":
        parts = [p for p in path.split("/") if p]

        if len(parts) >= 5 and parts[2] == "blob":
            owner, repo = parts[0], parts[1]
            rest = "/".join(parts[3:])
            host = "raw.githubusercontent.com"
            path = f"/{owner}/{repo}/{rest}"

        elif len(parts) >= 5 and parts[2] == "raw":
            owner, repo = parts[0], parts[1]
            rest = "/".join(parts[3:])
            host = "raw.githubusercontent.com"
            path = f"/{owner}/{repo}/{rest}"

    normalized = urlunparse(
        (
            parsed.scheme.lower(),
            host,
            path,
            "",
            parsed.query,
            "",
        )
    )

    reparsed = urlparse(normalized)
    if reparsed.scheme.lower() not in {"http", "https"}:
        return None
    if not reparsed.netloc:
        return None

    return normalized


def read_source_urls(path: Path) -> list[str]:
    if not path.exists():
        return []

    urls: list[str] = []

    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue

        url = normalize_source_url(line)
        if url:
            urls.append(url)

    return sorted(set(urls), key=str.casefold)


def is_comment_or_empty(raw_line: str) -> bool:
    line = raw_line.strip().lstrip("\ufeff")
    if not line:
        return True
    return line.startswith(COMMENT_PREFIXES)


def strip_wrapping_quotes(value: str) -> str:
    value = value.strip()

    while len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"', "`"}:
        value = value[1:-1].strip()

    return value


def strip_inline_comment(value: str) -> str:
    value = value.strip().lstrip("\ufeff")

    if not value:
        return ""

    for marker in (" #", "\t#", " ;", "\t;"):
        if marker in value:
            value = value.split(marker, 1)[0].rstrip()

    return value.strip()


def clean_line(raw_line: str) -> str:
    line = raw_line.strip().lstrip("\ufeff")
    line = YAML_LIST_PREFIX_RE.sub("", line)
    line = strip_inline_comment(line)
    line = strip_wrapping_quotes(line)

    while line.endswith(","):
        line = line[:-1].rstrip()

    return line.strip()


def to_idna_ascii(domain: str) -> str | None:
    labels = domain.split(".")
    ascii_labels: list[str] = []

    for label in labels:
        if not label:
            return None

        try:
            ascii_label = label.encode("idna").decode("ascii").lower()
        except UnicodeError:
            return None

        ascii_labels.append(ascii_label)

    return ".".join(ascii_labels)


def normalize_domain_token(raw: str, *, allow_single_label: bool = False) -> str | None:
    token = strip_wrapping_quotes(raw).strip().lower()

    if not token:
        return None

    if "://" in token:
        parsed = urlparse(token)
        token = parsed.hostname or ""

    if token.startswith("@@"):
        token = token[2:].strip()

    if token.startswith("||"):
        token = token[2:]

    if token.startswith("|"):
        token = token[1:]

    if token.startswith("*."):
        token = token[2:]

    if token.startswith("."):
        token = token[1:]

    token = token.strip(".")
    token = token.split("/", 1)[0]
    token = token.split("^", 1)[0]
    token = token.split("$", 1)[0]

    # 域名规则里不接受 IP。
    try:
        ipaddress.ip_address(token)
        return None
    except ValueError:
        pass

    # 去掉端口。IPv6 不会进入域名规则。
    if ":" in token:
        token = token.split(":", 1)[0]

    token = token.strip(".")
    if not token:
        return None

    ascii_token = to_idna_ascii(token)
    if not ascii_token:
        return None

    labels = ascii_token.split(".")
    if labels and labels[-1].isdigit():
        return None

    if "." in ascii_token:
        if DOMAIN_RE.match(ascii_token):
            return ascii_token
        return None

    if allow_single_label and SINGLE_LABEL_RE.match(ascii_token):
        return ascii_token

    return None


def normalize_domain_rule(rule_type: str, value: str) -> str | None:
    if rule_type == "DOMAIN-KEYWORD":
        keyword = strip_wrapping_quotes(value).strip().lower()

        if not keyword:
            return None

        # DOMAIN-KEYWORD 不应该带逗号。
        if "," in keyword:
            return None

        return f"{rule_type},{keyword}"

    allow_single_label = rule_type == "DOMAIN-SUFFIX"
    domain = normalize_domain_token(value, allow_single_label=allow_single_label)

    if not domain:
        return None

    return f"{rule_type},{domain}"


def normalize_ip_cidr_rule(rule_type: str, value: str) -> str | None:
    raw = strip_wrapping_quotes(value).strip()

    if not raw:
        return None

    try:
        net = ipaddress.ip_network(raw, strict=False)
    except ValueError:
        try:
            addr = ipaddress.ip_address(raw)
            prefix = 32 if addr.version == 4 else 128
            net = ipaddress.ip_network(f"{addr}/{prefix}", strict=False)
        except ValueError:
            return None

    if net.version == 4 and rule_type != "IP-CIDR":
        return None

    if net.version == 6 and rule_type != "IP-CIDR6":
        return None

    return f"{rule_type},{net.with_prefixlen}"


def normalize_bare_ip_or_cidr(value: str) -> str | None:
    raw = strip_wrapping_quotes(value).strip()

    if not raw:
        return None

    try:
        net = ipaddress.ip_network(raw, strict=False)
    except ValueError:
        try:
            addr = ipaddress.ip_address(raw)
            prefix = 32 if addr.version == 4 else 128
            net = ipaddress.ip_network(f"{addr}/{prefix}", strict=False)
        except ValueError:
            return None

    rule_type = "IP-CIDR" if net.version == 4 else "IP-CIDR6"
    return f"{rule_type},{net.with_prefixlen}"


def normalize_ip_asn_rule(value: str) -> str | None:
    token = strip_wrapping_quotes(value).strip().upper()

    if token.startswith("AS"):
        token = token[2:]

    if not token.isdigit():
        return None

    asn = int(token)

    if asn <= 0:
        return None

    return f"IP-ASN,{asn}"


def normalize_geoip_rule(value: str) -> str | None:
    token = strip_wrapping_quotes(value).strip().upper()

    if not token:
        return None

    if "," in token:
        return None

    if not re.fullmatch(r"[A-Z0-9_-]{2,32}", token):
        return None

    return f"GEOIP,{token}"


def normalize_typed_rule(rule_type: str, value: str) -> str | None:
    rule_type = strip_wrapping_quotes(rule_type).strip().upper()
    value = strip_wrapping_quotes(value).strip()

    if rule_type not in ACCEPTED_RULE_TYPES:
        return None

    if rule_type in {"DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD"}:
        return normalize_domain_rule(rule_type, value)

    if rule_type in {"IP-CIDR", "IP-CIDR6"}:
        return normalize_ip_cidr_rule(rule_type, value)

    if rule_type == "IP-ASN":
        return normalize_ip_asn_rule(value)

    if rule_type == "GEOIP":
        return normalize_geoip_rule(value)

    return None


def parse_adblock_domain(line: str) -> str | None:
    # 兼容 ||example.com^、|example.com、@@||example.com^ 这类格式。
    if line.startswith("@@"):
        line = line[2:].strip()

    domain = normalize_domain_token(line, allow_single_label=False)

    if not domain:
        return None

    return f"DOMAIN-SUFFIX,{domain}"


def normalize_line(raw_line: str) -> str | None:
    if is_comment_or_empty(raw_line):
        return None

    line = clean_line(raw_line)

    if not line:
        return None

    if line.lower() in {"payload:", "payload"}:
        return None

    if line.startswith("||") or line.startswith("|") or line.startswith("@@||"):
        return parse_adblock_domain(line)

    hosts_match = HOSTS_LINE_RE.match(line)
    if hosts_match:
        domain = normalize_domain_token(hosts_match.group(1), allow_single_label=False)
        if domain:
            return f"DOMAIN,{domain}"
        return None

    if "," in line:
        # 只保留：规则类型 + 主值。
        # 例如：
        # IP-CIDR,1.0.1.0/24,no-resolve -> IP-CIDR,1.0.1.0/24
        # DOMAIN-SUFFIX,baidu.com,DIRECT -> DOMAIN-SUFFIX,baidu.com
        parts = [part.strip() for part in line.split(",")]
        if len(parts) < 2:
            return None

        return normalize_typed_rule(parts[0], parts[1])

    # 裸 IP / 裸 CIDR。
    bare_ip_or_cidr = normalize_bare_ip_or_cidr(line)
    if bare_ip_or_cidr:
        return bare_ip_or_cidr

    # 裸域名。
    if line.startswith("*.") or line.startswith("."):
        domain = normalize_domain_token(line, allow_single_label=False)
        if domain:
            return f"DOMAIN-SUFFIX,{domain}"
        return None

    domain = normalize_domain_token(line, allow_single_label=False)
    if domain:
        return f"DOMAIN,{domain}"

    return None


def rule_sort_key(rule: str) -> tuple[int, str]:
    rule_type, _, value = rule.partition(",")

    order = {
        "DOMAIN": 10,
        "DOMAIN-SUFFIX": 20,
        "DOMAIN-KEYWORD": 30,
        "IP-CIDR": 40,
        "IP-CIDR6": 50,
        "IP-ASN": 60,
        "GEOIP": 70,
    }

    if rule_type in {"IP-CIDR", "IP-CIDR6"}:
        try:
            net = ipaddress.ip_network(value, strict=False)
            return (
                order.get(rule_type, 99),
                f"{net.version}:{int(net.network_address):039d}:{net.prefixlen:03d}",
            )
        except ValueError:
            pass

    if rule_type == "IP-ASN":
        try:
            return (order.get(rule_type, 99), f"{int(value):010d}")
        except ValueError:
            pass

    return (order.get(rule_type, 99), value.casefold())


def yaml_quote(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def write_clash_ruleset(path: Path, rules: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)

    lines = ["payload:"]
    lines.extend(f"  - {yaml_quote(rule)}" for rule in rules)

    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def print_type_stats(rules: list[str]) -> None:
    counts = Counter(rule.partition(",")[0] for rule in rules)

    for rule_type in sorted(ACCEPTED_RULE_TYPES, key=lambda item: rule_sort_key(f"{item},")):
        print(f"[STATS] {rule_type}: {counts.get(rule_type, 0)}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--offline", action="store_true", help="Build ONLY from fresh, verified data/ snapshots, with zero network access")
    args = parser.parse_args()
    OUTPUT_SURGE_FILE.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT_CLASH_FILE.parent.mkdir(parents=True, exist_ok=True)

    source_urls = read_source_urls(SOURCE_URLS_FILE)

    if not source_urls:
        print(f"[ERROR] no source urls in {SOURCE_URLS_FILE}", file=sys.stderr)
        return 1

    print(f"[INFO] source urls: {len(source_urls)}")
    downloaded = {}
    if args.offline:
        manifest = load_manifest("china")
        downloaded = {item["url"]: item for item in manifest["sources"] if item["bucket"] == "china"}
        if set(downloaded) != set(source_urls):
            raise RuntimeError("Current China source configuration differs from this run fresh downloaded snapshots")
        print(f"[INPUT] verified offline China inputs: {len(downloaded)} sources")

    SOURCE_CACHE_DIR.mkdir(parents=True, exist_ok=True)
    SOURCE_REPORT_FILE.parent.mkdir(parents=True, exist_ok=True)
    started_at = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    run_id = os.getenv("GITHUB_RUN_ID")
    run_url = (
        f"https://github.com/{os.getenv('GITHUB_REPOSITORY', 'master-zen/Net-Link')}/actions/runs/{run_id}"
        if run_id else None
    )
    all_rules: list[str] = []
    source_reports: list[dict[str, object]] = []
    ok_sources = 0

    for index, source in enumerate(source_urls, 1):
        try:
            if args.offline:
                snapshot = downloaded[source]
                cache_file = ROOT / snapshot["path"]
                original_bytes = cache_file.read_bytes()
                text = original_bytes.decode("utf-8-sig", errors="replace")
            else:
                text, original_bytes = fetch_text(source)
                url_digest = hashlib.sha256(source.encode("utf-8")).hexdigest()[:16]
                filename = re.sub(r"[^A-Za-z0-9._-]", "_", Path(urlparse(source).path).name)[:80] or "source.txt"
                cache_file = SOURCE_CACHE_DIR / f"{index:02d}_{url_digest}_{filename}"
                cache_file.write_bytes(original_bytes)
            before = len(all_rules)

            for raw_line in text.splitlines():
                rule = normalize_line(raw_line)
                if rule:
                    all_rules.append(rule)

            parsed = len(all_rules) - before

            source_reports.append({
                "url": source,
                "status": "ok" if parsed > 0 else "empty",
                "downloaded_at_utc": datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
                "raw_path": cache_file.relative_to(ROOT).as_posix(),
                "size_bytes": len(original_bytes),
                "sha256": hashlib.sha256(original_bytes).hexdigest(),
                "parsed_rule_count": parsed,
            })
            if parsed > 0:
                ok_sources += 1
                print(f"[INFO] downloaded {len(original_bytes)} bytes; parsed {parsed:>8} rules: {source}")
            else:
                print(f"[WARN] parsed zero accepted rules: {source}", file=sys.stderr)

        except Exception as exc:  # noqa: BLE001
            source_reports.append({"url": source, "status": "failed", "error": str(exc)[:300]})
            print(f"[WARN] fetch failed: {source} -> {exc}", file=sys.stderr)

    SOURCE_REPORT_FILE.write_text(
        json.dumps({
            "started_at_utc": started_at,
            "actions_run_url": run_url,
            "source_count": len(source_urls),
            "successful_sources": ok_sources,
            "sources": source_reports,
        }, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print(f"[INFO] source integrity report: {SOURCE_REPORT_FILE.relative_to(ROOT)}")
    # An incomplete upstream refresh must never replace the last published
    # complete output. Keep the previous delivery and fail the workflow.
    if ok_sources != len(source_urls):
        print(f"[ERROR] incomplete upstream download: {ok_sources}/{len(source_urls)} healthy", file=sys.stderr)
        return 1

    raw_count = len(all_rules)

    # 核心：只去重复。
    # 归一化后的同一条规则只保留一次。
    merged_rules = sorted(set(all_rules), key=rule_sort_key)

    if not merged_rules:
        print("[ERROR] no rules generated", file=sys.stderr)
        return 1

    # Publish one Surge ruleset. Keep intermediate source handling internal.
    # Conservative domain rules exclude broad TLD suffixes and all keywords.
    # ASN/GEOIP require independent verification before use for DIRECT.
    domain_rules = [
        rule for rule in merged_rules
        if rule.startswith("DOMAIN,")
        or (rule.startswith("DOMAIN-SUFFIX,")
            and "." in rule.partition(",")[2])
    ]
    ip_rules = []
    for family, kind in ((4, "IP-CIDR"), (6, "IP-CIDR6")):
        nets = []
        for rule in merged_rules:
            rule_kind, _, value = rule.partition(",")
            if rule_kind != kind:
                continue
            net = ipaddress.ip_network(value, strict=False)
            if net.version != family:
                continue
            if (not net.network_address.is_global
                    or not net.broadcast_address.is_global
                    or (family == 6 and net.network_address.ipv4_mapped is not None)):
                continue
            nets.append(net)
        for net in ipaddress.collapse_addresses(nets):
            ip_rules.append(f"{kind},{net.compressed}")
    final_rules = sorted(set(domain_rules + ip_rules), key=rule_sort_key)
    if not final_rules or not any(r.startswith("IP-CIDR,") for r in final_rules) or not any(
            r.startswith("IP-CIDR6,") for r in final_rules):
        raise RuntimeError("Incomplete unified China ruleset")
    print(f"[AUDIT] accepted domains={len(domain_rules)} IP rules={len(ip_rules)}")
    print(f"[AUDIT] excluded/merged rules={len(merged_rules) - len(final_rules)}")
    merged_rules = final_rules

    OUTPUT_SURGE_FILE.write_text("\n".join(merged_rules) + "\n", encoding="utf-8")
    write_clash_ruleset(OUTPUT_CLASH_FILE, merged_rules)

    # Keep only the current 12 source snapshots; remove any orphaned files if
    # the configured sources change. This directory is tracked by Git.
    current_snapshots = {ROOT / str(entry["raw_path"]) for entry in source_reports}
    for old_snapshot in SOURCE_CACHE_DIR.iterdir():
        if old_snapshot.is_file() and old_snapshot not in current_snapshots:
            old_snapshot.unlink()

    manifest = json.loads(SOURCE_REPORT_FILE.read_text(encoding="utf-8"))
    manifest.update({
        "completed_at_utc": datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "downloaded_bytes_total": sum(int(entry["size_bytes"]) for entry in source_reports),
        "normalized_raw_rule_count": raw_count,
        "published_rule_count": len(merged_rules),
        "published_files": {
            "Surge/Rules/ChinaDomain.list": hashlib.sha256(OUTPUT_SURGE_FILE.read_bytes()).hexdigest(),
            "Clash/Rules/ChinaDomain.yaml": hashlib.sha256(OUTPUT_CLASH_FILE.read_bytes()).hexdigest(),
        },
    })
    SOURCE_REPORT_FILE.write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )

    print(f"[DONE] raw accepted rules: {raw_count}")
    print(f"[DONE] duplicate rules removed: {raw_count - len(merged_rules)}")
    print(f"[DONE] {OUTPUT_SURGE_FILE.relative_to(ROOT)}: {len(merged_rules)} lines")
    print(f"[DONE] {OUTPUT_CLASH_FILE.relative_to(ROOT)}: {len(merged_rules)} lines")

    print_type_stats(merged_rules)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
