#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import ipaddress
import json
import os
import random
import re
import socket
import ssl
import struct
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from threading import Lock
from typing import Iterable
from urllib.request import Request, urlopen

from lib_rules import BUILD_DIR, normalize_rule_line

DOMAIN_SOURCES = [
    "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/refs/heads/master/rule/Surge/China/China_Domain.list",
]

IP_SOURCES = [
    "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/refs/heads/master/rule/Surge/ChinaIPs/ChinaIPs_Resolve.list",
    "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/refs/heads/master/rule/Surge/ChinaASN/ChinaASN_Resolve.list",
    "https://raw.githubusercontent.com/Loyalsoldier/surge-rules/release/ruleset/cncidr.txt",
    "https://raw.githubusercontent.com/Hackl0us/GeoIP2-CN/release/CN-ip-cidr.txt",
]

OUTPUT = Path("Surge/Rules/China.list")
VALIDATION_REPORT = BUILD_DIR / "china_validation.json"
REVIEW_REPORT = BUILD_DIR / "china_review.json"
REJECTED_REPORT = BUILD_DIR / "china_rejected.json"
UNRESOLVED_REPORT = BUILD_DIR / "china_unresolved.json"
DNS_CACHE_FILE = BUILD_DIR / "china_dns_cache.json"

COMMENT_PREFIXES = ("#", ";", "//")
DOMAIN_RULE_TYPES = {"DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD"}
IP_RULE_TYPES = {"IP-CIDR", "IP-CIDR6", "IP-ASN"}
NO_RESOLVE_RE = re.compile(r"(?i),\s*no-resolve\b")

# 国内公共 DNS：串行回退，前一台有有效答案就不再继续试下一台
DEFAULT_CN_DNS_SERVERS = [
    "119.29.29.29",      # DNSPod
    "180.76.76.76",      # Baidu
    "223.5.5.5",         # AliDNS
    "223.6.6.6",         # AliDNS
    "114.114.114.114",   # 114DNS
    "114.114.115.115",   # 114DNS
    "1.2.4.8",           # CNNIC SDNS
    "210.2.4.8",         # CNNIC SDNS
    "101.226.4.6",       # 360
    "218.30.118.6",      # 360
    "123.125.81.6",      # 360
    "140.207.198.6",     # 360
]

# 国际公共 DNS：串行回退，前一台有有效答案就不再继续试下一台
DEFAULT_INTL_DNS_SERVERS = [
    "1.1.1.1",           # Cloudflare
    "1.0.0.1",           # Cloudflare
    "8.8.8.8",           # Google
    "8.8.4.4",           # Google
    "9.9.9.9",           # Quad9
    "149.112.112.112",   # Quad9
    "208.67.222.222",    # OpenDNS
    "208.67.220.220",    # OpenDNS
    "64.6.64.6",         # Verisign
    "64.6.65.6",         # Verisign
    "4.2.2.1",           # Level3 / CenturyLink
    "4.2.2.2",
    "4.2.2.3",
    "4.2.2.4",
    "4.2.2.5",
    "4.2.2.6",
    "156.154.70.1",      # Neustar
    "156.154.71.1",      # Neustar
    "77.88.8.8",         # Yandex
    "77.88.8.1",         # Yandex
]

SAMPLE_PREFIXES = [
    "",
    "www",
    "m",
    "api",
    "img",
    "cdn",
    "static",
    "passport",
    "open",
    "music",
]

DNS_TIMEOUT = float(os.getenv("CHINA_DNS_TIMEOUT", "1.5"))
DNS_TCP_TIMEOUT = float(os.getenv("CHINA_DNS_TCP_TIMEOUT", "2.5"))
MAX_CNAME_DEPTH = int(os.getenv("CHINA_DNS_MAX_CNAME_DEPTH", "8"))
MAX_WORKERS = int(os.getenv("CHINA_MAX_WORKERS", "32"))
MIN_SUFFIX_CONFIRMED_HOSTS = int(os.getenv("CHINA_MIN_SUFFIX_CONFIRMED_HOSTS", "2"))
DNS_CACHE_TTL_SECONDS = int(os.getenv("CHINA_DNS_CACHE_TTL_SECONDS", str(48 * 60 * 60)))

TYPE_A = 1
TYPE_CNAME = 5
TYPE_AAAA = 28
CLASS_IN = 1

STATUS_KEEP = "keep"
STATUS_REJECT = "reject"
STATUS_REVIEW = "review"
STATUS_NO_RECORD = "no_record"

ENV_CN_DNS = [x.strip() for x in os.getenv("CHINA_CN_DNS_SERVERS", "").split(",") if x.strip()]
ENV_INTL_DNS = [x.strip() for x in os.getenv("CHINA_INTL_DNS_SERVERS", "").split(",") if x.strip()]
CN_DNS_SERVERS = ENV_CN_DNS or DEFAULT_CN_DNS_SERVERS
INTL_DNS_SERVERS = ENV_INTL_DNS or DEFAULT_INTL_DNS_SERVERS

CACHE_LOCK = Lock()


def fetch_text(url: str, timeout: int = 30, retries: int = 3) -> str:
    last_error = None
    for attempt in range(1, retries + 1):
        try:
            req = Request(
                url,
                headers={
                    "User-Agent": "Mozilla/5.0 (GitHub Actions china rules merger)",
                    "Accept": "text/plain, */*",
                },
            )
            context = ssl.create_default_context()
            with urlopen(req, timeout=timeout, context=context) as resp:
                charset = resp.headers.get_content_charset() or "utf-8"
                return resp.read().decode(charset, errors="replace")
        except Exception as exc:
            last_error = exc
            if attempt < retries:
                time.sleep(1.5 * attempt)
    raise RuntimeError(f"Failed to fetch {url}: {last_error}") from last_error


def ensure_parent_dirs() -> None:
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    VALIDATION_REPORT.parent.mkdir(parents=True, exist_ok=True)
    DNS_CACHE_FILE.parent.mkdir(parents=True, exist_ok=True)


def is_comment_or_empty(line: str) -> bool:
    s = line.strip().lstrip("\ufeff")
    return not s or any(s.startswith(prefix) for prefix in COMMENT_PREFIXES)


def strip_no_resolve_and_trailing_commas(line: str) -> str:
    line = NO_RESOLVE_RE.sub("", line).strip()
    while line.endswith(","):
        line = line[:-1].rstrip()
    return line


def normalize_domain_rule(line: str) -> str | None:
    s = strip_no_resolve_and_trailing_commas(line.strip())
    if is_comment_or_empty(s):
        return None

    normalized = normalize_rule_line(s, strip_policy=True)
    if not normalized:
        if s.startswith("."):
            normalized = normalize_rule_line(f"DOMAIN-SUFFIX,{s[1:]}", strip_policy=True)
        else:
            normalized = normalize_rule_line(f"DOMAIN,{s}", strip_policy=True)

    if not normalized:
        return None

    head = normalized.split(",", 1)[0].upper()
    if head not in DOMAIN_RULE_TYPES:
        return None
    return normalized


def normalize_ip_rule(line: str) -> str | None:
    s = strip_no_resolve_and_trailing_commas(line.strip())
    if is_comment_or_empty(s):
        return None

    normalized = normalize_rule_line(s, strip_policy=True)
    if normalized:
        head = normalized.split(",", 1)[0].upper()
        if head in IP_RULE_TYPES:
            return normalized

    try:
        network = ipaddress.ip_network(s, strict=False)
        if isinstance(network, ipaddress.IPv6Network):
            return f"IP-CIDR6,{network.compressed}"
        return f"IP-CIDR,{network.compressed}"
    except ValueError:
        pass

    try:
        ip_obj = ipaddress.ip_address(s)
        if isinstance(ip_obj, ipaddress.IPv6Address):
            return f"IP-CIDR6,{ip_obj.compressed}/128"
        return f"IP-CIDR,{ip_obj.compressed}/32"
    except ValueError:
        pass

    return None


def unique_sorted(items: Iterable[str]) -> list[str]:
    return sorted(set(items), key=lambda s: s.casefold())


def fetch_and_normalize(sources: list[str], normalizer) -> tuple[set[str], list[dict], list[dict]]:
    merged: set[str] = set()
    source_status: list[dict] = []
    failures: list[dict] = []

    for src in sources:
        try:
            text = fetch_text(src)
            kept: set[str] = set()
            for raw_line in text.splitlines():
                normalized = normalizer(raw_line)
                if normalized:
                    kept.add(normalized)
            merged.update(kept)
            source_status.append(
                {
                    "source_url": src,
                    "ok": True,
                    "normalized_count": len(kept),
                }
            )
        except Exception as exc:
            failures.append({"source_url": src, "error": str(exc)})
            source_status.append(
                {
                    "source_url": src,
                    "ok": False,
                    "error": str(exc),
                }
            )

    return merged, source_status, failures


def build_cn_networks(trusted_ip_rules: set[str]) -> list[ipaddress._BaseNetwork]:
    networks: list[ipaddress._BaseNetwork] = []
    for rule in trusted_ip_rules:
        parts = [p.strip() for p in rule.split(",") if p.strip()]
        if len(parts) < 2:
            continue
        head, value = parts[0].upper(), parts[1]
        if head not in {"IP-CIDR", "IP-CIDR6"}:
            continue
        try:
            networks.append(ipaddress.ip_network(value, strict=False))
        except ValueError:
            continue
    return networks


def ip_is_in_cn_networks(ip_text: str, cn_networks: list[ipaddress._BaseNetwork]) -> bool:
    try:
        ip_obj = ipaddress.ip_address(ip_text)
    except ValueError:
        return False
    return any(ip_obj.version == network.version and ip_obj in network for network in cn_networks)


def extract_rule_value(rule: str) -> tuple[str, str] | None:
    parts = [p.strip() for p in rule.split(",") if p.strip()]
    if len(parts) < 2:
        return None
    return parts[0].upper(), parts[1].lower().lstrip(".")


def encode_dns_name(name: str) -> bytes:
    labels = [x for x in name.rstrip(".").split(".") if x]
    out = bytearray()
    for label in labels:
        raw = label.encode("idna")
        if len(raw) > 63:
            raise ValueError(f"DNS label too long: {name}")
        out.append(len(raw))
        out.extend(raw)
    out.append(0)
    return bytes(out)


def build_dns_query(name: str, qtype: int, txid: int) -> bytes:
    header = struct.pack("!HHHHHH", txid, 0x0100, 1, 0, 0, 0)
    question = encode_dns_name(name) + struct.pack("!HH", qtype, CLASS_IN)
    return header + question


def read_exact(sock: socket.socket, size: int) -> bytes:
    data = b""
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise OSError("unexpected EOF while reading TCP DNS response")
        data += chunk
    return data


def read_dns_name(data: bytes, offset: int) -> tuple[str, int]:
    labels: list[str] = []
    jumped = False
    original_offset = offset
    seen_ptrs: set[int] = set()

    while True:
        if offset >= len(data):
            raise ValueError("dns name offset out of range")

        length = data[offset]

        if length & 0xC0 == 0xC0:
            if offset + 1 >= len(data):
                raise ValueError("dns name pointer truncated")
            ptr = ((length & 0x3F) << 8) | data[offset + 1]
            if ptr in seen_ptrs:
                raise ValueError("dns compression loop detected")
            seen_ptrs.add(ptr)
            if not jumped:
                original_offset = offset + 2
                jumped = True
            offset = ptr
            continue

        if length == 0:
            offset += 1
            break

        offset += 1
        if offset + length > len(data):
            raise ValueError("dns label truncated")
        label = data[offset:offset + length].decode("idna", errors="ignore")
        labels.append(label)
        offset += length

    return ".".join(labels), (original_offset if jumped else offset)


def parse_dns_message(data: bytes, expected_txid: int) -> dict:
    if len(data) < 12:
        raise ValueError("dns message too short")

    txid, flags, qdcount, ancount, nscount, arcount = struct.unpack("!HHHHHH", data[:12])
    if txid != expected_txid:
        raise ValueError("dns transaction id mismatch")

    qr = bool(flags & 0x8000)
    tc = bool(flags & 0x0200)
    rcode = flags & 0x000F
    if not qr:
        raise ValueError("dns response missing QR bit")

    offset = 12
    for _ in range(qdcount):
        _, offset = read_dns_name(data, offset)
        offset += 4
        if offset > len(data):
            raise ValueError("dns question section truncated")

    ips: set[str] = set()
    cnames: set[str] = set()

    total_rr = ancount + nscount + arcount
    for _ in range(total_rr):
        _, offset = read_dns_name(data, offset)
        if offset + 10 > len(data):
            raise ValueError("dns rr header truncated")
        rtype, rclass, _ttl, rdlength = struct.unpack("!HHIH", data[offset:offset + 10])
        offset += 10
        if offset + rdlength > len(data):
            raise ValueError("dns rr rdata truncated")

        rdata_offset = offset
        rdata = data[offset:offset + rdlength]
        offset += rdlength

        if rclass != CLASS_IN:
            continue

        if rtype == TYPE_A and rdlength == 4:
            ips.add(socket.inet_ntoa(rdata))
        elif rtype == TYPE_AAAA and rdlength == 16:
            ips.add(socket.inet_ntop(socket.AF_INET6, rdata))
        elif rtype == TYPE_CNAME:
            cname, _ = read_dns_name(data, rdata_offset)
            if cname:
                cnames.add(cname.rstrip("."))

    return {
        "rcode": rcode,
        "truncated": tc,
        "ips": sorted(ips),
        "cnames": sorted(cnames),
    }


def udp_dns_exchange(server: str, name: str, qtype: int, timeout: float) -> dict:
    txid = random.randint(0, 65535)
    payload = build_dns_query(name, qtype, txid)

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(timeout)
        sock.sendto(payload, (server, 53))
        data, _ = sock.recvfrom(65535)

    return parse_dns_message(data, txid)


def tcp_dns_exchange(server: str, name: str, qtype: int, timeout: float) -> dict:
    txid = random.randint(0, 65535)
    payload = build_dns_query(name, qtype, txid)
    framed = struct.pack("!H", len(payload)) + payload

    with socket.create_connection((server, 53), timeout=timeout) as sock:
        sock.settimeout(timeout)
        sock.sendall(framed)
        length_data = read_exact(sock, 2)
        resp_len = struct.unpack("!H", length_data)[0]
        data = read_exact(sock, resp_len)

    return parse_dns_message(data, txid)


def load_dns_cache() -> dict:
    if not DNS_CACHE_FILE.exists():
        return {}
    try:
        data = json.loads(DNS_CACHE_FILE.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def save_dns_cache(cache: dict) -> None:
    DNS_CACHE_FILE.parent.mkdir(parents=True, exist_ok=True)
    DNS_CACHE_FILE.write_text(
        json.dumps(cache, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )


def prune_dns_cache(cache: dict) -> dict:
    now = int(time.time())
    pruned = {}
    for key, value in cache.items():
        if not isinstance(value, dict):
            continue
        ts = int(value.get("timestamp", 0))
        if now - ts <= DNS_CACHE_TTL_SECONDS:
            pruned[key] = value
    return pruned


def make_dns_query_cache_key(server: str, host: str, qtype: int) -> str:
    return f"dnsq|{server}|{host.rstrip('.').lower()}|{qtype}"


def make_group_cache_key(group_name: str, host: str) -> str:
    return f"group|{group_name}|{host.rstrip('.').lower()}"


def get_cached_result(cache: dict, key: str) -> dict | None:
    with CACHE_LOCK:
        item = cache.get(key)
        if not isinstance(item, dict):
            return None
        ts = int(item.get("timestamp", 0))
        if int(time.time()) - ts > DNS_CACHE_TTL_SECONDS:
            return None
        result = item.get("result")
        return result if isinstance(result, dict) else None


def set_cached_result(cache: dict, key: str, result: dict) -> None:
    with CACHE_LOCK:
        cache[key] = {
            "timestamp": int(time.time()),
            "result": result,
        }


def dns_query(server: str, name: str, qtype: int, cache: dict) -> dict:
    key = make_dns_query_cache_key(server, name, qtype)
    cached = get_cached_result(cache, key)
    if cached is not None:
        return cached

    try:
        result = udp_dns_exchange(server, name, qtype, DNS_TIMEOUT)
        if result.get("truncated"):
            result = tcp_dns_exchange(server, name, qtype, DNS_TCP_TIMEOUT)
        result["server"] = server
        result["name"] = name
        result["error"] = ""
    except Exception as exc:
        result = {
            "server": server,
            "name": name,
            "rcode": None,
            "truncated": False,
            "ips": [],
            "cnames": [],
            "error": f"{type(exc).__name__}: {exc}",
        }

    set_cached_result(cache, key, result)
    return result


def resolve_host_via_server(server: str, host: str, cache: dict) -> dict:
    pending = [host.rstrip(".")]
    seen_names: set[str] = set()
    all_ips: set[str] = set()
    all_cnames: set[str] = set()
    seen_rcodes: set[int] = set()
    had_error = False
    had_positive = False

    while pending and len(seen_names) < MAX_CNAME_DEPTH:
        current = pending.pop(0).rstrip(".")
        if not current or current in seen_names:
            continue
        seen_names.add(current)

        for qtype in (TYPE_A, TYPE_AAAA):
            resp = dns_query(server, current, qtype, cache)
            if resp["error"]:
                had_error = True
                continue

            if resp["rcode"] is not None:
                seen_rcodes.add(resp["rcode"])

            if resp["ips"]:
                had_positive = True
                all_ips.update(resp["ips"])

            for cname in resp["cnames"]:
                cname = cname.rstrip(".")
                if cname and cname not in seen_names:
                    all_cnames.add(cname)
                    pending.append(cname)

    if all_ips:
        status = "answered"
    elif seen_rcodes == {3}:
        status = "nxdomain"
    elif seen_rcodes == {0} and not had_positive and not all_cnames:
        status = "nodata"
    elif had_error and not seen_rcodes:
        status = "error"
    else:
        status = "empty"

    return {
        "server": server,
        "host": host,
        "status": status,
        "ips": sorted(all_ips),
        "cnames": sorted(all_cnames),
        "rcodes": sorted(seen_rcodes),
        "had_error": had_error,
    }


def signatures_equal(a: dict, b: dict) -> bool:
    return (
        sorted(a.get("ips", [])) == sorted(b.get("ips", []))
        and sorted(a.get("cnames", [])) == sorted(b.get("cnames", []))
    )


def resolve_host_group_serial(group_name: str, servers: list[str], host: str, cache: dict) -> dict:
    key = make_group_cache_key(group_name, host)
    cached = get_cached_result(cache, key)
    if cached is not None:
        return cached

    tried_views: list[dict] = []
    no_record_like = True

    for server in servers:
        view = resolve_host_via_server(server, host, cache)
        tried_views.append(view)

        if view["status"] == "answered":
            result = {
                "group": group_name,
                "host": host,
                "status": "answered",
                "ips": sorted(view["ips"]),
                "cnames": sorted(view["cnames"]),
                "chosen_server": server,
                "tried_views": tried_views,
            }
            set_cached_result(cache, key, result)
            return result

        if view["status"] not in {"nxdomain", "nodata"}:
            no_record_like = False

    result = {
        "group": group_name,
        "host": host,
        "status": "no_record" if no_record_like else "error",
        "ips": [],
        "cnames": [],
        "chosen_server": "",
        "tried_views": tried_views,
    }
    set_cached_result(cache, key, result)
    return result


def classify_ip_set(ip_list: list[str], cn_networks: list[ipaddress._BaseNetwork]) -> tuple[set[str], set[str]]:
    cn_ips = set()
    non_cn_ips = set()
    for ip_text in ip_list:
        if ip_is_in_cn_networks(ip_text, cn_networks):
            cn_ips.add(ip_text)
        else:
            non_cn_ips.add(ip_text)
    return cn_ips, non_cn_ips


def verify_exact_host_dual_group(host: str, cn_networks: list[ipaddress._BaseNetwork], cache: dict) -> dict:
    host = host.strip().lower().lstrip(".")

    with ThreadPoolExecutor(max_workers=2) as executor:
        future_cn = executor.submit(resolve_host_group_serial, "cn", CN_DNS_SERVERS, host, cache)
        future_intl = executor.submit(resolve_host_group_serial, "intl", INTL_DNS_SERVERS, host, cache)
        cn_group = future_cn.result()
        intl_group = future_intl.result()

    # 两组结果不同，直接剔除
    if cn_group["status"] != intl_group["status"]:
        return {
            "status": STATUS_REJECT,
            "host": host,
            "reason": "cn_intl_status_diverged",
            "cn_group": cn_group,
            "intl_group": intl_group,
        }

    if cn_group["status"] == "answered":
        if not signatures_equal(cn_group, intl_group):
            return {
                "status": STATUS_REJECT,
                "host": host,
                "reason": "cn_intl_answer_diverged",
                "cn_group": cn_group,
                "intl_group": intl_group,
            }

        cn_ips, non_cn_ips = classify_ip_set(cn_group["ips"], cn_networks)
        if non_cn_ips:
            return {
                "status": STATUS_REJECT,
                "host": host,
                "reason": "answered_but_contains_non_cn_ip",
                "cn_group": cn_group,
                "intl_group": intl_group,
                "cn_ips": sorted(cn_ips),
                "non_cn_ips": sorted(non_cn_ips),
            }

        if not cn_ips:
            return {
                "status": STATUS_REJECT,
                "host": host,
                "reason": "answered_but_no_cn_ip",
                "cn_group": cn_group,
                "intl_group": intl_group,
                "cn_ips": [],
                "non_cn_ips": [],
            }

        return {
            "status": STATUS_KEEP,
            "host": host,
            "reason": "cn_intl_same_and_cn_only",
            "cn_group": cn_group,
            "intl_group": intl_group,
            "cn_ips": sorted(cn_ips),
            "non_cn_ips": [],
        }

    if cn_group["status"] == "no_record":
        return {
            "status": STATUS_NO_RECORD,
            "host": host,
            "reason": "cn_intl_both_no_record",
            "cn_group": cn_group,
            "intl_group": intl_group,
        }

    return {
        "status": STATUS_REJECT,
        "host": host,
        "reason": "cn_intl_both_error_or_empty",
        "cn_group": cn_group,
        "intl_group": intl_group,
    }


def sample_hosts_for_suffix(suffix: str) -> list[str]:
    suffix = suffix.strip().lower().lstrip(".")
    hosts: list[str] = []
    for prefix in SAMPLE_PREFIXES:
        if prefix:
            hosts.append(f"{prefix}.{suffix}")
        else:
            hosts.append(suffix)
    return hosts


def verify_suffix_dual_group(suffix: str, cn_networks: list[ipaddress._BaseNetwork], cache: dict) -> dict:
    suffix = suffix.strip().lower().lstrip(".")
    sampled_hosts = sample_hosts_for_suffix(suffix)
    host_results: list[dict] = []

    confirmed_keep = 0

    for host in sampled_hosts:
        result = verify_exact_host_dual_group(host, cn_networks, cache)
        host_results.append(result)

        if result["status"] == STATUS_REJECT:
            return {
                "status": STATUS_REJECT,
                "suffix": suffix,
                "sampled_hosts": sampled_hosts,
                "host_results": host_results,
                "reason": "sample_contains_rejected_host",
            }

        if result["status"] == STATUS_KEEP:
            confirmed_keep += 1

    if confirmed_keep >= MIN_SUFFIX_CONFIRMED_HOSTS:
        return {
            "status": STATUS_KEEP,
            "suffix": suffix,
            "sampled_hosts": sampled_hosts,
            "host_results": host_results,
            "reason": "enough_confirmed_hosts",
        }

    if all(x["status"] == STATUS_NO_RECORD for x in host_results):
        return {
            "status": STATUS_NO_RECORD,
            "suffix": suffix,
            "sampled_hosts": sampled_hosts,
            "host_results": host_results,
            "reason": "all_samples_no_record",
        }

    return {
        "status": STATUS_REVIEW,
        "suffix": suffix,
        "sampled_hosts": sampled_hosts,
        "host_results": host_results,
        "reason": "suffix_not_confident_enough",
    }


def verify_domain_rule(rule: str, cn_networks: list[ipaddress._BaseNetwork], cache: dict) -> tuple[str, dict]:
    parsed = extract_rule_value(rule)
    if not parsed:
        return STATUS_REVIEW, {"rule": rule, "reason": "malformed_rule"}

    head, value = parsed

    if head == "DOMAIN":
        result = verify_exact_host_dual_group(value, cn_networks, cache)
        record = {
            "rule": rule,
            "rule_type": head,
            "value": value,
            **result,
        }
        return result["status"], record

    if head == "DOMAIN-SUFFIX":
        result = verify_suffix_dual_group(value, cn_networks, cache)
        record = {
            "rule": rule,
            "rule_type": head,
            "value": value,
            **result,
        }
        return result["status"], record

    # 严格模式下不自动放行 DOMAIN-KEYWORD
    record = {
        "rule": rule,
        "rule_type": head,
        "value": value,
        "status": STATUS_REVIEW,
        "reason": "domain_keyword_disabled_in_strict_mode",
    }
    return STATUS_REVIEW, record


def validate_final_rules(
    final_rules: list[str],
    final_domain_rules: set[str],
    trusted_ip_rules: set[str],
) -> tuple[list[str], dict]:
    issues: list[str] = []
    domain_count = 0
    ip_count = 0
    asn_count = 0

    for idx, rule in enumerate(final_rules, start=1):
        parts = [p.strip() for p in rule.split(",") if p.strip()]
        if len(parts) < 2:
            issues.append(f"China.list:{idx}: malformed rule: {rule}")
            continue

        head = parts[0].upper()

        if head in {"DOMAIN", "DOMAIN-SUFFIX"}:
            domain_count += 1
            if rule not in final_domain_rules:
                issues.append(f"China.list:{idx}: domain rule not in kept set: {rule}")
        elif head == "DOMAIN-KEYWORD":
            issues.append(f"China.list:{idx}: DOMAIN-KEYWORD leaked into strict output: {rule}")
        elif head in {"IP-CIDR", "IP-CIDR6"}:
            ip_count += 1
            if rule not in trusted_ip_rules:
                issues.append(f"China.list:{idx}: IP rule not in trusted mainland IP set: {rule}")
        elif head == "IP-ASN":
            asn_count += 1
            if rule not in trusted_ip_rules:
                issues.append(f"China.list:{idx}: ASN rule not in trusted mainland ASN set: {rule}")
        else:
            issues.append(f"China.list:{idx}: unsupported rule type leaked: {rule}")

    summary = {
        "rule_count": len(final_rules),
        "domain_rule_count": domain_count,
        "ip_rule_count": ip_count,
        "asn_rule_count": asn_count,
    }
    return issues, summary


def main() -> int:
    ensure_parent_dirs()
    dns_cache = prune_dns_cache(load_dns_cache())

    trusted_domain_rules, domain_status, domain_failures = fetch_and_normalize(DOMAIN_SOURCES, normalize_domain_rule)
    trusted_ip_rules, ip_status, ip_failures = fetch_and_normalize(IP_SOURCES, normalize_ip_rule)

    cn_networks = build_cn_networks(trusted_ip_rules)
    if not cn_networks:
        print("No mainland IP networks were built from IP sources.", file=sys.stderr)
        return 1

    domain_rules = sorted(trusted_domain_rules, key=lambda s: s.casefold())

    kept_domain_rules: set[str] = set()
    review_records: list[dict] = []
    rejected_records: list[dict] = []
    unresolved_records: list[dict] = []

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {
            executor.submit(verify_domain_rule, rule, cn_networks, dns_cache): rule
            for rule in domain_rules
        }

        for future in as_completed(futures):
            rule = futures[future]
            try:
                status, record = future.result()
            except Exception as exc:
                review_records.append(
                    {
                        "rule": rule,
                        "status": STATUS_REVIEW,
                        "reason": f"exception:{type(exc).__name__}: {exc}",
                    }
                )
                continue

            if status == STATUS_KEEP:
                kept_domain_rules.add(rule)
            elif status == STATUS_REJECT:
                rejected_records.append(record)
            elif status == STATUS_NO_RECORD:
                unresolved_records.append(record)
            else:
                review_records.append(record)

    final_rules = unique_sorted(kept_domain_rules | trusted_ip_rules)
    if not final_rules:
        print("No valid China rules generated.", file=sys.stderr)
        save_dns_cache(dns_cache)
        return 1

    issues, summary = validate_final_rules(final_rules, kept_domain_rules, trusted_ip_rules)

    report = {
        "ok": not issues,
        "mode": "dual_group_serial_fallback_parallel_compare",
        "generated_at_unix": int(time.time()),
        "config": {
            "cn_dns_servers": CN_DNS_SERVERS,
            "intl_dns_servers": INTL_DNS_SERVERS,
            "dns_timeout": DNS_TIMEOUT,
            "dns_tcp_timeout": DNS_TCP_TIMEOUT,
            "max_cname_depth": MAX_CNAME_DEPTH,
            "max_workers": MAX_WORKERS,
            "min_suffix_confirmed_hosts": MIN_SUFFIX_CONFIRMED_HOSTS,
            "dns_cache_ttl_seconds": DNS_CACHE_TTL_SECONDS,
            "cn_group_serial": True,
            "intl_group_serial": True,
            "cn_intl_parallel": True,
            "cn_intl_diverged_direct_reject": True,
        },
        "summary": {
            **summary,
            "input_domain_rule_count": len(trusted_domain_rules),
            "kept_domain_rule_count": len(kept_domain_rules),
            "review_domain_rule_count": len(review_records),
            "rejected_domain_rule_count": len(rejected_records),
            "unresolved_domain_rule_count": len(unresolved_records),
            "cn_network_count": len(cn_networks),
            "dns_cache_entries": len(dns_cache),
        },
        "sources": {
            "domain_sources": domain_status,
            "ip_sources": ip_status,
        },
        "failures": {
            "domain_sources": domain_failures,
            "ip_sources": ip_failures,
        },
        "issues": issues,
    }

    VALIDATION_REPORT.write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    REVIEW_REPORT.write_text(
        json.dumps(review_records, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    REJECTED_REPORT.write_text(
        json.dumps(rejected_records, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    UNRESOLVED_REPORT.write_text(
        json.dumps(unresolved_records, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    save_dns_cache(dns_cache)

    if issues:
        print(json.dumps(report, ensure_ascii=False, indent=2), file=sys.stderr)
        return 1

    OUTPUT.write_text("\n".join(final_rules) + "\n", encoding="utf-8")
    print(f"{OUTPUT}: {len(final_rules)} lines")
    print(f"{VALIDATION_REPORT}: ok")
    print(f"{REVIEW_REPORT}: {len(review_records)} entries")
    print(f"{REJECTED_REPORT}: {len(rejected_records)} entries")
    print(f"{UNRESOLVED_REPORT}: {len(unresolved_records)} entries")
    print(f"{DNS_CACHE_FILE}: {len(dns_cache)} entries")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
