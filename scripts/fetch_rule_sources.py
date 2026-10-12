#!/usr/bin/env python3
"""Fresh, fail-closed upstream download stage for China and Adblock rules.

Nothing is generated from a previously committed snapshot. This script always
refreshes all configured URLs, writes original bytes under data/, and records
their SHA-256 hashes. Build scripts must verify this run's manifest offline.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parents[1]

PROFILES = {
    "china": {
        "china": "data/sources/ChinaDomainList_URLs.txt",
        "foreign_domain": "data/sources/ChinaForeignDomain_URLs.txt",
        "foreign_ip": "data/sources/ChinaForeignIP_URLs.txt",
    },
    "ad": {
        "block": "data/sources/AdBlockList_URLs.txt",
        "allow": "data/sources/AdAllowList_URLs.txt",
        "exception": "data/sources/AdExceptionList_URLs.txt",
    },
}


def utcnow() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def manifest_path(profile: str) -> Path:
    return ROOT / f"data/reports/{profile}_download_manifest.json"


def load_urls(profile: str) -> list[tuple[str, str]]:
    urls = []
    for bucket, filename in PROFILES[profile].items():
        seen = set()
        for line in (ROOT / filename).read_text(encoding="utf-8").splitlines():
            url = line.strip()
            if not url or url.startswith("#"):
                continue
            parsed = urlparse(url)
            if parsed.scheme != "https" or not parsed.hostname or url in seen:
                raise ValueError(f"Invalid or duplicated source URL: {filename}: {url}")
            seen.add(url)
            urls.append((bucket, url))
        if not seen:
            raise RuntimeError(f"Empty source group: {filename}")
    return sorted(urls)


def source_path(profile: str, bucket: str, url: str) -> Path:
    index_key = hashlib.sha256(url.encode("utf-8")).hexdigest()[:20]
    name = re.sub(r"[^A-Za-z0-9._-]", "_", Path(urlparse(url).path).name)[:72] or "source.txt"
    group = "upstream" if profile == "china" else f"upstream/{bucket}"
    return ROOT / f"data/{profile}/{group}/{index_key}_{name}"


def download(url: str) -> bytes:
    # No cache headers, no 304 responses, no redirects to plain HTTP.
    cmd = [
        "curl", "--fail", "--location", "--silent", "--show-error",
        "--compressed", "--connect-timeout", "12", "--max-time", "70",
        "--retry", "2", "--retry-delay", "2", "--retry-max-time", "150",
        "--proto", "=https", "--proto-redir", "=https",
        "--max-filesize", "30000000", "--header", "Cache-Control: no-cache",
        "--user-agent", "Net-Link fresh-source pipeline", "--", url,
    ]
    result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=160, check=False)
    if result.returncode or not result.stdout:
        raise RuntimeError(f"curl={result.returncode}, bytes={len(result.stdout)}, stderr={result.stderr.decode(errors='replace')[-230:]}")
    if len(result.stdout) > 30_000_000:
        raise RuntimeError(f"Unexpected oversized source: {len(result.stdout)}")
    return result.stdout


def load_manifest(profile: str) -> dict:
    data = json.loads(manifest_path(profile).read_text(encoding="utf-8"))
    expected = load_urls(profile)
    records = data.get("sources", [])
    recorded = [(item["bucket"], item["url"]) for item in records]
    if sorted(recorded) != expected or len(recorded) != len(set(recorded)):
        raise RuntimeError(f"{profile}: downloaded source set does not match configured URLs")
    if data.get("source_count") != len(expected) or data.get("downloaded_count") != len(expected):
        raise RuntimeError(f"{profile}: incomplete source download manifest")
    run_id = os.getenv("GITHUB_RUN_ID")
    if run_id and (data.get("github_run_id") != run_id
                   or data.get("github_run_attempt") != os.getenv("GITHUB_RUN_ATTEMPT", "1")):
        raise RuntimeError(f"{profile}: snapshot is from a different GitHub Actions run")
    if not run_id and time.time() - data.get("epoch_seconds", 0) > 3600:
        raise RuntimeError(f"{profile}: local snapshot is older than one hour")
    for item in records:
        path = source_path(profile, item["bucket"], item["url"])
        if path.resolve() != (ROOT / item["path"]).resolve():
            raise RuntimeError("Snapshot path mismatch")
        payload = path.read_bytes()
        if len(payload) != item["size_bytes"] or hashlib.sha256(payload).hexdigest() != item["sha256"]:
            raise RuntimeError(f"Snapshot mismatch: {item['url']}")
    return data


def fetch_all(profile: str) -> None:
    urls = load_urls(profile)
    started = utcnow()
    print(f"[DOWNLOAD] {profile}: fresh fetch of {len(urls)} sources", flush=True)
    payloads = {}
    errors = {}
    with ThreadPoolExecutor(max_workers=min(8, len(urls))) as pool:
        futures = {pool.submit(download, url): (bucket, url) for bucket, url in urls}
        for future in as_completed(futures):
            bucket, url = futures[future]
            try:
                payload = future.result()
                payloads[(bucket, url)] = payload
                print(f"[DOWNLOAD] {bucket} bytes={len(payload)} {url}", flush=True)
            except Exception as exc:
                errors[(bucket, url)] = str(exc)
                print(f"[DOWNLOAD FAILED] {bucket} {url} {exc}", flush=True)
    # Fail BEFORE replacing any snapshots or writing outputs. This prevents a
    # partial refresh from silently becoming a new 'successful' dataset.
    if errors or len(payloads) != len(urls):
        raise RuntimeError(f"Source download incomplete: {len(payloads)}/{len(urls)} succeeded")

    records = []
    for bucket, url in urls:
        path = source_path(profile, bucket, url)
        path.parent.mkdir(parents=True, exist_ok=True)
        payload = payloads[(bucket, url)]
        path.write_bytes(payload)
        records.append({
            "bucket": bucket, "url": url,
            "path": path.relative_to(ROOT).as_posix(),
            "size_bytes": len(payload),
            "sha256": hashlib.sha256(payload).hexdigest(),
        })
    # Source removals are staged as deletions during publication; never retain
    # a decommissioned upstream file as a valid input for a later build.
    expected_paths = {source_path(profile, b, u) for b, u in urls}
    upstream = ROOT / f"data/{profile}/upstream"
    for file in upstream.rglob("*"):
        if file.is_file() and file not in expected_paths:
            file.unlink()
    out = {
        "profile": profile,
        "fetched_at_utc": started,
        "epoch_seconds": time.time(),
        "github_run_id": os.getenv("GITHUB_RUN_ID"),
        "github_run_attempt": os.getenv("GITHUB_RUN_ATTEMPT", "1"),
        "source_count": len(urls),
        "downloaded_count": len(records),
        "source_bytes_total": sum(x["size_bytes"] for x in records),
        "sources": records,
    }
    dst = manifest_path(profile)
    dst.parent.mkdir(parents=True, exist_ok=True)
    dst.write_text(json.dumps(out, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    load_manifest(profile)
    print(f"[DOWNLOAD VERIFIED] {profile}: {len(records)}/{len(urls)} source snapshots in data/", flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("profile", choices=PROFILES)
    args = parser.parse_args()
    fetch_all(args.profile)
