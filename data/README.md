# Data Inputs

This directory contains repository-maintained input data used by the automation pipeline.

## Subdirectories

- `sources/`: upstream seed lists and discovery inputs.
- `allowlists/`: local exclusions, allowlists, and safety filters.

Changes here directly influence generated outputs and should be reviewed with the same care as code changes.

## China and Adblock: one reproducible pipeline each

Both automation workflows use the same **strict ordering**:

1. **Fresh download** every configured HTTPS source into tracked `data/<profile>/upstream/`, replacing the previous per-URL snapshot. If ANY source fails, abort without publishing partial output.
2. **Manifest verification**: `data/reports/<profile>_download_manifest.json` records source URL, byte size, SHA-256, Actions run ID and download time. The offline builder rejects input from a different run, even if old snapshots exist in Git.
3. **Build exclusively offline** from the newly downloaded input files; normalize, deduplicate, filter documented risks, and produce a single Surge rule delivery (plus the same Clash rules in another format).
4. **Validate** counts, full Surge/Clash content equality, source hashes, regional exclusions or Adblock safety exceptions; fail rather than replace a previously successful set on any detected anomaly.
5. **Publish** to GitHub's current `main` without a force push. Reject any build whose relevant source files or code were superseded since checkout; do not rebase conflicting generated timestamps.
6. **Verify the remote** Git object hashes for every input snapshot and final published file. Actions success is only reported once remote contents have been confirmed.

### China

- Configured domestic inputs: `data/sources/ChinaDomainList_URLs.txt`.
- Foreign-routing/domain comparison inputs: `ChinaForeignDomain_URLs.txt`.
- Foreign-IP/Asia-Pacific registry comparison inputs: `ChinaForeignIP_URLs.txt`.
- Curated high-confidence exclusions: `data/allowlists/ChinaForeignDomains.list`, `ChinaForeignIPs.list`.
- Downloaded input bytes: `data/china/upstream/`.
- Risk analysis: `data/reports/china_risk_audit.json`. Registry country is
  **allocation metadata**, not proof of actual IP geolocation. Proxy-category
  conflicts are reviewed rather than blindly treated as foreign geography.
- Only Surge delivery: `Surge/Rules/ChinaDomain.list`; contains domains,
  IPv4 and IPv6. `Clash/Rules/ChinaDomain.yaml` is its Clash-format equivalent.

### Adblock

- Configured blocks, allows and issue-backed breakage exceptions:
  `data/sources/AdBlockList_URLs.txt`, `AdAllowList_URLs.txt`,
  `AdExceptionList_URLs.txt` (AdGuard DNS exceptions).
- Downloaded input bytes: `data/ad/upstream/block/`, `allow/` and `exception/`.
- Extra protected login/checkout services: `data/allowlists/AdblockCriticalAllow.list`.
- Risk/audit decisions: `data/reports/ad_build_audit.json`.
- Only Surge delivery: `Surge/Rules/AdblockSet.list`; `Clash/Rules/AdblockSet.yaml`
  is its Clash-format equivalent.

Downloaded raw files are deliberately **tracked** in Git; Actions also uploads
short-lived ZIP artifacts. This allows independent inspection of what was
actually used, while still ensuring every new build fetches all sources again.
A normalized output file may keep its old Git modification timestamp when its
contents are byte-for-byte identical; check the current run manifest and its
output SHA-256 to verify the most recent rebuild. Updates are never fabricated
just to make GitHub show a newer file date.

**Limits**: third-party domains and IPs can change ownership, CDN hosting and
routing geography. Neither an RIR registration-country file nor external
proxy lists can guarantee that all network addresses are physically in mainland
China. A false-positive allowlist also cannot predict every future breakage;
reported new exceptions need ongoing verification.
