# China routing input evidence (not public subscriptions)

The sole Surge-deliverable China ruleset is
[`Surge/Rules/ChinaDomain.list`](../../Surge/Rules/ChinaDomain.list),
containing normalized domain, mainland IPv4 and IPv6 rules.

## Fresh download inputs

The CI job re-downloads ALL configured URLs on **every build** and commits
each original response under [`data/china/upstream/`](upstream/):

- 12 primary China sources: `data/sources/ChinaDomainList_URLs.txt`
- 4 supplementary CN/DIRECT candidates: `data/sources/ChinaSupplement_URLs.txt`
- 2 independent foreign-domain/routing reference sources:
  `data/sources/ChinaForeignDomain_URLs.txt`
- 2 independent foreign IP/APNIC registration sources:
  `data/sources/ChinaForeignIP_URLs.txt`

The downloader verifies source size and SHA-256, writes
[`china_download_manifest.json`](../reports/china_download_manifest.json),
and the generator is then forced to work **offline from this run's snapshots**.
Missing, failed, stale, or truncated inputs fail the entire refresh; previously
published subscriptions are retained.

## Supplementary CN/DIRECT safety policy

China cloud-company IP ownership does not imply mainland hosting, and a
proxy-provider `DIRECT` label does not prove country of operation.

- Supplement **domains** are admitted only if a trusted primary China rule
  already covers them. Unverified foreign services / arbitrary DIRECT
  exceptions are held out.
- Supplement **IPv4/IPv6** ranges are restricted to intersections with
  independently downloaded, country=`CN` APNIC allocation records.
  Non-CN allocations and foreign-service exclusions are then subtracted.
- Unsupported processes, keywords, global networks and private addresses
  are excluded. No standalone supplement file is published.
- Detailed per-source parsed/accepted/rejected counts and examples are saved
  in [`china_supplement_audit.json`](../reports/china_supplement_audit.json).
  [`china_risk_audit.json`](../reports/china_risk_audit.json) records broader
  foreign-reference exclusions and possible conflicts.

**Geographic limitation:** CN registration proves neither physical network
location nor exclusive mainland use. Rules requiring stronger evidence remain
unpromoted; the whitelist and risk sources cannot guarantee zero cross-border
misclassification.

The build performs normalization, exact and nested-domain deduplication,
IPv4/IPv6 CIDR collapse, independent foreign-network subtraction, integrity
validation and SHA-256 comparison between generated output and remote `main`.
The corresponding Clash file is a second **format**, not another China Surge
subscription. If output bytes are unchanged, its GitHub file modification date
correctly remains unchanged; the manifest always records the new build.
