# Data Inputs

This directory contains repository-maintained input data used by the automation pipeline.

## Subdirectories

- `sources/`: upstream seed lists and discovery inputs.
- `allowlists/`: local exclusions, allowlists, and safety filters.

Changes here directly influence generated outputs and should be reviewed with the same care as code changes.

## China rules: download and delivery

- `sources/ChinaDomainList_URLs.txt` is the canonical list of upstream URLs.
- Each China build fetches every configured source over HTTPS and saves its original
  response to `data/cache/china/` **before** parsing, filtering, or merging.
- `cache/china/` is a temporary, Git-ignored build directory; it is attached to
  the corresponding GitHub Actions run as `china-upstream-snapshots` (7-day retention).
  Raw upstream files are intentionally not committed to the repository.
- `reports/china_source_integrity.json` is published with the generated rules;
  it records each source URL, relative snapshot path, byte count, SHA-256, and
  parsed-rule count, or the failure reason.
- If even one upstream source fails to download or produces no accepted rules,
  the China job fails and preserves the last successfully published ruleset.
- The only Surge China delivery is `Surge/Rules/ChinaDomain.list`, which includes
  domains, IPv4, and IPv6. `Clash/Rules/ChinaDomain.yaml` is its other-format equivalent.
