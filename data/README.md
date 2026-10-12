# Data Inputs

This directory contains repository-maintained input data used by the automation pipeline.

## Subdirectories

- `sources/`: upstream seed lists and discovery inputs.
- `allowlists/`: local exclusions, allowlists, and safety filters.

Changes here directly influence generated outputs and should be reviewed with the same care as code changes.

## China rules: sources, provenance and delivery

- `sources/ChinaDomainList_URLs.txt` declares the upstream source URLs.
- Each China build downloads each full upstream source and saves the **original
  response bytes** to versioned files in `data/china/upstream/`, before parsing.
- These raw files are **committed to this repository** after validation and are
  visible under `data/china/upstream/`. This is deliberate: they are inspectable
  provenance, not ephemeral Adblock-related caches.
- `reports/china_source_integrity.json` records every URL, source snapshot,
  SHA-256 checksum, byte count, normalized parsed-rule count, UTC build
  timestamp, Actions run URL, and published Surge/Clash output checksums.
- Any failed/empty upstream source or checksum mismatch stops publication;
  the last validated rule set remains untouched. The workflow additionally
  stores snapshots as a short-lived downloadable Actions artifact.
- The **only Surge China rule delivery** is
  `Surge/Rules/ChinaDomain.list`; it contains domain rules and both IPv4 and
  IPv6 network rules. `Clash/Rules/ChinaDomain.yaml` carries the same rules
  in another syntax.
- A successful build may leave `ChinaDomain.list` with the previous Git
  modification time if its normalized content is identical. The published
  manifest timestamp and Actions run URL show when the last successful
  rebuild occurred, without needlessly rewriting an unchanged rules file.
