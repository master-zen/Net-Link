# China upstream inputs

This directory is **input evidence**, not a second output for Surge.

- `upstream/`: original bytes downloaded from each configured URL in
  `data/sources/ChinaDomainList_URLs.txt`. Snapshots are tracked in Git so
  users can inspect exactly what entered the build.
- `../reports/china_source_integrity.json`: per-source checksums, sizes,
  parsing counts, and the latest successful build time and GitHub Actions URL.
- `../../Surge/Rules/ChinaDomain.list`: the only published Surge China ruleset,
  after normalization, duplicate elimination, CIDR collapse, and risk filtering.

Snapshots are overwritten in place on upstream changes; they are not
alternate subscriptions or extra China rule outputs. If any source cannot be
downloaded or parsed, the job fails without publishing partial results.

Unchanged normalized rules correctly keep their previous Git modification
date. Consult the integrity report for the most recent validated run.
