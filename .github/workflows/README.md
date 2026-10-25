# GitHub Workflows

This directory contains the GitHub Actions workflows that regenerate and publish repository outputs.

## Scope

- `merge-ad-sets.yml` discovers ad source URLs and publishes:
  - `Surge/Rules/AdblockSet.list`
  - `Clash/Rules/AdblockSet.yaml`
- `merge-china-domain.yml` merges `data/sources/ChinaDomainList_URLs.txt` and publishes:
  - `Surge/Rules/ChinaDomain.list`
  - `Clash/Rules/ChinaDomain.yaml`
- `merge-trackers.yml` merges `data/sources/TrackersList_URLs.txt` and publishes:
  - `Surge/Rules/Trackers.list`
  - `Clash/Rules/Trackers.yaml`
  - `Trackers/Trackers.txt`
- `merge-surge-icons.yml` scans `Surge/Icon/` and publishes:
  - `Surge/Icon.json`

## Maintenance Notes

- Workflows should publish deterministic outputs only.
- Cache files and temporary scan artifacts should not be committed unless they are part of an intentional report.
- Build order, validation gates, and publication behavior should stay aligned with the scripts in `scripts/`.
- Schedules are staggered. Each workflow has its own concurrency group; the publisher fetches current `main`, checks that its own build inputs were not superseded, and retries non-force pushes if another workflow publishes first.
- `quality-check.yml` runs offline regression, syntax and tracked-output checks for pull requests.
