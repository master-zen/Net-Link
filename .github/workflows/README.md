# GitHub Workflows

This directory contains the GitHub Actions workflows that regenerate and publish repository outputs.

## Scope

- `merge-ad-sets.yml` discovers ad source URLs and publishes:
  - `Surge/Rules/AdblockSet.list`
  - `Surge/Rules/AdAllowSet.list`
- `merge-china-domain.yml` merges `data/sources/ChinaDomainList_URLs.txt` and publishes:
  - `Surge/Rules/ChinaDomain.list`
- `merge-trackers.yml` merges `data/sources/TrackersList_URLs.txt` and publishes:
  - `Surge/Rules/Trackers.list`
  - `Trackers/Trackers.txt`

## Maintenance Notes

- Workflows should publish deterministic outputs only.
- Cache files and temporary scan artifacts should not be committed unless they are part of an intentional report.
- Build order, validation gates, and publication behavior should stay aligned with the scripts in `scripts/`.
