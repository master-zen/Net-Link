# GitHub Workflows

This directory contains the GitHub Actions workflows that regenerate and publish repository outputs.

## Scope

- `merge-ad-sets.yml` discovers ad source URLs and publishes:
  - `Surge/Rules/AdblockSet.list`
  - `Surge/Rules/AdAllowSet.list`

## Maintenance Notes

- Workflows should publish deterministic outputs only.
- Cache files and temporary scan artifacts should not be committed unless they are part of an intentional report.
- Build order, validation gates, and publication behavior should stay aligned with the scripts in `scripts/`.
