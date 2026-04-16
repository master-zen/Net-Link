# GitHub Workflows

This directory contains the GitHub Actions workflows that regenerate and publish repository outputs.

## Scope

- `merge-ad-block-stack.yml` builds and validates the main ad blocking artifacts.
- `merge-china-list.yml` publishes the China ruleset.
- `merge-httpdns-block.yml` publishes the HTTPDNS blocking ruleset.
- `merge-trackers.yml` publishes tracker-related list outputs.
- `icon-json.yml` rebuilds `Surge/Icon.json` from the icon catalog.

## Maintenance Notes

- Workflows should publish deterministic outputs only.
- Cache files and temporary scan artifacts should not be committed unless they are part of an intentional report.
- Build order, validation gates, and publication behavior should stay aligned with the scripts in `scripts/`.
