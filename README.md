# Net-Link

Net-Link is a repository for curated Surge assets and related network data products.
Its primary goal is to publish stable, reviewable, automation-generated outputs that can be consumed directly by end users and automation systems.

## Published Outputs

- `Surge/Module/Adblock4limbo.sgmodule`
- `Surge/Module/StartUpAds.sgmodule`
- `Surge/Rules/AdblockSet.list` and `Clash/Rules/AdblockSet.yaml`
- `Surge/Rules/ChinaDomain.list` and `Clash/Rules/ChinaDomain.yaml`
- `Surge/Rules/httpDNS_Block.list`
- `Surge/Rules/Trackers.list` and `Clash/Rules/Trackers.yaml`
- `Trackers/Trackers.txt`
- `Surge/Icon.json`

## Repository Principles

- Final artifacts come first. The repository is maintained to serve the published outputs, not intermediate scratch files.
- Generated files should be reproducible. Source lists, allowlists, scanners, and builders are preferred over manual edits.
- Surge compatibility is validated against Surge module and rule syntax before publication.
- Security review, allowlist filtering, deduplication, and final validation are expected to happen in automation.

## Where To Look

- [Surge](./Surge/README.md): published Surge modules, rules, icons, and generated script assets.
- [data](./data/README.md): curated source lists and local allowlists that drive the builds.
- [scripts](./scripts/README.md): generators, validation, and safe publication.
- [Trackers](./Trackers/README.md): tracker data products and merged source material.
- [data/reports](./data/reports): input manifests and build audit reports.
- [.github/workflows](./.github/workflows/README.md): CI workflows that regenerate and publish supported artifacts.

## Local Checks

Run `python -m unittest discover -s tests -v` to check pure pipeline regressions.
Run `python scripts/validate_generated.py trackers` to check the published tracker URLs, rules and Clash payload against each other.
Other offline profiles are `icons`, `adblock`, and `moyu`. China and Adblock require fresh, run-specific upstream manifests before their full validators can pass.

## Editing Policy

Do not edit generated outputs directly unless the work is explicitly a recovery or debugging task.
Most changes should go into:

- `data/sources/`
- `data/allowlists/`
- `scripts/`
- `.github/workflows/`

Detailed implementation notes live with the relevant subproject folders instead of the repository root.
