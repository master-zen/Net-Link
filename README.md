# Net-Link

Net-Link is a repository for curated Surge assets and related network data products.
Its primary goal is to publish stable, reviewable, automation-generated outputs that can be consumed directly by end users and automation systems.

## Published Outputs

- `Surge/Module/Ad_Block.sgmodule`
- `Surge/Rules/Ad_Block.list`
- `Surge/Rules/China.list`
- `Surge/Rules/httpDNS_Block.list`
- `Surge/Rules/Trackers.list`
- `Surge/Icon.json`

## Repository Principles

- Final artifacts come first. The repository is maintained to serve the published outputs, not intermediate scratch files.
- Generated files should be reproducible. Source lists, allowlists, scanners, and builders are preferred over manual edits.
- Surge compatibility is validated against Surge module and rule syntax before publication.
- Security review, allowlist filtering, deduplication, and final validation are expected to happen in automation.

## Where To Look

- [Surge](./Surge/README.md): published Surge modules, rules, icons, and generated script assets.
- [data](./data/README.md): curated source lists and local allowlists that drive the builds.
- [scripts](./scripts/README.md): repository automation for discovery, normalization, scanning, building, and validation.
- [Trackers](./Trackers/README.md): tracker data products and merged source material.
- [build](./build/README.md): generated reports and staging outputs used by automation.
- [.github/workflows](./.github/workflows/README.md): CI workflows that regenerate and publish supported artifacts.

## Editing Policy

Do not edit generated outputs directly unless the work is explicitly a recovery or debugging task.
Most changes should go into:

- `data/sources/`
- `data/allowlists/`
- `scripts/`
- `.github/workflows/`

Detailed implementation notes live with the relevant subproject folders instead of the repository root.
