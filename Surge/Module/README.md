# Surge Modules

This folder contains generated Surge module files intended for direct subscription or import.

## Current Focus

- `Adblock4limbo.sgmodule` is produced by the ads-only Adblock4limbo generator.
- `StartUpAds.sgmodule` is produced by the Moyu startup-ads generator.

## Expectations

- Module headers must follow the required Surge-compatible metadata format.
- The domain-based ad-block rules are published separately as `Surge/Rules/AdblockSet.list`.
- Only validated outputs should be published here.

## Functional API protection

The Moyu converter intentionally excludes IT Home feed interception, Douban rewrites, movie media URLs, and high-risk initialization, configuration, update and business API routes. Exclusions also remove matching hostnames from MITM when the host is explicitly protected. The original upstream snapshot is retained for auditing.

Run `python3 -m unittest discover -s tests -p "test_moyu_safety.py"` and `python3 scripts/validate_generated.py moyu` before publishing. Exact DNS-level exceptions for the IT Home API, Douban API and the documented Douban trailer host are kept in `data/allowlists/AdblockCriticalAllow.list`. App playback still requires on-device checks against all simultaneously enabled Surge modules.

## Adblock4limbo interception safety

The ads-only variant retains narrowly scoped ad rewrites while excluding generic URL interceptions, video SDK blocking, application JavaScript, unrelated high-value websites and broad shared-CDN MITM wildcards.

The HTML loader only modifies HTML response bodies. It preserves original response headers and page \`window.open\` behavior, retains existing \`<head>\` attributes, and no longer pulls remote site-specific CSS from a separate upstream domain. Site CSS selectors that hide all images, frames or arbitrary page elements are also removed.

\`tests/test_adblock_safety.py\` and the \`adblock\` output validator run in CI, and upstream changes that break required transformation anchors stop publication.

