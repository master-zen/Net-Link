# Surge Modules

This folder contains generated Surge module files intended for direct subscription or import.

## Current Focus

- `Adblock4limbo.sgmodule` is produced by the ads-only Adblock4limbo generator.
- `AppStartUpADBlacklist.sgmodule` is generated from a reviewed opening-screen-only manifest.

## Expectations

- Module headers must follow the required Surge-compatible metadata format.
- The domain-based ad-block rules are published separately as `Surge/Rules/AdblockSet.list`.
- Only validated outputs should be published here.

## App Start Up AD Blacklist

Only dedicated opening-screen ads, explicit preload and narrowly reviewed response fields are included. The manifest records source provenance; the generator bounds literal hosts, paths and query discriminators, rejects overlap and preserves the protected host list. Shared initialization routes are never rejected wholesale. The local response script is fail-open and does not execute upstream JavaScript. No domain blocking, SDK blocking, information-feed filtering, payment or tracking interference, global UDP blocking or wildcard MITM is included.

Daily upstream auditing preserves reviewed rules and reports changed source hashes for review. New upstream rules are not silently published. Run `python scripts/validate_generated.py startup`, the Python regression tests and `node tests/test_app_startup_ad.js`. Live app/Surge behavior still requires device testing.

## Adblock4limbo interception safety

The ads-only variant retains narrowly scoped ad rewrites while excluding generic URL interceptions, video SDK blocking, application JavaScript, unrelated high-value websites and broad shared-CDN MITM wildcards.

The HTML loader only modifies HTML response bodies. It preserves original response headers and page \`window.open\` behavior, retains existing \`<head>\` attributes, and no longer pulls remote site-specific CSS from a separate upstream domain. Site CSS selectors that hide all images, frames or arbitrary page elements are also removed.

\`tests/test_adblock_safety.py\` and the \`adblock\` output validator run in CI, and upstream changes that break required transformation anchors stop publication.

## Douban split protection

Only `/v2/app_ads/splash` is intercepted by the startup module. General advertising, movie APIs and trailer CDN hosts are untouched; the independent AdblockSet exceptions remain in force.
