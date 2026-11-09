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
