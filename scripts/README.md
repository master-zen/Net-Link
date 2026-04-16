# Automation Scripts

This directory contains the repository's build and validation logic.

## Ad-Block Pipeline

The ad-block automation is organized as a staged pipeline:

1. discovery
2. allowlist discovery
3. normalization
4. script security scanning and compatibility conversion
5. staged build
6. deduplication inside the staged build
7. final validation
8. publication

`run_ad_block_pipeline.py` is the canonical local entry point for the ad-block stack.

## Maintenance Guidelines

- Prefer changing inputs and builders over editing generated outputs.
- Keep Surge syntax handling aligned with official Surge documentation.
- Validation should fail closed when a staged output is malformed or unsafe to publish.
