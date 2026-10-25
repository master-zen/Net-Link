# Build and Validation Scripts

| Script | Role |
| --- | --- |
| `fetch_rule_sources.py` | Download and hash fresh China or Adblock source snapshots |
| `build_china_domain.py` | Build mainland-domain/IP Surge and Clash outputs from verified snapshots |
| `build_ad_sets.py` | Build AdblockSet outputs from verified snapshots |
| `build_trackers.py` | Fetch, normalize and merge tracker URLs; emit Surge and Clash rules |
| `build_icon_json.py` | Index icons in `Surge/Icon/` |
| `validate_generated.py` | Check counts, syntax, integrity and cross-format consistency |
| `audit_rule_coverage.py` | Audit China and Adblock rule coverage and overlap |
| `publish_generated.py` | Safely publish validated generated outputs in GitHub Actions |

## Offline checks

From the repository root:

```sh
python -m unittest discover -s tests -v
python -m compileall -q scripts tests Surge/Module/.generator
python scripts/validate_generated.py trackers
python scripts/validate_generated.py icons
python scripts/validate_generated.py adblock
python scripts/validate_generated.py moyu
```

The `china` and `ad` validators require fresh, run-specific manifests and upstream snapshots. Scheduled workflows fetch sources, build, validate, publish and verify the remote state. Do not hand-edit generated outputs.
