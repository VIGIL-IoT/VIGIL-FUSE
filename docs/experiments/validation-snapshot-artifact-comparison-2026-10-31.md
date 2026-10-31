# Stored validation snapshot comparison

## Purpose

Compare the saved baseline and post-refinement FUSE reports for the same four pinned embedded-project scopes. This checks whether the stored finding objects changed between the two snapshots. It is not a scan rerun, manual adjudication, or accuracy estimate.

## Method

The comparison script requires the repository definitions and scan scopes in both manifests to match exactly. It joins findings by stable finding ID, counts added and removed IDs, and counts changed finding fields. The output contains repository IDs, rule IDs, field names, and counts. It does not copy finding evidence or field values.

Run from the repository root:

```powershell
py scripts\compare_repository_scan_snapshots.py `
  --baseline-manifest reports\repository-scans\fresh-validation-next\manifest.json `
  --baseline-report-root reports\repository-scans\fresh-validation-next\reports `
  --candidate-manifest reports\repository-scans\fresh-validation-next\post-refinement\manifest.json `
  --candidate-report-root reports\repository-scans\fresh-validation-next\post-refinement\reports `
  --output reports\repository-scans\fresh-validation-next\comparison.json
```

## Result

The repository IDs, pinned commits, and scan scopes match. The saved artifacts contain 23 baseline findings and 23 post-refinement findings. All 23 stable finding IDs remain, with no additions or removals. Eight finding objects differ only in the `rule_version` field, all for FUSE001. Other serialized fields of those findings are unchanged.

| Repository | Baseline | Post-refinement | Retained IDs | Added | Removed | Changed fields |
| --- | ---: | ---: | ---: | ---: | ---: | --- |
| Mynewt | 0 | 0 | 0 | 0 | 0 | None |
| Mbed TLS | 0 | 0 | 0 | 0 | 0 | None |
| OpenThread | 5 | 5 | 5 | 0 | 0 | One `rule_version` |
| ESP-IoT-Solution | 18 | 18 | 18 | 0 | 0 | Seven `rule_version` |

This demonstrates that the checked-in report artifacts have the same finding identities and payload fields apart from FUSE001 version metadata. It does not show that a detector is accurate, that each finding is valid, or that no findings were missed.

## Provenance limits

Both manifests name FUSE commit `b88f23565d3c6a9cb8d38b136c55813cd2aa2aa0` and set `source_tree_dirty` to `true`. Their source digests differ. Neither digest matches the committed FUSE source tree at that commit or any of the 94 reachable revisions that changed `src/vigil_fuse` or `pyproject.toml` through the current repository revision. The dirty scanner sources were not archived, so the exact implementations used to create these reports cannot be recovered from the repository.

The saved reports remain useful as historical artifacts, with this source-provenance limitation. The repository scan runner now refuses to create new reports with dirty scanner source. Its `--provenance-only` mode records provenance but does not scan.
