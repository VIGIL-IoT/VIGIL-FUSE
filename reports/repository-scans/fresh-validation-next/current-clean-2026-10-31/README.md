# Clean-source repeat, 31 October 2026

## Purpose and provenance

This run repeats the four pinned repository scopes from the earlier validation snapshots with a clean, committed FUSE source tree. FUSE was version 0.2.0 at commit `fa5cb3457d0ec20b059496996174999f2b962ec9`. The measured source digest is `8aa509331627698a61462d3aceac331542bcb5845f6c2d97463008729b446287`, and `source_tree_dirty` is `false`.

The candidate repositories and scopes are pinned in [`manifest.json`](manifest.json). FUSE performed source-only scans with no network access. It did not build or test the target repositories, query advisory services, extract firmware, or validate a device. The cohort has been reviewed before, so this is regression validation, not an untouched holdout or independent accuracy evaluation.

## Results

| Repository | Files scanned | Findings | Status |
| --- | ---: | ---: | --- |
| Apache Mynewt | 3,354 | 0 | Partial, one oversized file skipped |
| Mbed TLS | 121 | 0 | Complete for the selected scope |
| OpenThread | 909 | 5 | Complete for the selected scope |
| ESP-IoT-Solution | 3,885 | 21 | Partial, three oversized files skipped |
| **Total** | **8,269** | **26** | Four selected scopes |

Counts by rule: FUSE001 8, FUSE002 5, FUSE006 7, FUSE007 4, and FUSE-GHA-002 2. Counts by severity: high 5, medium 19, and informational 2. These are scanner classifications, not verified product vulnerabilities. The four skipped files were all over the configured size limit. The scoped hardware inventory found zero recognized hardware files; this does not establish that the repositories contain no hardware designs outside the selected paths or supported formats. Ten firmware-like files were inventoried by filename extension, not inspected as firmware images.

The machine-readable aggregate is [`summary.json`](summary.json). Per-repository JSON, text, and SARIF reports are under [`reports/`](reports/). SVG summaries are under [`plots/`](plots/).

## Comparison with the earlier stored report

[`historical-comparison.json`](historical-comparison.json) compares this clean run with the earlier post-refinement snapshot for the same pinned repository commits and scan scopes. The old reports use schema 1.6, while this run uses schema 1.10. The comparison therefore matches stable finding IDs and compares only fields present in both report objects.

The saved artifacts contain 23 earlier findings and 26 current findings: 23 IDs retained, 3 added, 0 removed, and 8 retained findings with changed fields. The eight changed objects are FUSE001 entries whose title, explanation, and rule version differ. The three additional stored-report IDs are one FUSE006 configuration candidate and two informational floating GitHub Actions reference candidates. The earlier scanner source tree was dirty and was not archived, so this difference cannot establish why the old report omitted those IDs or prove a detector improvement.

The comparison reports counts and changed field names only. It does not copy evidence or field values, rerun FUSE, adjudicate findings, or measure accuracy. Its cross-schema behavior is opt-in with `--allow-schema-mismatch`; by default the comparator rejects reports with different schemas.

## Review of the new signals

The three additional IDs are recorded in [`triage.md`](triage.md). They are review candidates with applicability unvalidated. The configuration signal appears in a target-specific ESP-IDF defaults file. The two workflow signals identify mutable `@master` references. None proves a released device uses the configuration or that an action has been compromised.

## Reproduction

From the FUSE repository root, with the pinned target checkouts available next to it at `..\fuse-scan-targets-fresh-validation-next`:

```powershell
py scripts\run_repository_scan_pilot.py ..\fuse-scan-targets-fresh-validation-next `
  --manifest reports\repository-scans\fresh-validation-next\current-clean-2026-10-31\manifest.json `
  --report-root reports\repository-scans\fresh-validation-next\current-clean-2026-10-31\reports

py scripts\build_holdout_scan_summary.py `
  --manifest reports\repository-scans\fresh-validation-next\current-clean-2026-10-31\manifest.json `
  --report-root reports\repository-scans\fresh-validation-next\current-clean-2026-10-31\reports `
  --output-root reports\repository-scans\fresh-validation-next\current-clean-2026-10-31

py scripts\compare_repository_scan_snapshots.py `
  --baseline-manifest reports\repository-scans\fresh-validation-next\post-refinement\manifest.json `
  --baseline-report-root reports\repository-scans\fresh-validation-next\post-refinement\reports `
  --candidate-manifest reports\repository-scans\fresh-validation-next\current-clean-2026-10-31\manifest.json `
  --candidate-report-root reports\repository-scans\fresh-validation-next\current-clean-2026-10-31\reports `
  --allow-schema-mismatch `
  --output reports\repository-scans\fresh-validation-next\current-clean-2026-10-31\historical-comparison.json
```

The FUSE source tree and `pyproject.toml` must be clean before the scan command runs. The historical source snapshots are unavailable, so the earlier reports cannot be exactly replayed.
