# Clean-source repeat of the four-repository validation cohort

## Question

Do the previously stored four-repository validation reports repeat when scanned with a clean, committed FUSE source tree, and what changes appear in a report-level comparison?

## Method

FUSE 0.2.0 at commit `fa5cb3457d0ec20b059496996174999f2b962ec9` scanned the four repositories and scopes pinned in [`manifest.json`](../../reports/repository-scans/fresh-validation-next/current-clean-2026-10-31/manifest.json). The recorded FUSE source digest is `8aa509331627698a61462d3aceac331542bcb5845f6c2d97463008729b446287`, and the source tree was clean. The scanner used no network access. This was a source scan; it did not build or test target projects or validate devices.

The run produced 26 findings across 8,269 files: 8 FUSE001, 5 FUSE002, 7 FUSE006, 4 FUSE007, and 2 FUSE-GHA-002. Mynewt and ESP-IoT-Solution were partial because one and three oversized files were skipped, respectively. Mbed TLS and OpenThread completed their selected scopes.

The report-level comparison used the earlier post-refinement reports, which record dirty FUSE source and schema 1.6, against the clean repeat's schema 1.10 reports. The comparator was explicitly run with `--allow-schema-mismatch`; it compares stable finding IDs and fields common to both report schemas. It does not copy evidence values into the comparison output.

## Result

The stored reports contain 23 earlier findings and 26 current findings: 23 retained IDs, 3 added IDs, and no removed IDs. Eight retained FUSE001 entries differ in `title`, `explanation`, and `rule_version`. The additional IDs are one target-specific ESP-IDF configuration candidate and two informational findings for floating GitHub Actions references. Manual review is recorded in [`triage.md`](../../reports/repository-scans/fresh-validation-next/current-clean-2026-10-31/triage.md).

## Interpretation and limits

Both report sets describe the same pinned target commits and scan scopes, but the historical FUSE source digests differ and the earlier source snapshots were not preserved. The old scans cannot be exactly replayed. The difference is therefore a comparison of stored artifacts, not evidence that the current implementation improved detection, that the earlier implementation missed a finding, or that the signals are confirmed vulnerabilities. The repeat uses a previously reviewed cohort and is not independent or blind accuracy evidence. See the [snapshot report README](../../reports/repository-scans/fresh-validation-next/current-clean-2026-10-31/README.md) and [machine-readable comparison](../../reports/repository-scans/fresh-validation-next/current-clean-2026-10-31/historical-comparison.json) for full detail.
