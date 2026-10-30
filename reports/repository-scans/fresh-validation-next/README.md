# Second fresh validation snapshot

This cohort was selected and pinned before the next FUSE rule refinement. It is separate from the 14-repository refinement corpus, the first four-repository regression set, and the first fresh validation cohort. It covers Mynewt, Mbed TLS, OpenThread, and ESP-IoT-Solution. See [`manifest.json`](manifest.json) for pinned commits and selected scopes.

The scan is source-only. FUSE does not build these projects, run their test suites, query vulnerability databases, or validate devices. Keep this cohort separate from the training dashboard and do not use its findings to tune the rule before the baseline snapshot is recorded.

The 23 raw findings were reviewed in a separate source-context pass. See [`triage.md`](triage.md) for grouped dispositions and limits. The review did not verify credential validity, effective build configuration, or deployed-product applicability, and it is not independent accuracy evidence.

Reproduce from the FUSE repository root with:

```powershell
py scripts\run_repository_scan_pilot.py ..\fuse-scan-targets-fresh-validation-next `
  --manifest reports\repository-scans\fresh-validation-next\manifest.json `
  --report-root reports\repository-scans\fresh-validation-next\reports

py scripts\build_holdout_scan_summary.py `
  --manifest reports\repository-scans\fresh-validation-next\manifest.json `
  --report-root reports\repository-scans\fresh-validation-next\reports `
  --output-root reports\repository-scans\fresh-validation-next
```
