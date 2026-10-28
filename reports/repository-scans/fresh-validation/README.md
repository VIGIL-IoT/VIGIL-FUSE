# Fresh repository validation snapshot

This cohort was selected and pinned after the 14-repository refinement corpus and the original four-repository regression set. It covers MicroPython, MCUboot, FreeRTOS Kernel, and NuttX applications. The selection protocol, commit IDs, profiles, and selected paths are recorded in [`manifest.json`](manifest.json).

The initial snapshot covers 5,885 selected files and contains seven raw signals. It is for qualitative transfer review, not an accuracy benchmark. FUSE did not build the projects, run their test suites, query vulnerability databases, or validate devices. See [`triage.md`](triage.md) for manual review. One prompt-string false positive guided a narrow FUSE001 refinement; original and post-change reports are stored separately.

Keep this cohort separate from the training dashboard. Scan results go under [`reports/`](reports/), the aggregate is [`summary.json`](summary.json), and separate plots go under [`plots/`](plots/).

Reproduce from the FUSE repository root with:

```powershell
py scripts\run_repository_scan_pilot.py ..\fuse-scan-targets-fresh-validation `
  --manifest reports\repository-scans\fresh-validation\manifest.json `
  --report-root reports\repository-scans\fresh-validation\reports

py scripts\build_holdout_scan_summary.py `
  --manifest reports\repository-scans\fresh-validation\manifest.json `
  --report-root reports\repository-scans\fresh-validation\reports `
  --output-root reports\repository-scans\fresh-validation
```
