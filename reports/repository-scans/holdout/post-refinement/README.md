# Holdout regression recheck

This is a regression recheck of the same four pinned repositories used in the initial holdout snapshot. The initial reports informed the fixture-backed rule and hardware-inventory changes, so this result is not an untouched blind holdout or an accuracy benchmark.

The scanner processed 13,050 files across four selected scopes and produced four static signals: two FUSE001 credential-like literals and two FUSE002 PEM key markers in Contiki-NG example code. RIOT, Crazyflie firmware, and Marlin produced no signals after the targeted refinements. FUSE found no hardware filename matches in the selected sparse scopes after excluding Kconfig files with `.net` suffixes. All four scans are partial because seven files were skipped under existing size or encoding limits.

The exact scanner source snapshot is recorded in [`manifest.json`](manifest.json). Per-scope JSON, text, and SARIF reports are under [`reports/`](reports/), aggregate counts are in [`summary.json`](summary.json), and separate plots are under [`plots/`](plots/). See the parent [`triage.md`](../triage.md) for the original findings, changes, manual review, and limitations.

To repeat this recheck and rebuild its local summary from the FUSE repository root:

```powershell
py scripts\run_repository_scan_pilot.py ..\fuse-scan-targets-holdout `
  --manifest reports\repository-scans\holdout\post-refinement\manifest.json `
  --report-root reports\repository-scans\holdout\post-refinement\reports

py scripts\build_holdout_scan_summary.py `
  --manifest reports\repository-scans\holdout\post-refinement\manifest.json `
  --report-root reports\repository-scans\holdout\post-refinement\reports `
  --output-root reports\repository-scans\holdout\post-refinement
```
