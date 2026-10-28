# FUSE independent holdout scans

This folder contains a separate, pinned scan cohort for checking whether the current FUSE rules transfer to embedded projects outside the rule-refinement corpus in [`../scan-manifest.json`](../scan-manifest.json).

The 2026-10-28 holdout includes selected source and configuration scopes from RIOT, Contiki-NG, Crazyflie firmware, and Marlin. Exact upstream commits, scan scopes, and the FUSE source snapshot are recorded in [`manifest.json`](manifest.json). Repository checkouts are maintained separately at `../fuse-scan-targets-holdout` relative to the FUSE repository root, and reports are stored under `reports/` in this folder.

This is a small purposive qualitative holdout, not a statistically representative benchmark. The four repositories are absent from the training manifest. Findings are static signals that need review, not confirmed vulnerabilities. The `generic` profile is used because FUSE does not yet provide dedicated RIOT, Contiki-NG, Crazyflie, or Marlin profiles. Selected scopes are not equivalent to a full repository or effective firmware build analysis.

The first scan produced 13 raw signals across 13,050 scanned files, with seven files skipped under existing input limits. Triage identified eight credential-name false positives, one unrelated `verify=false` match, and one hardware filename false positive. Fixture-backed changes were then checked against the same four repositories. The regression recheck produced four signals, and the hardware inventory no longer misclassifies `Kconfig.net`. These observed reductions are regression results, not a measured precision improvement. The repository set has now informed rule changes, so it is no longer an untouched blind holdout.

The original scan snapshot, summary, and charts are retained in this folder with [`pre-refinement-manifest.json`](pre-refinement-manifest.json). The regression recheck, current FUSE provenance, summary, charts, and local per-scope reports are in [`post-refinement/`](post-refinement/). The manual interpretation and limits are in [`triage.md`](triage.md). All reports are partial because seven selected files were skipped; each report records the skip reasons.

## Reproduce

From the FUSE repository root, with the pinned sparse checkouts available at `../fuse-scan-targets-holdout`:

```powershell
py scripts\run_repository_scan_pilot.py ..\fuse-scan-targets-holdout `
  --manifest reports\repository-scans\holdout\manifest.json `
  --report-root reports\repository-scans\holdout\reports
```

Each scope writes JSON, text, and SARIF reports. The runner checks the pinned commit and refuses to scan a dirty checkout. Holdout reports stay outside the training corpus summary and website dashboard.

Regenerate the holdout summary and plots after a completed scan with:

```powershell
py scripts\build_holdout_scan_summary.py
```

## Review protocol

For each signal, record whether the source is active or illustrative, whether the relevant build selects the path, whether the evidence actually supports the finding title, and what secure or negative context is missing. Track false positives and missed checks separately. Do not change rules based only on these scans; after this pass, turn any proposed changes into focused vulnerable and secure fixtures and rerun the original corpus as a distinct refinement cycle.
