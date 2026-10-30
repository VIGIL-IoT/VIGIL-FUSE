# Same-day cross-run repository performance comparison

| Field | Value |
| --- | --- |
| Date | 2026-10-31 |
| Earlier workflow | [41130740188](https://github.com/VIGIL-IoT/VIGIL-FUSE/actions/runs/41130740188), FUSE revision `fa600e01578db3555b9822085fb393d70f63bcf2` |
| Repeat workflow | [41136062930](https://github.com/VIGIL-IoT/VIGIL-FUSE/actions/runs/41136062930), FUSE revision `c67008d159015c3e56a8fbc4bdc1f5ed49b0623b` |
| Manifest SHA-256 | `cb75e3de0a9e5d7b3e97a3bd844dd9b5857f868e0cae4f4adff6a6732a30cfd1` |

## Question

How much did the measured median wall time and sampled process-tree RSS vary when the same four pinned repository scopes were scanned in a second GitHub-hosted workflow run?

This is a same-day repeatability check, not a controlled performance comparison. Each workflow used one warm-up and three measured scans per scope on Ubuntu, Windows, and macOS.

## Input and method checks

The two workflow runs used the same report schema, FUSE package version, tool metadata, manifest digest, repository commits, scan configuration, runner environment metadata for each operating system, scope limitations, selected and scanned file counts, source-byte totals, skipped-file reasons, native-analysis statuses, finding counts, and return codes. All reports recorded complete RSS sampling with zero inaccessible process samples.

The recorded FUSE commit changed from `fa600e0` to `c67008d`, but the `src/` tree and repository benchmark scripts were unchanged between those revisions. The reports therefore use different revision identifiers while exercising the same scanner and benchmark implementation.

For each scope, the table compares the median of three wall-time samples from each workflow run. The change is `(repeat median / earlier median - 1) × 100`. Median peak RSS is the median of the three sampled per-run maximum RSS values, converted from bytes to MiB.

## Results

| Runner | Scope | Earlier median (s) | Repeat median (s) | Change | Earlier median peak RSS (MiB) | Repeat median peak RSS (MiB) |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| Linux | Mynewt Core | 7.586 | 5.432 | -28.4% | 51.86 | 52.02 |
| Linux | Mbed TLS | 1.544 | 1.203 | -22.1% | 43.86 | 43.71 |
| Linux | OpenThread | 2.629 | 1.988 | -24.4% | 45.54 | 45.43 |
| Linux | ESP-IoT-Solution | 5.760 | 4.093 | -28.9% | 66.45 | 66.47 |
| Windows | Mynewt Core | 5.490 | 7.573 | +37.9% | 52.77 | 52.91 |
| Windows | Mbed TLS | 0.948 | 1.162 | +22.5% | 43.76 | 43.98 |
| Windows | OpenThread | 1.930 | 2.438 | +26.3% | 46.70 | 46.37 |
| Windows | ESP-IoT-Solution | 4.791 | 6.283 | +31.1% | 58.22 | 58.15 |
| macOS | Mynewt Core | 6.508 | 4.336 | -33.4% | 69.12 | 70.14 |
| macOS | Mbed TLS | 1.234 | 0.890 | -27.9% | 53.84 | 53.81 |
| macOS | OpenThread | 2.047 | 1.622 | -20.7% | 56.23 | 56.66 |
| macOS | ESP-IoT-Solution | 4.877 | 3.296 | -32.4% | 92.77 | 93.56 |

Across the 12 scope-runner pairs, the absolute median wall-time change ranged from 20.7% to 37.9%. Linux and macOS medians were lower in the repeat run for all four scopes, while Windows medians were higher for all four. Median peak RSS changed by 0.02 to 1.02 MiB in absolute terms.

The direction and size of the wall-time shifts differ by operating system, while the recorded input, coverage, and runner metadata match. The cause is unknown. The workflows used separate hosted runner instances, and this experiment did not measure host contention, cache state, or other sources of run-to-run variation. The two runs do not support a speed ranking, fixed timing threshold, or long-term variance estimate.

## Evidence files

The repeat workflow uploaded schema-validated JSON artifacts. They are archived in this repository:

- [Ubuntu report](../../reports/benchmark/repository-scan-performance-ubuntu-repeat-2026-10-31.json)
- [Windows report](../../reports/benchmark/repository-scan-performance-windows-repeat-2026-10-31.json)
- [macOS report](../../reports/benchmark/repository-scan-performance-macos-repeat-2026-10-31.json)
- [Earlier cross-platform experiment](repository-scan-performance-matrix-2026-10-31.md)

Reproduce the repeat run from the FUSE repository root:

```powershell
gh workflow run repository-performance.yml --ref main
```

## Limits and next measurement

The two runs occurred on the same date and recorded the same runner image metadata. They do not address variance across dates or runner generations. Only four selected source scopes were measured, two had oversized-file skips, and the 24 candidate signals remain unadjudicated. More dates and runner generations are needed before evaluating timing variability. Independent finding labels, real firmware behavior, and hardware measurements are separate evidence gaps.

No additional chart was added. Two workflow runs with unknown host conditions do not support a stable performance narrative; the table preserves the exact paired medians without implying a controlled ranking.
