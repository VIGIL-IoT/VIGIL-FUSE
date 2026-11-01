# Cross-platform pinned repository scan repeat, 2026-11-01

- Workflow runs: [41322196993](https://github.com/VIGIL-IoT/VIGIL-FUSE/actions/runs/41322196993) and [41323181197](https://github.com/VIGIL-IoT/VIGIL-FUSE/actions/runs/41323181197)
- FUSE revision: `17617916e91c28cd0f1cdd299743295d30c47e9f`
- Manifest SHA-256: `cb75e3de0a9e5d7b3e97a3bd844dd9b5857f868e0cae4f4adff6a6732a30cfd1`
- Report schema: 1.1

## Question

How repeatable are wall-time and sampled process-tree RSS measurements for the same FUSE revision, pinned repository scopes, configuration, and recorded runner metadata?

This is a descriptive repeatability check, not a controlled performance comparison or a detector-accuracy evaluation.

## Method and input checks

Each workflow scanned the same four pinned repository scopes on GitHub-hosted Ubuntu, Windows, and macOS. Every scope received one warm-up and three measured scans. Network and optional analyzers were disabled. The reports record the clean FUSE source revision, runner metadata, repository commits, input fingerprint, coverage, skipped inputs, findings, timing samples, and 20 ms process-tree RSS samples.

All six reports passed schema 1.1 validation. Across the two runs, the FUSE revision, operating-system metadata, manifest digest, target repository commits, configuration, selected and scanned file counts, skipped-file reasons, source bytes, finding counts, return codes, and RSS sample completeness match. Each run scanned 8,270 files from 8,273 selected files and recorded 24 candidate findings. One Mynewt input and two ESP-IoT-Solution inputs were skipped for size. These results apply only to the pinned scopes.

## Same-revision results

Each cell gives first-run median seconds, second-run median seconds, and the relative change from the first run. Positive change means the second run took longer.

| Scope | Linux | Windows | macOS |
| --- | --- | --- | --- |
| Mynewt Core | 7.918, 7.928, +0.1% | 9.786, 5.531, -43.5% | 4.699, 6.879, +46.4% |
| Mbed TLS | 2.025, 2.018, -0.3% | 2.202, 1.168, -47.0% | 1.176, 2.194, +86.6% |
| OpenThread | 3.424, 3.408, -0.5% | 4.427, 2.263, -48.9% | 2.107, 3.615, +71.6% |
| ESP-IoT-Solution | 6.469, 6.532, +1.0% | 9.035, 5.044, -44.2% | 3.783, 5.888, +55.7% |

Across the 12 scope and platform pairs, absolute median wall-time changes range from 0.1% to 86.6%. Linux changes range from -0.5% to +1.0%. All Windows medians are 43.5% to 48.9% lower in the second run, while all macOS medians are 46.4% to 86.6% higher. Median per-run peak RSS changes range from -5.8% to +1.1%.

The runs used the same FUSE revision and recorded runner metadata, but separate hosted runner instances. The cause of the platform-specific timing shifts is unknown. The reports do not establish whether host contention, caching, or another unrecorded factor explains the difference. Do not interpret this as a speed ranking, a stable performance regression, or a timing threshold.

## Comparison with the October 31 reports

The first November 1 run has higher median times than the October 31 repeat in all 12 scope and platform pairs, by 8.4% to 89.6%. This cross-date comparison is confounded by a different FUSE revision: the older reports use `c67008d`, while the new reports use `1761791`. The intervening diff includes 860 insertions and 55 deletions across nine source and package-metadata files. The timing difference therefore cannot be attributed to date, runner variability, or code changes alone, and is not a performance-regression result.

The checked-in [Ubuntu report](../../reports/benchmark/repository-scan-performance-ubuntu-2026-11-01.json), [Windows report](../../reports/benchmark/repository-scan-performance-windows-2026-11-01.json), and [macOS report](../../reports/benchmark/repository-scan-performance-macos-2026-11-01.json) are from the first run. The [Ubuntu repeat](../../reports/benchmark/repository-scan-performance-ubuntu-repeat-2026-11-01.json), [Windows repeat](../../reports/benchmark/repository-scan-performance-windows-repeat-2026-11-01.json), and [macOS repeat](../../reports/benchmark/repository-scan-performance-macos-repeat-2026-11-01.json) are from the second run.

## Limits and outcome

These two runs add same-revision, same-day data, but they do not characterize long-term variance or runner generations. One runner per operating system was used in each workflow. Sampled RSS can double-count shared pages and miss short peaks. The cohort remains selected and partial, and its finding counts are not accuracy measurements. No timing threshold or general speed claim is supported. The repository maturity assessment remains 91/100 because independent field accuracy, device validation, analyzer isolation, and distribution review remain open.
