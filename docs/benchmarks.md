# Benchmark and evaluation evidence

This page separates synthetic rule regression, pinned repository evaluation, and performance checks. These answer different questions and must not be combined into one accuracy claim.

## Environment

The current local engineering validation ran on Windows 11 with Python 3.14.7. The GitHub Actions workflow configures tests for Python 3.11, 3.12, 3.13, and 3.14 on Ubuntu. Local results for an uncommitted working tree do not substitute for a remote workflow run.

## Synthetic native-rule fixtures

`python scripts/evaluate_rule_benchmark.py --check` evaluated 16 labeled fixtures across seven native rules. All expected fixture outcomes matched the current implementation. FUSE003 includes two Python AST cases; each other rule has one vulnerable and one secure case, with additional true-negative coverage from other rule fixtures as represented by the benchmark script.

The fixture set is authored and synthetic. It is useful for detecting regressions in known examples, not for measuring field accuracy, general precision, recall, F1, or comparative performance. See [detection benchmark method](detection-benchmark.md) and `reports/benchmark/native-rule-fixtures.json`.

## Pinned public repository scan

The report dated 2026-10-28 records 14 pinned public repositories and 15 configured scopes. It reports 18,855 files scanned, four skipped files, 61 raw static signals, and 28 hardware filename matches. Nineteen signals were labeled high severity and 42 medium severity by the current rules. These are candidate matches, not confirmed vulnerabilities. Three scopes were partial. The scan did not build projects, run their tests, validate firmware behavior, or inspect physical hardware.

Inputs, scope, rule counts, caveats, and historical comparisons are in [`reports/repository-scans/README.md`](../reports/repository-scans/README.md), [`scan-manifest.json`](../reports/repository-scans/scan-manifest.json), and [`triage.md`](../reports/repository-scans/triage.md). A separate holdout and later regression material remain separately labelled under `reports/repository-scans/holdout/` and `reports/pilot-validation/`.

## FUSE self-scan smoke check

On 2026-10-29, the local Windows 11 / Python 3.14.7 working tree self-scan visited 222 files, reported zero findings, and completed discovery with JSON schema 1.10. The scan used `--no-network --no-sbom --no-vulnerabilities --no-firmware --no-git-history`. This checks that the current source tree can be scanned with complete discovery. It is not an independent security review, performance benchmark, or evidence that FUSE has no defects.

## Synthetic scan performance benchmark

`scripts/benchmark_scan.py` measures a fresh FUSE CLI process over a deterministic generated C project. It records the source revision, generated input hash, Python and psutil versions, OS and machine details, scanner options, warm-ups, repetitions, wall-time spread, throughput, and sampled process-tree RSS. Each scan must complete discovery, read the expected files and bytes, and produce zero findings for the benign input. Native rules FUSE001 through FUSE005 receive comment-only prefilter probes so the benchmark exercises their worker path without introducing a finding.

Run it after installing the development dependencies:

```powershell
python scripts/benchmark_scan.py --files 128 --warmups 1 --repetitions 5 --output reports/benchmark/scan-performance.json
```

The saved result uses [scan-performance.schema.json](../reports/benchmark/scan-performance.schema.json). CI runs a smaller one-repetition smoke check and has no timing threshold. The test matrix also exercises the benchmark runner on Ubuntu, Windows, and macOS. The process-tree RSS estimate uses psutil's per-process RSS readings. It sums RSS across the CLI and its descendants, so shared pages may be counted more than once, and 10 ms sampling can miss brief peaks. See the [psutil process and memory API documentation](https://psutil.readthedocs.io/stable/).

### Recorded local baseline

The pinned [baseline report](../reports/benchmark/scan-performance.json) was generated from clean revision `00bb3f2` on Windows 11 build `10.0.26300`, Python 3.14.7, and psutil 7.2.2. It scanned 128 synthetic C files containing 8,990 source bytes, with one warm-up and five measured runs. Discovery completed on all five runs, five native rules were exercised, and no findings were produced.

| Measure | Observed value |
| --- | ---: |
| Median wall time | 1.192724 s |
| Run range | 0.935354 s to 1.209947 s |
| Median absolute deviation | 0.017222 s |
| Throughput at median | 107.317 files/s, 0.007188 MiB/s |
| Maximum sampled process-tree RSS | 52,838,400 bytes |

This is one synthetic baseline on one Windows environment. It is useful for checking that the measurement path works and for future same-input comparisons. It does not represent a typical embedded repository, establish a cross-platform performance profile, estimate detection accuracy, or define a speed target. Extend the harness to representative pinned projects before making general performance claims.

## Comparison limits

No controlled comparison against Semgrep, CodeQL, Cppcheck, compiler analyzers, or another embedded security product is currently available. Similar rule names or overlapping scan outputs are not a fair comparison. A later study needs matched inputs, equivalent rule scope, pinned tool versions, independently reviewed labels, and disclosed exclusions before reporting comparative metrics.
