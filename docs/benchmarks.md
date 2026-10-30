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

## Performance metrics

The repository does not currently maintain a cross-platform throughput or memory benchmark. CI's self-scan checks completion and severity conditions, not elapsed time or memory. Historical local timing observations are not used here as a supported performance claim because they are not tied to a committed benchmark harness and stable input snapshot.

Future performance evidence should record the exact FUSE revision, OS, Python version, CPU and memory, repository manifest, scanner options, warm-up policy, repetition count, median and spread, files/bytes scanned, skipped inputs, and peak memory. A timing result must be kept separate from detection-quality evidence.

## Comparison limits

No controlled comparison against Semgrep, CodeQL, Cppcheck, compiler analyzers, or another embedded security product is currently available. Similar rule names or overlapping scan outputs are not a fair comparison. A later study needs matched inputs, equivalent rule scope, pinned tool versions, independently reviewed labels, and disclosed exclusions before reporting comparative metrics.
