# FUSE001 NIST SARD CWE-259 C catalogue regression

**Date:** 2026-10-31 | **FUSE revision:** recorded in the result JSON | **Rule:** FUSE001 1.9.0 | **Result type:** rule-specific catalogue regression

## Question

Does FUSE001 identify the NIST SARIF target source file in every accepted C case returned by the NIST SARD API query for CWE-259, Use of Hard-coded Password?

## Input selection and integrity

The [NIST SARD manual](https://www.nist.gov/itl/csd/secure-systems-and-applications/software-assurance-reference-dataset-sard-manual) documents the SARD API and versioned case artifacts. The [SARD documentation](https://samate.nist.gov/SARD/documentation) describes its test-case data. The pinned query selected accepted C cases tagged CWE-259. It returned 76 cases, all marked `mixed`. The complete query URL, retrieval time, selected metadata, source artifact paths, lengths, SHA-256 digests, archive sizes, archive URLs, and archive SHA-256 digests are recorded in [`sard-fuse001-cwe259-c-catalogue-manifest-2026-10-31.json`](../../reports/benchmark/sard-fuse001-cwe259-c-catalogue-manifest-2026-10-31.json).

The evaluator downloads each archive on demand, checks its byte count and pinned SHA-256, safely extracts it with entry, path, and expanded-size limits, and checks each listed source artifact's byte count and SHA-256 before scanning. Transient connection errors get up to three download attempts with bounded backoff. It runs FUSE's generic profile with optional SBOM, vulnerability, firmware, Git-history, and network analysis disabled. Neither source code nor scan reports from the temporary directories are retained.

Reproduce the full run from the repository root:

```powershell
python scripts/evaluate_sard_fuse001_catalogue.py
```

The checked-in machine-readable result is [`sard-fuse001-cwe259-c-catalogue-results-2026-10-31.json`](../../reports/benchmark/sard-fuse001-cwe259-c-catalogue-results-2026-10-31.json). The runner reports case progress and writes per-case target matches, finding counts, extra FUSE001 file observations, scan coverage, manifest digest, and source revision.

For a short connectivity smoke check, pass `--limit 1`; the resulting JSON explicitly marks that only part of the catalogue was evaluated.

## Results

| Measure | Result |
| --- | ---: |
| Accepted mixed C cases evaluated | 76 / 76 |
| NIST SARIF target source files with a FUSE001 finding | 76 / 76 |
| FUSE001 findings | 110 |
| Additional files with FUSE001 findings beyond the SARIF target file in their case | 34 |
| Source target artifacts integrity-checked | 112 |
| Files scanned across all case archives | 492 |
| Rule version observed | 1.9.0 |

The 34 additional file observations occur in 22 multi-file cases. Those observations remain separate from the target-hit count. They are not labeled false positives by this experiment.

## Interpretation and limits

The result demonstrates repeatable FUSE001 detection on this complete API result set for one CWE in synthetic Juliet-derived C cases. It is a broader rule-specific regression check than the previously recorded 10-case sample, and includes those earlier cases. It is not a blind holdout. A `mixed` case contains both good and bad paths, while SARIF targets mark weakness-flow locations. File-level findings beyond the listed SARIF target cannot be reliably labeled false positive or true positive from these labels alone.

This experiment does not estimate precision, recall, specificity, false-positive rate, general C/C++ compatibility, real-project accuracy, firmware accuracy, credential reachability, deployment, or exploitability. The scan does not build or execute source code. NIST's synthetic test cases are useful regression inputs, but they are not a substitute for independently adjudicated, representative embedded projects.

The repository maturity score remains 91/100. The result improves narrow reproducibility evidence and does not close independent field-accuracy, physical-device, real-firmware behavior, OS-level analyzer sandbox, or license-review gaps.
