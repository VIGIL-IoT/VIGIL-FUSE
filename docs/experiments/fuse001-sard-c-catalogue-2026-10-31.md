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

The checked-in machine-readable result is [`sard-fuse001-cwe259-c-catalogue-results-2026-10-31.json`](../../reports/benchmark/sard-fuse001-cwe259-c-catalogue-results-2026-10-31.json). The runner reports case progress and writes per-case target matches, finding counts, extra FUSE001 file observations, their source basenames and one-based line numbers, scan coverage, manifest digest, and source revision. For additional findings on supported C `#define` string-literal lines, it verifies the source length and SHA-256 again, then compares the case-folded macro name and exact source literal token with a finding in that case's NIST SARIF target. The literal remains in process memory. The result stores only `true`, `false`, or `null` and aggregate counts, never source text or credential values. The comparison does not decode C escapes, resolve macro expansion, or establish credential validity, use, or flow. The manifest pins hashes for the listed source artifacts.

For a short connectivity smoke check, pass `--limit 1`; the resulting JSON explicitly marks that only part of the catalogue was evaluated.

## Results

| Measure | Result |
| --- | ---: |
| Accepted mixed C cases evaluated | 76 / 76 |
| NIST SARIF target source files with a FUSE001 finding | 76 / 76 |
| FUSE001 findings | 110 |
| Additional files with FUSE001 findings beyond the SARIF target file in their case | 34 |
| Additional finding file and line references recorded | 34 |
| Additional locations with same macro name and exact source literal token as a NIST target | 34 / 34 |
| Additional literal comparisons unresolved | 0 |
| Source target artifacts integrity-checked | 112 |
| Files scanned across all case archives | 492 |
| Rule version observed | 1.9.0 |

The 34 additional file observations occur in 22 multi-file cases. The regenerated result records the source basename and one-based line for each. All 34 source lines use the same case-folded macro name and exact source literal token as a finding in their own NIST SARIF target. In case 93527, for example, the target is `CWE259_Hard_Coded_Password__w32_char_51a.c` and the duplicate token appears in companion file `CWE259_Hard_Coded_Password__w32_char_51b.c` at line 21. This identifies repeated source text, not 34 distinct credential tokens. FUSE still reports each affected file location so maintainers can remove every copy. A matching literal does not prove that it is valid or used, and it does not make the additional location a false positive.

## Interpretation and limits

The result demonstrates repeatable FUSE001 detection on this complete API result set for one CWE in synthetic Juliet-derived C cases. It is a broader rule-specific regression check than the previously recorded 10-case sample, and includes those earlier cases. It is not a blind holdout. A `mixed` case contains both good and bad paths, while SARIF targets mark weakness-flow locations. File and line references plus exact-token comparisons make the additional observations reviewable against the hash-pinned source artifacts, but do not label them true or false positives. Independent adjudication remains necessary.

This experiment does not estimate precision, recall, specificity, false-positive rate, general C/C++ compatibility, real-project accuracy, firmware accuracy, credential reachability, deployment, or exploitability. The scan does not build or execute source code. NIST's synthetic test cases are useful regression inputs, but they are not a substitute for independently adjudicated, representative embedded projects.

The full rerun used clean FUSE revision `5d49148`; its result records `source_working_tree_clean: true`, all 76 target matches, 34 additional locations, 34 exact macro-literal matches, and no unresolved comparisons. FUSE CI [run 41186762443](https://github.com/VIGIL-IoT/VIGIL-FUSE/actions/runs/41186762443) and CodeQL [run 41186762434](https://github.com/VIGIL-IoT/VIGIL-FUSE/actions/runs/41186762434) passed on that revision. This improves traceability for review but does not supply independent labels. The repository maturity score remains 91/100 because independent field-accuracy, physical-device, real-firmware behavior, OS-level analyzer sandbox, and license-review gaps remain.
