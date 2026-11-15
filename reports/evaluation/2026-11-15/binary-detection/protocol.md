# Binary Detection Completeness Evaluation Protocol

Status: preregistered before detector changes on 2026-11-15.

## Frozen baseline

- Pre-change FUSE commit: `9f696cad25e25feed0416b23e9f0d259c57c5f69`.
- Detector and fixture hashes: `prechange-manifest.json`.
- The November 14 evaluation and its evidence remain immutable.
- The November 14 records do not contain an independent security traversal status. Treat that status as unsupported or unknown, never as complete.

## Questions and success conditions

1. Can the independent security traversal detect a code-referenced plaintext HTTP or MQTT endpoint after more than 1,500 ordinary strings, even when the general string inventory stops at 1,024?
2. Does a complete security traversal report complete rule coverage while leaving a truncated general inventory marked partial?
3. Do secure HTTPS and MQTTS endpoints, and unreferenced plaintext endpoints, remain negative controls?
4. Does reaching a security traversal bound produce partial coverage instead of a clean negative?
5. Are existing input, timeout, output-size, cleanup, and redaction limits preserved?

Controlled binaries will include late-position HTTP and MQTT positives, secure HTTPS and MQTTS controls, unreferenced plaintext controls, optimization variants, stripped variants, and credential-bearing endpoint labels. These are regression controls with construction-based labels, not independent accuracy evidence.

## Real firmware comparison

Rebuild and analyze the pinned ESP-IDF `hello_world` example for ESP32, ESP32-S3, and ESP32-C6 using the pinned ESP-IDF image and commit in the existing workflow. Keep these results in this directory. Record input SHA-256, Ghidra and Java versions, inventory and security statuses, truncation metadata, rule findings, elapsed time, sampled process-tree RSS, and artifact bytes. Compare against the immutable November 14 records. An inventory remains partial wherever its own bound is reached, regardless of security traversal status.

## Independent evaluation boundaries

- Preserve the frozen holdout, reviewer packets, and all existing human-review records.
- Do not use controlled binary regression results as independent precision or recall.
- Do not report reviewer decisions unless reviewers actually provide them.
- Prepare a separately identified emitted-candidate supplement, with separate applicability sampling for ESP-IDF configuration rules. Keep candidate selection and adjudication distinct from this binary completeness experiment.
- Do not tune rules or evaluation thresholds against the frozen holdout.

## Reproducibility

Record the implementation commit, commands, toolchain pins, runtime versions, input hashes, raw machine-readable outputs, and report-generation commands. Retain failed and partial cases. Do not replace previous results or describe a partial inventory as complete.
