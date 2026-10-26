# FUSE development roadmap

FUSE is the inspection and evidence-orchestration tool in the [VIGIL-IoT suite](https://github.com/VIGIL-IoT), and a [VIGIL](https://github.com/VIGIL-IoT) Project. This roadmap follows the [research-backed universal-tool strategy](research/universal-fuse-tool-strategy.md). “Universal” means multiple input types with clear coverage and profile boundaries, not an unsupported claim to analyze every device equally.

## 0. Trusted CLI foundation - implemented

- CLI-first install and scan flow with text and JSON output.
- Common finding format with severity kept separate from confidence.
- Seven explicit static rules with redacted evidence, including two ESP-IDF boot-integrity configuration checks.
- Vulnerable and secure fixtures plus automated tests for each rule.
- Clear source/configuration file limits and no runtime-validation claim.

## 1. Contracts and source-project profiles - implemented baseline

- Version and publish the JSON schema; add stable fingerprints and scan coverage/provenance fields.
- Add `--output-dir`, TOML configuration/path filters, and explicit profiles such as generic source, ESP-IDF, Zephyr, and embedded Linux. Profiles extend file discovery; FUSE006 and FUSE007 are the first platform-specific rules, with broader platform rule families still future work.
- Use parser-aware language rules where syntax or data flow matters; retain FUSE-native IoT configuration checks.
- SARIF 2.1.0 export is available; parser-aware source checks remain future work.

## 2. Component inventory and vulnerability matching - first adapters implemented

- Accept project lockfiles/manifests and detect supplied CycloneDX/SPDX inputs; direct SBOM advisory matching is implemented.
- Optional Syft and OSV-Scanner subprocess adapters emit CycloneDX, normalize advisory findings, and record tool status/version/artifacts.
- Distinguish declared dependencies from components actually present in a firmware filesystem.
- Preserve package identifiers, versions, data source, and matching evidence.

## 3. Firmware intake - identification implemented; extraction deferred

- Explicit firmware mode hashes the image and can run Binwalk signature identification without extraction.
- Add an isolated, bounded extractor only after a disposable worker/container boundary is available.
- Any future extractor must run in a disposable, unprivileged worker with byte, file-count, recursion, time, and memory limits.
- Index extracted files without executing them; track original image and extraction-path provenance.
- Report unsupported formats, extraction failures, and partial coverage.

## 4. Firmware-specific static analysis - initial ESP-IDF rules implemented

- Add tested checks for update/signature configuration, cryptography, debug interfaces, embedded Linux services, and platform defaults. Initial ESP-IDF rules flag explicit bootloader settings that skip app-image validation; they do not infer the effective build configuration or runtime OTA/deep-sleep paths.
- Build platform profiles from evidence, not filename guesses alone.
- Keep board-dependent or runtime-dependent conclusions labeled as requiring review or lab validation.
- Evaluate precision and false-positive patterns against a documented embedded corpus.

## 5. Interoperability and workflows

- Export findings as SARIF and component inventory as CycloneDX; both formats are implemented in the CLI baseline.
- Add GitHub Actions and CI examples, then HTML, editor, and dashboard adapters for the [VIGIL-IoT suite](https://github.com/VIGIL-IoT).
- Keep report exporters independent from rule implementations.

## 6. [VIGIL-IoT suite](https://github.com/VIGIL-IoT) lab loop

- Add an explicit handoff from selected FUSE findings to SPECTRA-32.
- Track static evidence, controlled reproduction, mitigation, FUSE rescan, and overhead measurement as linked but distinct results.
- Do not call a static signal confirmed solely because a related lab scenario is reproducible.

## Rule release gate

1. Every rule has a stable ID, scope, severity, confidence, explanation, potential impact, remediation, and references where appropriate.
2. A vulnerable fixture produces the expected finding with sensitive evidence redacted.
3. A secure fixture produces no finding.
4. Automated tests cover the positive case, negative case, and important exclusions.
5. The rule states when its signal is only static and does not claim runtime exploitability without evidence.
