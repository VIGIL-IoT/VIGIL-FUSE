# FUSE development roadmap

FUSE is the inspection and evidence-orchestration tool in the [VIGIL-IoT suite](https://github.com/VIGIL-IoT), and a [VIGIL](https://github.com/VIGIL-IoT) Project. This roadmap follows the [research-backed universal-tool strategy](research/universal-fuse-tool-strategy.md). “Universal” means multiple input types with clear coverage and profile boundaries, not an unsupported claim to analyze every device equally.

## 0. Trusted CLI foundation - implemented baseline

- CLI-first install and scan flow with a terminal illustration, text/JSON/SARIF output, a default `.fuse-results` folder, `doctor`, and non-executing `scan --plan`.
- Common finding format with severity kept separate from confidence.
- Seven explicit static rules with redacted evidence, including two ESP-IDF boot-integrity configuration checks.
- Presence-only hardware artifact inventory in JSON and text reports, separate from security findings.
- Vulnerable and secure fixtures plus automated tests for each rule.
- Clear source/configuration file limits and no runtime-validation claim.

## 1. Contracts and source-project profiles - implemented baseline

- Version JSON schema 1.10; retain the 1.1 through 1.9 schemas for existing reports.
- Add `--output-dir`, TOML configuration/path filters, explicit profiles such as generic source, ESP-IDF, Zephyr, and embedded Linux, and default output reports. Profiles extend file discovery; FUSE006 and FUSE007 are the first platform-specific rules, with broader platform rule families still future work.
- Use parser-aware language rules where syntax or data flow matters; retain FUSE-native IoT configuration checks.
- SARIF 2.1.0 export includes source-root URI bases; parser-aware source checks remain future work.

## 1.1 Selected build context adapters - experimental

- `--build-dir` reads known generated ESP-IDF and Zephyr files from an explicitly selected directory inside the scan target. FUSE does not invoke `idf.py`, CMake, west, project scripts, or dependency resolution.
- ESP-IDF `sdkconfig.h` metadata and the selected `sdkconfig` are recorded, and the existing boot-validation rules inspect the selected generated settings. Result applicability stays `candidate` because a selected build is not proof of deployment.
- Zephyr `.config` or generated `autoconf.h` metadata is recorded when present. `--zephyr-hardening-report` imports the selected build's Zephyr `HARDENCONFIG_JSON` output, preserving the upstream profile, rationale, current value, recommendation, and pass/fail/applicability counts.
- The adapters are experimental, bounded to 4 MiB per context file, and report missing or unreadable generated configuration as partial. Imported hardening output must be inside the selected build directory; FUSE does not invoke `west`, CMake, or project scripts.
- ESP-IDF `dependencies.lock` inventory is implemented behind the optional `esp-idf` extra. It records resolved component metadata, preserves lock and manifest hashes, and leaves manifest freshness unverified.
- `scan --plan` reports recognized ESP-IDF/Zephyr project hints and a bounded preview of selected paths, unsupported file types, and hardware filenames. JSON/text reports retain unsupported type counts and mark the inventory incomplete when discovery hits a budget.
- PlatformIO context follows a bounded `extra_configs` include graph and records declared environments, default selections, allow-listed board metadata, `src_dir`, `build_src_filter`, and config digests without running PlatformIO. A supplied or root `compile_commands.json` is indexed for translation units and compiler families. Commands remain data and are never invoked. Compiler-semantic analysis remains future work.
- Firmware-like files in common build-output directories are inventoried by path, extension, and size only. They are not verified as firmware and are not passed to Binwalk unless separately selected.
- The GitHub Actions analyzer reports workflow-level `permissions: write-all`, counts recognized non-SHA action references, and creates findings only for obvious floating branches. It does not parse job-level permissions, expression taint, permission inheritance, or event reachability.
- A selected or uniquely detected KiCad XML netlist can produce informational debug-interface connectivity candidates. It does not establish PCB routing or physical exposure.
- Explicit CSV/TSV hardware BOM import produces normalized component inventory and a CycloneDX 1.6 hardware BOM artifact. The default filename inventory remains content-blind.
- CycloneDX VEX 1.5/1.6 can annotate dependency findings after exact product PURL, component PURL, and advisory matches. Imported review context never removes or downgrades a FUSE finding. VEX signature verification remains future work.
- An explicit in-toto SLSA statement can be compared with a firmware image SHA-256. A digest match is reported separately from signature, builder trust, and build-policy verification, which FUSE does not perform.
- Implemented: record the selected ESP-IDF `sdkconfig`, the observed `SDKCONFIG_DEFAULTS` order, target-specific default candidates, hashes, and missing or unreadable inputs in the report. Conventional defaults remain candidates when no selected build confirms them. Add pinned framework-version fixture coverage before any supported label. Zephyr hardening import remains experimental and requires the project's own JSON output.

## 0.3 research-backed foundations - in progress

- Added repository CI on Python 3.11 through 3.14, report-schema validation, wheel and source-distribution builds, and an installed-CLI scan smoke check. The workflow uses read-only repository permissions and SHA-pinned actions.
- The current report contract is schema 1.10. The report includes explicit legacy text decoding fallback, bounded firmware candidate inventory, workflow signals, KiCad netlist observations, PlatformIO include provenance and source-filter metadata, compilation-database indexing, optional hardware BOM import, product PURL and CycloneDX VEX context, and SLSA subject digest comparison.
- Implemented: `doctor` reports the current OS and architecture alongside Python and optional tools; bounded path and framework previews in `scan --plan`; a shared support matrix; strict no-network OSV mode; shareable target labels; explicit symlink refusal; bounded SBOM detection and matching; a 50 MiB SBOM cap; configurable scan-wide path, directory, source-byte, and time budgets with hard ceilings; and a 512 MiB default firmware cap configurable up to 2 GiB. Also implemented are interruptible per-rule subprocess timeouts with per-rule coverage statuses; conservative rule-owned input prefilters; line-shift-stable SARIF `primaryLocationLineHash` values; bounded analyzer diagnostics; SARIF result truncation accounting; CVSS vector preservation; finding applicability/validation fields; honest incomplete exit statuses; and Binwalk version reporting. Intentional rule-level skips are distinct from partial coverage. A successful signature-only Binwalk run is complete for its documented scope; a truncated saved artifact is partial.
- Implemented `baseline create`, `baseline diff`, `baseline suppress`, and `baseline unsuppress`. Baselines require complete scan reports; diffs retain suppressed counts, mark incomplete scans as exit 2, and do not infer resolved findings when coverage is incomplete. Suppressions are bound to the target label and profile and include a required reason, optional owner, creation time, and optional expiry. Native comparison identity ignores line-number shifts and uses rule, path, category, title, and redacted evidence. A second path-independent identity classifies a file move only when one unmatched old finding and one unmatched current finding agree; ambiguous duplicates remain new and resolved for review. Moves do not carry suppressions to a new path. OSV findings remain path-sensitive.
- Implemented opt-in Git-history scanning with Gitleaks. It scans commits reachable from `HEAD` only when requested, keeps historical exposure separate from working-tree results, never stores raw match or secret fields, and reports shallow history as partial.
- Firmware image size is independently configurable with `--max-firmware-bytes` or `scan.max_firmware_bytes`. Oversized images receive a report and are rejected before hashing or Binwalk analysis.
- The results viewer accepts external links only when they use HTTPS and the exact `github.com` host. The dashboard builder normalizes target labels in the aggregate without rewriting scanner-produced JSON, text, or SARIF reports.
- Implemented a local pinned qualitative corpus of 14 repositories and 15 scopes across ESP-IDF, Zephyr, Arduino, Pico SDK, ESPHome, OpenWrt, Buildroot, and Yocto component repositories. The latest clean-source snapshot at `fe6dfd2` records 18,857 scanned files, 35 raw signals, two skipped files, and per-scope coverage; earlier 78-, 62-, 61-, and 38-signal passes are retained as historical comparisons. This is not a representative accuracy benchmark.
- Implemented in this cycle: add a separate four-project corpus outside the 14-repository tuning set, preserve its initial pinned snapshot, and produce independent JSON/SVG summaries plus manual triage. Fixture-backed refinements now distinguish UI-language names and NMEA parser tokens from credentials, require TLS context for generic `verify=false`, and exclude `Kconfig.net` from netlist inventory. On the same 13,050-file validation corpus, signals fell from 13 to 4 and the hardware filename false positive fell from 1 to 0. This is a regression comparison on observed cases, not a precision or accuracy score. Reports record seven skipped inputs, and holdout results are not mixed into the training dashboard.
- Implemented in this cycle: pin a fresh four-project cohort of MicroPython, MCUboot, FreeRTOS Kernel, and NuttX apps outside both earlier corpora; scan 5,885 files; and produce separate JSON/SVG summaries plus manual triage. The initial seven signals included a prompt-string false positive, three related conditional TLS verification signals, two known test-key files, and one example PPP credential. The prompt false positive guided a narrow FUSE001 refinement; initial and post-change reports remain separate and outside the training dashboard. This cohort is now a regression set, not a blind sample.
- Implemented in this cycle: pin a second independent four-project cohort of Mynewt, Mbed TLS, OpenThread, and ESP-IoT-Solution before the FUSE001 change; scan 8,108 files and retain its reports separately. The pre-change baseline contains 23 raw signals, and two of four scopes are partial. This cohort was not used to select the FUSE001 change and is kept out of the training dashboard.
- Remaining: enable and monitor GitHub private reporting, add framework-version and build-target variation, and select another independent set before future rule changes use these observed cohorts.
- Release gate: resolve the restrictive license against PyPI's Terms of Service and Acceptable Use Policy before any package upload.

## 2. Component inventory and vulnerability matching - first adapters implemented

- Accept project lockfiles/manifests and detect supplied CycloneDX/SPDX inputs; direct SBOM advisory matching is implemented.
- ESP-IDF lock inventory reads a root `dependencies.lock` without running the component manager; a lock entry is not proof of inclusion in a released image.
- Optional Syft and OSV-Scanner subprocess adapters emit CycloneDX, normalize advisory findings, and record tool status/version/artifacts.
- Optional CycloneDX VEX import annotates exact component and advisory matches. The original finding and threshold behavior remain unchanged.
- Distinguish declared dependencies from components actually present in a firmware filesystem.
- Preserve package identifiers, versions, data source, and matching evidence.

## 3. Firmware intake - identification implemented; extraction deferred

- Explicit firmware mode hashes the image and can run Binwalk signature identification without extraction.
- The pinned Binwalk v3.1.0 adapter workflow passed synthetic gzip, XZ, and CRC-valid U-Boot uImage positives plus clean and invalid-header controls on Ubuntu and Windows; see the [signature matrix experiment](experiments/binwalk-signature-matrix-2026-10-31.md). Hash-pinned Tasmota v16.0.0 and OpenWrt 25.12.6 Malta BE samples also passed their expected gzip and SquashFS signature checks on both systems; see the [real firmware experiment](experiments/binwalk-real-firmware-2026-10-31.md) and [real filesystem experiment](experiments/binwalk-real-filesystem-2026-10-31.md). These identification checks do not inspect filesystem contents. Broader firmware, filesystem formats, and device behavior remain future work.
- Optional in-toto SLSA provenance intake compares the statement's subject digest to a selected firmware image. It does not authenticate the statement or claimed builder.
- Add an isolated, bounded extractor only after a disposable worker/container boundary is available.
- Any future extractor must run in a disposable, unprivileged worker with byte, file-count, recursion, time, and memory limits.
- Index extracted files without executing them; track original image and extraction-path provenance.
- Report unsupported formats, extraction failures, and partial coverage.

## 4. Firmware-specific static analysis - initial ESP-IDF rules implemented

- Add tested checks for update/signature configuration, cryptography, debug interfaces, embedded Linux services, and platform defaults. Initial ESP-IDF rules flag explicit bootloader settings that skip app-image validation; they do not evaluate Kconfig dependencies or infer runtime OTA/deep-sleep paths.
- Build platform profiles from evidence, not filename guesses alone.
- Keep board-dependent or runtime-dependent conclusions labeled as requiring review or lab validation.
- Evaluate precision and false-positive patterns against a documented embedded corpus.

## 5. Interoperability and workflows

- Export findings as SARIF and component inventory as CycloneDX; both formats are implemented in the CLI baseline.
- A pinned SHA and least-privilege GitHub Actions example uploads canonical reports, publishes SARIF in a separate job, and restores FUSE's exit status. Additional CI integrations, then HTML, editor, and dashboard adapters for the [VIGIL-IoT suite](https://github.com/VIGIL-IoT), remain future work.
- The FUSE repository has a separate Python compatibility and package-build workflow in `.github/workflows/ci.yml`.
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
