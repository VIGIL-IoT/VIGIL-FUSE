# FUSE feature opportunities

**Research note - 26 October 2026**  
**A [VIGIL](https://github.com/VIGIL-IoT) Project**

**Implementation update - 28 October 2026:** the local CLI now includes the default report bundle, `doctor`, `scan --plan`, bounded scan execution, conservative rule-owned prefilters, line-shift-stable SARIF fingerprints, hardware filename inventory, a pinned GitHub Actions example, baseline create/diff/suppress/unsuppress commands with conservative file-move classification, stable shareable target labels, an opt-in import path for Zephyr hardenconfig JSON, and opt-in redacted Gitleaks history scanning. Selected ESP-IDF generated-configuration findings carry candidate applicability and generated-config provenance. The pinned 14-repository snapshot was refreshed after rule refinements. Two separate four-repository validation cohorts are pinned; the first exposed a FUSE001 prompt-string false positive and the second was preserved as an independent pre-change set. Framework/build-target variation remains open.

**Implementation update, continued:** FUSE now has repository CI for Python 3.11 through 3.14, schema validation, package builds, and an installed CLI smoke scan. Schema 1.8 records metadata-only PlatformIO environment and compilation-database inventories, opt-in CSV/TSV hardware BOM import with CycloneDX HBOM output, exact-match CycloneDX VEX review context, and in-toto SLSA subject digest comparison for firmware. These additions do not run platform build commands, authenticate VEX or provenance signatures, or perform compiler-semantic C/C++ analysis.

**Implementation update, 28 October 2026:** schema 1.10 adds explicit reporting when legacy text files are decoded with an ISO-8859-1 fallback. Schema 1.9 added bounded PlatformIO `extra_configs` provenance and source-filter metadata, a firmware-like extension/size inventory across common output folders, narrow GitHub Actions checks for workflow-level `write-all` and recognized action references, and informational KiCad debug-net candidates from a bounded XML netlist. Non-SHA action references are counted, but only obvious floating branches produce findings. These checks do not resolve effective source compilation, inspect firmware candidate bytes, model workflow event data flow, or prove physical debug access.

**Implementation update, 31 October 2026:** `FUSE-GHA-003` adds a high-confidence review candidate for an exact `pull_request_target` trigger combined with `actions/checkout` of the pull request head SHA or ref. `FUSE-GHA-004` adds a bounded allowlist check for selected untrusted event fields directly interpolated into step run scripts. Fixtures cover direct inline and block interpolation, environment-mediated values, action inputs, and a trusted context control. FUSE does not infer whether subsequent steps execute checked-out code or whether a script interpolation is exploitable.

## Summary

FUSE already has a useful local scanning foundation: a CLI, seven tested static rules, severity and confidence as separate fields, redacted evidence, text/JSON/SARIF reports, scan coverage metadata, optional Syft and OSV-Scanner adapters, Binwalk signature identification, and opt-in redacted Git-history scanning through Gitleaks. The highest-value next step is to make FUSE more context-aware and easier to use in a normal development workflow, not to add a large number of unvalidated pattern rules.

Recommended order:

1. Expand build-context coverage across framework versions, targets, and declared environments while keeping selection evidence visible.
2. Add parser-aware analyzer adapters only where syntax or data flow improves a specific embedded check.
3. Improve package-presence evidence and VEX trust handling while preserving the original advisory and FUSE finding.
4. Expand firmware analysis only after a bounded, isolated extraction boundary exists.

“Universal” should mean that FUSE can route different artifact types to suitable analyzers and show exactly what it covered. It should not mean that one scan can prove every property of every device.

## Current scope and product gaps

| Area | Present in the repository | Useful next capability |
| --- | --- | --- |
| Source and configuration | Seven conservative rules, generic and embedded discovery profiles, selected build context, and imported Zephyr hardening results | Effective build configuration checks with broader framework-version and board coverage |
| Findings | Versioned JSON, text, SARIF, evidence, remediation, separate severity and confidence, move-aware baselines | Review move classifications across real project changes and integrate baseline policy into PRs |
| Dependencies | Optional Syft inventory, OSV-Scanner advisory matching, component PURLs, and exact-match CycloneDX VEX review context | Preserve whether a component came from a source manifest, installed image, or SBOM; authenticate VEX signatures |
| Firmware | Hashing, optional Binwalk signature identification, and in-toto subject digest comparison without extraction | Isolated bounded extraction with file ancestry and partial-coverage reporting; authenticate statements and builder trust |
| Secrets | Native checks on selected working-tree files and opt-in Gitleaks scan of commits reachable from `HEAD` | Run Gitleaks against full and shallow histories, then refine path and test-fixture behavior |
| CI | Python compatibility workflow, package build smoke checks, SARIF export, severity exit threshold, pinned consuming-repository workflow example | PR annotations and policy integration for baseline diffs |
| Reports | `.fuse-results` with text, JSON, SARIF, and optional analyzer artifacts | Optional HTML review page after finding identity and triage are stable |
| Research workflow | FUSE and SPECTRA-32 are described as complementary | A later handoff record linking a static hypothesis to a controlled lab run and mitigation measurement |

The current ESP-IDF and Zephyr profiles expand file discovery and support selected build context. Zephyr can also import the upstream hardening tool's JSON report. A selected profile still does not mean that FUSE understands every part of the effective configuration or applies a complete platform hardening baseline.

## Evidence from primary documentation

NIST organizes IoT technical security capabilities into device identification, configuration, data protection, logical access, software update, cybersecurity state awareness, and device security. It describes the catalog as a starting point whose abilities should be filtered to a profile suited to the use case. This supports a context-aware profile and coverage model, while cautioning against presenting a generic scan as a compliance verdict. [NIST technical capability catalog](https://pages.nist.gov/IoT-Device-Cybersecurity-Requirement-Catalogs/technical/)

Espressif's security guidance treats secure boot, flash encryption, debug interfaces, TLS, provisioning, OTA, secure storage, and device control as distinct areas. These are strong candidates for ESP-IDF checks, but the check should identify the actual configuration evidence and whether it came from a build configuration, source file, or firmware image. [ESP-IDF security overview](https://docs.espressif.com/projects/esp-idf/en/stable/esp32/security/security.html)

Zephyr provides a hardening tool that compares an application's Kconfig values against a maintained recommendation database. It has base and strict profiles, accounts for hardware-dependent options, and identifies options marked experimental, deprecated, or not secure. FUSE should avoid maintaining a competing copy of every Zephyr recommendation. It can either consume results from the upstream tool or implement a small, documented set of checks over a generated build configuration. [Zephyr hardening tool](https://docs.zephyrproject.org/latest/security/hardening-tool.html)

GitHub accepts SARIF from third-party tools for code-scanning alerts. Its documentation describes stable rule IDs, file paths, and fingerprints as important for matching results across runs and avoiding duplicate alerts. FUSE already emits SARIF, so a workflow template is an achievable integration. Code-scanning availability depends on repository visibility and its GitHub plan. [SARIF support](https://docs.github.com/en/code-security/reference/code-scanning/sarif-files/sarif-support), [uploading SARIF](https://docs.github.com/en/code-security/how-tos/find-and-fix-code-vulnerabilities/integrate-with-existing-tools/upload-sarif-file)

OSV-Scanner separates source manifests from installed artifacts because they answer different questions. FUSE should keep that distinction visible in dependency evidence, especially when it begins inspecting extracted firmware. [OSV-Scanner supported artifacts and manifests](https://google.github.io/osv-scanner/supported-languages-and-lockfiles/)

CycloneDX VEX represents exploitability information in the context of a product and its components. FUSE now imports CycloneDX VEX as exact-match review metadata and retains the underlying advisory and finding. The next work is stronger component-presence evidence, authenticated VEX signatures, and carefully scoped support for additional status formats. [CycloneDX VEX](https://cyclonedx.org/capabilities/vex/)

Semgrep's rule format supports language-aware patterns and rule testing. This is a possible optional adapter for source-code checks where syntax or code context matters. FUSE's own rules should remain focused on embedded configuration and IoT context that a general source analyzer does not express well. [Semgrep rule syntax](https://semgrep.dev/docs/writing-rules/rule-syntax), [Semgrep rule testing](https://semgrep.dev/docs/writing-rules/testing-rules)

## Prioritized opportunities

### P0: Effective build-configuration audits

Add checks against the configuration that will actually be built, rather than treating every checked-in config fragment as active. Start with a narrow ESP-IDF and Zephyr scope.

Candidate checks include explicit insecure OTA validation settings, explicit TLS verification bypasses in active configuration, release builds with debug interfaces or shell features enabled, and platform-specific boot or flash protections that a selected production profile requires. Report configuration provenance and mark a check unknown when the effective configuration or target hardware is unavailable.

Use a profile such as `esp-idf:production` or `zephyr:strict` to state the expected policy. A profile should say which requirements were assessed, not claim that the device is compliant. A missing option is not evidence that a protection is disabled unless the selected framework's configuration semantics support that conclusion.

### P0: GitHub Actions and SARIF stability

Provide a small workflow that installs or invokes FUSE, scans the project, uploads `findings.sarif`, and retains the `.fuse-results` directory as a workflow artifact. Keep local reports useful even when GitHub code scanning is unavailable.

Before depending on alert deduplication, ensure rule IDs remain stable and SARIF fingerprints do not change merely because a nearby line moved. Keep paths relative to the scan root and add tests that scan the same fixture twice and after a harmless line insertion. Respect repository permissions and GitHub plan requirements in setup documentation.

### P0: Baseline, diff, and suppression lifecycle

Implemented locally as `baseline create`, `baseline diff`, `baseline suppress`, and `baseline unsuppress`.

Teams can distinguish new, persistent, moved, resolved, and suppressed findings. Suppressions include a required reason, optional owner, and optional expiration. Identical repeated matches in one file receive separate suppression identities. The diff retains suppressed counts and scan coverage so suppressions cannot make an incomplete scan look clean. Baseline creation requires complete coverage; incomplete current scans do not infer resolved findings.

The path-sensitive comparison identity survives harmless line insertion. A second identity can classify a native finding as moved only when exactly one unmatched baseline finding and one unmatched current finding agree on rule, analyzer, category, title, and redacted evidence. Ambiguous duplicates remain new and resolved for review. OSV inventory findings remain path-sensitive, and suppressions do not follow a finding to a new path. Baseline format 1.1 records the move identity while FUSE continues to read 1.0 baselines without move matching.

### P1: NIST-aligned capability coverage

Map rules to the seven NIST technical capability areas. In reports, show states such as assessed, signal found, not assessed, and not applicable, with the evidence source. Let projects choose a device profile that filters relevant capabilities and checks.

Keep this as a navigation and coverage aid. Do not label the report NIST compliant, certified, or secure unless a separately scoped assessment justifies that claim.

### P1: Safe firmware extraction and artifact provenance

Move from signature identification toward a staged pipeline: identify and hash the image, extract in a disposable unprivileged worker, inventory extracted content, then route files to existing analyzers. Enforce limits on input size, extracted bytes, file count, recursion, CPU, memory, and wall time. Disable network access and program execution by default. Preserve the parent image hash and extraction path for every result, and report partial or failed extraction explicitly.

This can unlock filesystem configuration, installed package inventory, embedded certificates, and service configuration checks. It is a higher-effort change because untrusted firmware parsing expands FUSE's attack surface.

### P1: Product-context evidence and VEX trust

CycloneDX VEX input and exact product, component, and advisory matching are implemented. A reviewed `not affected` status requires a recognized reason and remains attached to the original advisory. Improve component identity and image-presence evidence before authenticating signatures or adding another VEX vocabulary. Never infer `not affected` solely because FUSE found no vulnerable code path.

### P2: Optional parser-aware source analysis

Offer an optional adapter for a suitable language analyzer when a rule requires syntax or code context. Normalize its results into the FUSE finding model while preserving original rule IDs, tool versions, analyzer status, and coverage. Keep a fixture and tests for each FUSE-native rule; do not present a generic analyzer run as embedded platform coverage.

### P2: HTML report and SPECTRA-32 handoff

An offline HTML report can make a result folder easier to review once finding identity, baselines, and suppression behavior are stable. Later, a small machine-readable handoff can link selected static findings to a controlled SPECTRA-32 experiment, mitigation, FUSE rescan, and measured overhead. Static evidence and lab results should remain separate records.

## Landing page recommendations

The current landing page already shows the CLI workflow, a sample finding, seven implemented rules, evidence boundaries, local report outputs, and the SPECTRA-32 relationship. Keep those as the present-tense product claims.

The most useful additions would be a short supported-inputs and analyzer matrix, a capability map that distinguishes implemented checks from planned areas, and a preview of the actual `.fuse-results` folder. The CLI baseline workflow, repository CI, exact-match CycloneDX VEX context, and local report bundle are implemented. HTML output, isolated firmware extraction, authenticated provenance verification, richer component-presence evidence, and SPECTRA-32 lab handoff remain future work. The Actions example is a documented template and still needs adaptation and permissions review in each consuming repository.

## Suggested implementation sequence

1. Stabilize SARIF rule IDs, paths, and fingerprints. Implemented locally with repeated-scan and line-insertion checks; repository-specific GitHub upload behavior still needs maintainer configuration.
2. Ship one GitHub Actions example and document local fallback reports. The pinned example is documented in `docs/github-actions.md`.
3. Add a baseline/diff model with explicit suppression reasons and coverage accounting. Implemented locally; see the CLI examples in the README.
4. Choose a concrete ESP-IDF or Zephyr production profile and test it against paired secure and insecure build configurations.
5. Add capability coverage metadata without making compliance claims.
6. Design and threat-model the isolated firmware extraction worker before enabling extraction.
7. Improve component-presence evidence and authenticated VEX workflows after source identity and trust-policy contracts are stable. Add parser-aware analyzer adapters where syntax or data flow is required.

## Research method

The sources above were retrieved directly with the locally installed Crawl4AI 0.9.5 package on 26 October 2026. This was a documentation review, not a benchmark of tools or a compliance assessment. Source pages were selected from standards, platform documentation, and official project documentation. Recommendations are a product synthesis of those sources and the repository's current implementation.
