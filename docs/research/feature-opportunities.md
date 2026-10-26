# FUSE feature opportunities

**Research note - 26 October 2026**  
**A [VIGIL](https://github.com/VIGIL-IoT) Project**

## Summary

FUSE already has a useful local scanning foundation: a CLI, seven tested static rules, severity and confidence as separate fields, redacted evidence, text/JSON/SARIF reports, scan coverage metadata, optional Syft and OSV-Scanner adapters, and Binwalk signature identification. The highest-value next step is to make FUSE more context-aware and easier to use in a normal development workflow, not to add a large number of unvalidated pattern rules.

Recommended order:

1. Add build-configuration audits for one or two supported embedded frameworks, starting with ESP-IDF and Zephyr.
2. Add a GitHub Actions example and verify stable SARIF identity across repeat scans.
3. Add baselines, finding diffs, and reviewable suppressions.
4. Expand firmware analysis only after a bounded, isolated extraction boundary exists.
5. Add device-context vulnerability status through VEX and optional parser-aware analyzers.

“Universal” should mean that FUSE can route different artifact types to suitable analyzers and show exactly what it covered. It should not mean that one scan can prove every property of every device.

## Current scope and product gaps

| Area | Present in the repository | Useful next capability |
| --- | --- | --- |
| Source and configuration | Seven conservative rules, generic and embedded discovery profiles | Effective build configuration checks with board and release context |
| Findings | Versioned JSON, text, SARIF, evidence, remediation, separate severity and confidence | Stable cross-run identity, baseline and diff state |
| Dependencies | Optional Syft inventory and OSV-Scanner advisory matching | Preserve whether a component came from a source manifest, installed image, or SBOM; add product-context VEX |
| Firmware | Hashing and optional Binwalk signature identification without extraction | Isolated bounded extraction with file ancestry and partial-coverage reporting |
| CI | SARIF export and severity exit threshold | GitHub Actions workflow, PR annotations, new-findings policy |
| Reports | `.fuse-results` with text, JSON, SARIF, and optional analyzer artifacts | Optional HTML review page after finding identity and triage are stable |
| Research workflow | FUSE and SPECTRA-32 are described as complementary | A later handoff record linking a static hypothesis to a controlled lab run and mitigation measurement |

The current ESP-IDF and Zephyr profiles mainly expand file discovery. A selected profile does not yet mean that FUSE understands the effective configuration or applies a full platform hardening baseline.

## Evidence from primary documentation

NIST organizes IoT technical security capabilities into device identification, configuration, data protection, logical access, software update, cybersecurity state awareness, and device security. It describes the catalog as a starting point whose abilities should be filtered to a profile suited to the use case. This supports a context-aware profile and coverage model, while cautioning against presenting a generic scan as a compliance verdict. [NIST technical capability catalog](https://pages.nist.gov/IoT-Device-Cybersecurity-Requirement-Catalogs/technical/)

Espressif's security guidance treats secure boot, flash encryption, debug interfaces, TLS, provisioning, OTA, secure storage, and device control as distinct areas. These are strong candidates for ESP-IDF checks, but the check should identify the actual configuration evidence and whether it came from a build configuration, source file, or firmware image. [ESP-IDF security overview](https://docs.espressif.com/projects/esp-idf/en/stable/esp32/security/security.html)

Zephyr provides a hardening tool that compares an application's Kconfig values against a maintained recommendation database. It has base and strict profiles, accounts for hardware-dependent options, and identifies options marked experimental, deprecated, or not secure. FUSE should avoid maintaining a competing copy of every Zephyr recommendation. It can either consume results from the upstream tool or implement a small, documented set of checks over a generated build configuration. [Zephyr hardening tool](https://docs.zephyrproject.org/latest/security/hardening-tool.html)

GitHub accepts SARIF from third-party tools for code-scanning alerts. Its documentation describes stable rule IDs, file paths, and fingerprints as important for matching results across runs and avoiding duplicate alerts. FUSE already emits SARIF, so a workflow template is an achievable integration. Code-scanning availability depends on repository visibility and its GitHub plan. [SARIF support](https://docs.github.com/en/code-security/reference/code-scanning/sarif-files/sarif-support), [uploading SARIF](https://docs.github.com/en/code-security/how-tos/find-and-fix-code-vulnerabilities/integrate-with-existing-tools/upload-sarif-file)

OSV-Scanner separates source manifests from installed artifacts because they answer different questions. FUSE should keep that distinction visible in dependency evidence, especially when it begins inspecting extracted firmware. [OSV-Scanner supported artifacts and manifests](https://google.github.io/osv-scanner/supported-languages-and-lockfiles/)

CycloneDX VEX represents exploitability information in the context of a product and its components. FUSE could import and export VEX records to capture reviewed product-specific status. A VEX statement should retain its justification and evidence, and should not silently erase the underlying advisory or FUSE finding. [CycloneDX VEX](https://cyclonedx.org/capabilities/vex/)

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

Add a baseline command or report option so teams can distinguish new, persistent, resolved, and suppressed findings. Suppressions should include a reason, owner if known, and optional expiration. The output should retain suppressed counts and scan coverage so suppressions cannot make an incomplete scan look clean.

This should follow stable finding identity work. The current location-based ID and line-sensitive fingerprint are not sufficient for reliable long-lived baselines when files move or lines are inserted.

### P1: NIST-aligned capability coverage

Map rules to the seven NIST technical capability areas. In reports, show states such as assessed, signal found, not assessed, and not applicable, with the evidence source. Let projects choose a device profile that filters relevant capabilities and checks.

Keep this as a navigation and coverage aid. Do not label the report NIST compliant, certified, or secure unless a separately scoped assessment justifies that claim.

### P1: Safe firmware extraction and artifact provenance

Move from signature identification toward a staged pipeline: identify and hash the image, extract in a disposable unprivileged worker, inventory extracted content, then route files to existing analyzers. Enforce limits on input size, extracted bytes, file count, recursion, CPU, memory, and wall time. Disable network access and program execution by default. Preserve the parent image hash and extraction path for every result, and report partial or failed extraction explicitly.

This can unlock filesystem configuration, installed package inventory, embedded certificates, and service configuration checks. It is a higher-effort change because untrusted firmware parsing expands FUSE's attack surface.

### P1: Product-context vulnerability status

Add optional CycloneDX VEX input and output after FUSE has a clear component identity contract. A reviewed `not affected` status should include a reason and evidence, remain linked to the advisory and component, and never be inferred solely because FUSE found no vulnerable code path.

### P2: Optional parser-aware source analysis

Offer an optional adapter for a suitable language analyzer when a rule requires syntax or code context. Normalize its results into the FUSE finding model while preserving original rule IDs, tool versions, analyzer status, and coverage. Keep a fixture and tests for each FUSE-native rule; do not present a generic analyzer run as embedded platform coverage.

### P2: HTML report and SPECTRA-32 handoff

An offline HTML report can make a result folder easier to review once finding identity, baselines, and suppression behavior are stable. Later, a small machine-readable handoff can link selected static findings to a controlled SPECTRA-32 experiment, mitigation, FUSE rescan, and measured overhead. Static evidence and lab results should remain separate records.

## Landing page recommendations

The current landing page already shows the CLI workflow, a sample finding, seven implemented rules, evidence boundaries, local report outputs, and the SPECTRA-32 relationship. Keep those as the present-tense product claims.

The most useful additions would be a short supported-inputs and analyzer matrix, a capability map that distinguishes implemented checks from planned areas, and a preview of the actual `.fuse-results` folder. Mark CI uploads, baselines, HTML output, extraction, VEX, and lab handoff as planned until each exists in the CLI. This makes the landing page more informative without suggesting that the roadmap is already implemented.

## Suggested implementation sequence

1. Stabilize SARIF rule IDs, paths, and fingerprints. Add repeat-scan tests.
2. Ship one GitHub Actions example and document local fallback reports.
3. Add a baseline/diff model with explicit suppression reasons and coverage accounting.
4. Choose a concrete ESP-IDF or Zephyr production profile and test it against paired secure and insecure build configurations.
5. Add capability coverage metadata without making compliance claims.
6. Design and threat-model the isolated firmware extraction worker before enabling extraction.
7. Add VEX and parser-aware analyzer adapters after component identity and adapter contracts are stable.

## Research method

The sources above were retrieved directly with the locally installed Crawl4AI 0.9.5 package on 26 October 2026. This was a documentation review, not a benchmark of tools or a compliance assessment. Source pages were selected from standards, platform documentation, and official project documentation. Recommendations are a product synthesis of those sources and the repository's current implementation.
