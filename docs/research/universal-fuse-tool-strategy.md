# FUSE as a broad embedded and IoT security analysis tool

**Research and architecture recommendation - 25 October 2026**  
**A [VIGIL](https://github.com/VIGIL-IoT) Project**

## Executive recommendation

Build FUSE as a **modular analysis orchestrator with an IoT-focused finding and evidence model**. Its scope can grow from source repositories and configuration files to software inventories and firmware images, while each input type is handled by a suitable parser or external-analysis adapter.

“Universal” should mean that FUSE accepts several useful input types, selects relevant analyzers, and reports what it did and did not inspect. It should not mean one ruleset claims to understand every chip, RTOS, boot chain, binary format, and runtime. NIST’s device-capability catalog explicitly describes a broad baseline and says capabilities must be filtered for the situation; its categories include identity, configuration, data protection, logical access, software update, state awareness, and device security.[NIST technical capability catalog](https://pages.nist.gov/IoT-Device-Cybersecurity-Requirement-Catalogs/technical/), [NISTIR 8259A](https://csrc.nist.gov/pubs/ir/8259/a/final)

FUSE should own the **workflow, IoT-specific checks, evidence, confidence, correlation, and report**. It should integrate mature specialist tools for firmware extraction, software inventory, language-aware source analysis, and vulnerability matching instead of reimplementing all of them. FUSE should never silently convert an indicator into a claim that a device is exploitable or secure.

## What the research shows

| Source or project | Relevant design evidence | What FUSE should take from it |
| --- | --- | --- |
| [NISTIR 8259A capability catalog](https://pages.nist.gov/IoT-Device-Cybersecurity-Requirement-Catalogs/technical/) | Organizes device security around capabilities and ability statements, and supports tailoring to the device context. | Use capability categories and device profiles. Mark whether a check is static, inventory-based, or requires lab/runtime evidence. |
| [OWASP Firmware Security Testing Methodology (FSTM)](https://github.com/scriptingxss/owasp-fstm) | Describes a multi-stage firmware assessment spanning acquisition, extraction, static analysis, emulation/dynamic work, and reporting. | Keep firmware ingestion, extraction, static analysis, and dynamic validation as distinct stages. FUSE should cover the static inspection stages and exchange evidence with lab tooling. |
| [EMBA](https://github.com/e-m-b-a/emba) | Presents an integrated firmware workflow with extraction, static analysis, SBOM work, dynamic/emulation profiles, and a web report; its own project cautions that analysts must interpret and verify results. | Study its pipeline and report model, but keep EMBA optional as an adapter. FUSE's findings should remain reviewable evidence, not automatic verdicts. |
| [FACT](https://github.com/fkie-cad/fact_core) | Describes a modular analysis system that takes firmware samples through analysis and makes contents/results browsable, searchable, and comparable. | Preserve artifact provenance and support comparison between scan runs; avoid making FUSE rules depend on a single front end. |
| [Binwalk](https://github.com/ReFirmLabs/binwalk) | Identifies and optionally extracts embedded files/data, supports a broad signature set, and offers entropy analysis; its Rust implementation can be integrated into other Rust projects. | Treat extraction and carving as a specialized adapter. Extraction is a starting point for later analyzers, not a vulnerability finding by itself. |
| [CycloneDX](https://cyclonedx.org/specification/overview/) | Its current specification is modular and can represent software, hardware, source/configuration components, services, dependencies, and provenance. | Use a standard BOM for inventory exchange instead of inventing a FUSE-only component format. |
| [Syft](https://github.com/anchore/syft) and [OSV-Scanner](https://google.github.io/osv-scanner/supported-languages-and-lockfiles/) | Syft generates SBOMs from filesystems/images; OSV-Scanner accepts source artifacts, lockfiles/manifests, and SBOMs, and distinguishes source manifests from installed artifacts. | Keep component identification separate from advisory matching. Let an SBOM connect those stages and record which evidence came from a source manifest versus an installed filesystem. |
| [SARIF 2.1.0](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html) | Provides a standard interchange format for static-analysis results, including rule identifiers and source locations. | Keep the FUSE JSON model as the canonical format and add a SARIF exporter for code-host and CI integrations. |
| [Semgrep rule syntax](https://docs.semgrep.dev/writing-rules/rule-syntax) and [rule-writing methodology](https://semgrep.dev/blog/2020/writing-semgrep-rules-a-methodology/) | Supports declarative, language-aware rules, metadata, and example-based rule testing. | Use language-aware analyzers for code semantics; reserve FUSE-native rules for IoT configuration and cross-file/context checks that generic SAST does not cover. |

Primary references: [OWASP FSTM](https://github.com/scriptingxss/owasp-fstm), [EMBA](https://github.com/e-m-b-a/emba), [FACT](https://github.com/fkie-cad/fact_core), [Binwalk](https://github.com/ReFirmLabs/binwalk), [CycloneDX specification](https://cyclonedx.org/specification/overview/), [Syft](https://github.com/anchore/syft), [OSV-Scanner supported artifacts](https://google.github.io/osv-scanner/supported-languages-and-lockfiles/), [OASIS SARIF 2.1.0](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html), and [Semgrep rule syntax](https://docs.semgrep.dev/writing-rules/rule-syntax).

This is an architecture synthesis, not a measured head-to-head benchmark. The upstream tools have different operating assumptions and licenses: EMBA and FACT identify as GPL-3.0 projects, while the Binwalk repository identifies as MIT. Review compatibility and packaging obligations before bundling any tool or code; a subprocess boundary is an integration choice, not an automatic license conclusion.[EMBA](https://github.com/e-m-b-a/emba), [FACT](https://github.com/fkie-cad/fact_core), [Binwalk](https://github.com/ReFirmLabs/binwalk)

## Implemented baseline in this repository

The initial recommendation has been turned into a local Python package and CLI. It scans selected source/configuration files with seven tested FUSE-native rules, including two explicit ESP-IDF bootloader image-validation setting checks. It recognizes supplied CycloneDX/SPDX inventories for direct advisory matching, can request Syft SBOM generation and OSV-Scanner matching, can request Binwalk signature identification for one raw firmware image, and can optionally scan Git history with Gitleaks while retaining only redacted finding metadata. The default `vigil-fuse scan .` workflow writes text, schema-versioned JSON, and SARIF reports to `.fuse-results`; generated analyzer artifacts are listed with hashes. `doctor`, a non-executing `scan --plan`, a support matrix, bounded input and subprocess handling, strict no-network mode, hardware filename inventory, and explicit incomplete statuses are implemented. The separate baseline commands compare complete reports, manage reasoned expiring suppressions, and conservatively classify unique native findings that move between files.

Firmware extraction, emulation, runtime validation, parser-backed cross-file analysis, broader platform-specific rule families, and hosted integrations remain deferred. Binwalk is run without extraction flags. A successful signature pass is complete for that documented stage, while a truncated saved signature report is partial. OSV advisory severity is sourced from upstream labels or supported CVSS vectors; unsupported or missing scores stay `unknown`. This baseline is a useful local package, not a claim of complete coverage across device classes.

## Recommended product boundary

FUSE should be the **glue and IoT analysis layer**, not an attempt to replace every existing scanner.

- **FUSE-native:** IoT configuration checks, embedded defaults, cross-file signals, profile selection, evidence normalization, scan coverage, deduplication, and remediation context.
- **Language analyzers:** use parser-aware tools such as Semgrep or compiler/static-analysis tooling for C/C++ and other supported languages when the detection depends on control flow, data flow, or syntax. Keep simple literal/configuration rules small and tested.
- **Firmware extraction:** call an optional, version-checked extractor such as Binwalk or a selected firmware-analysis framework. Record extraction warnings and never treat “files were extracted” as proof that the full image was understood.
- **Component inventory:** use an SBOM generator such as Syft, then query known-vulnerability data through OSV-Scanner or another explicit provider. Do not scrape arbitrary web pages at scan time to make vulnerability decisions.
- **Dynamic validation:** hand selected candidates to a controlled lab workflow. FUSE should not automatically execute or emulate unknown firmware; SPECTRA-32 is the natural partner in the [VIGIL-IoT suite](https://github.com/VIGIL-IoT) for controlled reproduction and overhead measurement.

Crawl4AI is useful for the **research and documentation collection** that informed this plan. Crawl4AI 0.9.5 was installed here and used to retrieve the upstream EMBA, FACT, and Binwalk project READMEs. It should not be a required runtime dependency of the scanner. For vulnerability intelligence, prefer structured APIs and versioned feeds with identifiers and provenance over general-purpose page crawling. See the [Crawl4AI SDK reference](https://docs.crawl4ai.com/complete-sdk-reference/).

## Target analysis pipeline

```text
input → identify and hash → inventory → select profile/adapters → analyze
      → normalize and correlate → report findings + coverage + provenance
                                      └→ optional SPECTRA-32 lab validation
```

1. **Accept and identify inputs.** Begin with a source directory/repository, configuration files, lockfiles/manifests, and an existing SBOM. Later accept firmware archives and raw images. Record the input kind, relative paths, file hashes, and scan-root boundaries.
2. **Choose a profile.** Examples: generic source/configuration, ESP-IDF, Zephyr, embedded Linux, or a user-defined device profile. A profile chooses relevant rules and adapters; it must not hide unsupported evidence.
3. **Inventory artifacts.** Distinguish source manifests from packages actually present in an extracted image. Preserve original path and extraction provenance so a result can be traced back to a file inside an image.
4. **Run specialized analyzers.** Run local rules, language-aware analyzers, component/SBOM generation, advisory matching, and firmware extraction as separate stages. Each adapter reports its version, result, warnings, limits, and whether it ran.
5. **Normalize and correlate.** Convert adapter output to the FUSE finding model, deduplicate only when rule, artifact, location, and evidence support it, and preserve the original adapter finding as provenance.
6. **Report findings and coverage.** Generate findings plus an explicit analysis summary: scanned, skipped, unsupported, extracted, and failed stages. “No findings” must not imply complete coverage.
7. **Validate experimentally when needed.** Send selected findings to a controlled lab, record the reproduction outcome separately, apply mitigation, rescan with FUSE, and measure performance/security overhead with SPECTRA-32.

## Architecture to grow into

Keep the public CLI thin and split the internal system into stable boundaries:

- **Input adapters:** source tree, single text/config file, SBOM/lockfile, firmware image/archive.
- **Artifact inventory:** normalized relative paths, file type, hashes, size, origin, and extraction parent.
- **Profile resolver:** platform/framework hints and explicit user selections; uncertain identification stays uncertain.
- **Analyzer adapters:** native FUSE rules, language analyzers, firmware extractors, SBOM generators, vulnerability providers.
- **Rule registry:** stable rule IDs, applicability, severity, confidence, category, explanation, remediation, references, and test fixtures.
- **Evidence/finding model:** one canonical schema for all adapters, with adapter-specific details retained as provenance.
- **Correlator:** cross-file or cross-stage joins, such as endpoint configuration plus credentials, without inventing proof of runtime use.
- **Report exporters:** text/JSON first, SARIF for static code findings, CycloneDX for component inventory, then HTML/dashboard.
- **Execution boundary:** timeouts, version checks, bounded temp storage, cancellation, and adapter-specific sandbox policy.

Use plugin/adapter contracts rather than importing each third-party scanner into the core package. An adapter should declare its input types, optional executable/version, arguments, timeout/resource limits, output parser, and capability gaps. Run command arguments as an argument list, not a shell-concatenated string; capture stdout/stderr as evidence only after redacting secrets.

## Finding and scan contract

The current FUSE schema already separates severity from confidence and carries location, evidence, explanation, potential impact, remediation, and references. Preserve that contract. The baseline also includes rule and analyzer provenance, stable fingerprints, scan coverage, artifact hashes, and a versioned JSON schema. Grow it additively with:

- stable rule ID and a separate location/content fingerprint for deduplication and scan-to-scan comparison;
- asset identity (source tree or firmware hash), source path, and extraction ancestry;
- observation source (`native-rule`, `Semgrep`, `Syft`, `OSV`, `Binwalk`, etc.) and tool/ruleset versions;
- evidence type and redacted excerpt, plus the exact static/configuration basis for the claim;
- analysis state and coverage metadata, including stages not run or files omitted;
- applicability/profile context and an explicit “needs runtime validation” state when relevant.

Define confidence in project documentation: **high** means direct, specific static evidence for the stated observation; **medium** means a contextual association or heuristic; **low** means a weak indicator requiring review. High confidence must not imply high impact. Severity expresses potential impact given assumptions; confidence expresses support for this particular claim. Do not collapse them into one score.

## Safety and trust boundaries

Firmware inputs and archive contents are untrusted. Extraction and parsing expand FUSE’s attack surface. Before enabling image scans:

- run extraction in a disposable, unprivileged worker or container;
- set limits for total input size, extracted bytes, file count, recursion depth, CPU, memory, and wall time;
- reject or safely contain absolute paths, `..` traversal, and dangerous symlink behavior;
- do not execute extracted programs, init scripts, or firmware by default;
- keep network access disabled unless an explicitly selected advisory adapter needs it;
- report partial extraction and unsupported formats instead of silently treating them as clean;
- retain hashes and tool versions so a report is reproducible.

This boundary is a prerequisite for firmware support, not polish to add afterward. It also supports a privacy promise: source and firmware remain local by default; remote lookups should send only the identifiers required by the selected provider.

## Phased roadmap and release gates

### Phase 0 - trusted CLI foundation (implemented)

Keep conservative rules, paired vulnerable/secure fixtures, redacted evidence, and JSON/text output. Default reports, hardware inventory, `doctor`, dry-run planning, resource limits, analyzer coverage, and baseline review are implemented. Do not expand the rule list as a substitute for architecture.

### Phase 1 - stable contracts and source-project profiles (baseline implemented)

The baseline ships a versioned JSON schema, `--output-dir`, TOML configuration/path filters, fingerprints, SARIF output, and generic/ESP-IDF/Zephyr/embedded-Linux discovery profiles. Keep general-source rules separate from platform rules. Add parser-backed checks where source semantics matter and stabilize a public adapter interface as integrations expand.

**Gate:** every rule has its fixture pair and tests; skipped/unsupported files appear in summary; repeat scans produce stable fingerprints; scans do not modify their target.

### Phase 2 - dependency and inventory adapter (initial adapters implemented)

Optional Syft CycloneDX generation, OSV-Scanner advisory matching, source-manifest fallback, and direct CycloneDX/SPDX SBOM inputs are implemented. Validate known-vulnerable versus patched package behavior on embedded corpora. Continue to distinguish a declared dependency from an installed component and include ecosystem, version, and match provenance in findings.

**Gate:** known vulnerable and patched package fixtures produce the expected different results; offline/failure behavior is reported; dependency findings cite the matched component and advisory.

### Phase 3 - safe firmware intake and extraction (identification baseline implemented)

Raw-image fingerprinting and optional Binwalk signature identification are implemented without extraction. Add an optional extractor only after a disposable, bounded worker exists. Index extracted filesystem contents without executing them. Start with a bounded set of image/filesystem formats instead of claiming support for every vendor container.

**Gate:** malicious archive/path/recursion/resource fixtures are contained; partial extraction is visible; every extracted file maps to its original image and offset/path where possible.

### Phase 4 - firmware-specific static analysis (initial ESP-IDF rules implemented)

The baseline includes two ESP-IDF boot-integrity rules for explicit settings that skip bootloader app-image validation. Continue with tested rule families for other OTA/update verification, embedded Linux services/default accounts, crypto choices, and debug/JTAG/UART indicators. Rules should say when context is required (board config, bootloader, build profile, or runtime).

**Gate:** evaluate precision and false-positive patterns on a documented embedded corpus; keep device profiles and rule exclusions reviewable.

### Phase 5 - interoperability and workflows (core formats implemented)

Versioned JSON, SARIF findings export, CycloneDX inventory generation, and a pinned GitHub Actions workflow example are implemented or documented. HTML, editor, and hosted-dashboard integrations remain future work until report identities, baselines, and diff behavior have seen use across projects.

### Phase 6 - [VIGIL-IoT suite](https://github.com/VIGIL-IoT) lab loop

Add an explicit handoff contract to SPECTRA-32 for chosen hypotheses. Record FUSE static evidence, lab reproduction, mitigation, rescan, and measured overhead as separate linked artifacts.

**Gate:** never label a static finding “confirmed” solely because the lab can reproduce a related scenario; confirmation must refer to the same asset/configuration and documented setup.

## Decisions to make later

These are product choices, not blockers for the current CLI:

1. Which first user profile matters most: ESP-IDF/MCUs, Zephyr/RTOS, or embedded Linux?
2. Which optional tools can users install and run in their environment, and which supported platforms will FUSE maintain?
3. Should firmware extraction run locally in a container, a separate worker, or remain an external user-managed step in the first firmware release?
4. Which disclosure/privacy model should apply to advisory lookups, logs, and uploaded reports?
5. FUSE now uses a custom source-available license that allows personal and commercial use but prohibits redistribution and published modifications. This is not an OSI-approved open-source license. Continue to keep third-party tools as optional adapters and review each upstream license before bundling code or binaries.

These choices affect implementation order; they do not change the core recommendation: **FUSE owns orchestration, IoT-specific evidence, and honest coverage; specialist tools own their mature extraction, language, SBOM, and advisory functions.**
