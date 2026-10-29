# FUSE field follow-up research

**Date:** 28 October 2026  
**Identity:** A [VIGIL Project](https://github.com/VIGIL-IoT)  
**Product:** FUSE, Firmware & Unified Security Engine

This note adds field evidence and current documentation checks to the broader [FUSE universality research](fuse-universality-research-2026-10-27.md) and [feature opportunities](feature-opportunities.md). It focuses on what a fresh PlatformIO scan and a real KiCad BOM reveal about the next engineering steps. It does not repeat the earlier full architecture, packaging, firmware extraction, or evaluation proposals.

## Executive recommendation

Do not add another broad regex rule yet. The next release should make the evidence FUSE already finds more specific to the actual build and artifact:

1. Read PlatformIO `extra_configs` as a bounded include graph so declared environments do not disappear from coverage.
2. Label where a finding came from and whether the selected build includes that code. Keep severity, rule-match confidence, and product applicability separate.
3. Inventory likely firmware binaries in directory scans, but require an explicit selection before image analysis or extraction.
4. Preserve the current hardware filename and BOM inventory boundary. Add component intelligence only after a BOM supplies stable manufacturer part identifiers.

These steps directly address the observed scan gaps. Workflow security rules, deeper OTA validation, and verified build attestations are worthwhile later modules, with their own evidence requirements and fixtures.

## Local implementation update

The follow-up work now implements four bounded stages in the local checkout: PlatformIO `extra_configs` closure and source-filter context; firmware-like filename and size inventory across common output folders; narrow GitHub Actions checks for explicit `write-all` and non-SHA action references, with findings limited to obvious floating branches; and a KiCad XML netlist check for debug-labeled nets connected to connector candidates. Reports use schema 1.9. The implementation does not execute project code, run PlatformIO, read firmware candidate contents, export KiCad files, or claim device exposure.

Verification completed locally: the full suite passed with 163 tests. The Tasmota rescan inspected 6,800 of 6,802 selected files and reported 15 native matches, one informational workflow candidate, 106 PlatformIO environments across four available config files, and 30 firmware filename candidates. PlatformIO remains partial because two declared include files are absent. Five workflows contained 66 non-SHA action references, but only one obvious floating branch produced a finding. No KiCad netlist was detected in Tasmota. The package build also produced a wheel and source archive for version 0.2.0; `twine check` passed for both, and an isolated virtual environment installed the wheel and loaded schema 1.9 successfully.

### PyPI release gate

No package was uploaded. PyPI requires a verified email address for project registration and uploads, and 2FA is mandatory. TestPyPI also has a separate account. The current Acceptable Use Policy says PyPI is for package installation and runtime use, not research, and includes vulnerability research in its explanation. Ask PyPI support whether a defensive static analyzer used on authorized embedded and IoT projects fits that policy before creating an upload token or publishing to either index.

There is also a license conflict to resolve. PyPI's current Terms of Service require an included license to permit redistribution through PyPI by the PSF, service users, and mirror facilities. Without such an included license, the upload terms grant broad redistribution rights to the PSF and other service users. FUSE's custom license currently prohibits redistribution and mirroring. The local custom `LicenseRef` and license file pass packaging checks, but that metadata validation does not make the license compatible with PyPI's upload terms. Keep the package local until the policy question is answered and the owner chooses whether to grant redistribution rights or use another distribution channel. See the [PyPI Acceptable Use Policy](https://policies.python.org/pypi.org/Acceptable-Use-Policy/) and [PyPI Terms of Service](https://policies.python.org/pypi.org/Terms-of-Service/).

## Fresh field evidence

### PlatformIO configuration is split across files

The pre-change Tasmota pilot's root `platformio.ini` has five `extra_configs` entries. Two present included files contain 37 and 69 `[env:name]` sections. The old FUSE scan inspected only the root file and reported zero environments, so it could not associate source matches with a declared target. The repository has no `compile_commands.json`.

PlatformIO documents `extra_configs` as multiple paths or patterns for extending the base configuration, where later options override earlier values. It also documents interpolation for project and system environment values. Per-environment `build_src_filter` rules control which source files are included or excluded, with ordered glob patterns. The new FUSE parser merges bounded includes and preserves declared `src_dir` and ordered filters as metadata. It deliberately does not evaluate interpolation or resolve filters into an effective compiled-file set. Missing files, unresolved variables, cycles, and unsafe paths remain visible as partial coverage rather than being silently skipped. See [PlatformIO `extra_configs`](https://docs.platformio.org/en/latest/projectconf/sections/platformio/options/generic/extra_configs.html), [PlatformIO interpolation](https://docs.platformio.org/en/latest/projectconf/interpolation.html), [PlatformIO environment inheritance](https://docs.platformio.org/en/latest/projectconf/sections/env/options/advanced/extends.html), and [`build_src_filter`](https://docs.platformio.org/en/latest/projectconf/sections/env/options/build/build_src_filter.html).

PlatformIO can generate `compile_commands.json` through its `compiledb` target. This provides a useful user-controlled bridge to compiler-aware analysis. FUSE should report how to generate the database when it is absent, but should not run the build or project scripts implicitly. Clang's database records the working directory, source file, and compiler command for each translation unit, which is the context needed by compatible Clang tools. See [PlatformIO compilation database generation](https://docs.platformio.org/en/latest/integration/compile_commands.html), [Clang's compilation database format](https://clang.llvm.org/docs/JSONCompilationDatabase.html), and [Clang Static Analyzer](https://clang.llvm.org/docs/ClangStaticAnalyzer.html).

### Tasmota signals need build and source-role context

The fresh scan produced 15 high-confidence rule matches, but every result has unknown target applicability. The matches include an example credential, optional Berry drivers, third-party mail library code, an integration header, a scripting driver, a build helper, and an OTA-related extension. These are real textual matches, not confirmed product vulnerabilities. The pilot did not compile a target, inspect a released image, or test a device.

This suggests a report-level context model that records:

- source role: project code, vendored library, example, test, build helper, generated file, or runtime extension
- evidence stage: source text, declared configuration, selected configuration, compiled translation unit, firmware image, or device test
- target status: included, excluded, conditional, or unknown, with the evidence used
- applicability: unknown until evidence ties the match to a selected target or artifact

Source role should inform review ordering, not suppress a result by itself. A credential in an example can still be copied into a product; a library marker can still be reached by a shipped build. Keep the rule's severity separate from confidence in the match and confidence that it applies to a product.

### A source-tree scan can see firmware candidates without analyzing them

The Tasmota input inventory lists 6 `.bin`, 19 `.hex`, and 5 `.ota` files outside the native text-rule scope. These extensions are clues, not proof that every file is a firmware release. FUSE now inventories filename, extension, and size across common output folders, while leaving candidates unverified and unread. PlatformIO documents that its configured `build_dir` stores compiled objects, libraries, firmware, and other cached build outputs. See [PlatformIO `build_dir`](https://docs.platformio.org/en/latest/projectconf/sections/platformio/options/directory/build_dir.html).

The candidate inventory records no binary digest or format-identification result. A user still selects one image explicitly with the existing firmware mode to run signature identification. A signature miss or unsupported format must stay `unknown` or `unsupported`, not become a clean firmware result.

### Hardware presence and hardware security are different claims

The KiCad pilot found 10 hardware artifacts and imported the selected BOM as 102 components with quantity total 120. The selected CSV contained references, values, footprints, and quantities, but no manufacturer part number. That is enough for an inventory artifact and not enough to reliably identify exact parts for advisory matching.

CycloneDX describes HBOM as a hardware inventory and lifecycle-management format. KiCad documents BOM and netlist export from schematic data. Its schematic format has explicit `in_bom` and `on_board` attributes, so exported BOM and netlist views may intentionally omit some schematic objects. FUSE now reads a bounded selected or uniquely detected KiCad XML netlist and reports an informational candidate only when a named debug/programming signal connects to a connector-designator or connector-like part. It does not export a netlist or claim an exposed JTAG/debug port. PCB routing, population state, enclosure access, and device configuration remain outside the netlist evidence. See [CycloneDX HBOM](https://cyclonedx.org/capabilities/hbom/), [KiCad schematic and BOM documentation](https://docs.kicad.org/9.0/en/eeschema/eeschema.html#bom-export), [KiCad schematic netlist export](https://docs.kicad.org/9.0/en/cli/cli.html#schematic_netlist_export), and the [KiCad schematic file format](https://dev-docs.kicad.org/en/file-formats/sexpr-schematic/index.html).

## Additional feature candidates

The broad capability areas below already appear in the earlier roadmap. This section narrows them into implementable modules and release gates.

### P0: PlatformIO include closure, implemented with bounded metadata

FUSE now follows a bounded `extra_configs` graph with a 64-file, 8-level, 2 MiB-per-file, and 10 MiB-total limit. It root-checks paths, refuses symlinks, sorts glob matches, records config hashes, and marks unresolved or missing references partial. The resolver merges later settings before resolving `extends` and `default_envs`.

FUSE does not evaluate `${sysenv.*}` values, run project scripts, or invoke PlatformIO. It preserves `src_dir` and `build_src_filter` as declared metadata, but does not yet resolve their patterns to source files or record per-value origin. A later step can add that only with explicit handling of unresolved variables and ordered include/exclude behavior.

**Current fixtures:** multiple included files, deterministic glob order, inherited environments, source-filter overrides, missing includes, outside-root rejection, include cycles, unresolved variables, and recursive-glob partial coverage. Remaining edge fixtures include symlinks, oversized includes, and an unresolved source-filter template.

### P0: Source-role and applicability evidence

Add context to the finding model without reducing severity automatically. The Tasmota scan shows why a finding path alone is not enough to tell whether a match is part of a release. Where a selected build or compilation database is unavailable, keep applicability unknown. A later target-aware analyzer can upgrade this to candidate or included only when it has explicit configuration or compile evidence.

The scan summary should use language such as “15 rule matches, product applicability unresolved” instead of implying 15 confirmed vulnerabilities. Preserve the original rule evidence, line, and file. Add paired fixtures for examples, vendored libraries, build scripts, optional modules, test code, generated files, and active production configuration. Do not add blanket exclusions for paths such as `examples/` or `lib/`.

### P1: Firmware candidate inventory, implemented with explicit limits

FUSE inventories common firmware-like extensions across the project and common build outputs, including `.pio`, `build`, `dist`, and `out`. It records at most 500 paths while preserving bounded extension counts and sizes. This is not firmware validation and it does not read or hash candidate bytes. A user must select a specific image for the existing signature stage.

**Current fixtures:** candidate-like extensions inside `.pio/build`, gzip variants, and an ignored dependency directory. Remaining cases should add malformed, duplicate, renamed, and path-limit candidates. Extension-only results stay explicitly labeled as candidates.

### P1: Embedded CI workflow checks, narrow first pass implemented

FUSE now has a separate repository-supply-chain analyzer for explicit workflow-level `permissions: write-all` and action references not pinned to full commit SHAs. It counts recognized non-SHA references, but only reports obvious floating branches such as `@main`; ordinary version tags are counted without findings. It does not yet check job-level permission blocks, event-controlled shell interpolation, or pull-request trigger and checkout data flow. GitHub recommends least-privilege permissions, careful handling of untrusted input, and locking third-party workflow dependencies. See [GitHub Actions secure use](https://docs.github.com/en/actions/reference/security/secure-use).

These findings are reported as repository workflow candidates, not device firmware vulnerabilities. Paired positive and negative fixtures cover explicit broad permissions, a mutable action ref, least-privilege permissions, and a SHA-pinned action. The parser is intentionally limited to simple scalar lines, so quoted or structurally complex YAML forms remain future test and implementation work.

### P1: Target-aware OTA checks

An HTTP URL is a transport indicator, not a complete OTA verdict. TUF and SUIT describe trusted metadata, signatures, target hashes, freshness, versioning, and rollback protections. ESP-IDF separately documents signed update images, secure boot, rollback, and anti-rollback. FUSE should represent these checks as separate evidence: transport security, update signature verification, trusted key configuration, downgrade protection, recovery behavior, and selected target applicability. See [TUF specification](https://theupdateframework.github.io/specification/latest/), [RFC 9019 firmware update architecture](https://datatracker.ietf.org/doc/html/rfc9019), [RFC 9124 SUIT manifest model](https://datatracker.ietf.org/doc/html/rfc9124), and [ESP-IDF security overview](https://docs.espressif.com/projects/esp-idf/en/stable/esp32/security/security.html).

For ESP-IDF, base any release-policy check on the selected target's generated configuration where available. A checked-in fragment is weaker evidence than the effective build configuration. Do not infer secure OTA merely from HTTPS, a signature function call, or a configuration key in an unused file.

### P2: Verified artifact provenance

FUSE's current in-toto/SLSA adapter compares a statement subject digest with a firmware image; it does not authenticate the statement or establish trust in its builder. A later adapter should delegate signature verification to established tools such as `gh attestation verify` or Sigstore Cosign, then apply a FUSE policy to the verified result. Check the artifact digest, expected repository identity, builder or workflow, predicate type, source revision, and trusted root. Keep “signature valid” separate from “builder trusted under this policy.”

GitHub supports online and offline attestation verification. Its offline guidance also warns that trusted-root material can become stale and that repository names may change, so offline verification requires recorded repository identity and trust-root freshness. The in-toto statement binds a subject and digest to a predicate type, while SLSA provenance carries build-definition and material context. For FUSE's own future wheel and source archive, a GitHub immutable release can also record its tag, commit, assets, and release attestation. That protects distribution of FUSE itself and does not validate scan findings. See [GitHub artifact attestations](https://docs.github.com/en/actions/how-tos/secure-your-work/use-artifact-attestations/use-artifact-attestations), [offline verification](https://docs.github.com/en/actions/how-tos/secure-your-work/use-artifact-attestations/verify-attestations-offline), [SLSA artifact verification](https://slsa.dev/spec/v1.2/verifying-artifacts), [SLSA provenance](https://slsa.dev/spec/v1.2/provenance), [in-toto Statement](https://github.com/in-toto/attestation/blob/main/spec/v1/statement.md), [GitHub immutable releases](https://docs.github.com/en/code-security/concepts/supply-chain-security/immutable-releases), and [Cosign verification](https://docs.sigstore.dev/cosign/verifying/verify/).

### P2: Hardware identifier enrichment

Keep presence detection and BOM parsing available with no network. When manufacturer and part-number fields exist, normalize them and preserve the raw value and source column. If part identifiers are missing, report that part-level advisory matching is not assessable. A later offline catalog or vendor-data adapter can annotate lifecycle or vulnerability context with source date and matching confidence. Do not manufacture a part number from a footprint or component value.

Keep netlist facts separate from physical exposure. Parsing labels, symbol pins, and connector nets can produce a review lead. It does not prove that a physical board has a populated connector, exposes that connector outside its enclosure, or has debug access enabled.

### P3: KiCad debug-interface candidate checks, implemented as netlist review leads

The bounded XML reader checks named debug or programming nets such as SWD, JTAG, or UART that connect to a connector-designator or connector-like part. It reports an informational review lead with net and node evidence. A naming match is not proof that a production board exposes a debug port, and a missing name is not proof that debug pins are absent. Population state and connector footprint approval are not yet analyzed. See [KiCad's schematic and netlist documentation](https://docs.kicad.org/9.0/en/eeschema/eeschema.html) and [schematic netlist export through the CLI](https://docs.kicad.org/9.0/en/cli/cli.html#schematic_netlist_export).

**Fixture gate:** named SWD and UART nets connected to a connector; net labels that appear only in comments; unpopulated or do-not-populate connectors; internal-only debug signals; arbitrary net names; and multi-sheet connections. The report should describe connectivity found in the exported design, never physical accessibility.

The existing [feature opportunities memo](feature-opportunities.md) already covers richer SBOM/VEX context and the safety boundary for firmware extraction. Those remain later work after FUSE can reliably associate a source finding with a selected target and artifact.

## Suggested sequence

| Stage | Work | Exit gate |
| --- | --- | --- |
| 0.3 follow-up | Bounded PlatformIO include closure and schema 1.9 context | Implemented locally; Tasmota pilot and residual partial reasons verified below |
| 0.4 | Firmware candidate inventory and generated `compile_commands.json` guidance | Filename and size candidate inventory implemented; compiler database guidance remains |
| 0.5 | GitHub Actions workflow analyzer | Narrow write-all and non-SHA checks implemented with positive and negative fixtures; complex YAML and event-taint checks remain |
| 0.5 hardware | KiCad debug-net candidate review | Bounded XML candidate analyzer implemented; board routing and physical-access validation remain |
| 0.6 | Selected-target OTA profiles | At least one ESP-IDF target with generated-config fixtures, signature and rollback evidence, and unknown-state tests |
| 0.7+ | Verified provenance and richer HBOM identity | Valid, invalid, wrong-builder, stale-root, missing-MPN, and ambiguous-component cases remain distinct |

Do not claim “universal” because more file extensions are recognized. Expand supported inputs only when FUSE can name the analyzer, evidence source, limits, and partial-coverage reason for each stage.

## Crawl4AI method and scope

The local Crawl4AI 0.9.5 installation retrieved 50 documentation URLs on 28 October 2026. Forty-seven returned an HTTP status below 400. Three stale URL guesses returned 404; official PlatformIO, GitHub, and KiCad navigation links led to the correct pages, which were then fetched successfully. The source index records titles, status, word counts, and short relevant excerpts at [`reports/pilot-validation/crawl4ai-source-index.json`](../../reports/pilot-validation/crawl4ai-source-index.json).

The retrieved pages cover PlatformIO configuration and compile databases, Clang tooling, GitHub Actions security and attestations, Sigstore, SLSA, TUF, SUIT, ESP-IDF OTA, KiCad, CycloneDX HBOM/VEX, OSV, CISA KEV, FIRST EPSS, Zephyr hardening, NIST, PyPA, SARIF, OWASP IoT, and Crawl4AI's SDK. Sources are official documentation or standards pages. This is a documentation synthesis, not a scan-accuracy benchmark, compliance assessment, build, or device test. The broader 27 October research document contains the earlier multi-source tool and standards review.

This follow-up does not claim that three to four hours of wall-clock time elapsed. It records the additional Crawl4AI review and scan-grounded conclusions without inflating research time or scan accuracy.
