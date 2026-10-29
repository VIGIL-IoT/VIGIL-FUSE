# FUSE universality research

- **Research date:** 27 October 2026
- **Name:** FUSE, Firmware & Unified Security Engine
- **Project:** Firmware and IoT security analysis module
**Identity:** A [VIGIL](https://github.com/VIGIL-IoT) Project

**Implementation update - 27 October 2026:** FUSE now accepts an explicitly selected Zephyr `HARDENCONFIG_JSON` report through `--zephyr-hardening-report`. It keeps Zephyr's recommendation database upstream, bounds and validates the report, and maps failed checks into candidate findings with unknown severity. FUSE does not run `west` or the build. See the [roadmap](../roadmap.md) for current implementation status.

**Implementation update - 28 October 2026:** SARIF now includes a `primaryLocationLineHash` derived from normalized redacted evidence, with an occurrence counter for duplicate matches. Regression coverage confirms it remains stable after harmless line insertion. The JSON report fingerprint remains location-sensitive, and baseline comparison retains its separate identity. Baseline suppressions now use stable per-occurrence identities so repeated identical findings can be reviewed independently; older baseline and suppression files remain readable.

**Implementation update - 28 October 2026:** Baseline format 1.1 adds a path-independent identity for native findings. A move is reported only when exactly one unmatched old finding and one unmatched current finding agree on analyzer, rule, category, title, and normalized redacted evidence. Ambiguous matches remain visible as new and resolved entries; OSV inventory matches stay path-sensitive, and suppressions do not transfer to a moved file. Format 1.0 baselines remain readable and continue to use exact path-sensitive matching.

**Implementation update - 28 October 2026:** ESP-IDF build context now records a selected `sdkconfig`, observed `SDKCONFIG_DEFAULTS` cache values, target-specific default variants, file hashes, and missing or unreadable inputs. It reads only bounded files inside the chosen project. Conventional defaults are shown as candidates unless selected-build evidence confirms the source; FUSE does not execute CMake, evaluate project code, resolve Kconfig dependencies, or infer release deployment. JSON report schema 1.7 adds this provenance object.

**Implementation follow-up - 28 October 2026:** the current report schema is 1.8. FUSE now has repository CI, metadata-only PlatformIO and compilation-database inventory, opt-in CSV/TSV hardware BOM import with CycloneDX HBOM output, exact-match CycloneDX VEX review context, and an SLSA subject digest comparison for selected firmware. These stages do not run PlatformIO, compile code, authenticate VEX or provenance signatures, or extract firmware.

**Field follow-up - 28 October 2026:** schema 1.9 adds bounded PlatformIO include provenance and source-filter context, filename/size-only firmware candidates, narrow GitHub Actions workflow checks, and candidate-only KiCad netlist connectivity review. See the [field follow-up](fuse-field-follow-up-2026-10-28.md) for fixtures, pilot validation, and remaining limits.

## Executive recommendation

FUSE should become a universal entry point and evidence layer for embedded security analysis. It should not try to replace every firmware unpacker, general source analyzer, SBOM generator, vulnerability database client, or board-specific hardening tool.

The useful meaning of universal is: one installable CLI recognizes common embedded inputs, selects checks that have evidence to run, invokes optional specialist tools when requested and available, and produces one report that says what it analyzed, what it skipped, where each result came from, and how certain its applicability is.

The strongest next steps are:

1. Make the default workflow predictable: one install command, `vigil-fuse scan .`, and a `.fuse-results/` directory containing the three core reports.
2. Add `doctor` and `scan --plan` so users can see platform detection, selected analyzers, missing optional tools, network use, and expected coverage before scanning.
3. Add project and build-context adapters for ESP-IDF and Zephyr first, then consume native security and component reports from Yocto and Buildroot.
4. Extend the finding model with applicability and validation provenance so a precise source match is not mistaken for a confirmed issue in a shipped device.
5. Stabilize cross-run identities, add GitHub Actions guidance, and introduce baselines with reasoned, expiring suppressions.
6. Defer automatic firmware extraction and dynamic emulation until a disposable, resource-limited worker and a clear coverage model exist.
7. Resolve the restricted-license and PyPI upload-terms interaction before the first public package release. Commercial use is allowed by the current license, but that alone does not grant downstream redistribution rights.

This direction preserves the current small Python core and its tested native rules. It turns FUSE into a router and normalizer around focused analyzers, with IoT-specific rules and honest coverage as FUSE-owned value.

## Starting repository baseline before implementation

This section records the repository state observed at the start of this research. The implementation status after the research is tracked in the [roadmap](../roadmap.md).

The repository already contains an installable Python project named `vigil-fuse`, a `vigil-fuse` console command, Python 3.11 or newer support, and no mandatory runtime dependencies. The CLI scans project directories, selected source/configuration files, single SBOM files, and firmware images when firmware mode is selected. At the time of this 27 October baseline review, the package emitted text, JSON schema 1.8, and SARIF reports. The 28 October local follow-up updates the report contract to schema 1.9. Optional Syft, OSV-Scanner, and Binwalk adapters run as external executables.

There are seven native rules. Each has a vulnerable and secure fixture. The existing design already separates severity from confidence, redacts secret-like evidence, records file coverage and skipped paths, hashes selected inputs, and distinguishes unavailable or failed optional tools from completed analysis. Profiles named `generic`, `esp-idf`, `zephyr`, and `embedded-linux` currently expand file discovery. They do not yet represent a complete framework analyzer or an effective production configuration.

| Input or workflow | Current behavior | Current boundary |
| --- | --- | --- |
| Source repository | Native rules scan selected text and configuration extensions | No automatic project/build environment resolution; files outside selected types are not analyzed by native rules |
| ESP-IDF project | Profile includes common config and source files; FUSE006 and FUSE007 inspect explicit Kconfig-style values | Does not resolve target, defaults ordering, the active `sdkconfig`, or release build selection |
| Zephyr project | Profile includes `prj.conf`, Kconfig, overlays, and common build files | Does not consume generated `.config`, devicetree output, or Zephyr's hardening database |
| Embedded Linux project | Profile includes common source, services, recipes, and system config | Does not interpret a selected image build or its compiled package set |
| SBOM | CycloneDX and SPDX input can be routed to OSV-Scanner; Syft can generate CycloneDX | Component origin and product applicability need to be retained more explicitly |
| Firmware image | Binwalk signature identification is optional | No extraction, firmware filesystem analysis, or execution |
| CI | SARIF output and `--fail-on` exist | No repository workflow template, baseline, or suppression lifecycle is present |
| Default output | Text can be printed to the terminal; `--output-dir` writes JSON, text, and SARIF together | A plain `vigil-fuse scan .` does not currently create a report folder unless configured or optional tools trigger one |
| Vercel results site | Static `site/` page renders the checked-in pilot summary, generated JSON, and plots from pinned repository reports | This is a curated pilot snapshot, not a live service for arbitrary user scans; keep the JSON reports as inputs and review any data before publishing |

The current Syft adapter emits a CycloneDX JSON artifact and the OSV adapter saves the raw OSV-Scanner JSON. The normalized `Finding` stores ecosystem, package name, version, source path, advisory identity, severity, and references, but does not yet expose package URL, affected range, dependency relationship, cataloger origin, or a source-to-image link as structured fields. The raw artifacts retain more detail, but consumers should not have to reconstruct important product context by joining undocumented fields across them.

The package is already an installable package project, but the public PyPI release path and next version still need to be handled as a separate release decision. The current project version is 0.2.0. Do not reuse that version for a later package upload.

## What the repository pilot shows

The initial 0.2.0 pilot run recorded eight distinct public repositories and nine scan scopes, not ten repositories. Its summary totaled 9,590 discovered paths, 9,463 selected files, 9,460 scanned files, and three skipped files, one not UTF-8 and two over the per-file size limit. It reported 20 raw static signals: 13 high and 7 medium by rule-assigned severity. The scan report and triage explicitly say that these are not confirmed vulnerabilities and that no project builds, firmware images, physical boards, or device behavior were validated.

The 20 results are useful test cases for the next design decisions:

| Rule | Pilot result | What needs context |
| --- | ---: | --- |
| FUSE001 credential-like literals | 5 | Two repositories contain the same upstream source; other matches include example or default passwords. The rule cannot tell whether the value is accepted, active, or shipped. |
| FUSE002 PEM private-key markers | 3 | All three matches are in Raspberry Pi Pico example paths. The rule cannot tell whether the files are test material or included in a product image. |
| FUSE003 TLS verification bypass syntax | 10 | Matches are in Tasmota libraries and scripts, including optional or vendored code. A match does not prove that the code is selected or reachable in a release build. |
| FUSE004 plaintext HTTP endpoint indicators | 2 | One is a build helper download; one is OTA-related Berry configuration. The first is not evidence of device runtime traffic. |
| FUSE005 explicit `mqtt://` URI | 0 | The rule does not resolve a broker assembled from separate host, port, and TLS settings. |
| FUSE006 and FUSE007 ESP-IDF boot validation settings | 0 | The selected ESP-IDF scan scopes did not include effective release configuration inputs. |

The initial raw count fell from 1,663 in 0.1.0 to 20 in 0.2.0 while scanned-file coverage grew from 8,856 to 9,460. The 98.8 percent reduction is not a measured precision rate. The rule definitions changed, coverage changed, and findings are not fully adjudicated against build output. Keep this distinction on the website and in future reports.

### Follow-up corpus expansion, 27 October 2026

The local pinned corpus has 14 distinct repositories and 15 scan scopes. Six additions cover Pico SDK, Arduino-ESP32, Buildroot, OpenEmbedded Core, Meta-OpenEmbedded, and Meta-Yocto. The pinned commit and selected path list for each scope are in [`scan-manifest.json`](../../reports/repository-scans/scan-manifest.json). The pre-refinement expanded run recorded 18,991 discovered paths, 18,855 selected files, 18,851 scanned files, and four skipped files. The latest rescan discovers 18,999 paths, selects 18,859 files, and scans 18,855 files after including target-suffixed ESP-IDF defaults files. That run reported 78 raw static signals, 19 high and 59 medium by rule-assigned severity, plus a separate filename-only inventory of 28 hardware artifacts. Fixture-backed refinements first reduced this snapshot to 62 signals; a later FUSE001 string-context refinement brings the current report to 61 signals, 19 high and 42 medium. Three scan scopes remain partial. The current per-scope summaries and limitations are in [`summary.json`](../../reports/repository-scans/summary.json) and [`triage.md`](../../reports/repository-scans/triage.md).

The new scopes exposed concrete precision gaps: sample hash inputs are mistaken for credentials; BitBake summary text and computed password expressions produce FUSE001 matches; the HTTP rule reports test hosts and a vendor connectivity example; and the TLS rule matches an API method implementation as if it were a call site. These observations should become positive and negative rule fixtures before code changes. The added findings remain static observations, and no build or device was validated.

The active Yocto collection no longer uses the Poky `master` branch as an aggregate source. At this snapshot that repository's README points users toward maintained component repositories, so the corpus pins OpenEmbedded Core, Meta-OpenEmbedded, and Meta-Yocto instead. See the [Poky repository](https://github.com/yoctoproject/poky) and the pinned component entries in the manifest.

The immediate lesson is not to add more broad regular expressions. FUSE needs to connect a source indicator to its build target, selected configuration, installed component, or firmware artifact when that information exists. When it does not exist, the result should say applicability is unknown.

The pilot points to a small set of precision improvements before adding new rule families:

| Existing signal or gap | Better next step |
| --- | --- |
| Credential-like values in examples, vendored code, and defaults | Keep secret-likelihood separate from shipped-product applicability. Add explicit placeholders, examples, generated credentials, and repeated upstream files to fixtures. Preserve the path and build inclusion state |
| TLS verification calls in optional or vendored code | Add syntax and call-site context for a supported client library, then record the target or compile condition when known. Leave unresolved reachability as conditional |
| HTTP URLs used both by build scripts and device code | Classify build-time artifact downloads separately from device runtime or OTA transport. Record the consumer and transfer context before assigning a product-level impact |
| MQTT host, port, and TLS settings assembled across separate values | Start with one supported framework configuration format and resolve its fields with fixtures. Do not broaden the URI regex and claim general MQTT coverage |
| No FUSE006 or FUSE007 matches in selected ESP-IDF scopes | Consume the selected generated configuration. Keep source fragments and default files marked as candidates until the build target and precedence are resolved |

The evidence and scope limits are recorded in the checked-in [pilot summary](../../reports/repository-scans/summary.json) and [triage notes](../../reports/repository-scans/triage.md).

## What universal should mean

FUSE can present one command and one report format without pretending every input supports the same checks. Its plan should route by input evidence and report a per-stage capability matrix.

| Target class | Best evidence to start with | FUSE role | Recommended order |
| --- | --- | --- | --- |
| Source repository | Source files, project markers, lockfiles, build descriptions | Native IoT rules, project detection, optional general analyzers | Core now |
| Generated build configuration | Selected board/environment, generated configuration, framework/toolchain version | Platform hardening checks with board-aware applicability | First platform expansion |
| Build-produced component data | SPDX or CycloneDX SBOM, package manifest, vendor vulnerability report | Normalize and correlate component/advisory findings | Near-term |
| Raw firmware image | Hash, format/signature inventory, offsets, architecture indicators | Identify the artifact and route to an explicitly enabled firmware adapter | Current identification only |
| Extracted firmware filesystem | Package databases, init scripts, certificates, services, config | Analyze files while preserving image hash and extraction ancestry | Future isolated worker |
| Lab or runtime evidence | Device, board, emulator, traffic, selected test output | Link evidence to a separate validation record, potentially with SPECTRA-32 | Research stage |

A scan plan should be generated before analysis. For each stage it should state `planned`, `running`, `completed`, `partial`, `unavailable`, `skipped`, or `failed`, with a reason. For example, a firmware target with Binwalk available but no extractor should report signature identification only, not a complete firmware scan.

### Public support labels

FUSE should publish input detection, analysis, and validation as separate support claims. A detected marker does not mean that a rule ran, and a successful scan of selected source files does not mean the target build or device was assessed.

| Label | Promise to the user |
| --- | --- |
| `detected` | FUSE recognizes the project or file type, but this alone says no analyzer completed |
| `basic` | The documented native checks ran over the documented selected file types, without resolving an effective target build |
| `partial` | Some useful stages completed, while at least one required, requested, or input-applicable stage was unavailable, skipped, or failed |
| `supported` | The named input, framework version range, operating systems, and analyzer versions have positive, secure, boundary, and pinned-project regression coverage |
| `experimental` | An opt-in adapter is available, but its supported scope or output contract is not stable enough for a general support claim |
| `planned` | There is no current scan capability; the item is shown only as roadmap coverage |

Expose these labels from one machine-readable support matrix so `doctor`, the scan plan, README, and website describe the same capabilities. The matrix should scope each claim to the input type and version. Avoid a single blanket `firmware supported` or `Zephyr supported` badge.

### Test catalog and non-automated coverage

The OWASP IoT Security Testing Guide models a device as components and interfaces, then selects test cases from that device context. Its methodology separates general component categories from specializations such as installed firmware and firmware updates. Individual cases describe access assumptions, objectives, assessment steps, remediation, and references. This is a useful pattern for FUSE's rule metadata, but it also makes clear that a complete IoT assessment includes work outside a source scanner.

FUSE can borrow the catalog structure while keeping its automated scope honest. Each check should declare target and input prerequisites, method (`automated`, `external_tool`, or `operator_guided`), expected evidence, access needs, applicability, exclusions, remediation, and references. A serial-debug lock check may be an operator checklist item unless a signed device provisioning record is available. It should appear as `not_assessed` in coverage, not as an absent vulnerability finding. This lets FUSE describe what still needs a lab, board, or human review without implying it performed that work.

The firmware catalog also suggests useful checks beyond source-pattern matching. Their evidence requirements differ, so they should be separate analyzers or assessment entries rather than more variants of one text rule:

| Assessment area | Evidence needed | FUSE automation boundary |
| --- | --- | --- |
| Binary exploit mitigations | Release ELF or firmware binary, architecture, toolchain context | Inspect emitted binaries when a supported backend is available. Build flags alone are candidate evidence, not proof the linked artifact contains the mitigation |
| Outdated software | Image-specific package inventory and vendor or distribution vulnerability data | Import Yocto or Buildroot results with their patch and ignored states. A source recipe match alone does not establish that the package shipped |
| Unnecessary software | Installed package inventory plus the product's intended functions | Identify packages for owner review. Whether a service is unnecessary depends on device purpose and deployment |
| Secrets in shipped firmware | Source or extracted binary signal plus path from the built image | Keep source-only matches conditional until build or image evidence ties them to a release |
| Update signature and rollback | Selected update configuration, code path, update metadata, and sometimes a device test | Static checks can locate candidate verification logic. An operator or lab test is needed to establish enforcement and downgrade behavior |
| Weak cryptography | Algorithm selection, use site, key size or configuration, and sometimes library or binary evidence | Treat a library name or string match as a candidate. Validate actual use and target-specific settings before rating impact |

Sources: [OWASP IoT device model](https://github.com/OWASP/owasp-istg/blob/main/src/02_framework/device_model.md), [OWASP testing methodology](https://github.com/OWASP/owasp-istg/blob/main/src/02_framework/methodology.md), [OWASP firmware test catalog](https://github.com/OWASP/owasp-istg/blob/main/src/03_test_cases/firmware/README.md), and [OWASP installed firmware update mechanism checks](https://github.com/OWASP/owasp-istg/blob/main/src/03_test_cases/firmware/firmware_update_mechanism.md).

## Platform research and consequences for FUSE

### ESP-IDF

ESP-IDF configuration depends on Kconfig defaults, one or more `sdkconfig.defaults` files, target-specific defaults, the selected `IDF_TARGET`, and saved user values in `sdkconfig`. File order matters. A `sdkconfig.ci` file is part of the CI framework and is ignored by normal builds. FUSE should not treat any file whose name resembles a config file as the active release configuration.

First support should accept a user-selected build directory or generated configuration and record the target and ESP-IDF version. Source-only scans can still report a candidate configuration indicator, but should mark it conditional or unknown. FUSE should not build an untrusted project implicitly to discover the configuration.

ESP-IDF OTA behavior also separates image verification, boot selection, rollback, and runtime confirmation. These are related but distinct checks. Rules should state whether they concern a Kconfig setting, a source call, an image property, or device behavior. A static scan should not claim that an OTA path is safe or unsafe without the relevant evidence.

ESP-IDF's Component Manager adds another useful project input: `idf_component.yml` declares component dependencies, while generated `dependencies.lock` records a flattened resolved graph, target, and manifest hash. The lock may contain local paths and can be stale if the target or manifest hash no longer matches. FUSE should validate that context and label local or source-control dependencies rather than treating the lock as a shipped image inventory. Do not run the package manager or resolve dependencies just to scan a repository.

Sources: [ESP-IDF configuration structure](https://docs.espressif.com/projects/esp-idf/en/latest/esp32/api-guides/kconfig/configuration_structure.html), [ESP-IDF build system and defaults ordering](https://docs.espressif.com/projects/esp-idf/en/latest/esp32/api-guides/build-system.html), [ESP-IDF dependencies lock file](https://docs.espressif.com/projects/idf-component-manager/en/latest/reference/dependencies_lock.html), [ESP-IDF component manifest](https://docs.espressif.com/projects/idf-component-manager/en/latest/reference/manifest_file.html), and [ESP-IDF OTA behavior](https://docs.espressif.com/projects/esp-idf/en/stable/esp32/api-reference/system/ota.html).

### Zephyr

Zephyr's Kconfig output is target and build dependent. The generated `.config`, `autoconf.h`, and devicetree artifacts are more authoritative for an application build than a source fragment alone. Zephyr already has a maintained hardening database and a `hardenconfig` target with `base` and `strict` profiles. Recommendations can be hardware dependent and include rationale.

FUSE should not copy the full Zephyr database into a second rule set. It should prefer an adapter that consumes the selected build's Zephyr hardening output, or a small native check over validated generated configuration. The report should retain the board, profile, toolchain version, and which options were not applicable. Multi-domain builds need a separate record for each domain. West manifests name project revisions, but can use branch names; where a workspace is available, preserve the actual checked-out commit and active project groups alongside the requested manifest revision.

Sources: [Zephyr hardening tool](https://docs.zephyrproject.org/latest/security/hardening-tool.html), [Zephyr Kconfig output](https://docs.zephyrproject.org/latest/build/cmake/index.html), [Zephyr build and configuration directories](https://docs.zephyrproject.org/latest/develop/west/build-flash-debug.html), and [West manifests and project revisions](https://docs.zephyrproject.org/latest/develop/west/manifest.html).

### PlatformIO and Arduino

One PlatformIO project may declare multiple `[env:NAME]` environments with different boards, frameworks, dependencies, and build tasks. Arduino's Fully Qualified Board Name includes vendor, architecture, board ID, and optional menu selections. The target can materially change which code and security options are compiled.

FUSE should list detected environments and ask for or accept an explicit target selection rather than silently treating one environment as the whole project. A later matrix mode can scan multiple environments and group shared findings while preserving per-target applicability. `platformio.ini` dependencies can be declarations or versioned and Git-based package specifications; `pio pkg list` reports the installed dependency tree and can filter by environment. Importing that local resolved view is stronger evidence than the declaration, but it still does not prove every listed package was linked into the firmware image. Keep PlatformIO's own analyzers as an optional integration rather than making them a Python dependency.

Sources: [PlatformIO environment sections](https://docs.platformio.org/en/stable/projectconf/section_env.html), [PlatformIO library dependencies](https://docs.platformio.org/en/latest/projectconf/sections/env/options/library/lib_deps.html), [PlatformIO installed package tree](https://docs.platformio.org/en/latest/core/userguide/pkg/cmd_list.html), and [Arduino CLI FQBN format](https://arduino.github.io/arduino-cli/dev/FAQ/).

### OpenWrt, Yocto, and Buildroot

Yocto can produce an SPDX SBOM and an image-specific CVE report based on components compiled into an image. Its vulnerability report distinguishes statuses such as patched, unpatched, and ignored. Buildroot's manual documents `show-info`, `pkg-stats`, generation of a CycloneDX SBOM, and package CVE reports for the selected configuration.

OpenWrt is another strong adapter candidate, especially because it is represented in the existing pilot. Current OpenWrt build rules generate an image `.manifest` and can emit a CycloneDX image SBOM named with `.bom.cdx.json` when `CONFIG_JSON_CYCLONEDX_SBOM` is enabled. Package feeds can also emit `Packages.bom.cdx.json`. OpenWrt package-manager output changes by release, with `opkg` in older releases and `apk` in newer ones. FUSE should identify the build version and consume whichever image-level artifact the selected build actually produced. Do not assume that package-feed inventory equals the packages included in a device image.

There is a vulnerability-matching compatibility gap to measure. The current OpenWrt CycloneDX emitters set `specVersion` 1.4 and emit CPE identifiers where package metadata provides them; the inspected emitters do not add Package URLs. OSV-Scanner documents SBOM matching for SPDX or CycloneDX that uses Package URLs. Grype accepts CPE identifiers, but its own guidance warns that CPE matching can produce false positives and miss vulnerabilities because CPE coverage and ecosystem distinctions are incomplete. FUSE should retain the original CPE, mark the matcher as CPE-based, and benchmark against a pinned OpenWrt image package list before reporting a clean OSV result. Do not synthesize a PURL or claim a package is unaffected without a validated mapping.

For embedded Linux, FUSE should consume the build system's selected-image outputs before trying to reconstruct the installed package set from recipe source. This should reduce wrong matches from unbuilt packages and preserve vendor patch or ignored-CVE decisions as evidence. Preserve the source report and its status rather than silently replacing it with a generic database match.

Sources: [Yocto vulnerability checks and image reports](https://docs.yoctoproject.org/current/security-manual/vulnerabilities.html), [Yocto SBOM generation](https://docs.yoctoproject.org/current/dev-manual/sbom.html), [Buildroot package information, CVE, and CycloneDX features](https://buildroot.buildroot.org/downloads/manual/manual.html), [OpenWrt package SBOM generation](https://github.com/openwrt/openwrt/blob/main/package/Makefile), [OpenWrt image manifest and SBOM generation](https://github.com/openwrt/openwrt/blob/main/include/image.mk), [OpenWrt APK SBOM generator](https://raw.githubusercontent.com/openwrt/openwrt/main/scripts/make-sbom.py), [OpenWrt CycloneDX package metadata generator](https://raw.githubusercontent.com/openwrt/openwrt/main/scripts/package-metadata.pl), [OpenWrt package manager by release](https://openwrt.org/packages/start), and [Grype CPE matching scope and accuracy](https://oss.anchore.com/docs/guides/vulnerability/ecosystems/).

## Tool landscape and where FUSE adds value

| Need | Established tools and evidence | Recommended FUSE relationship |
| --- | --- | --- |
| Package inventory | Syft supports directories, images, filesystems, and archives; it distinguishes declared from installed components | Keep Syft optional and retain the cataloger/source evidence. Add embedded-specific context, not another generic package cataloger |
| Advisory matching | OSV-Scanner consumes supported lockfiles and named CycloneDX or SPDX SBOM formats. Its SBOM guidance expects Package URLs. Grype can consume SPDX or CycloneDX, accept CPE identifiers, and carry distro context for matching | Use OSV for supported manifests and PURL SBOMs. Preserve CPE and vendor identifiers for other inputs. Benchmark Grype and build-system advisory outputs on pinned OpenWrt, Yocto, and Buildroot images before choosing a second default engine |
| General all-in-one scanning | Trivy's filesystem target offers vulnerability, misconfiguration, secret, license, and SBOM scanners. Its C/C++ dependency coverage documents Conan lockfiles | Compare it later only if one optional adapter simplifies install and coverage without obscuring which scanner or database produced each result. It overlaps with the planned Syft, OSV-Scanner, and Gitleaks paths, and its documented Conan input does not extend FUSE's platform configuration analysis |
| General source analysis | Semgrep supports syntax and data-flow rules with its own rule-testing workflow. Clang Static Analyzer analyzes C, C++, and Objective-C using path-sensitive interprocedural symbolic execution | Add optional adapters for checks requiring syntax or data flow, and pass the selected build context where needed. Keep FUSE-native rules focused on embedded configuration and IoT context instead of recreating general code analyzers with regular expressions |
| Secret scanning | Gitleaks is a mature repository secret scanner | Implemented locally as an opt-in Git-history adapter with default rules, redacted FUSE findings, and a separate history artifact. Keep Gitleaks optional and retain its rule ID and tool version as provenance |
| Repository security practices | OpenSSF Scorecard checks repository and development practices with heuristics and per-check scores; its CLI needs GitHub access for public repository analysis | Keep this as an optional repository-posture stage. Preserve its source, authorization and network scope, and individual check results. Do not mix its aggregate project score into firmware severity or product applicability |
| Firmware signatures | Binwalk identifies embedded formats and can optionally extract | Keep current FUSE mode identification-only. Preserve offsets and the image hash if a future extractor is enabled |
| Binary component vulnerability checks | OSSF's CVE Binary Tool detects over 350 common components in binaries, accepts component lists and several SBOM formats, and can emit JSON or VEX. Its repository identifies the tool as GPL-3.0 licensed | Evaluate it as a separately installed optional firmware or extracted-filesystem backend against Syft plus Grype on a pinned corpus. Review the license boundary before bundling it or copying code. Keep component detection provenance and database freshness visible, and do not present a signature miss as proof that the image is clean |
| Firmware extraction | unblob covers many archive and filesystem formats with recursive extraction and external dependencies | Treat as a future opt-in backend with depth, CPU, memory, time, file-count, and output-byte limits |
| Full firmware analysis | EMBA and FACT provide broad firmware workflows with many modules and operational requirements | Document or integrate them as separate specialist backends. Do not reimplement their broad pipelines inside the core Python package |
| Platform hardening | Zephyr hardening, ESP-IDF build outputs, Yocto and Buildroot metadata | Prefer their selected-target output and normalize it to FUSE evidence instead of cloning their rule databases |

FUSE's durable value should be the target router, common evidence model, embedded-specific rules, provenance between source/build/image, coverage accounting, and a report that does not overstate what a specialist tool found.

The distinction between source dependencies and installed firmware components matters. A source repository may declare a library that is never built. A firmware filesystem may include a binary package with no source manifest. The report must preserve whether a component came from a project manifest, generated build output, installed root filesystem, supplied SBOM, or binary inference.

Cross-platform support belongs to each adapter, not to a blanket product claim. Syft and OSV-Scanner publish Linux, macOS, and Windows binaries. Binwalk v3 release notes include Windows compilation support, which still needs to be checked for the exact version FUSE supports. EMBA recommends a protected Linux or Docker environment, has substantial system requirements, and its own feature guide says core checks are optimized for Linux firmware. FUSE's default Python scan can remain portable while the capability matrix accurately reports which optional checks run on the current host.

Sources: [Syft scan target behaviors](https://oss.anchore.com/docs/guides/sbom/scan-targets/), [Syft catalogers](https://oss.anchore.com/docs/guides/sbom/catalogers/), [Syft installation platforms](https://oss.anchore.com/docs/installation/syft/), [OSV source scanning](https://google.github.io/osv-scanner/usage/scan-source), [OSV installation platforms](https://google.github.io/osv-scanner/installation/), [Grype SBOM integration](https://oss.anchore.com/docs/architecture/grype/), [Trivy filesystem scanning](https://trivy.dev/docs/latest/target/filesystem/), [Trivy C/C++ dependency coverage](https://trivy.dev/docs/latest/coverage/language/c/), [Semgrep rule testing](https://semgrep.dev/docs/writing-rules/testing-rules), [Clang Static Analyzer overview](https://clang.llvm.org/docs/ClangStaticAnalyzer.html), [CVE Binary Tool](https://github.com/ossf/cve-bin-tool), [CVE Binary Tool output and VEX options](https://cve-bin-tool.readthedocs.io/en/latest/MANUAL.html), [Binwalk](https://github.com/ReFirmLabs/binwalk), [Binwalk releases](https://github.com/ReFirmLabs/binwalk/releases), [unblob](https://github.com/onekey-sec/unblob), [EMBA installation and requirements](https://github.com/e-m-b-a/emba/wiki/Installation), [EMBA feature overview](https://github.com/e-m-b-a/emba/wiki/Feature-overview), and [FACT](https://fkie-cad.github.io/FACT_core/).

OSV-Scanner's current source-scan documentation identifies SBOMs by recognized filenames and supports SPDX and CycloneDX inputs that contain Package URLs. It can inspect C and C++ submodules and vendored directories, and may estimate a version when copied source no longer has Git history. That is a useful optional path for embedded libraries, but the estimated source identity must remain visible as estimated. OSV-Scanner also documents call analysis for some languages, not as a guarantee for every embedded C or C++ project. A FUSE adapter should record which identity fields were present and which OSV modes actually ran. It should distinguish manifest scanning, SBOM matching, source-based dependency attribution, estimated versions, and call analysis in the coverage summary.

The current OSV source command discovers supported lockfiles, SBOMs, and Git directories in a project tree. Its recursive mode can find more nested inputs, but the official guide warns that very deep trees may take a long time. FUSE currently invokes this mode recursively for a directory target. Keep this as an explicit coverage choice: show the selected roots and discovered inventory files, bound runtime, and avoid scanning the same vendored or nested repository more than once. A source lockfile finding should remain tied to source context; it does not establish that the package made it into a selected device image.

For embedded C and C++, OSV-Scanner's supported-manifest table lists `conan.lock`, and its source scanner can analyze vendored and submoduled dependencies using commit-level records. The OSV guide cautions that its C/C++ database coverage is incomplete and that vulnerability records without commit-level data can be missed. It also recommends resolved lockfiles over broad manifests because best-effort version extraction may not represent an installed version. FUSE should show those limits in the dependency coverage summary and prefer build-produced inventories for deployed-image claims. No match from this path is not evidence that a firmware component is clear. See [OSV-Scanner's supported inputs and limitations](https://google.github.io/osv-scanner/supported-languages-and-lockfiles/).

### SBOM quality and source context

CISA's 2026 minimum-elements guidance replaces the NTIA 2021 version and treats an SBOM as both structured data and lifecycle practice. It calls out component identifiers, producer, version, dependency relationships, licenses, hashes and hash algorithms, plus SBOM author and signature, format and format version, generation context, timestamp, tool and tool version, and SBOM version. Its coverage guidance includes transitive components and distinguishes information that is unknown from information intentionally withheld. For FUSE, this supports a separate inventory-quality view: record each field as present, explicitly unknown, withheld, absent, or unsupported; preserve component-level relationships and the source lifecycle phase; and flag an incomplete inventory without turning schema validity into a claim of complete product coverage. A hash or signature should be reported as evidence only until its integrity and signer are verified under a stated trust policy.

Sources: [CISA 2026 SBOM minimum-elements page](https://www.cisa.gov/resources-tools/resources/2026-minimum-elements-software-bill-materials-sbom) and [the 2026 guidance PDF](https://www.cisa.gov/sites/default/files/2026-07/2026_cisa_sbom_minimum_elements_508c.pdf).

### Component identity and artifact provenance

Vulnerability matching needs more than a name and a version-shaped string. OSV records can distinguish a strict package ecosystem and version range from a source repository and Git commit range. The OSV schema recommends separate affected entries when a record needs to describe both kinds of identity. FUSE should preserve the original ecosystem, package name, PURL or source repository, version or commit, and range type. If it cannot resolve an embedded fork or vendor version to an upstream package identity, it should report an unresolved component or a candidate match, not invent a definitive affected version.

Build attestations can link the source and toolchain to the exact artifact digest. SLSA artifact verification guidance says to verify the attestation signature, confirm that the subject digest matches the artifact, check the expected predicate type, and validate the builder identity and build parameters against a trusted policy. Syft documents in-toto/SLSA-compatible SBOM attestations. FUSE could later import or verify these records so an SBOM and firmware image are correlated only when their subject digest and provenance support the link. An attestation establishes provenance claims under a trust policy. It does not prove the product has no vulnerabilities.

This also suggests a safe rule-update boundary. The initial package should run rules shipped with its pinned release and report their version. It should not download and execute mutable rule code during a scan. If remote rule data is eventually needed, distribute signed, versioned data with an integrity and rollback policy, and keep executable extensions separately reviewed.

Sources: [OSV schema guidance on strict ecosystems and Git ranges](https://ossf.github.io/osv-schema/#depicting-multiple-ecosystems-in-the-same-record), [SLSA v1.2 artifact verification](https://slsa.dev/spec/v1.2/verifying-artifacts), [Syft SBOM attestations](https://oss.anchore.com/docs/guides/sbom/attestation/), and [The Update Framework specification](https://theupdateframework.github.io/specification/latest/).

## Recommended architecture, incrementally

```text
vigil-fuse CLI
    |
    +-- target probe: source tree, build output, SBOM, firmware, prior report
    |
    +-- scan plan: selected target/profile, enabled checks, dependencies, network, limitations
    |
    +-- analyzers: current native rules plus optional framework and external-tool adapters
    |
    +-- evidence normalization: preserve original tool IDs, versions, inputs, and locations
    |
    +-- correlation: duplicate source, build, package, and image findings without deleting evidence
    |
    +-- reports: text, canonical JSON, SARIF, and separate SBOM/VEX artifacts as supported
```

Do not rewrite the current package to achieve this. Add a small target descriptor and planning step around `scanner.py`, then split `analyzers.py` into separate adapter modules only when a new integration makes that useful. Keep `rules/`, the finding model, and report serializers as the current stable seams.

Keep the module responsibilities narrow as the package grows:

| Module area | Owns |
| --- | --- |
| `cli.py` | Arguments, command routing, and documented process exit codes |
| discovery and planning | Input inventory, target candidates, exclusions, selected stages, prerequisites, and expected coverage before analyzers run |
| `rules/` | FUSE-owned deterministic checks with rule metadata and paired fixtures |
| target adapters | Framework-specific configuration and dependency evidence, such as ESP-IDF or Zephyr build outputs |
| external integrations | Versioned subprocess wrappers for Syft, OSV-Scanner, Binwalk, Gitleaks, or a later optional adapter |
| `model.py` | Findings, stage results, artifacts, provenance, coverage, and product context |
| `reporting.py`, `sarif.py`, `schemas/` | Stable JSON, text, and SARIF serialization, with versioned schemas |

This is a direction for splitting responsibilities when needed, not a request to move every current file now. An optional project-level `.fuse.toml` can later hold a named target, include/exclude paths, policy, output choice, and explicitly enabled external tools. Keep the first scan zero-configuration. Resolve settings in a documented order: explicit CLI values, project configuration, unambiguous target detection, then built-in defaults. If several build targets are present and none is selected, plan each separately or report the ambiguity instead of silently picking one. Show resolved settings in `scan --plan` and include the effective configuration in the report so local choices do not disappear into hidden auto-detection.

An adapter contract should declare:

- accepted input kinds and required target context;
- whether it is native, an optional executable, or a future plugin;
- supported operating systems and supported versions;
- whether network access is used;
- version detection and invocation arguments;
- execution and output limits;
- findings, artifacts, status, and coverage it can produce;
- known limitations and information the adapter did not receive.

Use argument arrays rather than shell-composed commands. Keep external analyzer output as untrusted data. Do not automatically import arbitrary third-party Python plugins in-process. PyPA documents package metadata and entry points as a standard plugin-discovery option, but discovering an installed entry point and importing its code should be separate steps: require an explicit allowlist or opt-in before execution, then show the plugin name, version, capabilities, and network behavior in the scan plan. A named analyzer should be explicitly enabled and versioned. The current custom license also limits public plugin and modification sharing, so a plugin SDK needs a separate permission model before it is advertised as an open community ecosystem. See [PyPA's plugin discovery guide](https://packaging.python.org/en/latest/guides/creating-and-discovering-plugins/).

## Finding and report format

Keep JSON as the canonical FUSE report and keep severity separate from confidence. A future schema revision should add the information needed to distinguish a clear static match from an applicable device issue:

| Field | Recommended meaning |
| --- | --- |
| `id` | Unique finding record identifier for this report |
| `rule_id`, `rule_version` | Stable detector or advisory identity and the exact rule version that produced the result |
| `analyzer` | Analyzer name and version, including whether it is FUSE-native or an external tool |
| `title` | Short, actionable description of the observed condition |
| `category` | Consistent weakness area such as credentials, network transport, cryptography, debug access, update, or dependency |
| `location` | Project-relative file and line range, or artifact hash plus byte offset/component path when no source line exists |
| `evidence` | Minimal redacted evidence that supports the detector result |
| `explanation` | Why this evidence matched and which assumptions remain unverified |
| `potential_impact` | What could happen if the finding applies to the selected product or target |
| `remediation` | Concrete next step, scoped to the framework or component when known |
| `references` | Relevant vendor, project, standard, or advisory links |
| `severity` | Potential impact if the condition applies. Use `unknown` when evidence does not justify a rating |
| `severity_source` | Original score, vector, scale, and source when severity comes from an advisory or external analyzer |
| `confidence` | Strength of evidence that the detector observed the reported signal |
| `applicability` | `applicable`, `conditional`, `not_applicable`, or `unknown` for the selected target/build/product |
| `validation_level` | `static`, `generated_config`, `build_artifact`, `firmware_image`, `runtime`, or `lab` |
| `component_presence` | For dependency findings, the best-supported state: `declared`, `resolved`, `built`, `observed_in_image`, `runtime_observed`, or `unknown` |
| `provenance` | Input kind, relative path or artifact, source tool, analyzer version, component identifier, and evidence pointer |
| `match_method` | The external correlation method and identity used, such as PURL plus ecosystem version, Git commit range, CPE, or binary signature |
| `target_context` | Framework, board/FQBN, build environment, toolchain version, or image identity when known |
| `status` | Triage lifecycle such as `unreviewed`, `confirmed`, `accepted`, `false_positive`, `fixed`, or `suppressed` |
| `fingerprint` | Stable identity across runs, line movement, output formatting, and secret redaction where possible |
| `policy_mapping` | Optional, versioned control or standard references with an assessment state and evidence |
| `threat_context` | Optional, timestamped exploitation signals such as CISA KEV membership and an EPSS probability, each with source and dataset version |

The current `Finding` model already includes the core identity, rule version, analyzer, title, severity, confidence, category, source location, evidence, explanation, potential impact, remediation, and references. Preserve that tested seam. The important gap is the target and component context needed to interpret those fields; add it through versioned schema changes instead of replacing the finding object.

For example, a current source match that has not been tied to an effective build should remain a conditional static result:

```json
{
  "id": "finding-001",
  "rule_id": "FUSE001",
  "rule_version": "0.2.0",
  "analyzer": "fuse-native",
  "title": "Credential-like literal found",
  "severity": "high",
  "confidence": "medium",
  "category": "credentials",
  "location": {
    "file": "src/network.c",
    "start_line": 28,
    "end_line": 28
  },
  "evidence": "password = \"[REDACTED]\"",
  "explanation": "A password-like assignment matched a static heuristic. This does not establish that the value is valid or used by the selected device.",
  "potential_impact": "If the value authenticates an exposed service, unauthorized access may be possible.",
  "remediation": "Remove fixed credentials and use a per-device provisioning or secure secret-storage design.",
  "references": [],
  "applicability": "unknown",
  "validation_level": "static",
  "target_context": {
    "framework": "unknown",
    "build_target": "unknown"
  },
  "status": "unreviewed"
}
```

This is an illustrative shape, not an additional current rule or a confirmed product vulnerability. Severity describes potential impact, confidence describes the observed match, and applicability remains unknown until build or product evidence supports a conclusion.

Keep these as finding fields for analyzer-produced security signals. Product-level operator assessments should use a separate record type so missing evidence, owner statements, and vulnerability findings do not share an implied severity model.

Do not reuse `confidence` to represent whether the target is affected. `match_method` explains how an engine linked the package to an advisory, but does not replace confidence or applicability. Do not promote a static signal to a confirmed vulnerability because its potential severity is high. Keep a reviewed VEX state linked to the advisory and package rather than deleting the advisory. A result with no finding is not a pass if the analyzer did not run or the input was outside its scope.

For dependency findings, keep `component_presence` separate from `applicability`. A declaration in `idf_component.yml` or `platformio.ini` proves intent, a lock or resolved package graph identifies selected versions, a build SBOM describes build output, and an image package manifest or bounded extraction can support an image-presence claim. Runtime observation is a separate validation step. Use `unknown` when the evidence does not establish one of these states; use an explicit non-observation state only when the inventory scope and completeness support it.

Keep vulnerability impact, match confidence, product applicability, and threat activity as separate fields. CISA's KEV catalog records vulnerabilities exploited in the wild and recommends using it as an input to prioritization. FIRST's EPSS estimates the probability that exploitation activity will be observed across its data partners in the next 30 days; EPSS explicitly says this is not a severity or complete risk score. A future optional enrichment can preserve KEV membership and catalog version, plus EPSS probability and score date, without implying exploitation on the scanned device. Do not collapse the signals into an undocumented universal score. Make network use, cache age, and missing or stale context visible, and let the user's policy decide how to prioritize.

Sources: [CISA Known Exploited Vulnerabilities catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog), [CISA KEV JSON feed](https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json), and [FIRST guidance on using EPSS](https://www.first.org/epss/using-epss.html).

Longer term, represent provenance as an artifact graph rather than a flat list: repository commit -> selected build environment -> generated configuration -> firmware image hash -> installed component inventory -> optional lab evidence. Each edge should be supported by a build manifest, artifact metadata, or explicit user input. Never infer that a source file is present in a firmware image solely because it exists in the repository.

Keep the report schema backward compatible where possible. Add fields in a minor schema revision only after a migration plan and fixture coverage; preserve original analyzer results when normalizing them.

### Existing Vercel results viewer and future HTML export

The repository already has the static Vercel viewer and a scan-results pipeline. [`run_repository_scan_pilot.py`](../../scripts/run_repository_scan_pilot.py) checks pinned, clean repository snapshots and writes one FUSE report set per scan scope. [`build_repository_scan_dashboard.py`](../../scripts/build_repository_scan_dashboard.py) reads the manifest and reports, builds `site/data/repository-scan-results.json`, and generates SVG plots; [`site/script.js`](../../site/script.js) renders that snapshot. Keep `findings.json` as the per-scan interface and the generated site data as a derived aggregate. The dashboard builder now accepts the retained report schemas 1.1 through 1.7, normalizes labels only in memory, and preserves the scanner-produced files. Continue updating this pipeline as the canonical schema evolves instead of creating a second dashboard.

Target-label normalization happens only in the derived aggregate. The builder preserves scanner-produced JSON, text, and SARIF files so the per-scan artifacts remain auditable.

Do not make a CLI scan upload findings to the website automatically. Local paths, source excerpts, and analyzer artifacts can reveal credentials or project details, so remote publishing should remain an explicit action with a reviewable payload. The current page renders dynamic text through DOM text nodes and the plot generator escapes SVG labels; retain that handling for untrusted evidence. External links from the aggregate are now accepted only for HTTPS URLs on the exact `github.com` host. Text-node encoding does not validate a link destination. The dashboard builder also normalizes the target label only in its in-memory aggregate, preserving the scanner-produced JSON, text, and SARIF files. OWASP's XSS guidance calls for context-appropriate output encoding. See the [site link renderer](../../site/script.js#L145) and [dashboard report normalizer](../../scripts/build_repository_scan_dashboard.py#L23).

A standalone local HTML export can be considered later if users need a report outside the Vercel site. It should render saved JSON, stay separate from scanning, and wait until the schema and redaction contract are stable.

Source: [OWASP Cross Site Scripting Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html).

Relevant formats include [SARIF 2.1.0](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html), [GitHub SARIF support](https://docs.github.com/en/code-security/reference/code-scanning/sarif-files/sarif-support), [CycloneDX](https://cyclonedx.org/specification/overview/), [SPDX](https://spdx.dev/use/specifications/), and [CycloneDX VEX](https://cyclonedx.org/capabilities/vex/). CISA's [2026 SBOM minimum elements](https://www.cisa.gov/resources-tools/resources/2026-minimum-elements-software-bill-materials-sbom) update and replace the 2021 NTIA minimum elements. Use them as an interoperability reference for future inventory quality reporting, not as a claim that FUSE satisfies a regulatory requirement. CISA's [VEX minimum requirements](https://www.cisa.gov/sites/default/files/2023-04/minimum-requirements-for-vex-508c.pdf) remain a separate reference for product-level applicability statements.

## Prioritized feature plan

**Implementation status - 28 October 2026:** P0 items 1 through 16 are implemented in the local 0.3 foundation. The list below records the gaps found during the original audit; the [roadmap](../roadmap.md) is the current status summary. The adjustable source-scan budgets and separately configurable firmware-image limit were completed in this implementation pass.

### P0: Make the basic CLI predictable and reviewable

1. Make `vigil-fuse scan .` create `.fuse-results/` by default with `findings.json`, `findings.txt`, and `findings.sarif`. Keep `--output-dir` and stdout modes available for CI and scripts. This is a proposed behavior change; today a basic scan prints to stdout unless output is configured. Treat JSON as the canonical report, text as the terminal-friendly view, SARIF as the CI interchange file, and keep raw analyzer artifacts alongside them:

   ```text
   .fuse-results/
   ├── findings.json
   ├── findings.txt
   ├── findings.sarif
   └── artifacts/
       ├── components.cdx.json
       ├── osv-results.json
       └── firmware-identification.txt
   ```

   Only create artifact files for stages that actually ran, and record every artifact path and hash in the canonical JSON report. Exclude the report directory from later source walks by default so a previous report is not scanned as project source.
2. Add `vigil-fuse doctor` to list Python version, installed optional executables, versions, platform availability, and capabilities. A missing optional tool should not block native scanning.
3. Add `vigil-fuse scan --plan` or an equivalent dry-run view. Show detected frameworks, selected profile, selected files, skipped file types, planned analyzers, network behavior, and expected limits before reading or processing an image.
4. Add a minimal GitHub Actions example that uploads SARIF and the canonical JSON report. CI should read analyzer coverage from JSON as well as findings from SARIF. Use read-only token permissions for the scan job, keep release credentials away from pull-request code, and lock workflow dependencies where supported or pin third-party actions to full commit SHAs. An empty alert file is not proof that each requested scan stage completed. See [GitHub's secure-use guidance](https://docs.github.com/en/actions/reference/security/secure-use).
5. Define exit codes for complete scans, policy findings, and incomplete scans according to the requested scan plan. Distinguish an analyzer that completed its documented narrow contract, such as Binwalk signature identification, from a requested stage that was skipped, unavailable, or unsupported. A code-path review found that `--vulnerabilities --firmware` can record OSV as `skipped` when Syft cannot create a firmware SBOM, then still return success if other requested tools completed. The OSV adapter also emits `partial` for some unrecognized inputs, but the CLI exit check does not treat `skipped`, `partial`, or `analysisPerformed=false` as incomplete. An unsupported source directory can therefore return 0 without a completed analyzer. Preserve intentional skips, such as not regenerating an SBOM supplied as input. Add regression coverage before using exit status as a CI gate. See the [firmware SBOM prerequisite](../../src/vigil_fuse/cli.py#L138), [OSV partial status](../../src/vigil_fuse/analyzers.py#L459), and [exit-status check](../../src/vigil_fuse/cli.py#L270).
6. Report oversized SBOMs as unsupported or incomplete instead of silently falling through. FUSE's SBOM detector rejects files over 50 MiB; the generic text scanner defaults to 2 MiB per file. A larger JSON SBOM can therefore be treated as source, skipped as too large, and produce no SBOM analysis. See the [SBOM detection limit](../../src/vigil_fuse/input_types.py#L25) and [native file limit](../../src/vigil_fuse/scanner.py#L15).
7. Stabilize rule IDs, URI-safe relative paths, and SARIF fingerprints before using cross-run alert deduplication. FUSE's current serializer writes relative artifact URIs without an `uriBaseId` or `originalUriBaseIds` root. GitHub says that a base identifier is required for valid SARIF when relative URIs are used, even though it is not required just to display code-scanning results. Add a project-root base and verify path stability for scans run from different working directories. See the [SARIF serializer](../../src/vigil_fuse/sarif.py) and [GitHub's SARIF path requirements](https://docs.github.com/en/code-security/reference/code-scanning/sarif-files/sarif-support).
8. Make strict network behavior distinct from offline vulnerability queries. FUSE's `--offline-vulnerabilities` currently forwards OSV-Scanner's `--offline-vulnerabilities`; OSV documents that other features, such as transitive dependency scanning, may still make network requests. Its stricter `--offline` mode uses a local database and does not send project or dependency information anywhere. Add a true no-network option, list networked stages in the plan, record local database age, and report missing offline data as incomplete without silently switching online. See [OSV-Scanner offline mode](https://google.github.io/osv-scanner/usage/offline-mode/) and the [FUSE CLI option](../../src/vigil_fuse/cli.py#L42).
9. Keep the canonical FUSE JSON complete if a CI export has provider limits. GitHub documents a 25,000-result maximum per SARIF run and says only the top 5,000 are included after truncation. Report the exported count and any omitted results in the coverage summary rather than making an upload look complete. See [GitHub SARIF limits](https://docs.github.com/en/code-security/reference/code-scanning/sarif-files/sarif-support).
10. Fix Binwalk status and version handling before relying on firmware identification. The successful path in `identify_firmware` never calls `_tool_version`, so the report omits the version. Its timeout, launch-error, output-limit, and artifact-path error branches refer to a `version` name that is never defined, so those error conditions can raise `NameError` instead of returning an analyzer status. Initialize and retain the version before execution, and cover the success and each failure path in adapter tests. See the [Binwalk adapter implementation](../../src/vigil_fuse/analyzers.py#L487).
11. Make subprocess output limits effective while output is produced. `_run` currently uses `capture_output=True`, and the 10 MiB checks run only after the full stdout and stderr are held in memory. A noisy or misbehaving analyzer can consume memory beyond the stated limit before FUSE rejects it. Python's subprocess documentation says captured pipe data is buffered in memory and warns against using this method for large or unlimited output. Use bounded streaming or a capped temporary file and terminate the child when the limit is exceeded; keep report artifact limits separate from diagnostic limits. See the [subprocess runner and output caps](../../src/vigil_fuse/analyzers.py#L17) and [Python subprocess documentation](https://docs.python.org/3/library/subprocess.html#subprocess.Popen.communicate).
12. Clarify file-coverage counts and the input digest scope. `files_discovered` currently counts only paths accepted by the active profile, while `files_filtered` counts those supported candidates rejected by include or exclude patterns. Unsupported file types and pruned directories are absent from these counts. The directory digest is built from selected or skipped profile candidates, not every repository path, so label it as a selected-input manifest rather than a whole-repository hash. Add plan/report fields for unsupported inputs and scope when users need coverage percentages. See [profile filtering and candidate counts](../../src/vigil_fuse/scanner.py#L37) and [scan manifest/result construction](../../src/vigil_fuse/scanner.py#L192).
13. Prevent reports from exposing local workspace paths. The scan result currently stores the target string passed by the user and the JSON report emits it as `target`. When a caller scans using an absolute path, that value can disclose a username or private directory if the report is shared. Use a safe display label by default and make absolute-path retention explicit; review raw analyzer artifacts for paths and secrets before publishing any result to the Vercel page. See [scan target storage](../../src/vigil_fuse/scanner.py#L187) and [JSON report serialization](../../src/vigil_fuse/reporting.py#L15).
14. **Implemented.** FUSE bounds path discovery, directory traversal, aggregate source bytes, and native source-scan time. Defaults remain 100,000 paths, 20,000 directories, 512 MiB, and 600 seconds; CLI flags and TOML values can raise these only to hard ceilings. Reports expose incomplete coverage and the reached limit. Exact counts are retained for discovered candidate files skipped after source-byte or time caps; path and directory exhaustion marks the inventory incomplete when remaining paths cannot be counted safely. Optional analyzers retain separate timeouts. See [shared limits](../../src/vigil_fuse/limits.py), [bounded discovery and source processing](../../src/vigil_fuse/scanner.py), and [CWE-400 resource exhaustion](https://cwe.mitre.org/data/definitions/400.html).
15. Define explicit file-symlink behavior. Directory traversal skips symbolic links, but when a user passes a file path directly, `Path.is_file()` accepts a link and `_load_source()` opens its target. Decide whether explicit links outside the target are supported, reject them, or show and record the resolved path scope. Keep directory and direct-file behavior consistent and cover the choice with regression checks. See [direct file handling](../../src/vigil_fuse/scanner.py#L43), [directory symlink filtering](../../src/vigil_fuse/scanner.py#L49), and [file reading](../../src/vigil_fuse/scanner.py#L67).
16. **Implemented.** Firmware images have a separate default 512 MiB cap, configurable from 1 byte through 2 GiB with `--max-firmware-bytes` or `scan.max_firmware_bytes`. FUSE checks the size before hashing, bounds the streaming hash against files that grow during the read, records an unsupported input status and limit in the report, skips Binwalk, and returns the incomplete-scan exit code. CLI regression coverage verifies report creation and that neither hashing nor Binwalk runs for an oversized input. See [the configured firmware limit](../../src/vigil_fuse/limits.py), [firmware input handling](../../src/vigil_fuse/scanner.py), and [the CLI report path](../../src/vigil_fuse/cli.py).

### P1: Preserve advisory severity formats

OSV's schema supports CVSS v4 vectors. FUSE's current severity normalizer calculates string vectors only for CVSS 3.0 and 3.1; if an advisory has no separate database severity label or numeric score, a CVSS v4 vector currently falls through to `unknown`. Preserve the original severity type, vector, score, and source, then either support the relevant version with a maintained parser or leave the mapped severity unknown with the source value visible. Do not run a v4 vector through the v3 formula. Add rule-independent fixtures for CVSS v2, v3, v4, numeric scores, advisory labels, and absent severity. See the [OSV severity normalizer](../../src/vigil_fuse/analyzers.py#L177), the [CVSS v3-only vector parser](../../src/vigil_fuse/analyzers.py#L214), [OSV severity types](https://ossf.github.io/osv-schema/#severity-field), and the [FIRST CVSS v4 specification](https://www.first.org/cvss/v4.0/specification-document).

### P1: Scan secret history as a separate stage

FUSE's native rules inspect selected working-tree files, so they cannot identify a credential that was committed and later removed. The opt-in Gitleaks adapter distinguishes Git history from working-tree scanning, scopes results to commits reachable from `HEAD`, and marks shallow or unknown history as partial. It passes `--redact=100`, parses the tool's JSON in memory, and copies only allow-listed path, commit, date, line, rule, and fingerprint metadata into FUSE findings and the separate history artifact. It does not retain match, secret, author, email, or message fields. Historical exposure remains separate from a currently present secret. Review the path and commit evidence, then rotate a genuine credential without reproducing it. The adapter remains unverified against a real Gitleaks installation until that optional executable is available.

Source: [Gitleaks README, scanning modes, redaction, and baselines](https://github.com/gitleaks/gitleaks/blob/master/README.md).

### P1: Analyze the effective target configuration and dependencies

1. Zephyr: accept a completed build directory, selected board, `.config`, devicetree output, and Zephyr version. Prefer Zephyr's own `hardenconfig` output. Record `base` or `strict`, passing and non-applicable checks, and the recommendation source.
2. ESP-IDF: accept the selected target and generated configuration. Respect defaults-file order and current `sdkconfig`; report when only fragments are available. Add OTA, TLS, debug, boot, and flash checks only as each has paired fixtures for supported IDF versions.
3. PlatformIO and Arduino: enumerate environments and board identifiers, allow an explicit target or matrix, and avoid merging results across different build environments without showing the target.
4. Start embedded-Linux inventory with OpenWrt because the existing pilot already contains an OpenWrt target. Test its pinned 18.06.2 scope separately from a current branch, and consume the image manifest or CycloneDX SBOM that the selected build actually provides. Then import Yocto and Buildroot image outputs. Preserve package-manager/build versions, vendor states, and source metadata.
5. Add platform-native source dependency inventory without resolving or building the target: validate ESP-IDF `dependencies.lock` against its target and manifest hash, record Zephyr manifest revisions plus actual workspace commits, and import PlatformIO's installed package graph per environment. Label dependencies as declared, resolved, built, or present in an image, then pass supported identifiers to advisory matching.
6. For general C and C++ code analysis, offer an optional Clang Static Analyzer adapter that first consumes a user-supplied `compile_commands.json`. Clang's compilation database records the actual compiler call for each translation unit, which gives analysis the include paths, defines, and flags needed to interpret that target. CMake emits the file only when the option is enabled and the generator supports it. Do not launch an arbitrary project build as an implicit scan step. If no compatible compilation database exists, mark this analyzer unavailable or partial instead of treating an unconfigured source scan as a clean result. Keep results separate by build target. See [Clang's compilation database format](https://clang.llvm.org/docs/JSONCompilationDatabase.html) and [CMake's export option and generator limits](https://cmake.org/cmake/help/latest/variable/CMAKE_EXPORT_COMPILE_COMMANDS.html).

### P1: Add a baseline and review lifecycle

Provide `baseline`, `diff`, and `suppress` workflows after stable finding identity is defined. A suppression should have a reason, optional owner, creation time, and optional expiry. Keep suppressed counts visible. Do not let an incomplete scan produce a green status merely because its old findings were suppressed.

### P1: Build a device capability map without compliance claims

Map checks to the seven NISTIR 8259A technical capability areas: identification, configuration, data protection, logical access, software update, cybersecurity state awareness, and device security. Let projects select a product context so irrelevant checks can be marked not applicable with a reason. NISTIR 8259 Rev. 1 emphasizes manufacturer activities and product context; it is a reason to include lifecycle evidence, not to turn a source scan into a certificate.

| NIST technical capability | Candidate FUSE evidence | Current boundary |
| --- | --- | --- |
| Device identification | User-supplied model, board, target, firmware version, and artifact hashes | FUSE can hash an input but does not establish the physical device identity |
| Device configuration | Selected build environment, generated configuration, target-aware hardening checks | Current profiles mostly select files and do not resolve full build configuration |
| Data protection | TLS verification, plaintext transport, secret storage, encryption configuration | A source indicator does not prove an active path or hardware encryption state |
| Logical access to interfaces | Default credentials, enabled shell/service, authenticated interfaces, debug console configuration | FUSE001 covers credential-like literals; no complete access-control analysis exists |
| Software update | OTA signature verification, rollback, transport, selected update mechanism | Current ESP-IDF checks are narrow Kconfig indicators, not end-to-end update validation |
| Cybersecurity state awareness | Logging, audit signals, version/update status, vulnerability reporting metadata | No native FUSE rule family currently assesses lifecycle reporting or operational telemetry |
| Device security | Secure boot, debug lock state, flash protection, hardware-dependent mitigations | Static configuration cannot prove that a fuse, debug pin, or hardware protection is active on a shipped board |

ETSI EN 303 645 applies to consumer IoT and expressly excludes products primarily intended for manufacturing, healthcare, or other industrial use. CRA obligations also have different application dates and depend on product and manufacturer scope. Any future standards view should use versioned mappings, show assessment states and evidence, and avoid saying `compliant` or `certified` based only on a FUSE scan.

Sources: [NISTIR 8259A](https://csrc.nist.gov/pubs/ir/8259/a/final), [NISTIR 8259 Rev. 1](https://csrc.nist.gov/pubs/ir/8259/r1/final), [ETSI EN 303 645 v3.1.3](https://www.etsi.org/deliver/etsi_en/303600_303699/303645/03.01.03_60/en_303645v030103p.pdf), [European Commission Cyber Resilience Act overview](https://digital-strategy.ec.europa.eu/en/policies/cyber-resilience-act), and [EU Cyber Resilience Act legal text](https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=celex:32024R2847).

### Manufacturer and support evidence context

NISTIR 8259 Rev. 1, published in April 2026, organizes manufacturer guidance across pre-market and post-market activities, including expected customers and use cases, product capabilities, support planning, ongoing support through end of life, and customer communications. NISTIR 8259B complements the technical device capabilities in NISTIR 8259A with four non-technical supporting capabilities: documentation, information and query reception, information dissemination, and education and awareness. These are actions by a manufacturer or supporting organization across a device's lifecycle. A source repository can contain evidence about them, but cannot establish that a support channel is staffed, a vulnerability report receives a response, or a promised update will be delivered.

NISTIR 8259 Rev. 1 frames its goal as making products securable by giving customers capabilities and information to manage risk, rather than claiming that a manufacturer can establish absolute security in every deployment. FUSE's product reports should follow that evidence-based framing: show capabilities, assumptions, and support evidence for the selected use case instead of assigning an absolute `secure` label.

Keep this as an optional, operator-guided product record beside scan results, not as a vulnerability rule or compliance score. Represent it in a separate `assessments` collection, not in `findings`, so an owner assertion cannot inherit a vulnerability severity. It could capture the selected product and use case, product composition, support period and end-of-life plan, public security contact, update and vulnerability-notice documentation, customer configuration guidance, evidence URL or document, evidence owner, review date, and an explicit state such as `not_assessed`, `located_in_project`, `owner_attested`, or `independently_verified`. Distinguish `not_found_in_project` from `does_not_exist`, and `documented` from `operationally_verified`. Expire stale evidence visibly. This gives a team a place to connect FUSE's technical findings to lifecycle actions without claiming that a repository scan assessed the manufacturer's process.

NISTIR 8425 is specifically a consumer IoT profile and describes outcomes intended for the entire consumer product. FUSE should therefore attach such mappings to a selected product sector and version rather than applying a consumer profile silently to industrial, medical, or research equipment. CISA's Secure by Design guidance is a useful product-development context, but its principles should not be presented as a FUSE certification. The separate CISA Secure by Design Pledge is voluntary and focused on enterprise software; its published scope explicitly excludes physical IoT devices and consumer products.

Sources: [NISTIR 8259 Rev. 1, Foundational Cybersecurity Activities for IoT Product Manufacturers](https://csrc.nist.gov/pubs/ir/8259/r1/final), [NISTIR 8259B, IoT Non-Technical Supporting Capability Core Baseline](https://csrc.nist.gov/pubs/ir/8259/b/final), [NISTIR 8425, Profile of the IoT Core Baseline for Consumer IoT Products](https://csrc.nist.gov/pubs/ir/8425/final), [CISA Secure by Design](https://www.cisa.gov/securebydesign), and [CISA Secure by Design Pledge scope](https://www.cisa.gov/securebydesign/pledge).

### P2: Firmware extraction and deeper analysis

First keep the current firmware mode identification-only. A future extraction stage should run in a disposable, unprivileged worker with no network and no execution of extracted programs by default. Set maximum input bytes, extracted bytes, file count, recursion depth, CPU time, memory, and wall time. Defend against path traversal, link following, decompression bombs, and parser crashes. These are concrete input-processing risks described by [CWE-22](https://cwe.mitre.org/data/definitions/22.html), [CWE-59](https://cwe.mitre.org/data/definitions/59.html), [CWE-400](https://cwe.mitre.org/data/definitions/400.html), and [CWE-409](https://cwe.mitre.org/data/definitions/409.html). If Python performs TAR extraction, explicitly select its `data` filter or fail closed when it is unavailable. The standard library documents that extraction-filter support can be backported and recommends feature detection rather than inferring availability solely from the Python version; the default filter also changes by Python release. A filter does not replace byte, file-count, CPU, and memory limits. Python's ZIP documentation separately warns that decompression bombs can exhaust disk space. Keep the original image SHA-256, tool version, extraction offsets, and parent path for every extracted file. Report extraction failure and partial coverage explicitly. See [Python's TAR extraction filters](https://docs.python.org/3/library/tarfile.html#extraction-filters) and [ZIP decompression pitfalls](https://docs.python.org/3/library/zipfile.html#decompression-pitfalls).

Publish support per firmware format and stage, not as one `firmware supported` claim. Binwalk identifies and can optionally extract embedded files and data. unblob's format catalogue lists common embedded Linux contents such as SquashFS, JFFS2, UBI/UBIFS, ext, CPIO, archives, and compression formats, and its project page describes recursive extraction across 78 or more formats. Those are backend capabilities, not current FUSE coverage. Start with a small, named set of root-filesystem formats, pin the backend version, and mark a format supported only after valid, malformed, boundary, and pinned real-image cases pass. See [unblob's supported format catalogue](https://unblob.org/formats/).

Image acquisition is a separate coverage boundary from scanning an image already on disk. A 2018 study reviewed hardware extraction methods across 24 products and found exposed UART sufficient for a firmware dump in more than 45 percent of its sample. That small historical sample is not an estimate for the current IoT market. It does show why FUSE should distinguish repository files and vendor downloads from operator-supplied device dumps, and record acquisition method, device model/version, capture date, and image hash when that evidence is available. FUSE should not imply that it acquired a device image or proved a physical debug interface was locked. See [the CARDIS 2018 firmware extraction study](https://tomchothia.gitlab.io/Papers/CARDIS18.pdf).

Binwalk, unblob, EMBA, and FACT have different scope and operational costs. The 2026 arXiv extended version of an NDSS 2027 accepted paper on ARM Cortex-M emulation-based dynamic analysis studied 4,571 firmware samples and reports that 34.5 percent could be fuzzed by at least one studied tool, with 10 percent average code coverage among those samples and many false crashes or hangs. These results apply to that study's dataset and tools, not to FUSE. They reinforce that emulation and fuzzing are separate, uncertain stages, not a quick universal switch. Keep them opt-in and link experiments to SPECTRA-32 as lab validation rather than merging them into static severity.

Linux firmware emulation is its own adapter lane. The FirmAE ACSAC 2020 study reports that its heuristic emulation method ran 892 of 1,124 router and IP-camera images in its dataset. That result depends on the study corpus and Linux-specific emulation environment; it does not establish coverage for MCU firmware or predict success on a new image. If FUSE later invokes a backend such as FirmAE, preserve emulation success, target architecture, environment, and dynamic test output as separate coverage and evidence records. See the [ACSAC FirmAE paper page](https://www.acsac.org/2020/program/final/s313.html).

Sources: [Binwalk](https://github.com/ReFirmLabs/binwalk), [unblob](https://github.com/onekey-sec/unblob), [unblob's supported format catalogue](https://unblob.org/formats/), [EMBA](https://github.com/e-m-b-a/emba), [FACT](https://fkie-cad.github.io/FACT_core/), and [SoK preprint on ARM Cortex-M emulation-based firmware analysis](https://arxiv.org/abs/2609.38872).

### P2: VEX and richer component context

After package provenance is reliable, accept product-context VEX with evidence and rationale. Preserve the source format, original status, advisory, component identifier, affected range, assessor statement, and the mapping used to interpret it. CycloneDX and OpenVEX use different status vocabularies. The OpenVEX specification currently describes itself as a draft, so do not silently translate an unfamiliar value or map it to `not_affected`. OpenVEX requires a justification or impact statement for `not_affected`, and an action statement for `affected`. FUSE should begin with one well-tested input format and a loss-aware internal status model before adding additional import or export formats. A `not_affected` statement requires a justified product-level assessment. A missing code match is insufficient.

Sources: [CycloneDX VEX](https://cyclonedx.org/capabilities/vex/), [CycloneDX 1.7 JSON schema](https://cyclonedx.org/docs/1.7/json/), [OpenVEX specification status and schema](https://github.com/openvex/spec/blob/main/OPENVEX-SPEC.md), and [OpenVEX format and status overview](https://github.com/openvex/spec/blob/main/README.md).

### P2: Versioned cryptographic policy evidence

Avoid a generic `weak crypto` rule based on an algorithm name appearing in source. A useful assessment needs the algorithm, mode, key length, operation, selected library and code path, target configuration, and the policy version being applied. NIST SP 800-131A Rev. 2 is final, while its Rev. 3 remains listed as a draft in NIST's current key-management publication table. NIST's June 2026 crypto-agility update also treats algorithm replacement as a lifecycle capability spanning software, hardware, and firmware. FUSE should attach the named policy, revision, and final or draft status to any mapping; keep an uncertain use as a candidate, and avoid presenting a draft migration schedule as a compliance finding. See [NIST's current key-management publications](https://csrc.nist.gov/Projects/key-management/publications), [SP 800-131A Rev. 2](https://csrc.nist.gov/pubs/sp/800/131/a/r2/final), and [NIST's 2026 crypto-agility paper](https://csrc.nist.gov/pubs/cswp/39/upd1/considerations-for-achieving-crypto-agility/final).

### P2: Optional exploitation context

After package identity and applicability are reliable, optionally enrich advisory matches with CISA KEV and FIRST EPSS data. Store the data-source revision and retrieval date so that a report can be reproduced. KEV is a record of confirmed exploitation in the wild, while EPSS is a daily forward-looking probability estimate. Neither establishes that the scanned product is affected or reachable. Support cached/offline datasets and preserve `unknown` when an advisory has no usable identifier or a source is unavailable.

Sources: [CISA KEV catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog), [CISA KEV JSON feed](https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json), and [FIRST EPSS guidance](https://www.first.org/epss/using-epss.html).

### P2: Record manufacturer support evidence

Offer an opt-in operator-guided record for documentation, vulnerability contact and intake, update and vulnerability notices, customer education, and declared support duration. Link each assertion to dated evidence and its source. Mark whether it was found in project files, supplied by an owner, or independently verified. Keep unassessed and stale items visible, and do not turn missing repository evidence into a claim that a manufacturer has no process. Do not label the record compliant or certified.

Source: [NISTIR 8259B](https://csrc.nist.gov/pubs/ir/8259/b/final).

### P2: Optional repository posture adapter

If users need repository governance signals, allow an explicitly enabled Scorecard adapter as a separate posture section. Scorecard evaluates repository and development practice heuristics, not whether a firmware component is vulnerable or whether a device setting is exploitable. Preserve its individual check results and limitations instead of collapsing them into a single FUSE security score. Its CLI uses GitHub access for public repositories, so this stage must be visible as networked and may require a token; it must not run under a strict no-network scan.

Sources: [OpenSSF Scorecard CLI and project goals](https://github.com/ossf/scorecard/blob/main/README.md) and [Scorecard check criteria and limitations](https://github.com/ossf/scorecard/blob/main/docs/checks.md).

### P3: Dynamic research handoff

Keep static output and lab output distinct. A later handoff could link a FUSE finding to a SPECTRA-32 experiment, controlled reproduction, mitigation revision, FUSE rescan, and measured security/performance overhead. Mark `reproduced` only when a lab record establishes it. A static FUSE result alone remains a candidate hypothesis.

### P3: Optional analysis assistance

Defer LLM-generated findings and severity decisions. A 2026 review reports that firmware-analysis evaluations often use generic x86 binaries, have benchmark-contamination concerns, lack a measured firmware hallucination rate, and have limited independent replication for some self-reported exploit results. If FUSE later offers an assistant, constrain it to summarizing existing evidence with links to the source finding, label generated text clearly, record model/provider/version and network use, and never let it create, confirm, downgrade, or suppress a finding. Evaluate that feature separately on held-out firmware cases before making accuracy claims. This is a product safeguard based on the review's stated evidence gaps, not a tested FUSE capability. See [Firmware Reverse Engineering: A Comprehensive Review and Directions](https://www.mdpi.com/2079-9292/15/17/3830).

## Evaluation plan

The existing fixture-first approach is correct. Every added native rule should include a vulnerable fixture, a secure counterpart, explicit exclusions, and automated tests. Framework-specific rules should include multiple target configurations and, when semantics depend on a generated build, test that generated artifact rather than only a handwritten fragment.

Do not treat passing paired fixtures or a 12 to 16 project regression corpus as proof of soundness or completeness. NIST's SATE VI Ockham criteria defined soundness as every reported finding being correct and distinguished it from completeness, which concerns finding all weaknesses. Its study-specific protocol used at least 100 applicable test sites and required exclusions to be reported. FUSE need not claim those criteria or adopt that threshold as a release gate. Use the distinction to report reviewed false findings separately from known misses, define what makes a test site applicable to each rule, and disclose unsupported or excluded cases. The existing seven rule fixture pairs validate selected behavior, not ecosystem-wide accuracy. See [NIST's SATE VI Ockham criteria](https://www.nist.gov/itl/ai/ai-standards-and-guidelines-group/sate-vi-ockham-sound-analysis-criteria).

A 2026 review of 118 firmware-analysis works spans physical acquisition, unpacking, binary static analysis, emulation, fuzzing, and AI-assisted analysis across Linux IoT, MCUs, RTOS, UEFI, PLC/ICS, and automotive devices. It identifies the lack of unified evaluation benchmarks as a field gap. This supports measuring each FUSE stage against its own inputs and evidence rather than publishing one overall accuracy score. The review is a literature synthesis, not a benchmark of FUSE or the tools it discusses. See [Firmware Reverse Engineering: A Comprehensive Review and Directions](https://www.mdpi.com/2079-9292/15/17/3830).

Add a small, curated benchmark layer for general code weaknesses. NIST's Software Assurance Reference Dataset contains more than 450,000 test cases spanning over 150 CWE classes, from small synthetic examples to larger applications. Use a reviewed subset of applicable C and C++ cases to cross-check FUSE's code-level rules, while retaining the source case ID, suite/version, expected state, and original CWE. Treat it as supplemental evidence only: the dataset is not an embedded configuration or firmware benchmark, so passing it cannot establish that FUSE detects IoT product weaknesses or that a match is exploitable. SARD also includes materials from other entities and its documentation disclaims responsibility for their quality and use. Check the terms for each selected suite before copying any cases into this repository; when redistribution rights are unclear, keep an external acquisition step and record a checksum instead of vendoring the files.

Sources: [NIST SARD overview](https://samate.nist.gov/SARD/) and [SARD test-suite and material notes](https://samate.nist.gov/SARD/documentation).

Use NIST's Static Analysis Tool Exposition as a methodology reference, not a leaderboard. NIST describes it as a non-competitive study in which tools analyze shared programs and researchers examine the returned outputs; its stated purpose is not to select the best tool. For FUSE, hold commits, scopes, tool versions, and expected coverage constant, then report analyst-triaged results and limitations instead of comparing raw finding counts from different projects or scan scopes. See [NIST's SATE overview](https://www.nist.gov/itl/csd/secure-systems-and-applications/samate/static-analysis-tool-exposition-sate).

For real-project regression, maintain a practical, pinned corpus of roughly 12 to 16 repositories across six or more supported families, with two or three projects per family where available. The current local corpus reaches 14 repositories across the candidate families ESP-IDF, Zephyr, PlatformIO/Arduino, Raspberry Pi Pico SDK, ESPHome, OpenWrt, Yocto, and Buildroot. Track exact commits, scan scopes, expected tool versions, and human triage. This is a regression corpus, not a representative sample of the embedded ecosystem and not enough to claim a universal true-positive rate.

Keep firmware-container tests as a separate corpus from those source repositories. Their first job is to test whether an explicitly supported format can be identified, safely processed, and given an honest complete, partial, failed, or unsupported result. For each format that FUSE later enables, include a small known-good artifact, a malformed artifact, and security boundary fixtures for traversal, link behavior, excessive nesting, and decompression expansion. A separate real-image sample should record device family, vendor release, acquisition source and date, SHA-256, redistribution terms, expected filesystem inventory, and extractor version. Do not turn successful extraction of this corpus into a vulnerability-accuracy claim; keep findings evaluation tied to separately labeled evidence. The Python archive documentation notes version-dependent TAR filter defaults and ZIP disk exhaustion from decompression bombs, which reinforces the need to test these boundaries on every supported Python line. See [Python TAR extraction filters](https://docs.python.org/3/library/tarfile.html#extraction-filters), [Python ZIP decompression pitfalls](https://docs.python.org/3/library/zipfile.html#decompression-pitfalls), and [CWE-409](https://cwe.mitre.org/data/definitions/409.html).

Keep some pinned projects or scan scopes out of rule-tuning decisions as a holdout set. The expanded 14-repository corpus is currently being used for development and is not a holdout set. Repeatedly adding exclusions until counts fall risks optimizing for these known repositories. Apply candidate changes to a held-out project only after the rule and its expected behavior have been fixed, then publish the holdout scope and any misses or unsupported inputs. Treat the holdout as a regression check, not a statistically representative market sample.

Keep per-repository results intact, but flag identical or copied source in aggregate evaluation. The current IoTGoat and OpenWrt scopes include the same upstream credential assignment, so they are two product-scope observations and one independent source example. This distinction prevents repeated vendored or forked code from inflating the apparent number of independent rule confirmations.

The existing [`scan-manifest.json`](../../reports/repository-scans/scan-manifest.json) and [`run_repository_scan_pilot.py`](../../scripts/run_repository_scan_pilot.py) already provide a batch regression harness that checks pinned commits and clean working trees. Extend that development harness for evaluation rather than adding repository-cloning behavior to the end-user scanner.

Track these separately:

- fixture pass rate for the intended rule behavior;
- analyst-adjudicated true, false, and unresolved findings;
- new, fixed, duplicate, and suppressed results across pinned revisions;
- discovered, selected, filtered, scanned, unsupported, and skipped inputs;
- configuration targets and boards actually assessed;
- external tool presence, versions, statuses, network use, and database timestamps;
- wall time and peak resource use by analyzer and input class;
- missed known test fixtures and findings that require a build or runtime to classify.

Do not calculate precision or recall from the current 20 pilot findings. The pilot has no labeled representative set and no confirmed product behavior. Manual triage should update finding status while preserving original evidence.

## Packaging and distribution

FUSE already has the project structure for a command-line Python package. Keep the pure-Python core small, and do not add large firmware analysis tools as mandatory dependencies. Install specialist executables separately unless their redistribution terms have been reviewed; wrapping a tool as a subprocess does not transfer its license or permission to bundle it. The eventual simple user path should be similar to:

```text
pipx install vigil-fuse
cd embedded-project
vigil-fuse scan .
```

Crawl4AI belongs in research and documentation workflows, not the scanner's runtime dependency set. A scan should remain deterministic and work offline by default. When vulnerability enrichment is enabled, use a named structured API or versioned feed with the source, timestamp, and network behavior recorded in the report instead of scraping general web pages at scan time.

PyPA recommends `pipx` for standalone command-line tools because it isolates package dependencies while exposing the command on the user's path. Its guide includes Windows setup with `py -m pip install --user pipx` and `py -m pipx ensurepath`, followed by `pipx install PACKAGE`. FUSE's README should show this flow for Windows alongside macOS and Linux guidance, then explain the three report files and optional analyzer artifacts. See [PyPA's standalone command-line tool guide](https://packaging.python.org/en/latest/guides/installing-stand-alone-command-line-tools/).

If the license review clears public PyPI distribution, keep PyPI as the canonical Python package source, document `pipx install vigil-fuse` as the default isolated installation, and offer `uv tool install vigil-fuse` as an alternative for users who already use uv. uv's tool commands also install applications in isolated environments and expose their command-line entry points. Do not make users install both tool managers or make either manager a FUSE runtime dependency. See [uv's tool installation guide](https://docs.astral.sh/uv/guides/tools/).

GitHub Packages is not a second Python package index for this workflow. Its current registry documentation lists the Container, Docker, RubyGems, npm, Apache Maven, Gradle, and NuGet registries, with no Python registry. If PyPI's terms are resolved, use PyPI as the `pipx` and `uv` source; use GitHub Releases for source archives or other release assets if useful. This is based on the registries in GitHub's [official package registry index](https://docs.github.com/en/packages/learn-github-packages/introduction-to-github-packages), not a claim that FUSE must publish a separate archive.

Treat other package-manager listings as later distribution work, not a requirement for the first package release. Homebrew Core requires a license compatible with the Debian Free Software Guidelines, so the current restricted-use license is not eligible for a Core formula. An official FUSE tap would require a separate acceptance and maintenance decision. Windows Package Manager uses versioned YAML manifests with an installer URL, SHA-256, license, and supported installer details; its submission workflow also validates the package. Microsoft requires that installer URL to point to the publisher's own release location. Add Winget only if a stable Windows installer can be maintained and supports the install behavior required by its manifest. Product inference from these installation guides and acceptance rules: if license review clears it, start with PyPI as the canonical release, document pipx as the normal isolated install and uv as an alternative, then add an OS package channel only when users need it and its installer lifecycle can be maintained. See [Homebrew's formula acceptance policy](https://docs.brew.sh/Acceptable-Formulae), [Microsoft's WinGet manifest reference](https://learn.microsoft.com/en-us/windows/package-manager/package/manifest), [the WinGet repository submission process](https://learn.microsoft.com/en-us/windows/package-manager/package/repository), and [Microsoft's WinGet package policies](https://learn.microsoft.com/en-us/windows/package-manager/package/windows-package-manager-policies).

The user's confirmed license preference is to allow commercial use. That permission is already present in this repository's custom license. In plain terms, a company may use FUSE in paid work and share its analysis output, but may not give another organization a copy of FUSE or publish its own patches without written permission. No license wording change is needed to express that preference. This does not resolve the earlier MIT grant described below.

The default scan should use native rules only. `doctor` should list optional tools, and the scan plan should show what enabling each one will do. If PyPI is selected after the license decision, integrate Trusted Publishing through the GitHub release workflow instead of storing a long-lived upload token. Recheck package-name availability immediately before the first upload.

Before the first public package release, publish a `SECURITY.md` with the supported release line and a private vulnerability-reporting route that a maintainer actually monitors. State the scope clearly and avoid a response-time promise until there is a staffed process. GitHub's security policy guidance specifically recommends documenting supported versions and how to report a vulnerability; PyPI directs package vulnerability reports to the project's security policy. See [GitHub's security policy guide](https://docs.github.com/en/code-security/how-tos/report-and-fix-vulnerabilities/configure-vulnerability-reporting/add-security-policy) and [PyPI's reporting guidance](https://docs.pypi.org/using-pypi/package-security/reporting-issues/).

The current custom VIGIL-FUSE Restricted Use License allows personal and commercial use, but prohibits redistribution and publishing modifications. It is source-available, not open source under the Open Source Definition: those restrictions conflict with its criteria for free redistribution and distributable derived works. PyPA permits custom `LicenseRef` expressions in package metadata, but metadata acceptance does not settle registry terms. PyPI's current Terms of Service require an included license to permit redistribution through PyPI by the PSF, service users, and mirrors. Without that included license, uploading grants the PSF and other service users broad redistribution rights. FUSE's current license prohibits redistribution and mirroring, so public PyPI publication is a release-blocking license decision if that restriction is essential. Separately, PyPI's Acceptable Use Policy says its platform is for package installation and runtime use, not security research, and specifically references vulnerability research. Ask PyPI support whether FUSE's defensive static analysis use fits the policy, and get legal review of the license interaction before uploading. Do not assume a custom metadata expression preserves the no-redistribution intent. The same ownership and contribution questions affect forks, downstream mirrors, published patches, and third-party plugin contributions. The plugin contract and contributor terms must be explicit before inviting community integrations. See the [Open Source Definition criteria 1 and 3](https://opensource.org/osd), [PyPA license-expression specification](https://packaging.python.org/en/latest/specifications/license-expression/), [PyPI Terms of Service](https://policies.python.org/pypi.org/Terms-of-Service/), and [PyPI Acceptable Use Policy](https://policies.python.org/pypi.org/Acceptable-Use-Policy/).

For the package decision, separate how people receive FUSE from what they may do with copies:

| Priority | Distribution direction | Practical consequence |
| --- | --- | --- |
| Easy public `pipx` or `uv` install | Use PyPI only after PyPI policy confirmation and license review | Public listing is straightforward, but current PyPI terms require redistribution rights that conflict with FUSE's no-redistribution license. Get PyPI's policy answer and legal review before upload. |
| Restrict who can download FUSE | Use an access-controlled package or artifact service operated by VIGIL-IoT | Adds account and hosting work. Every authorized user still needs a copy to install, so the license must explicitly allow that access and use. |
| Allow downstream mirrors, forks, patches, and community plugins | Adopt a compatible open-source license or separately grant those rights | This is a different ownership and contribution model from the current restriction. |

This is a product decision matrix, not legal advice. A public GitHub repository also allows people to view and fork it under GitHub's platform behavior, so public visibility and strict copy control are in tension even before package publication.

The PyPI JSON API returned HTTP 404 for the normalized `vigil-fuse` project name on 2026-10-27. This is only a point-in-time availability check and does not reserve the name; repeat it immediately before the first upload.

PyPI's current organization-account documentation lists corporate organization seats at $5 per member per month and says qualifying community organizations can use the same organization features at no cost. If the package should be owned by VIGIL-IoT on PyPI, check community-organization eligibility and approval before assuming that publisher setup is free. PyPI's pricing page lists organization-account pricing; it does not list a per-package publishing charge. If organization approval is unavailable or not worth the setup, a user-owned PyPI project is a possible fallback with an explicit maintainer and publisher mapping. Recheck the current terms before creating the publisher account.

PyPI's account guide also says 2FA is required for accounts and a verified email is required to register a project and upload releases. Trusted Publishing removes the need to store a long-lived upload token in the GitHub workflow; it does not remove account setup or verification requirements. PyPI's organization FAQ gives no approval timeline for organization requests, so submit a community-organization request before the planned release if VIGIL-IoT should own the package.

If PyPI remains the selected distribution path after license review, use Trusted Publishing so a narrowly configured GitHub Actions workflow obtains short-lived OIDC credentials instead of keeping a long-lived upload token in repository secrets. Consider publishing build provenance attestations for the exact wheel and source archive, then document how a consumer can verify the repository, commit, and workflow identity. An attestation documents where and how a package was built. It is not evidence that the package is vulnerability-free.

Sources: [PyPI project lookup](https://pypi.org/pypi/vigil-fuse/json), [PyPI account requirements](https://docs.pypi.org/your-account/managing-your-account/), [PyPI Terms of Service](https://policies.python.org/pypi.org/Terms-of-Service/), [PyPI Acceptable Use Policy](https://policies.python.org/pypi.org/Acceptable-Use-Policy/), [PyPI Trusted Publishing](https://docs.pypi.org/trusted-publishers/), [PyPI attestations](https://docs.pypi.org/attestations/), and [GitHub artifact attestations](https://docs.github.com/en/actions/concepts/security/artifact-attestations).

There is a separate GitHub constraint: GitHub's licensing documentation says that users can view and fork public repositories, and that changing a repository to private does not remove existing forks or local copies. A restrictive `LICENSE` therefore does not prevent GitHub's public fork mechanism from creating repository copies. The relationship between that platform right and this custom license's no-redistribution terms is a separate legal question, not something the FUSE scan can resolve. The v0.2.0 tag points to commit `72a0c3b` from 26 October 2026 and contains no `LICENSE` file. MIT text was added to public history in the later commit `ec91524` on 27 October, then replaced by the current restricted-use terms in `b88f235`. The [LICENSE at the MIT commit](https://github.com/VIGIL-IoT/VIGIL-FUSE/blob/ec91524/LICENSE) granted broad rights to copy, modify, publish, distribute, and sell the Software. The tag history and MIT commit should be described separately; changing the current file does not erase permissions already granted to copies obtained under the earlier text. If strict copy control is required, make a deliberate hosting decision and review the earlier public license history.

Sources: [PyPA license expression specification](https://packaging.python.org/en/latest/specifications/license-expression/), [PyPA licensing examples](https://packaging.python.org/en/latest/guides/licensing-examples-and-user-scenarios/), [PyPI Terms of Service](https://policies.python.org/pypi.org/Terms-of-Service/), [PyPI Acceptable Use Policy](https://policies.python.org/pypi.org/Acceptable-Use-Policy/), [PyPI organization account pricing](https://docs.pypi.org/organization-accounts/pricing-and-payments/), [PyPI organization account FAQ](https://docs.pypi.org/organization-accounts/org-acc-faq/), [PyPI account requirements](https://docs.pypi.org/your-account/managing-your-account/), [PyPI Trusted Publishers](https://docs.pypi.org/trusted-publishers/), [GitHub licensing a public repository](https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/customizing-your-repository/licensing-a-repository), and [GitHub Terms of Service](https://docs.github.com/en/site-policy/github-terms/github-terms-of-service).

## Suggested release sequence

### 0.3: Make the CLI easy to trust and repeat

- Default report folder and stable output contract.
- `doctor` and a non-executing scan plan.
- Basic GitHub Actions example and SARIF path/fingerprint regression tests.
- Rule status, target provenance, and honest coverage messaging.
- Correct complete, policy-finding, and incomplete exit states; preserve external severity vectors including CVSS v4.
- Provide a strict no-network mode distinct from offline vulnerability-database queries.
- Implemented locally on 28 October 2026: optional Git-history scanning runs Gitleaks with its default rules and full redaction, normalizes only commit/path/rule/line metadata, and writes a separate redacted artifact. The adapter refuses non-root scopes, labels shallow or unknown history as partial, and returns a non-zero scan status when the requested stage is unavailable or incomplete. The Gitleaks tool remains an optional system executable.
- Mark oversized SBOM inputs as unsupported, bound total source and firmware bytes and scan time, and define behavior for explicitly supplied symlinks.
- Repair Binwalk version and failure reporting, stream or cap subprocess output as it is produced, and report when SARIF export limits omit results.
- Add URI base information for relative SARIF paths, and make finding identities stable before enabling cross-run deduplication.
- Keep full target paths out of shareable reports by default; preserve scanner-produced artifacts when building the aggregate results site.
- Maintain the 14-repository pinned qualitative corpus; add framework-version and build-target variation, then establish a holdout set.
- Publish a monitored `SECURITY.md` and resolve the current PyPI Terms of Service, Acceptable Use Policy, and restricted-license interaction before any package upload.

### 0.4: Resolve build context for two platforms

- Choose ESP-IDF generated configuration and Zephyr build output as the first target adapters.
- For Zephyr, consume its supported hardening output where possible. Implemented locally as an opt-in bounded import of `HARDENCONFIG_JSON`; multi-domain build context and framework-version coverage remain open.
- For ESP-IDF, record target, version, and configuration origin. Implemented as candidate provenance for sdkconfig and defaults files; never treat a filename alone as proof of active settings.
- Import ESP-IDF resolved dependencies only when target and manifest hash match; retain Zephyr revisions and checked-out commits; preserve PlatformIO environments.
- Add a multi-target matrix only after the single-target evidence path is correct.

### 0.5: Build system inventory and triage

- Import Yocto and Buildroot SBOM and CVE artifacts.
- Add package origin and advisory provenance.
- Add baseline/diff/suppression states with expiry and visible counts.
- Implemented locally on 28 October 2026: `--git-history` scans commits reachable from `HEAD`; the canonical report and separate artifact omit raw match, secret, author, email, and message fields. A real Gitleaks installation still needs to be checked on representative full and shallow repositories before relying on the adapter in CI.
- After component identity and product applicability are reliable, add cached KEV, EPSS, and VEX context with source timestamps.
- Evaluate OSV and Grype matching on pinned embedded Linux inventories before selecting whether a second database adapter is worth maintaining.

### 0.6 or later: Firmware expansion

- Threat-model and implement an isolated extraction worker.
- Inventory extracted files and component databases with image ancestry.
- Add optional adapters for specialist firmware platforms rather than embedding their dependencies.
- Keep emulation, fuzzing, physical-board testing, and SPECTRA-32 experiment results in a distinct validation layer.

### 1.0: Stabilize public contracts

- Stabilize the JSON schema and adapter contract after real use across the supported input families.
- Consider a VS Code extension only after that contract is stable. Keep it as a thin launcher and finding viewer over the FUSE CLI and canonical JSON instead of building a second scanner.
- Publish the support matrix, coverage semantics, minimum analyzer versions, and license terms.
- Only call a target family supported after its positive, secure, boundary, and real-project regression cases pass.
- Add a static HTML report or Vercel viewer over the stable JSON contract, with escaped report content and explicit publishing.

The version numbers above are planning labels, not release commitments. Do not use them to imply a feature exists before it is implemented.

## Open product decisions

1. Should a basic scan always create `.fuse-results/`, or should stdout remain the default for scripts?
2. Which ESP-IDF versions and boards are the first supported configuration matrix?
3. Should Zephyr's hardening tool be a required optional integration or should FUSE parse a supported subset of generated Kconfig?
4. Which platform build outputs may FUSE import without building or executing the user's project?
5. Should new findings default to advisory reporting or fail CI at a documented policy threshold?
6. Which VEX status values require human approval and what evidence is required?
7. Is public GitHub forking acceptable under the new license, or is the intended restriction strict enough to require private source hosting?
8. What written permission should third-party analyzer and plugin authors receive under the restricted-use license?
9. Does the PyPI upload license grant align with the intended no-redistribution terms, or does FUSE need a different distribution channel or license before publication?

## Research method and limitations

The documentation review used locally installed Crawl4AI 0.9.5 directly through `AsyncWebCrawler`, with focused page retrieval and bounded link discovery. Earlier crawler passes included 21 Zephyr documentation pages and nine NIST capability catalog pages. This research pass also crawled official ESP-IDF, Zephyr, OpenWrt, Yocto, Buildroot, PlatformIO, Arduino CLI, NIST, SARD, SATE and its Ockham criteria, cryptographic-transition guidance, CycloneDX, SPDX, OSV-Scanner and OSV schema, SLSA, GitHub Actions, GitHub, Syft, Grype, Trivy filesystem and C/C++ coverage, CVE Binary Tool, Semgrep, LLVM Clang Static Analyzer, Clang compilation database and CMake build metadata documentation, the Open Source Definition, Binwalk, unblob and its format catalogue, EMBA, FACT, OpenSSF Scorecard, The Update Framework, OWASP IoT testing, OpenVEX, PyPA, PyPI, CISA, MITRE CWE, OWASP XSS, ACSAC FirmAE material, Homebrew package acceptance, uv tool installation, WinGet manifests, submission, and package policies, GitHub security policies, PyPI Terms of Service and package-security reporting, Python TAR, ZIP, and subprocess handling, and the 2026 firmware-analysis review or project sources. NISTIR 8259 Rev. 1 and NISTIR 8259B PDF links were discovered from official pages with Crawl4AI; direct browser navigation started a download, so the PDFs were retrieved and their relevant sections were extracted with `pypdf`. The CISA 2026 SBOM PDF was also text-extracted. Crawl4AI's direct navigation to the CARDIS 2018 PDF also started a download; the paper was retrieved with `requests` and its relevant text was checked with `pypdf`. A final HTTP status audit with `requests` checked 127 unique external links cited here: 124 returned HTTP 200, the MDPI review URL returned HTTP 403 to `requests` but was successfully retrieved with Crawl4AI, the EUR-Lex legal-text URL returned HTTP 202 without extracted text, and the `vigil-fuse` PyPI lookup returned HTTP 404 as expected because the name is not published. The OpenWrt wiki was intermittent: a final request returned page content with HTTP 200 after an earlier timeout, while Crawl4AI received its anti-bot challenge. OpenWrt's SBOM and image-manifest behavior was verified in official GitHub build files. PyPI and GitHub package registry guidance was checked against their official documentation, including the current GitHub registry list. The CRA scope note was checked against the accessible European Commission overview. The review relies primarily on official documentation and original project sources, with selected research papers and one current literature review for context. Search helped locate current official pages and relevant primary research pages; the claims cited in this report were then checked against source pages, project documentation, or extracted paper text. Firecrawl was not used. Crawl4AI is a research tool in this work, not a proposed FUSE runtime dependency.

This report is a source review and product architecture synthesis, not a head-to-head performance benchmark, legal opinion, compliance assessment, or independent audit of every external tool. It audits the checked-in repository scan pilot and does not run new FUSE scans. The research corpus is a set of selected sources. Platform documentation and tool capabilities change, so versions and links should be rechecked before implementation or release. The ARM Cortex-M emulation paper is an arXiv preprint and its results apply to its dataset and studied tools, not to all firmware or FUSE.
