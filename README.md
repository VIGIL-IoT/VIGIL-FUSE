# FUSE

## FUSE - Firmware & Unified Security Engine

**A [VIGIL](https://github.com/VIGIL-IoT) Project**

FUSE is available under the custom [VIGIL-FUSE Restricted Use License](LICENSE).
Individuals and organizations may use it for personal or commercial work, but may
not redistribute it or publish modified copies. It is source-available, not
open-source software.

FUSE is the Firmware & Unified Security Engine, a VIGIL Project in the [VIGIL-IoT suite](https://github.com/VIGIL-IoT). It analyzes embedded projects and firmware artifacts for security-relevant weaknesses, with evidence and clear coverage limits.

FUSE is CLI-first and reports security signals with evidence, severity, confidence, and remediation guidance. The native scanner checks selected source and configuration files. Optional Syft and OSV-Scanner adapters can create a component inventory and match known dependency advisories. The optional Binwalk adapter identifies firmware signatures only; FUSE does not extract or execute firmware.

## Current capabilities

The native scanner currently has seven conservative rules:

| Rule | What it reports | Severity | Confidence |
| --- | --- | --- | --- |
| `FUSE001` | Credential-like names assigned non-placeholder literals, including unquoted `.env` values | Medium | High |
| `FUSE002` | PEM private-key block markers outside recognized test-only paths | High | High |
| `FUSE003` | Explicit TLS verification bypass syntax in code, excluding comments, strings, and test-only paths | High | High |
| `FUSE004` | Non-loopback `http://` endpoints in endpoint-specific assignments or recognized network calls | Medium | High |
| `FUSE005` | Non-loopback `mqtt://` URIs in broker/endpoint context | Medium | High |
| `FUSE006` | ESP-IDF Kconfig inputs explicitly skip bootloader app-image validation | Medium | High |
| `FUSE007` | ESP-IDF Kconfig inputs skip image validation after deep-sleep wake | Medium | High |

These findings describe static indicators. HTTP and MQTT rules require endpoint context and skip recognized test-only paths, comments, loopback addresses, and obvious URL templates. They still do not prove that a connection is reachable or that a code path uses it. Credential checks skip localization files, likely UI labels, path and characteristic constants, placeholders, computed string expressions, and test-only source while continuing to inspect `.env.test` files. Private-key and TLS checks also skip recognized test-only paths. FUSE006 and FUSE007 inspect Kconfig-style source inputs and, when `--build-dir` is selected for ESP-IDF, its generated configuration. Generated-config findings remain candidates because a selected build does not prove what is deployed. FUSE does not test credentials, contact endpoints, or claim exploitability. Secret-like values are redacted in evidence. These filters reduce known noise and can also miss indicators in excluded context, so review the coverage and rule limits.

## Install and run

Requires Python 3.11 or newer. FUSE has no runtime dependencies.

```powershell
py -m pip install -e .
py -m vigil_fuse doctor
py -m vigil_fuse scan . --plan
py -m vigil_fuse scan .
py -m vigil_fuse scan firmware-project --format json --output fuse-report.json
py -m vigil_fuse scan firmware-project --profile esp-idf --output-dir .fuse-results
py -m vigil_fuse scan firmware-project --target-label my-lab/firmware-project
py -m vigil_fuse scan firmware-project --profile esp-idf --build-dir build
py -m vigil_fuse scan zephyr-project --profile zephyr --build-dir build
py -m vigil_fuse scan platformio-project --platformio-env release
py -m vigil_fuse scan firmware-project --compile-commands build/compile_commands.json
py -m vigil_fuse scan hardware-project --hardware-bom hardware/controller-bom.csv
py -m vigil_fuse scan firmware-project --sbom --vulnerabilities --output-dir .fuse-results
py -m vigil_fuse scan device-firmware.bin --firmware --output-dir .fuse-results
py -m vigil_fuse scan device-firmware.bin --firmware --max-firmware-bytes 1073741824
py -m vigil_fuse scan bom.cdx.json --vulnerabilities --output-dir .fuse-results
py -m vigil_fuse scan firmware-project --vulnerabilities --vex product.vex.json --product-purl pkg:generic/device@1.0
py -m vigil_fuse scan device-firmware.bin --firmware --provenance firmware.intoto.json --output-dir .fuse-results
py -m vigil_fuse scan firmware-project --vulnerabilities --no-network
py -m vigil_fuse scan . --git-history --output-dir .fuse-results
py -m vigil_fuse scan . --fail-on high
py -m vigil_fuse baseline create .fuse-results/findings.json --output .fuse-results/baseline.json
py -m vigil_fuse baseline diff .fuse-results/findings.json --baseline .fuse-results/baseline.json --fail-on-new high
```

The normal project flow is a one-time editable install followed by `vigil-fuse scan .`. It prints a terminal illustration when attached to an interactive terminal and creates this folder inside the scanned project directory by default:

```text
.fuse-results/
├── findings.json
├── findings.txt
└── findings.sarif
```

Selecting `--hardware-bom` also writes `hardware-bom.cdx.json` into this directory.

The scanner reads selected code and configuration extensions, including C/C++, Arduino, Berry scripts, Python, JavaScript/TypeScript, Go, Rust, YAML, JSON, TOML, INI, environment files, and PEM files. `--profile` expands discovery to common ESP-IDF, Zephyr, and embedded-Linux filenames. `FUSE006` and `FUSE007` are the first platform-specific checks; other platform rule families remain future work. The default per-file limit is 2 MiB. By default, the native source scan reads at most 512 MiB, visits 100,000 file paths or 20,000 directories, and runs for at most 10 minutes. Set `--max-source-bytes`, `--max-discovered-paths`, `--max-discovered-directories`, or `--max-scan-seconds`, or use the matching `[scan]` TOML values. Hard ceilings are 8 GiB, 1,000,000 paths, 200,000 directories, and 60 minutes. Optional external analyzers have their own timeouts. Native rules run in a killable subprocess with a 2-second per-rule, per-input timeout by default. Use `--rule-timeout` to set a value from 0.1 to 30 seconds. Conservative rule-owned prefilters avoid invoking a rule when selected inputs lack its required markers. Reports show an intentional `skipped` status when no selected input matches a rule's supported scope; this alone does not make the scan incomplete. A rule that times out or fails is disabled for the rest of that scan and reported with partial coverage. Other selected rules continue when possible. Unsupported and binary files are not analyzed by native rules.

Firmware input uses a separate 512 MiB default cap. Set `--max-firmware-bytes` or `scan.max_firmware_bytes` to raise or lower it, up to 2 GiB. An image above the selected limit is reported as unsupported before its contents are hashed or passed to Binwalk.

Every scan also inventories recognized hardware artifacts by filename, independently of the source profile: schematics, PCB layouts and design projects, Gerber and drill outputs, named BOMs, mechanical CAD, netlists, HDL files, and KiCad footprint libraries. The inventory records paths, categories, and counts in JSON and text reports. It does not open those files or create security findings, so presence is not a hardware security assessment. Directory scans skip common generated/dependency folders, symbolic links, and paths explicitly matched by `--exclude`. A single-file scan reports only that file's scope.

`--output-dir` creates `findings.json`, `findings.txt`, and `findings.sarif` together. JSON schema 1.8 also records PlatformIO environment metadata, optional compilation-database inventory, explicitly imported hardware BOMs, product PURL and VEX review context, and firmware provenance digest comparison. Per-rule analyzer entries make timeouts and failures visible. Use `scan --plan` to see framework hints, the declared build matrix, compilation-database coverage, a bounded selected-file preview, expected stages, timeout settings, and missing tools before analysis. `doctor` reports the Python runtime and installed optional analyzers. Reports hide the absolute target path by default.

PlatformIO support is metadata-only. FUSE reads `platformio.ini`, reports declared environments and selected defaults, and accepts repeatable `--platformio-env` selectors. It does not run PlatformIO, resolve project scripts, build targets, or claim that every environment passed tests. If `compile_commands.json` is present, FUSE indexes translation units and compiler families. It never executes commands from that database and does not yet provide compiler-semantic C/C++ analysis.

Hardware filename inventory remains presence-only by default. To parse a BOM, pass `--hardware-bom hardware/controller-bom.csv` or a UTF-8 TSV. FUSE accepts common reference, value, footprint, manufacturer, part number, and quantity columns, records imported component metadata, and writes `.fuse-results/hardware-bom.cdx.json` as CycloneDX 1.6. This is an inventory export, not a part authenticity check, circuit review, or hardware vulnerability assessment. The import is opt-in because a BOM may reveal board composition.

Product and build provenance are separate context from FUSE findings. `--vex product.vex.json --product-purl pkg:generic/device@1.0 --vulnerabilities` imports CycloneDX VEX 1.5 or 1.6 and annotates only exact product PURL, component PURL, and advisory ID matches. The original finding and severity-based exit behavior remain intact. A VEX `not_affected` state requires a recognized justification. FUSE does not authenticate the VEX signature.

For firmware digest context, `--firmware --provenance firmware.intoto.json` parses an in-toto SLSA provenance statement and compares its subject SHA-256 with the selected image. A subject match confirms only that the supplied statement lists the same digest. FUSE does not verify the statement signature, trust the claimed builder, or validate the build policy. A mismatch is reported and returns a non-zero status.

For ESP-IDF and Zephyr, `--build-dir` selects an existing build directory relative to the scan target. FUSE reads bounded configuration and metadata files only. It records ESP-IDF's selected `sdkconfig` and observed defaults order, while treating conventional defaults as candidates when the build does not identify them. It does not run CMake, `idf.py`, `west`, project scripts, or dependency resolution. ESP-IDF generated boot-validation findings are marked as candidates, not proof that the build is released.

For Zephyr, FUSE can import JSON produced by [Zephyr's hardening tool](https://docs.zephyrproject.org/latest/security/hardening-tool.html). From the selected Zephyr build, export the report and then pass it to FUSE:

```powershell
west build -t hardenconfig -- -DHARDENCONFIG_JSON=../hardenconfig.json
py -m vigil_fuse scan . --profile zephyr --build-dir build --zephyr-hardening-report build/hardenconfig.json
```

The imported options retain Zephyr's profile and rationale. A deviation is reported with unknown severity and high confidence that Zephyr marked the selected configuration as failing its recommendation. It remains a candidate configuration signal, not proof about a released image. FUSE requires the report to be inside the selected build directory, bounds it to 4 MiB, and never runs the Zephyr tool itself.

ESP-IDF dependency lock inventory is available through `pip install 'vigil-fuse[esp-idf]'`. On an ESP-IDF profile scan, FUSE reads a bounded root `dependencies.lock` and reports resolved component names, versions, source types, dependency edges, and lock metadata. It does not run the component manager or prove that a resolved component was compiled into firmware. The lockfile manifest hash is retained, but freshness is not verified.

FUSE reports a support label and actual stage status separately. The same packaged [support matrix](src/vigil_fuse/support-matrix.json) is shown by `doctor` and referenced by `scan --plan`; `basic` means documented source checks ran, while firmware signature identification remains `experimental` and hardware-file recognition is presence-only. A successful Binwalk run completes its signature-identification scope, while a truncated saved signature report is partial. SARIF exports are capped at 9 MiB and record available, included, and omitted finding counts in the SARIF run properties.

Optional analyzers are separate system executables, not Python runtime dependencies:

- `--sbom` asks local **Syft** to create `components.cdx.json` in CycloneDX format.
- `--vulnerabilities` asks **OSV-Scanner** to match a generated inventory against advisories; if Syft is unavailable or fails for a project directory, FUSE falls back to OSV's source-manifest/lockfile scan. This uses the network unless `--offline-vulnerabilities` selects OSV-Scanner's local vulnerability database or `--no-network` requires its strict offline mode. Vulnerability scanning automatically attempts Syft first.
- `--firmware` requires a single firmware image and asks **Binwalk** for signature identification. The output is `firmware-identification.txt`; no extraction or execution occurs. A signature pass is partial firmware coverage, not a complete firmware assessment.
- `--git-history` asks **Gitleaks** to inspect commits reachable from the current `HEAD`. It is separate from working-tree checks, requires a repository-root target plus Git and Gitleaks, and marks shallow history as partial. The adapter uses Gitleaks' default rules, does not save its raw report, and writes only redacted finding metadata to `git-history-findings.json`. Historical matches use unknown severity and candidate applicability until reviewed. If a match is genuine, revoke or rotate the credential even when it is absent from the current files.
- An existing CycloneDX or SPDX SBOM can be passed directly as the target; `--vulnerabilities` sends that inventory to OSV-Scanner without regenerating it with Syft.

When requested, analyzer files are saved beside the three FUSE reports: `components.cdx.json`, `osv-results.json`, `firmware-identification.txt`, and/or `git-history-findings.json`. The report lists artifact paths and SHA-256 hashes. Analyzer absence, failure, or partial coverage is recorded and causes a non-zero exit for a requested stage. An unsupported input or a scan that performs no analysis also exits nonzero. Optional analyzers process untrusted files, so use current trusted tool builds and isolated environments for sensitive or hostile firmware.

Install optional tools from their official projects: [Syft installation](https://oss.anchore.com/docs/installation/syft/), [OSV-Scanner installation](https://google.github.io/osv-scanner/installation/), [Binwalk installation](https://github.com/ReFirmLabs/binwalk#how-do-i-get-it), and [Gitleaks](https://github.com/gitleaks/gitleaks). FUSE does not bundle them.

A TOML configuration file can set profiles, path filters, disabled rules, file-size limits, output directory, and optional analysis stages; see [`fuse.example.toml`](fuse.example.toml). `--rule-timeout 5` raises the native rule limit to 5 seconds per input for scans that need more time.

`--fail-on` sets the minimum finding severity that produces exit code 1, which is useful in CI. Its default is `none`, so a successful scan exits 0 even when findings are present. Invalid input or report-write errors exit nonzero.

Baseline review is a separate command group. Create a baseline only from a complete scan, then compare later `findings.json` reports with it. Use `--target-label organization/repository` when the folder name is not unique across your projects. The label is stored in reports and binds baselines and suppressions; local paths remain private.

```powershell
py -m vigil_fuse baseline create .fuse-results/findings.json --output .fuse-results/baseline.json
py -m vigil_fuse baseline diff .fuse-results/findings.json --baseline .fuse-results/baseline.json --fail-on-new high
py -m vigil_fuse baseline suppress .fuse-results/findings.json --finding PASTE_FINGERPRINT_HERE --reason "Accepted until the next hardware revision" --owner "firmware team" --expires 2027-01-31
py -m vigil_fuse baseline diff .fuse-results/findings.json --baseline .fuse-results/baseline.json --suppressions .fuse-results/suppressions.json
py -m vigil_fuse baseline unsuppress .fuse-results/findings.json --finding PASTE_FINGERPRINT_HERE --output .fuse-results/suppressions.json
```

The diff reports new, persistent, moved, resolved, and suppressed counts. Suppressions require a reason and can include an owner and expiry date. Native-rule comparison identity ignores line-number changes but includes rule, file path, title, category, and redacted evidence. Repeated identical matches receive separate occurrence identities, so suppressing one does not hide the others. A native finding is marked moved only when exactly one unmatched baseline finding and one current finding agree on analyzer, rule, category, title, and normalized redacted evidence. Ambiguous matches remain new and resolved for review, and suppressions do not transfer to a new path. OSV findings remain path-sensitive. Baseline format 1.1 stores move identities and FUSE continues to read format 1.0. An incomplete scan exits 2 and does not mark missing baseline findings resolved, even when all current findings are suppressed. `--fail-on-new` exits 1 for an unsuppressed new finding at the selected severity or higher.

See the [GitHub Actions SARIF workflow example](docs/github-actions.md). Vulnerability disclosures should use the private channel described in [SECURITY.md](SECURITY.md); repository settings must enable and monitor GitHub private vulnerability reporting.

Run the rule and CLI tests with:

```powershell
py -m pip install -e ".[test]"
py -m pytest -q
```

## Finding model

Every finding keeps **severity** (potential impact), **confidence** (strength of the evidence), **applicability** (whether it applies to the shipped product), and **validation status** as separate fields. Static and advisory matches default to applicability `unknown` and validation `not-validated`; FUSE does not present them as lab-confirmed issues. Dependency findings preserve the upstream severity basis and CVSS vector, including CVSS v4 vectors. An unscored v4 vector remains attached to the finding while severity stays `unknown` unless the advisory supplies a qualitative label. The JSON report uses schema version `1.8` and includes a stable finding ID and fingerprint, rule/analyzer provenance, scan coverage, hardware inventory, selected build context, product PURL and VEX context, optional hardware BOM, firmware provenance metadata, unsupported file-type counts, redacted evidence, explanation, potential impact, remediation, and references where useful. Dependency findings can omit source line numbers when an inventory only identifies a manifest or SBOM. See [the finding schema](docs/finding-schema.md) and the machine-readable [JSON Schema](src/vigil_fuse/schemas/fuse-report-1.8.schema.json).

## Architecture

```text
CLI → input/profile → native rules + optional analyzers → normalized findings → text / JSON / SARIF
```

Rules are isolated modules with metadata and a scanner function. A dedicated worker process receives the normalized relative path and decoded source text. The parent can terminate that worker when a rule exceeds its per-input limit, then continue with other enabled rules. Rule outcomes appear in coverage. See [the architecture notes](docs/architecture.md) and the [research-backed universal-tool strategy](docs/research/universal-fuse-tool-strategy.md).

## Relationship to the VIGIL-IoT suite

FUSE complements **SPECTRA-32** within the [VIGIL-IoT suite](https://github.com/VIGIL-IoT). A typical research workflow is:

```text
embedded project → FUSE analysis → controlled SPECTRA-32 reproduction → mitigation
                 → FUSE rescan → SPECTRA-32 overhead measurement
```

FUSE identifies and explains candidate weaknesses. SPECTRA-32 can experimentally reproduce selected weaknesses in a controlled lab and measure the cost of mitigations. FUSE should then confirm that the hardened implementation no longer matches the relevant rule.

## Development roadmap

1. **Foundation:** CLI, common finding format, conservative rules, vulnerable/secure fixtures, and tests.
2. **Contracts and source profiles:** JSON schema 1.8, profiles, path filters, default output directories, hardware artifact inventory, selected ESP-IDF and Zephyr build context, PlatformIO environment inventory, compilation-database indexing, ESP-IDF sdkconfig/defaults provenance and lock metadata, unsupported-input counts, and SARIF export are implemented; compiler-semantic C/C++ checks remain future work.
3. **Component inventory:** optional Syft CycloneDX generation, OSV-Scanner matching, and direct CycloneDX/SPDX SBOM inputs are implemented; validate behavior and precision on embedded corpora and improve package-level evidence.
4. **Safe firmware intake:** optional Binwalk signature identification is implemented without extraction. Bounded, isolated extraction and extracted-file provenance remain future work.
5. **Firmware-specific checks:** add tested OTA, crypto, debug/interface, and embedded-platform rules with explicit context requirements.
6. **Interoperability:** text, JSON, SARIF, and CycloneDX inventory outputs are available; add CI examples, then HTML, editor, and dashboard adapters.
7. **Lab validation:** link selected findings to controlled SPECTRA-32 reproduction and mitigation-overhead measurements.

See the [incremental roadmap](docs/roadmap.md) and [research-backed universal-tool strategy](docs/research/universal-fuse-tool-strategy.md) for acceptance criteria and design rationale. Rules should ship with a vulnerable fixture, a secure fixture, expected outcomes, and automated tests. Severity and confidence remain separate, and uncertain indicators must be described as such.

## Project identity

**FUSE - Firmware & Unified Security Engine**

**A [VIGIL](https://github.com/VIGIL-IoT) Project**

## Project site

The CLI-first landing page is in [site/](site/) and presents FUSE as a VIGIL Project, with a link to the [VIGIL-IoT initiative](https://github.com/VIGIL-IoT). Its report examples come from rule fixtures and are labelled as test data. Vercel serves the static site from the site output directory configured in [vercel.json](vercel.json); the analyzer package remains independent. See the [site notes](docs/website.md) for local preview instructions.

## Repository scan pilot

On 2026-10-28, FUSE 0.2.0 scanned 14 pinned public repository snapshots across 15 scopes, covering 18,855 files. The current follow-up reports 61 raw static signals: 19 high and 42 medium severity. These are rule matches, not confirmed vulnerabilities. Hardware inventory found 28 filename-matched artifacts across the corpus. Three scopes were partial because four files could not be scanned. See the [scan report and scope notes](reports/repository-scans/README.md), [triage notes](reports/repository-scans/triage.md), and [machine-readable summary](reports/repository-scans/summary.json). The scans did not build repositories, run their test suites, or validate behavior on hardware. The earlier 78-signal and 62-signal expanded snapshots and eight-repository snapshot with 20 signals are retained as historical comparisons in the scan report.

The web page reads the generated snapshot from `site/data/repository-scan-results.json`. After updating scan reports, regenerate the summary and plots with:

```powershell
py scripts\build_repository_scan_dashboard.py
```

This refreshes the published scan summary, supported-input matrix, and repository plots.
