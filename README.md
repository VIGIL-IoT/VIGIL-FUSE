# FUSE

## FUSE - Firmware & Unified Security Engine

**A [VIGIL](https://github.com/VIGIL-IoT) Project**

FUSE is released under the [MIT License](LICENSE).

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

These findings describe static indicators. HTTP and MQTT rules require endpoint context and skip recognized test-only paths, comments, loopback addresses, and obvious URL templates. They still do not prove that a connection is reachable or that a code path uses it. Credential checks skip localization files, likely UI labels, path and characteristic constants, placeholders, computed string expressions, and test-only source while continuing to inspect `.env.test` files. Private-key and TLS checks also skip recognized test-only paths. FUSE006 and FUSE007 are limited to Kconfig-style input filenames and do not prove those files are the active release configuration. FUSE does not test credentials, contact endpoints, or claim exploitability. Secret-like values are redacted in evidence. These filters reduce known noise and can also miss indicators in excluded context, so review the coverage and rule limits.

## Install and run

Requires Python 3.11 or newer. FUSE has no runtime dependencies.

```powershell
py -m pip install -e .
py -m vigil_fuse scan . --profile generic --output-dir .fuse-results
py -m vigil_fuse scan firmware-project --format json --output fuse-report.json
py -m vigil_fuse scan firmware-project --profile esp-idf --output-dir .fuse-results
py -m vigil_fuse scan firmware-project --sbom --vulnerabilities --output-dir .fuse-results
py -m vigil_fuse scan device-firmware.bin --firmware --output-dir .fuse-results
py -m vigil_fuse scan bom.cdx.json --vulnerabilities --output-dir .fuse-results
py -m vigil_fuse scan . --fail-on high
```

The normal project flow is a one-time editable install followed by one scan command. The command creates this folder:

```text
.fuse-results/
├── findings.json
├── findings.txt
└── findings.sarif
```

The scanner reads selected code and configuration extensions, including C/C++, Arduino, Berry scripts, Python, JavaScript/TypeScript, Go, Rust, YAML, JSON, TOML, INI, environment files, and PEM files. `--profile` expands discovery to common ESP-IDF, Zephyr, and embedded-Linux filenames. `FUSE006` and `FUSE007` are the first platform-specific checks; other platform rule families remain future work. It skips common generated/dependency directories and files larger than 2 MiB. Unsupported and binary files are not analyzed by native rules.

`--output-dir` creates `findings.json`, `findings.txt`, and `findings.sarif` together. JSON schema 1.2 records the profile, input-manifest digest, timestamps, rules/analyzers, artifacts, and skipped-file reasons so incomplete scans are not presented as clean scans. If optional analyzers are enabled without an explicit output directory, FUSE writes to `.fuse-results`.

Optional analyzers are separate system executables, not Python runtime dependencies:

- `--sbom` asks local **Syft** to create `components.cdx.json` in CycloneDX format.
- `--vulnerabilities` asks **OSV-Scanner** to match a generated inventory against advisories; if Syft is unavailable or fails for a project directory, FUSE falls back to OSV's source-manifest/lockfile scan. This uses the network unless `--offline-vulnerabilities` selects OSV-Scanner's cached database. Vulnerability scanning automatically attempts Syft first.
- `--firmware` requires a single firmware image and asks **Binwalk** for signature identification. The output is `firmware-identification.txt`; no extraction or execution occurs. A signature pass is partial firmware coverage, not a complete firmware assessment.
- An existing CycloneDX or SPDX SBOM can be passed directly as the target; `--vulnerabilities` sends that inventory to OSV-Scanner without regenerating it with Syft.

When requested, analyzer files are saved beside the three FUSE reports: `components.cdx.json`, `osv-results.json`, and/or `firmware-identification.txt`. The report lists artifact paths and SHA-256 hashes. Analyzer absence or failure is recorded and causes a non-zero exit for the requested analyzer. Optional analyzers process untrusted files, so use current trusted tool builds and isolated environments for sensitive or hostile firmware.

Install optional tools from their official projects: [Syft installation](https://oss.anchore.com/docs/installation/syft/), [OSV-Scanner installation](https://google.github.io/osv-scanner/installation/), and [Binwalk installation](https://github.com/ReFirmLabs/binwalk#how-do-i-get-it). FUSE does not bundle them.

A TOML configuration file can set profiles, path filters, disabled rules, file-size limits, output directory, and optional analysis stages; see [`fuse.example.toml`](fuse.example.toml).

`--fail-on` sets the minimum finding severity that produces exit code 1, which is useful in CI. Its default is `none`, so a successful scan exits 0 even when findings are present. Invalid input or report-write errors exit nonzero.

Run the rule and CLI tests with:

```powershell
py -m unittest discover -s tests -v
```

## Finding model

Every finding keeps **severity** (potential impact) separate from **confidence** (strength of the evidence). Dependency findings with no advisory severity stay explicitly `unknown`; FUSE does not invent a score. The JSON report uses schema version `1.2` and includes a stable finding ID and fingerprint, rule/analyzer provenance, scan coverage, redacted evidence, explanation, potential impact, remediation, and references where useful. Dependency findings can omit source line numbers when an inventory only identifies a manifest or SBOM. See [the finding schema](docs/finding-schema.md) and the machine-readable [JSON Schema](src/vigil_fuse/schemas/fuse-report-1.2.schema.json).

## Architecture

```text
CLI → input/profile → native rules + optional analyzers → normalized findings → text / JSON / SARIF
```

Rules are isolated modules with metadata and a scanner function. The scanner supplies each rule with a normalized relative path and decoded source text. Rules emit the common finding model; reporters serialize it without changing its meaning. See [the architecture notes](docs/architecture.md) and the [research-backed universal-tool strategy](docs/research/universal-fuse-tool-strategy.md).

## Relationship to the VIGIL-IoT suite

FUSE complements **SPECTRA-32** within the [VIGIL-IoT suite](https://github.com/VIGIL-IoT). A typical research workflow is:

```text
embedded project → FUSE analysis → controlled SPECTRA-32 reproduction → mitigation
                 → FUSE rescan → SPECTRA-32 overhead measurement
```

FUSE identifies and explains candidate weaknesses. SPECTRA-32 can experimentally reproduce selected weaknesses in a controlled lab and measure the cost of mitigations. FUSE should then confirm that the hardened implementation no longer matches the relevant rule.

## Development roadmap

1. **Foundation:** CLI, common finding format, conservative rules, vulnerable/secure fixtures, and tests.
2. **Contracts and source profiles:** JSON schema 1.2, profiles, provenance, path filters, output directories, and SARIF export are implemented; parser-aware source checks remain future work.
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

The CLI-first landing page is in [site/](site/) and follows the FUSE identity within the [VIGIL-IoT suite](https://github.com/VIGIL-IoT). Its report examples come from rule fixtures and are labelled as test data. Vercel serves the static site from the site output directory configured in [vercel.json](vercel.json); the analyzer package remains independent. See the [site notes](docs/website.md) for local preview instructions.

## Repository scan pilot

On 2026-10-26, FUSE 0.2.0 rescanned eight pinned public repository snapshots across nine scan scopes. It scanned 9,460 files and reported 20 raw signals, down from 1,663 in 0.1.0. Coverage also expanded by 604 Tasmota Berry source files, so the count drop is not a precision score or a strict like-for-like comparison. See the [scan report and scope notes](reports/repository-scans/README.md), [triage notes](reports/repository-scans/triage.md), and [machine-readable summary](reports/repository-scans/summary.json). The scans did not build repositories, run their test suites, or validate behavior on hardware.

The web page reads the generated snapshot from `site/data/repository-scan-results.json`. After updating scan reports, regenerate the summary and plots with:

```powershell
py scripts\build_repository_scan_dashboard.py
```
