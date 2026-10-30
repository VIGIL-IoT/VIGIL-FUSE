# Project requirements and identity

## Identity

- **Project:** FUSE, Firmware & Unified Security Engine
- **Affiliation:** A VIGIL Project in the VIGIL-IoT initiative
- **Type:** Local CLI software for embedded and IoT cybersecurity analysis, with research and engineering evaluation data
- **Maturity:** Alpha, version `0.2.0`; source-available under the custom VIGIL-FUSE Restricted Use License

## Problem and motivation

Embedded projects combine application source, build configuration, credentials, dependency declarations, firmware artifacts, hardware design data, and CI workflows. Reviewers often need to inspect these sources before a project is built or deployed. General-purpose scanners may not preserve embedded build context, hardware inventory, firmware intake limits, or uncertainty about whether a source match reaches a product.

FUSE provides a local, bounded first-pass inspection path. Its engineering motivation is to make candidate findings reproducible and reviewable, with evidence, severity, confidence, applicability, validation status, and scan coverage represented separately. Its research motivation is to study how such signals behave on embedded repositories and where target selection, language semantics, hardware context, and measurement evidence are missing.

This is an engineering gap statement, not a claim that existing tools lack all embedded capabilities or that FUSE is novel. FUSE has not been compared comprehensively against alternative analyzers.

## Users and use cases

- Embedded developers checking a project before review or deployment.
- Product security engineers triaging source, configuration, dependency, and workflow indicators.
- Researchers studying rule behavior on pinned public repository snapshots.
- Maintainers producing local text, JSON, or SARIF reports for manual review.
- Hardware teams inventorying design files or reviewing a selected KiCad netlist and BOM.

## Objectives and success criteria

| ID | Objective | Evidence or acceptance criterion |
| --- | --- | --- |
| O-1 | Inspect supported project inputs without running the target project | Bounded discovery and rule tests pass; analysis paths do not invoke project build scripts or firmware |
| O-2 | Make findings reviewable and uncertainty explicit | Report schema carries separate severity, confidence, applicability, validation status, evidence, impact, and remediation |
| O-3 | Expose incomplete or unavailable analysis | Reports identify scan coverage and analyzer status; partial scans are not presented as complete |
| O-4 | Support incremental rule quality work | Every native rule has vulnerable and secure fixtures and a CI-checked fixture benchmark |
| O-5 | Preserve useful embedded project context | Hardware inventory and selected platform/build adapters emit scoped metadata with explicit limits |
| O-6 | Keep routine use reproducible | Documented install, scan, test, benchmark, and package-build commands work in CI or a clean local environment |
| O-7 | Evaluate signals without overstating accuracy | Pinned manifests, scan reports, manual triage records, and synthetic fixture limits are disclosed |

These criteria assess engineering behavior. They do not establish that FUSE finds every vulnerability or that a scanned product is secure.

## Scope

### Implemented

- CLI-driven local source and configuration inspection using seven native rules.
- Bounded discovery, supported-input profiles, source decoding, and explicit scan coverage.
- Text, JSON, and SARIF reports with a versioned JSON schema.
- Separate severity, confidence, applicability, and validation status fields.
- Filename-based hardware and firmware candidate inventories.
- Selected, bounded KiCad netlist parsing, BOM import, platform/build metadata, GitHub Actions checks, and Zephyr hardening report intake.
- Opt-in integrations for Syft, OSV-Scanner, Binwalk, and Gitleaks.
- Local baseline review and suppression workflow.

### Partially implemented or experimental

- Rule matches are static candidates. Most do not resolve target reachability or shipped-product applicability.
- ESP-IDF, Zephyr, PlatformIO, compilation-database, hardware-netlist, BOM, VEX, provenance, and Git-history stages inspect limited formats and do not verify deployment or authenticity.
- Binwalk performs optional signature identification only. It does not extract or semantically analyze firmware.
- Public repository studies provide qualitative regression and holdout evidence, not representative field accuracy.

### Out of scope for the current implementation

- Building or executing scanned projects, project scripts, or firmware.
- Connecting to devices, testing credentials, fuzzing hardware, flashing firmware, or conducting network probes.
- Proving source reachability, exact product applicability, exploitability, or hardware exposure from filename or netlist evidence alone.
- Complete compiler-semantic C/C++ analysis, general OTA verification, or bounded isolated firmware extraction.
- Hosted service, dashboard backend, editor integration, or automatic package publication.

## Functional requirements

| ID | Requirement | Current status |
| --- | --- | --- |
| FR-1 | Accept a local project or selected artifact and bound discovery, size, and time | Implemented; see `limits.py`, `scanner.py`, and scanner tests |
| FR-2 | Emit findings with evidence, remediation, and independent severity and confidence | Implemented; see `model.py`, report schema, and rule/report tests |
| FR-3 | Report incomplete, skipped, failed, or unavailable analysis explicitly | Implemented for represented stages; optional tools need installed-tool integration testing |
| FR-4 | Produce text, JSON, and SARIF output | Implemented; reporter and SARIF tests |
| FR-5 | Identify hardware and firmware artifact candidates without claiming validation | Implemented as bounded inventory; hardware and inventory tests |
| FR-6 | Parse selected supported hardware/build metadata without invoking project commands | Implemented for documented formats; format limits remain |
| FR-7 | Support optional dependency, firmware-signature, and Git-history tools | Implemented adapters; external tools were unavailable during this audit |
| FR-8 | Provide rule-level regression fixtures and automated checks | Implemented for the seven native rules; benchmark is synthetic |

## Nonfunctional requirements

- **Safety:** Treat project input as untrusted; bound file sizes, discovery, execution time, and selected parsers; do not execute project content.
- **Honesty:** Preserve uncertainty and report coverage; do not call static candidates confirmed vulnerabilities.
- **Portability:** Support Python 3.11 and later on platforms supported by its standard library and optional tools.
- **Maintainability:** Keep rules, analyzers, report models, adapters, and CLI boundaries modular; preserve the `vigil_fuse.analyzers` compatibility facade.
- **Reproducibility:** Pin repository scan inputs and scopes, keep fixtures in version control, and document environment and commands.
- **Privacy:** Write reports locally by default, redact secret-like evidence, and avoid exposing absolute target paths by default.
- **Interoperability:** Maintain versioned JSON and emit SARIF and CycloneDX artifacts where implemented.

## Technology and constraints

| Area | Current choice |
| --- | --- |
| Language | Python `>=3.11`, package currently tested locally on Python `3.14.7` |
| Build | PEP 517/518 setuptools backend, `setuptools>=77.0.3` |
| Runtime dependencies | None required for the core package |
| Optional Python dependency | PyYAML `>=6,<7` for selected ESP-IDF lock metadata |
| Development dependencies | Build, coverage, jsonschema, pytest, pytest-cov, Ruff, and Twine, with ranges in `pyproject.toml` |
| Optional system analyzers | Syft, OSV-Scanner, Binwalk, and Gitleaks, invoked only when requested |
| Reports | Text, JSON Schema 2020-12, SARIF, and selected CycloneDX outputs |
| CI | GitHub Actions on Ubuntu with Python 3.11 to 3.14 |
| Site | Static files in `site/`, configured by `vercel.json`; independent of the analyzer runtime |

## Assumptions and constraints

- The user has authorization to inspect the selected repository and artifacts.
- Filename, textual, and metadata indicators are evidence for review, not proof of behavior.
- Optional analyzer tools have their own versions, parsers, network behavior, and residual risks.
- The current restricted-use license is not an OSI-approved open-source license and limits redistribution and registry uploads. No license change is implied by this engineering document.
- No physical board or controlled lab is required to run FUSE, and none was used for the repository scan studies.
- External package publication and GitHub releases require separate owner and license review.

## Maturity

FUSE is an alpha-stage engineering tool. The implementation has CI, rule fixtures, schema tests, package smoke checks, and pinned repository-scan evidence. It does not have broad independent accuracy evaluation, complete language-aware analysis, hardware-in-the-loop validation, or remote CI evidence for the uncommitted changes in this workspace.
