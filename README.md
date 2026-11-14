# FUSE

## Firmware & Unified Security Engine

**A [VIGIL](https://github.com/VIGIL-IoT) Project**

FUSE is a CLI-first analysis tool for embedded and IoT project repositories. It checks selected source and configuration files, inventories hardware and firmware candidates, reads selected build metadata, and can run optional dependency or firmware analyzers. Reports include evidence and explicit coverage so a static signal is not mistaken for a confirmed vulnerability.

[![CI](https://img.shields.io/github/actions/workflow/status/VIGIL-IoT/VIGIL-FUSE/ci.yml?branch=main&label=CI)](https://github.com/VIGIL-IoT/VIGIL-FUSE/actions/workflows/ci.yml)
[![Latest release](https://img.shields.io/github/v/release/VIGIL-IoT/VIGIL-FUSE)](https://github.com/VIGIL-IoT/VIGIL-FUSE/releases)
[![PyPI version](https://img.shields.io/pypi/v/vigil-fuse.svg?logo=pypi&label=PyPI)](https://pypi.org/project/vigil-fuse/)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-3776AB?logo=python&logoColor=white)](pyproject.toml)
[![License: VIGIL-FUSE Restricted Use](https://img.shields.io/badge/license-VIGIL--FUSE%20Restricted%20Use-7c3aed)](LICENSE)

**Alpha · 0.3.0**

## Start here

Requires Python 3.11 or newer. The native scanner has no runtime dependencies.

```sh
pipx install vigil-fuse==0.3.0
vigil-fuse doctor
vigil-fuse scan path/to/embedded-project --plan
vigil-fuse scan path/to/embedded-project --output-dir .fuse-results
```

A normal scan writes `findings.json`, `findings.txt`, and `findings.sarif` to `.fuse-results/`. Start with `--plan` to review selected inputs, supported stages, limits, and available tools before scanning.

See the [usage guide](docs/usage.md) for setup, scan options, optional analyzers, and report review.

Install the published [PyPI package](https://pypi.org/project/vigil-fuse/) or browse the [GitHub releases](https://github.com/VIGIL-IoT/VIGIL-FUSE/releases).

## How a scan works

![FUSE scan flow from a selected local project through bounded discovery, native checks, context inventory, optional analyzers, normalized findings, and local reports](docs/figures/fuse-scan-flow.svg)

[Open the standalone diagram source](site/diagrams/fuse-scan-flow.html).

Native rules analyze selected text without importing or executing project code. FUSE does not flash devices, contact device services, or prove that a static signal is reachable in a deployed product. Optional external analyzers run on the host by default. Explicit Docker mode uses local digest-pinned images, read-only inputs, bounded output capture, no network by default, and resource limits. The report directory is never bind-mounted, and nested report paths are hidden behind bounded temporary storage. Host mode remains unsandboxed.

![FUSE trust boundaries: untrusted project input, local analysis, and optional analyzers running on the host or in explicit Docker isolation](docs/figures/fuse-trust-boundaries.svg)

The diagram shows the difference between default host execution and the explicitly configured Docker option. [Open its editable source](docs/diagrams/fuse-trust-boundaries.html).

## Understand a finding

Severity describes potential impact. Confidence describes the strength of the evidence. Applicability and validation are separate fields. FUSE does not combine these into a single risk score.

![Conceptual FUSE finding model showing separate severity and confidence fields](docs/figures/fuse-finding-model.svg)

The figure starts from the illustrative `FUSE001` record in the [finding format](docs/finding-schema.md). It is a teaching example, not a scan result or a physical FUSE device. [Open the interactive version](site/diagrams/fuse-finding-model.html).

## Current scope

- Seven conservative native rules for credential-like literals, private-key markers, TLS verification bypasses, plaintext HTTP and MQTT endpoints, and two ESP-IDF image-validation settings.
- Hardware and firmware candidate inventories. These report recognized files and metadata, not hardware or firmware security assessments.
- Optional Ghidra 12.2 Headless Analyzer support for selected ELF, PE, Mach-O, or explicitly mapped raw binaries. It writes bounded evidence and keeps static endpoint references as unvalidated candidates.
- Selected ESP-IDF, Zephyr, PlatformIO, compilation database, and GitHub Actions metadata checks.
- Optional Syft and OSV-Scanner dependency analysis, Binwalk firmware signature identification, and Gitleaks history checks.
- Text, schema-versioned JSON, SARIF, CycloneDX inventory, scan coverage, evidence, and remediation guidance.

See [supported inputs and limits](src/vigil_fuse/support-matrix.json), [firmware analysis](docs/firmware-analysis.md), [optional Ghidra analysis](docs/ghidra-analysis.md), [hardware analysis](docs/hardware-analysis.md), and [known limitations](docs/limitations.md) for exact boundaries. FUSE does not provide compiler-semantic C/C++ analysis, general firmware extraction, device testing, or hardware-in-the-loop validation.

## Measured scan sample

The same pinned four-scope cohort was scanned on GitHub-hosted Linux, Windows, and macOS runners with one warm-up and three measured runs per scope.

| Selected scope | Linux | Windows | macOS | Coverage |
| --- | ---: | ---: | ---: | --- |
| Apache Mynewt Core | 7.586 s | 5.490 s | 6.508 s | 3,354 / 3,355, partial |
| Mbed TLS | 1.544 s | 0.948 s | 1.234 s | 121 / 121, complete |
| OpenThread | 2.629 s | 1.930 s | 2.047 s | 909 / 909, complete |
| ESP-IoT-Solution | 5.760 s | 4.791 s | 4.877 s | 3,886 / 3,888, partial |

These timings include 20 ms memory sampling and are descriptive samples from one hosted runner per OS, not a controlled speed ranking. Mynewt Core and ESP-IoT-Solution had oversized selected files skipped on every platform. The linked report also records sampled process-tree RSS. See the [method, limitations, and raw reports](docs/experiments/repository-scan-performance-matrix-2026-10-31.md).

## Relationship to the VIGIL-IoT suite

FUSE is a VIGIL Project. Within the wider [VIGIL-IoT suite](https://github.com/VIGIL-IoT), it inspects candidate weaknesses while SPECTRA-32 can reproduce selected cases in a controlled lab, evaluate mitigations, and measure overhead. Findings remain candidates until the relevant behavior is validated.

## Documentation

- [Architecture and data flow](docs/architecture.md)
- [Compatibility and CI evidence](docs/compatibility.md)
- [Finding fields and JSON schema](docs/finding-schema.md)
- [Rules and fixture requirements](docs/rule-development.md)
- [Configuration and integrations](docs/integrations.md)
- [Ghidra analysis and its limits](docs/ghidra-analysis.md) · [Third-party credits](docs/THIRD_PARTY_CREDITS.md)
- [Ghidra pipeline figure](site/diagrams/fuse-ghidra-pipeline.html) · [Controlled Ghidra benchmark](docs/experiments/ghidra-adapter-2026-11-03.md)
- [Threat model](docs/threat-model.md) · [Limitations](docs/limitations.md)
- [Methodology](docs/methodology.md) · [Traceability](docs/traceability.md)
- [Benchmark method and evidence](docs/benchmarks.md) · [Synthetic scan baseline](reports/benchmark/scan-performance.json) · [Pinned repository performance report](reports/benchmark/repository-scan-performance.json) · [Cross-platform report set](docs/experiments/repository-scan-performance-matrix-2026-10-31.md)
- [Repository scan reports](reports/repository-scans/README.md) · [FUSE 0.3.0 transfer replay](reports/repository-scans/release-0.3.0-transfer-2026-11-12/README.md) · [Evaluation notes](docs/experiments/pilot-scan-2026-10.md)
- [Development roadmap](docs/roadmap.md) · [Release process](docs/release-process.md)
- [Repository audit and maturity evidence](docs/REPOSITORY_AUDIT.md) · [AI skills and specialist tools reference](docs/AI_SKILLS_REFERENCE.md) · [Research source ledger](docs/research-sources.md)
- [Project site](site/) · [Website maintenance notes](docs/website.md)

## Develop

```sh
python -m pip install -e ".[dev]"
python -m pytest -q
python -m ruff check src tests scripts
python -m mypy
python scripts/validate_docs.py
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for repository setup and [rule development](docs/rule-development.md) for the vulnerable fixture, secure fixture, and expected-result workflow.

## License status

FUSE is source-available under the [VIGIL-FUSE Restricted Use License, version 1.1](LICENSE). It permits personal and commercial use, private modifications, and redistribution of unmodified official packages through PyPI and its compatible mirrors for installation and use. It does not permit rehosting through other registries or publishing modified versions without written permission from VIGIL-IoT. This is a custom license, not an OSI-approved open-source license. Version 0.3.0 is published on PyPI. Channel and rights review remain open.

An earlier public snapshot included MIT terms at [commit `ec91524`](https://github.com/VIGIL-IoT/VIGIL-FUSE/commit/ec91524). This license does not revoke permissions already granted for copies made available under those earlier terms. Review the license attached to the specific version you use.

Because this repository is public on GitHub, GitHub's [Terms of Service](https://docs.github.com/en/site-policy/github-terms/github-terms-of-service) allow users to view and fork it within the service. This license does not disable GitHub's fork feature.

---

**FUSE · Firmware & Unified Security Engine · A [VIGIL](https://github.com/VIGIL-IoT) Project**

## Multi-repository evaluation report

Read the [LaTeX evaluation and reproduction record](reports/repository-scans/multi-repository-2026-11-14/README.md) or the [PDF on GitHub Pages](https://vigil-iot.github.io/VIGIL-FUSE/report.pdf). Four pinned scopes yielded three static review candidates across 4,347 scanned files, with coverage limitations recorded.
