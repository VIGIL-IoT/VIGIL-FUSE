# Project completion and maintenance status

- **Completed:** 2026-11-15
- **Release:** `v0.4.0`
- **Release source commit:** `7d2dcb0476ec8fd6d323807aa439744b5bd9bb44`
- **Maintenance mode:** active

VIGIL-FUSE is a cross-platform, read-only CLI for inspecting supported embedded and IoT source, configuration, metadata, hardware files, and selected firmware inputs. It reports static evidence, severity, confidence, findings, and scan coverage without executing target project code or firmware. A clean scan is not proof of security.

The initial scope includes native text and configuration rules, project profiles, a non-executing scan plan, optional Binwalk and Ghidra analysis, optional Syft, OSV-Scanner, and Gitleaks adapters, coverage reporting, terminal output, JSON, SARIF, and `doctor`. It excludes universal firmware support, firmware extraction or execution, device testing, general compiler-semantic analysis, and independent field-accuracy claims.

## Gate 1: Implementation

**PASS.** The original CLI and analysis scope are implemented and documented. Missing optional tools are reported without preventing use of the native scanner. Reports expose unsupported inputs, skipped files, and incomplete analysis.

## Gate 2: Release acceptance

**PASS.** On Windows 11 with Python 3.14.7, the clean-tree suite reported 383 passed, one environment-gated Docker test skipped, and 184 subtests passed. Coverage was 78%, above the 75% threshold. Ruff lint and formatting, strict Mypy, documentation validation for 109 Markdown files, the 24-case synthetic rule benchmark, build, Twine, clean-wheel installation, CLI help and doctor checks, and representative text, JSON, and SARIF scans passed. The local pytest run emitted one non-failing deprecation warning from the installed AnyIO pytest plugin. The published PyPI wheel was installed separately and reported `FUSE 0.4.0`.

The hosted FUSE CI [run 43727828373](https://github.com/VIGIL-IoT/VIGIL-FUSE/actions/runs/43727828373) passed the release commit across Ubuntu with Python 3.11 through 3.14, Windows and macOS with Python 3.11, package build and install, quality and coverage, and Docker fixture integration. CodeQL passed in [run 43727828442](https://github.com/VIGIL-IoT/VIGIL-FUSE/actions/runs/43727828442). The dedicated Ghidra 12.2 workflow passed in [run 43727828463](https://github.com/VIGIL-IoT/VIGIL-FUSE/actions/runs/43727828463). The selected ESP-IDF build-context workflow passed in [run 43727828391](https://github.com/VIGIL-IoT/VIGIL-FUSE/actions/runs/43727828391).

The November 15 ESP-IDF comparison reported partial inventories for ESP32, ESP32-S3, and ESP32-C6 while the independent security traversal completed without findings. Its rebuilt ELF hashes differ from the immutable November 14 artifacts, so this is not a byte-identical rerun. The [comparison report](../reports/evaluation/2026-11-15/binary-detection/README.md) records the limits. Controlled fixtures are regression evidence, not independent accuracy evidence.

## Gate 3: Security and governance

**PASS.** At final verification, the active `Protect main` ruleset required pull requests and required checks. GitHub reported zero open code-scanning alerts and zero open secret-scanning alerts. Shantanu confirmed copyright ownership, authorized Restricted Use License v1.2 and release 0.4.0, and accepted responsibility for the distribution decision. VIGIL-IoT remains the project identity and namespace.

Third-party notices cover Ghidra, the vendored Anatomy kit, Archify output, and the embedded JetBrains Mono font. Ghidra remains an optional external installation. Earlier MIT permissions remain valid for copies distributed under those terms. No external legal review is claimed. PyPI Support issue [#12999](https://github.com/pypi/support/issues/12999) remains open. Successful publication is not PyPI policy approval.

## Gate 4: Release

**PASS.** The annotated `v0.4.0` tag targets the verified main commit. The [GitHub release](https://github.com/VIGIL-IoT/VIGIL-FUSE/releases/tag/v0.4.0) was published on 2026-11-15. The existing [trusted-publishing workflow run 43729913149](https://github.com/VIGIL-IoT/VIGIL-FUSE/actions/runs/43729913149) built and validated the release distributions, matched their version to the tag, and published them to PyPI. The public files' SHA-256 digests match PyPI metadata, both distributions include `LICENSE`, the package metadata names `LicenseRef-VIGIL-FUSE-Restricted-Use-1.2`, and a fresh public installation reports `FUSE 0.4.0`.

## Known limitations

- Native rules cover selected textual and configuration patterns, not general language semantics, reachability, or runtime behavior.
- Firmware analysis is bounded and optional. The November 15 ESP-IDF rebuilds had partial inventories, and their hashes differ from the immutable November 14 artifacts.
- Human reviewer adjudication and independent field accuracy remain pending. No precision or recall claim is made.
- Host-mode optional analyzers are not sandboxed. Docker checks cover recorded fixtures, not every daemon or operating-system configuration.
- FUSE does not validate physical hardware, execute firmware, or prove exploitability.
- License v1.2 is custom source-available and has not received external legal review. PyPI has not provided project-specific policy approval.

## Maintenance policy

Initial feature development is complete and FUSE is in maintenance mode. Maintenance permits confirmed defect and security fixes, dependency and supported-platform compatibility, packaging fixes, documentation corrections, and regression tests. New analyzers, rule families, research features, firmware emulation, hardware programming, and UI redesigns require separately approved future scope.

## Independent evaluation status

The November 14 evaluation remains immutable. The November 15 binary comparison is separately recorded with inputs, hashes, timings, memory samples, and truncation metadata. The preregistered reviewer process and ESP-IDF configuration applicability supplement remain pending. No reviewer decisions or independent field metrics are reported.

## Release artifact record

| Item | Value |
| --- | --- |
| Release source commit | `7d2dcb0476ec8fd6d323807aa439744b5bd9bb44` |
| Annotated tag | `v0.4.0` |
| Annotated tag object SHA-1 | `d1e7a01930f9a89a5b3380c1fe77c190eff3289f` |
| Tag target commit | `7d2dcb0476ec8fd6d323807aa439744b5bd9bb44` |
| Wheel SHA-256 | `b1131aa9160d375e2beb0cff13e96c6c3bbc1468cb0df4cbd6ac0a8f58a6022f` |
| Source distribution SHA-256 | `e20bc18bc63b7bae7afc5287a129b14e4a539e813c7517965a2baf6404094275` |
| GitHub release | [FUSE 0.4.0](https://github.com/VIGIL-IoT/VIGIL-FUSE/releases/tag/v0.4.0) |
| PyPI package | [vigil-fuse 0.4.0](https://pypi.org/project/vigil-fuse/0.4.0/) |
| GitHub release published | 2026-11-15 15:26:43 UTC |
| PyPI upload | 2026-11-15 15:27:11 UTC |
| FUSE CI | [run 43727828373](https://github.com/VIGIL-IoT/VIGIL-FUSE/actions/runs/43727828373) |
| CodeQL | [run 43727828442](https://github.com/VIGIL-IoT/VIGIL-FUSE/actions/runs/43727828442) |
| Ghidra integration | [run 43727828463](https://github.com/VIGIL-IoT/VIGIL-FUSE/actions/runs/43727828463) |
| ESP-IDF build contexts | [run 43727828391](https://github.com/VIGIL-IoT/VIGIL-FUSE/actions/runs/43727828391) |
| PyPI trusted publishing | [run 43729913149](https://github.com/VIGIL-IoT/VIGIL-FUSE/actions/runs/43729913149) |

## Completion declaration

**COMPLETE**

> VIGIL-FUSE initial development is complete. The project has entered maintenance mode.
