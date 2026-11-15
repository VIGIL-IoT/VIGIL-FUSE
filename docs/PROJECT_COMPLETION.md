# Project completion and maintenance status

- **Prepared:** 2026-11-15
- **Release candidate:** `0.4.0`
- **Latest published release at preparation:** `v0.3.0`
- **Release commit, tag, artifact hashes, and publication date:** to be recorded after publication

VIGIL-FUSE is a cross-platform, read-only CLI for inspecting supported embedded and IoT source, configuration, metadata, hardware files, and selected firmware inputs. It reports static evidence, severity, confidence, findings, and scan coverage without executing target project code or firmware. A clean scan is not proof of security.

The initial scope includes native text and configuration rules, project profiles, a non-executing scan plan, optional Binwalk and Ghidra analysis, optional Syft, OSV-Scanner, and Gitleaks adapters, coverage reporting, terminal output, JSON, SARIF, and `doctor`. It excludes universal firmware support, firmware extraction or execution, device testing, general compiler-semantic analysis, and independent field-accuracy claims.

## Gate 1: Implementation

**PASS.** The original CLI and analysis scope are implemented and documented. Missing optional tools are reported without preventing use of the native scanner. Reports expose unsupported inputs, skipped files, and incomplete analysis.

## Gate 2: Release acceptance

**PASS, pending final main-branch run record.** The Windows Python 3.14.7 acceptance pass recorded 383 tests passed, one environment-gated Docker test skipped, and 184 subtests passed. Combined statement and branch coverage was 78%, above the 75% threshold. Ruff lint and formatting, strict Mypy, documentation validation, synthetic fixture benchmark, build, Twine validation, clean-wheel installation, CLI checks, representative text/JSON/SARIF scans, and failure-path checks passed.

The previous main-branch FUSE CI [run 43713685076](https://github.com/VIGIL-IoT/VIGIL-FUSE/actions/runs/43713685076) and CodeQL [run 43713685081](https://github.com/VIGIL-IoT/VIGIL-FUSE/actions/runs/43713685081) passed on commit `d7fdb0cd2da0edf707d1e8fbb8071f67fbe2992d`. Final release-branch and post-merge run IDs will replace these after v0.4.0 acceptance. The dedicated Ghidra workflow and cross-platform matrix must pass for the release commit.

The November 15 ESP-IDF comparison reported partial inventories for ESP32, ESP32-S3, and ESP32-C6 while the independent security traversal completed without findings. Its rebuilt ELF hashes differ from the immutable November 14 artifacts, so it is not a byte-identical rerun. The [comparison report](../reports/evaluation/2026-11-15/binary-detection/README.md) records the limits. Controlled fixtures are regression evidence, not independent accuracy evidence.

## Gate 3: Security and governance

**PASS, pending release-branch verification.** Main CodeQL passed and there were zero open code-scanning and secret-scanning alerts at preparation. The active `Protect main` ruleset requires pull requests, CI, package build, quality, Docker integration, and CodeQL while blocking deletion and force pushes. The owner has explicitly confirmed Shantanu as copyright holder, authorized Restricted Use License v1.2 and release 0.4.0, and accepted responsibility for the distribution decision. VIGIL-IoT remains the project identity and namespace.

The license identifies third-party software as excluded where separate terms apply. Ghidra remains an optional external installation. Credits and notices cover Ghidra, the vendored Anatomy kit, Archify output, and the embedded JetBrains Mono font. The owner decision and historical MIT terms are recorded in the [rights and distribution record](governance/rights-review-packet.md). No external legal review is claimed. PyPI Support issue [#12999](https://github.com/pypi/support/issues/12999) remains open, and successful publication is not PyPI policy approval.

The owner has authorized the official unmodified wheel and source distribution through PyPI after technical checks pass. No distribution channel beyond those stated in Restricted Use License v1.2 is implied.

## Gate 4: Release

**BLOCKED until publication.** The release candidate is `0.4.0`. Gate 4 passes only after the verified main commit is tagged `v0.4.0`, the GitHub release is published, the trusted-publishing workflow succeeds, and the public PyPI files, metadata, license, hashes, and installed CLI are verified. Until then, the initial development scope is not declared complete.

## Known limitations

- Native rules cover selected textual and configuration patterns, not general language semantics, reachability, or runtime behavior.
- Firmware analysis is bounded and optional. The November 15 ESP-IDF rebuilds had partial inventories, and their hashes differ from the immutable November 14 artifacts.
- Human reviewer adjudication and independent field accuracy remain pending. No precision or recall claim is made.
- Host-mode optional analyzers are not sandboxed. Docker checks cover recorded fixtures, not every daemon or operating-system configuration.
- FUSE does not validate physical hardware, execute firmware, or prove exploitability.
- License v1.2 is custom source-available and has not received external legal review. PyPI has not provided project-specific policy approval.

## Maintenance policy

After the verified 0.4.0 release, feature development for the initial scope is frozen. Maintenance permits confirmed defect and security fixes, dependency and supported-platform compatibility, packaging fixes, documentation corrections, and regression tests. New analyzers, rule families, research features, firmware emulation, hardware programming, and UI redesigns require separately approved future scope.

## Independent evaluation status

The November 14 evaluation remains immutable. The November 15 binary comparison is separately recorded with inputs, hashes, timings, memory samples, and truncation metadata. The preregistered reviewer process and ESP-IDF configuration applicability supplement remain pending. No reviewer decisions or independent field metrics are reported.

## Release artifact record

| Item | Value |
| --- | --- |
| Main commit | Pending release merge |
| Annotated tag and tag SHA | Pending |
| Source distribution SHA-256 | Pending |
| Wheel SHA-256 | Pending |
| GitHub release | Pending |
| PyPI package | Pending |
| Publication date | Pending |
| FUSE CI run | Pending |
| CodeQL run | Pending |
| Ghidra integration run | Pending |

## Completion declaration

**RELEASE BLOCKED**
