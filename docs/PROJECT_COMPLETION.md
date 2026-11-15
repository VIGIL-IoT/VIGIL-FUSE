# Project completion and maintenance status

- **Assessed:** 2026-11-15
- **Code baseline evaluated:** `a475dcec0d2442ed598f7467b9915bf9e1de8083`
- **Latest published version:** `v0.3.0`
- **Proposed next version:** `v0.4.0`, not tagged or published

This assessment freezes the initial feature scope. Implementation and acceptance passed, but unresolved rights and distribution decisions block a new release. The project is not declared formally complete.

## Product purpose

VIGIL-FUSE is a cross-platform, read-only CLI for inspecting supported embedded and IoT project source, configuration, metadata, hardware files, and selected firmware inputs. It reports evidence, severity, confidence, findings, and scan coverage without executing target project code or firmware. A clean scan is not proof of security.

## Scope

The initial scope includes native text and configuration rules, generic and embedded project profiles, a non-executing scan plan, optional Binwalk and Ghidra firmware analysis, optional Syft, OSV-Scanner, and Gitleaks adapters, coverage reporting, terminal output, JSON, SARIF, and the `doctor` command. Optional tools remain separate installations. Unsupported files and unavailable tools must remain visible in coverage.

The scope excludes general semantic C or C++ analysis, universal firmware support, firmware extraction or execution, device and hardware testing, and independently measured field accuracy. Detailed boundaries are in [limitations](limitations.md), [threat model](threat-model.md), and [support matrix](compatibility.md).

## Gate 1: Implementation

**PASS.** The current CLI exposes `doctor`, `baseline`, and `scan`. Scan help includes supported profiles, bounded inputs, the non-executing `--plan`, optional analyzers, and text, JSON, and SARIF outputs. Missing optional programs are reported by `doctor` while the core scanner remains available. The README and [usage guide](usage.md) document installation and use.

Evidence is in the packaged source under `src/vigil_fuse/`, the report schemas under `src/vigil_fuse/schemas/`, and regression tests under `tests/`.

## Gate 2: Acceptance testing

**PASS.** Local acceptance ran on the available Windows environment with Python 3.14.7.

- `python -m pytest -q`: 383 passed, 1 environment-gated Docker test skipped, and 184 subtests passed. Pytest emitted one deprecation warning from the installed AnyIO plugin.
- `python -m coverage run -m pytest -q` and `python -m coverage report -m --fail-under=75`: 78% combined statement and branch coverage, above the 75% gate.
- Ruff checks and formatting, strict Mypy, the 24-case and 7-rule synthetic fixture benchmark, documentation validation, and package path checks were run. The tracked-file path check found no match. The local Git-object note is recorded under Gate 3.
- `python -m build`, `python -m twine check`, clean virtual environment wheel installation, and installed `vigil-fuse` version, help, doctor, and scan-help commands passed.
- Clean-wheel CLI smoke checks passed for scan planning, a plaintext HTTP JSON finding, a secure HTTPS SARIF no-finding result, and redirected machine output without the terminal banner. Invalid input, unsupported binary input, a source-size limit, and an unwritable report destination returned nonzero status without a traceback.
- GitHub Actions FUSE CI [run 43708705224](https://github.com/VIGIL-IoT/VIGIL-FUSE/actions/runs/43708705224) passed on the six supported hosted combinations: Ubuntu Python 3.11 through 3.14, Windows Python 3.11, and macOS Python 3.11. Package build, quality, self-scan, and the hosted Ubuntu Docker fixture integration also passed.
- The dedicated Ghidra 12.2 integration [run 43708705205](https://github.com/VIGIL-IoT/VIGIL-FUSE/actions/runs/43708705205) passed. CodeQL [run 43708705218](https://github.com/VIGIL-IoT/VIGIL-FUSE/actions/runs/43708705218) passed and the default branch has no open code-scanning alerts.

Docker and Ghidra were unavailable in the local environment. Their hosted workflow results are used instead of claiming local execution. The installed wheel's `doctor` command returned successfully and identified missing optional tools.

## Gate 3: Security and governance

**BLOCKED.** Default-branch CodeQL is green, GitHub secret scanning and push protection are enabled, and the API reports zero open secret-scanning alerts. Third-party credits identify Ghidra and its license, state that Ghidra is not bundled, and retain the vendored Anatomy license and notice.

The active repository ruleset [Protect main](https://github.com/VIGIL-IoT/VIGIL-FUSE/rules/27311371) requires pull requests, all six FUSE CI matrix checks, package build, quality and Docker checks, and CodeQL. It blocks force pushes and deletion, requires zero approvals, and has no bypass actors. This permits a solo maintainer to merge after required checks pass.

One local `check_repository_paths.py` run also found an unreachable Git blob. `git rev-list --objects --all` does not list that object, so it is not reachable from a local or remote ref. No tracked file was flagged. The object was inspected and left untouched. The hosted path audit passed on the fresh checkout in FUSE CI run 43708705224. No Git history was rewritten.

The distribution review remains incomplete. The custom license has not received qualified legal review. Repository history contains earlier MIT terms that the current license cannot revoke. The rights packet does not establish the complete rights-holder and third-party asset record or the authorized terms for future releases. PyPI Support issue [#12999](https://github.com/pypi/support/issues/12999) remained open with only an automated acknowledgement on 2026-11-15. PyPI's [Acceptable Use Policy](https://policies.python.org/pypi.org/Acceptable-Use-Policy/) addresses dual-use content used for vulnerability research and says PyPI primarily supports installation and runtime use rather than research. PyPI has not given FUSE a project-specific decision. The existing `0.3.0` upload does not resolve these questions.

Six Dependabot pull requests remain open. The CodeQL action updates in PRs [#5](https://github.com/VIGIL-IoT/VIGIL-FUSE/pull/5) and [#7](https://github.com/VIGIL-IoT/VIGIL-FUSE/pull/7) have failing CodeQL checks on their branches. Both logs show HTTP 504 while downloading the CodeQL bundle, not a source finding. Main's CodeQL run passes. These updates remain separate maintenance review items.

No maturity score was changed. Product completion and research maturity are separate assessments.

## Gate 4: Release

**BLOCKED.** The latest GitHub release and PyPI package are `0.3.0`. The project remains alpha and does not document stable 1.x API guarantees. `0.4.0` is the proposed next version for the unreleased changes in the changelog; it has not been prepared, tagged, or published. No release was created in this assessment. Do not publish until Gate 3 decisions are recorded and the release is explicitly approved.

## Known limitations

- Native rules cover a small set of textual and configuration patterns. They do not provide general language semantics, reachability, or runtime validation.
- The November 15 ESP-IDF rerun reported partial inventories for ESP32, ESP32-S3, and ESP32-C6. Independent Ghidra security traversal completed without findings, but the rebuilt ELF hashes differ from the immutable November 14 artifacts. See the [comparison report](../reports/evaluation/2026-11-15/binary-detection/README.md).
- Controlled fixture results are regression evidence, not independent accuracy evidence. Human reviewers have not completed the independent evaluation. No field precision or recall is claimed.
- Host-mode optional analyzers are not sandboxed. The Docker checks cover the recorded fixture and Windows Syft sample, not all daemon or operating-system configurations.
- FUSE does not validate physical hardware, execute firmware, or establish that a finding is reachable or exploitable.

## Maintenance policy

Feature development for the initial scope is frozen. Maintainer work is limited to confirmed defects, security fixes, dependency and supported-platform compatibility, documentation corrections, regression tests, and necessary packaging fixes. New analyzers, rule families, research features, firmware emulation, hardware programming, and UI redesigns require a separately approved scope. Public code contributions remain paused while ownership and contribution terms are unresolved.

## Independent evaluation status

The November 14 evaluation remains preserved. The November 15 comparison is separate and records its own inputs, hashes, timings, memory samples, truncation, and results. The independently preregistered reviewer process and ESP-IDF configuration applicability supplement are still pending. No reviewer decisions or independent field metrics are reported.

## Completion declaration

**RELEASE BLOCKED**
