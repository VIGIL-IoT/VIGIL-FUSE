# Limitations

FUSE is an alpha-stage static inspection tool. A clean report means only that enabled checks did not match within the supported and scanned scope.

## Detection and accuracy

- Seven native rules cover narrow textual or configuration indicators. They do not provide general semantic analysis of C/C++, linker output, preprocessor state, data flow, or runtime behavior.
- The Python AST check for FUSE003 covers selected qualified Requests and HTTPX calls. Other languages and wrappers use narrower lexical logic.
- Findings do not generally establish whether code is built, selected, reachable, shipped, or enabled. Product applicability often remains `unknown`.
- Fixture benchmark labels are synthetic and authored for regression testing. They are not independent ground truth and do not estimate field precision or recall.
- Public repository scans are selected snapshots and scopes. They contain partial coverage, possible overlap, and manual triage assumptions. They are not representative of all embedded projects.

## Firmware and hardware

- Directory firmware discovery is based on names, extensions, and size. It does not verify file format or inspect firmware bytes.
- Optional Binwalk use identifies signatures only. FUSE does not extract firmware, emulate it, disassemble it, or prove that it is safe.
- Hardware discovery is filename-based. KiCad netlist analysis reports selected connectivity candidates, not physical routing, device population, enclosure access, or debug-port state.
- BOM import records supplied component data. It does not verify part authenticity, component lifecycle, circuit function, or design correctness.
- FUSE has no hardware-in-the-loop test suite and does not interact with a physical device.

## Platform and build context

- PlatformIO, ESP-IDF, and Zephyr adapters inspect bounded selected metadata only. They do not execute build tools or fully resolve the effective compiled program.
- Compilation database support indexes metadata but does not invoke compiler-semantic analysis.
- GitHub Actions checks cover a small set of workflow patterns, not all YAML structures, permission inheritance, or event-data flows.
- VEX and provenance intake are review aids. They do not verify signatures, trust authorities, or establish builder identity.

## Optional tools and security

- Syft, OSV-Scanner, Binwalk, and Gitleaks have separate parsers and risks. FUSE does not sandbox them. Tools may be unavailable, fail, time out, or use the network depending on options.
- The native worker process provides timeout control, not privilege isolation. Run FUSE and external analyzers with least privilege on untrusted input.
- Reports can expose paths, component inventories, build settings, and security indicators. Review and sanitize reports before sharing them.
- A bounded parser can still contain defects. Limits reduce resource exposure but do not prove parser safety.

## Reproducibility and project status

- The pinned repository scans reproduce selected historical snapshots, not current upstream branches.
- Performance evidence currently consists of one synthetic C workload on one Windows environment. It does not characterize typical embedded repositories or support a general speed claim. The sampled process-tree RSS estimate may double-count shared pages and miss brief peaks.
- CI tests Ubuntu with Python 3.11 through 3.14, and Windows and macOS with Python 3.11. Its quality job runs Ruff lint and formatting checks over `src`, `tests`, and `scripts`, strict Mypy across all 44 source modules plus the scan benchmark script, documentation and path validation, a FUSE self-scan, and a small benchmark smoke run. FUSE CI run #263 for `00bb3f2` succeeded. This is evidence for that revision, not a promise that every commit has passed.
- The package workflow builds and installs a wheel, then exercises the installed CLI. Strict Mypy and Ruff formatting are development and CI checks, not runtime dependencies.
- Gitleaks 8.30.0, Syft 1.55.0, OSV-Scanner 2.7.0, and Binwalk v2.3.3 passed bounded local smoke checks. Binwalk was checked in WSL2 Ubuntu, not on Windows natively or with v3.1.0. These checks do not establish broad detector accuracy or cross-platform behavior.
- The package is version `0.2.0` and alpha. The custom license restricts redistribution and registry uploads without written permission; distribution rights need review before publication.

## Explicit non-claims

FUSE does not certify a project, prove the absence of vulnerabilities, confirm exploitability, validate physical hardware, or replace code review, build provenance verification, dependency policy, firmware testing, or a controlled security assessment.
