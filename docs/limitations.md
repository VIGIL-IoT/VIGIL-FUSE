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
- A separate pinned workflow built the official ESP-IDF hello-world example on nine release and target combinations. This is evidence for those builds and the selected metadata adapter, not hardware-in-the-loop, runtime behavior, general framework coverage, or detector accuracy. The [experiment record](experiments/esp-idf-generated-build-matrix-2026-10-31.md) preserves the reports.
- Compilation database support indexes metadata but does not invoke compiler-semantic analysis.
- GitHub Actions checks cover a small set of workflow patterns, including one exact `pull_request_target` checkout pattern and an allowlist of untrusted event expressions directly placed in step shell scripts. They do not cover all YAML structures, permission inheritance, shell semantics, sanitization, or event-data flows. Findings do not prove exploitability or that checked-out code executes.
- VEX and provenance intake are review aids. They do not verify signatures, trust authorities, or establish builder identity.

## Optional tools and security

- Syft, OSV-Scanner, Binwalk, and Gitleaks have separate parsers and risks. Each invocation gets temporary default home, config, cache, data, and temp locations, including Windows home variables, plus a scratch working directory unless the adapter selects a target directory. This avoids ordinary per-user defaults but does not prevent explicit config paths or access to any file readable by the current user. Their wall time, captured output, and pipe draining are bounded. On timeout or output-limit breach, FUSE attempts to terminate a POSIX process group or a Windows Job Object, with a Windows `taskkill` fallback. Cleanup remains best effort, so detached descendants or OS-level failures may leave processes running. This is not a sandbox. Tools may be unavailable, fail, or use the network depending on options.
- The native worker process provides timeout control, not privilege isolation. Run FUSE and external analyzers with least privilege on untrusted input.
- Reports can expose paths, component inventories, build settings, and security indicators. Review and sanitize reports before sharing them.
- A bounded parser can still contain defects. Limits reduce resource exposure but do not prove parser safety.

## Reproducibility and project status

- The pinned repository scans reproduce selected historical snapshots, not current upstream branches.
- Performance evidence includes one synthetic C workload on one Windows environment and one pinned four-scope cohort run on each GitHub-hosted Linux, Windows, and macOS platform, with 20 ms process-tree RSS sampling. These timing and RSS samples are descriptive because runner hardware, architecture, OS images, and Python patch versions differ. The cohort is not representative of all embedded repositories and does not support a general speed or memory claim. Summed RSS may double-count shared pages, 20 ms sampling can miss brief peaks, and other system memory is not included.
- CI tests Ubuntu with Python 3.11 through 3.14, and Windows and macOS with Python 3.11. Its quality job runs Ruff lint and formatting checks, strict Mypy, documentation and path validation, a FUSE self-scan, a small benchmark smoke run, and branch coverage. FUSE CI [run 41181660224](https://github.com/VIGIL-IoT/VIGIL-FUSE/actions/runs/41181660224) passed all eight configured jobs on `efbcb66`. This is evidence for that revision, not a promise that every commit has passed.
- The package workflow builds and installs a wheel, then exercises the installed CLI. Strict Mypy and Ruff formatting are development and CI checks, not runtime dependencies.
- Gitleaks 8.30.0, Syft 1.55.0, and OSV-Scanner 2.7.0 passed bounded cross-platform integration checks. Binwalk v2.3.3 passed in WSL2 Ubuntu. Pinned v3.1.0 passed synthetic gzip, XZ, and U-Boot uImage controls plus SHA-256-checked upstream samples on hosted Ubuntu and native Windows: compressed Tasmota, OpenWrt Malta BE uImage, SquashFS and ext4 rootfs images, and MT7621 initramfs-kernel and SquashFS sysupgrade images. The ext4 sample produced Binwalk's generic EXT marker. These signature checks do not inspect extracted contents, verify boot or upgrade behavior, or establish broad firmware compatibility or detector accuracy. See the [Binwalk evidence records](experiments/binwalk-signature-matrix-2026-10-31.md), [real-image records](experiments/binwalk-real-firmware-2026-10-31.md), [filesystem records](experiments/binwalk-real-filesystem-2026-10-31.md), [ext4 record](experiments/binwalk-real-ext4-2026-10-31.md), [uImage record](experiments/binwalk-real-uimage-2026-10-31.md), and [MT7621 record](experiments/binwalk-openwrt-mt7621-2026-10-31.md).
- The package is version `0.2.0` and alpha. The custom license restricts redistribution and registry uploads without written permission; distribution rights need review before publication.

## Explicit non-claims

FUSE does not certify a project, prove the absence of vulnerabilities, confirm exploitability, validate physical hardware, or replace code review, build provenance verification, dependency policy, firmware testing, or a controlled security assessment.
