# ADR-0006: Optional Ghidra Headless adapter

- **Status:** Accepted for implementation
- **Date:** 2026-11-03
- **Release status:** Public release remains subject to the repository's open rights and distribution review.

## Context

FUSE's Binwalk adapter identifies firmware signatures but does not inspect executable program structure. An optional static analysis adapter can add binary format, loader, architecture, function, symbol, string, and cross-reference evidence. That evidence must remain bounded and must not be presented as proof of runtime behavior or exploitability.

Ghidra supplies a maintained Headless Analyzer and public scripting interfaces. It is a separately installed application with its own Java runtime requirements and license. Bundling the application would add substantial size and third-party distribution obligations. Running target-provided scripts, extensions, or binaries would cross FUSE's non-execution boundary.

## Decision

1. Use Ghidra Headless Analyzer 12.2 as an opt-in external tool. Require a separately installed Ghidra tree and a compatible JDK. Do not download or bundle Ghidra during package installation or a scan.
2. Analyze one selected regular file. Detect ELF, PE, and Mach-O from file magic. Require an explicit Ghidra language ID and load address before accepting raw bytes.
3. Stage the input under a generated temporary name and hash it during the bounded copy. Apply the existing input, wall-time, diagnostic, output, and process cleanup controls.
4. Run only FUSE's packaged `FuseExport.java` script. Do not execute the input, use target-provided scripts or extensions, connect to Ghidra Server, extract firmware, or export decompiled code.
5. Export bounded JSON evidence with the input digest, tool and loader metadata, inventory counts and truncation state. Validate the artifact schema and digest before normalizing findings.
6. Keep HTTP and MQTT cross-reference findings low severity, high confidence in the observed reference, and explicitly unvalidated for runtime behavior. Imported symbols and strings without a cross reference do not independently create endpoint findings.
7. Make an unavailable, failed, timed out, partial, or unsupported requested stage visible in coverage and the exit status. Do not provide a Docker host fallback.
8. Version the common report as schema 1.11 and retain all prior report schemas and baseline readability.

## Consequences

- The optional analyzer adds no Python runtime dependency and does not change default scans.
- Supported evidence remains bounded, redacted, schema-validated, and reviewable in the common FUSE report.
- The host still parses untrusted binary formats with the caller's permissions. Time and size limits are not OS-level isolation. High-risk files should be analyzed in a separately managed disposable environment.
- Only Ghidra 12.2 with JDK 25 or newer and controlled ELF x86-64, PE x86, and PE x64 samples are currently validated. This does not establish complete processor, loader, raw firmware, or ESP32 support.
- The dedicated integration workflow must pass on its hosted Ubuntu runner. Its execution does not remove the separate rights review gate for public release or distribution.

## Validation evidence

- Unit tests cover discovery, compatibility, file selection, bounded staging, schema and digest checks, redaction, expected findings, failure states, timeout behavior, and CLI reporting.
- Local integration runs completed for controlled ELF x86-64 and PE x86 samples using Ghidra 12.2 and JDK 25.
- The [benchmark record](../experiments/ghidra-adapter-2026-11-03.md) contains one descriptive local measurement with explicit limitations.
- The [pinned Ghidra integration workflow](../../.github/workflows/ghidra-adapter.yml) checks the upstream archive digest, schema output, expected candidate findings, redaction, and temporary workspace cleanup. Hosted workflow status is checked after push.
