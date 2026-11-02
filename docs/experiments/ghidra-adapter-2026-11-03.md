# Optional Ghidra adapter integration and benchmark

**Recorded:** 2026-11-03
**Purpose:** verify a selected controlled executable with the optional Ghidra 12.2 adapter, then record descriptive startup, wall-time, and sampled process-tree memory measurements.

## Method

The controlled ELF was compiled locally from a small C fixture containing one referenced HTTP URL, one referenced MQTT URL, and a password-shaped string used to exercise redaction. FUSE invoked the separately installed Ghidra 12.2 Headless Analyzer under JDK 25. The executable was staged into FUSE's temporary workspace. The resulting evidence and FUSE report were validated against their packaged JSON Schemas. The scan did not execute the input program.

The benchmark script records a separate Ghidra `-help` startup probe, installation discovery, one fresh headless JVM analysis, total adapter wall time, and sampled process-tree RSS at 20 ms intervals. The persisted machine-readable values are in [`ghidra-adapter-windows-2026-11-03.json`](../../reports/benchmark/ghidra-adapter-windows-2026-11-03.json).

## Result

The ELF run completed and produced both expected static endpoint candidates, `FUSE-BIN-001` and `FUSE-BIN-002`. The password-shaped test value did not appear in the report artifacts. Ghidra reported ELF with the x86 64-bit language, function and string inventories, and cross references. The adapter emitted a bounded artifact and removed the temporary project workspace. Separate local runs also completed on controlled PE x86 and PE x64 files. The PE x64 secure control referenced HTTPS and MQTTS strings and produced no plaintext endpoint findings.

The benchmark record identifies the sample only by format, byte count, and SHA-256. It does not store a local filesystem path or the controlled binary.

## Limits

This is one controlled input on one Windows environment. The startup and analysis timings are not repeated samples, there is no performance threshold, and the result does not support general throughput or memory claims. RSS sampling can miss brief process peaks and does not account for all system memory. One ELF x86-64 result does not establish support for every processor, loader, or firmware format. The separate PE x86 validation is documented in the [Ghidra integration guide](../ghidra-analysis.md).

The benchmark is integration evidence, not accuracy evidence. The findings are static candidates, not proof of reachable communication or a deployed weakness. The Ghidra integration still parses untrusted files with the current user's permissions and is not an OS sandbox.
