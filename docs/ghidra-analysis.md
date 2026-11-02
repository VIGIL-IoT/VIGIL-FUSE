# Optional Ghidra analysis

FUSE can request static analysis of one compiled executable or firmware image through the separately installed Ghidra Headless Analyzer. This extends the existing firmware path. Binwalk continues to identify binary signatures without extraction; Ghidra adds loader, architecture, function, symbol, string, and cross-reference evidence. Neither adapter executes the selected firmware.

The [pipeline diagram](../site/diagrams/fuse-ghidra-pipeline.html) shows the optional route. The FUSE integration is Python. The trusted `FuseExport.java` script runs inside Ghidra and writes the versioned `ghidra-analysis.json` evidence artifact. FUSE validates and normalizes that artifact into its common finding model.

The design decision and trust boundaries are documented in [ADR-0006](decisions/ADR-0006-optional-ghidra-headless-adapter.md).

## Requirements and installation

Ghidra is not bundled in FUSE, is not a Python dependency, and is not downloaded during a scan. Install Ghidra from the [official National Security Agency Ghidra repository](https://github.com/NationalSecurityAgency/ghidra). This integration currently validates Ghidra 12.2 with JDK 25 or newer, following the [Ghidra 12.2 release notes](https://github.com/NationalSecurityAgency/ghidra/blob/Ghidra_12.2_build/Ghidra/Configurations/Public_Release/src/global/docs/WhatsNew.md). Other Ghidra releases are reported as incompatible until tested.

The integration requires the installation directory to include `Ghidra/application.properties`, `Ghidra/Framework/Utility/lib/Utility.jar`, and the host's `support/analyzeHeadless` launcher. Discovery order is explicit CLI path, configured path, `GHIDRA_INSTALL_DIR`, then the launcher found on `PATH`. FUSE does not search entire disks.

Check discovery and Java compatibility with:

```sh
vigil-fuse doctor
vigil-fuse doctor --ghidra-install-dir /path/to/ghidra_12.2_PUBLIC
```

Set the location for future commands with `GHIDRA_INSTALL_DIR`, or add it to `fuse.toml`:

```toml
[analysis]
ghidra = false
ghidra_install_dir = "tools/ghidra_12.2_PUBLIC"
ghidra_timeout_seconds = 300
```

Relative paths in this section are resolved from the configuration file's directory. The analysis remains disabled unless `ghidra = true` or `--ghidra` is supplied.

## ELF, PE, and Mach-O inputs

FUSE recognizes ELF, PE, and Mach-O by file magic, not filename extension. Select one regular file and opt in:

```sh
vigil-fuse scan firmware.elf \
  --ghidra \
  --output-dir .fuse-results
```

To run the existing Binwalk signature stage too, request it separately:

```sh
vigil-fuse scan firmware.elf \
  --firmware \
  --ghidra \
  --output-dir .fuse-results
```

`--plan` reports whether Ghidra is requested and available without launching it. Ghidra requires one executable or firmware file, not a project directory. `--ghidra-timeout-seconds` accepts 15 through 3600 seconds, with a 300 second default.

The integration has been exercised on Ghidra 12.2 and JDK 25 with controlled ELF x86-64, PE x86, and PE x64 executables. The local PE x64 control referenced HTTPS and MQTTS strings and produced no plaintext endpoint findings. Other loader and processor combinations are not implied by those checks. Ghidra includes Xtensa support, but that does not establish complete ESP32 firmware support. FUSE currently records the language, processor, loader, and observed result. It does not claim that every ESP32 image is recognized or fully analyzed.

## Raw firmware

FUSE does not guess the processor or load address for raw bytes. Pass both an exact Ghidra language ID and an explicit base address from trusted build metadata or independent review:

```sh
vigil-fuse scan image.bin \
  --ghidra \
  --ghidra-language 'ARM:LE:32:v8' \
  --ghidra-base-address 0x08000000 \
  --output-dir .fuse-results
```

The example values are illustrative. Check the selected Ghidra installation's processor and language definitions before use. `--ghidra-compiler-spec` is optional and only applies to raw input. A language and base address mismatch can make the resulting metadata misleading, so inspect the artifact's language and image base.

## Output and initial findings

The report directory contains `ghidra-analysis.json` when the stage produces a validated artifact. Its separate [JSON Schema](../src/vigil_fuse/schemas/ghidra-analysis.schema.json) covers:

- input SHA-256, format, and byte size
- Ghidra version, loader, processor, language, compiler specification, endianness, pointer size, and image base
- entry points, memory blocks, functions, symbols, imports, exports, strings, cross references, and selected API references
- per-inventory limits, observed and reported counts, truncation flags, warnings, and analysis status

One [controlled local benchmark](experiments/ghidra-adapter-2026-11-03.md) records Ghidra startup, headless-process and adapter wall time, and sampled process-tree RSS. It is a single Windows sample without a performance threshold. It does not support general speed or memory claims.

The Python adapter redacts password-like assignments, JWT-shaped values, private-key blocks, and URL paths, credentials, queries, and fragments before writing the normalized artifact. Static candidate findings are:

| Rule | Evidence required | Severity | Confidence |
| --- | --- | --- | --- |
| `FUSE-BIN-001` | A Ghidra cross reference from a function to an `http://` string | Low | High |
| `FUSE-BIN-002` | A Ghidra cross reference from a function to an `mqtt://` string | Low | High |

Both rules use candidate applicability and `not-validated` validation status. A cross reference does not prove that the function runs, that traffic reaches the endpoint, or that a device is affected. Imported symbols alone do not create vulnerability findings.

Report schema 1.11 adds the Ghidra analyzer status and compiled-binary capability while preserving previous report schemas. Requested analysis failures remain visible and make the CLI return an incomplete-scan exit status.

## Resource and security boundaries

FUSE treats the input binary as hostile. The adapter uses a temporary workspace and project, stages one regular file under a generated filename, rejects symbolic links, hashes while copying, caps input at 128 MiB, applies a wall-time timeout, limits process diagnostics to 10 MiB, caps the structured artifact at 8 MiB, and removes the temporary project after the call. The Java export script caps each collection and output size, reports truncation, and does not emit decompiled code or instruction listings. Java tool-option overrides are filtered for the invocation. The process runner attempts process-tree cleanup on timeout.

This is host process control, not an OS sandbox. Ghidra parses complex untrusted formats with the current user's permissions and can access files available to that user. Use least privilege and a disposable VM or separately managed sandbox for high-risk inputs. FUSE's Docker analyzer mode does not support Ghidra and never falls back to a host process. No Ghidra Server, network repository, target-provided script, extension, or code execution is used.

FUSE does not perform symbolic execution, taint analysis, general data-flow analysis, reachability analysis, full decompilation export, firmware extraction, emulation, or device testing. P-code remains a possible future basis for architecture-independent checks, not an implemented analysis claim.

## Troubleshooting

| Status or message | Check |
| --- | --- |
| `unavailable` | Confirm the path points to the extracted Ghidra installation, the Headless Analyzer files exist, and Java is on `PATH` or in `JAVA_HOME`. |
| `incompatible` | Use Ghidra 12.2 and a JDK satisfying its bundled `application.properties`; current validation requires JDK 25 or newer. |
| `unsupported` | Use an ELF, PE, or Mach-O input, or supply both raw-binary options. Docker analyzer mode does not provide a Ghidra adapter. |
| `timeout` or `partial` | Reduce the sample, increase the configured timeout within its limit, or review artifact truncation and Ghidra's per-file analysis status. |
| `failed` | Review the report detail and installation integrity. FUSE does not accept a partial or malformed JSON artifact as completed analysis. |

## Attribution

Ghidra was developed by the National Security Agency Research Directorate and is distributed under Apache License 2.0. FUSE invokes the separately installed Headless Analyzer and does not bundle Ghidra. The FUSE-owned Java script uses documented public Ghidra APIs. This integration does not imply endorsement, affiliation, or sponsorship. See [third-party credits](THIRD_PARTY_CREDITS.md) and the [official Ghidra repository](https://github.com/NationalSecurityAgency/ghidra).
