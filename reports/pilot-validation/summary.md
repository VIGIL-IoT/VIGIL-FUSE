# FUSE local pilot validation

**Date:** 28 October 2026  
**Identity:** A [VIGIL Project](https://github.com/VIGIL-IoT)  
**Scope:** One public PlatformIO firmware repository and one user-owned KiCad project. These are diagnostic scans, not a detector accuracy benchmark.

## Results

| Pilot | What FUSE inspected | Result | What the result does not establish |
| --- | --- | --- | --- |
| Tasmota local checkout | 6,802 files discovered and selected, 6,800 scanned, about 104.9 MB read, 2 files skipped for the per-file size limit | 15 native rule matches: 10 high-severity and 5 medium-severity assignments. Rule counts: FUSE001 3, FUSE003 10, FUSE004 2. The new workflow analyzer added 1 informational candidate. PlatformIO context now includes 106 environments across 4 config files. Firmware inventory lists 30 candidates: 6 `.bin`, 19 `.hex`, and 5 `.ota`. Hardware filename inventory found 2 Fritzing project files. | The report does not prove the matched source is built, reachable, shipped, exploitable, or present in a released image. No build or device test was run. Firmware candidate contents were not read. |
| User-owned KiCad project | Hardware filename inventory across the project and one explicitly selected BOM CSV | 10 hardware artifacts were inventoried: 2 BOMs, 3 hardware libraries, 1 project, 1 netlist, 1 PCB layout, and 2 schematics. The selected BOM imported 102 components with total quantity 120. Source-rule scan found 0 matches in the selected CSV. | This is not a schematic security review, component vulnerability result, PCB exposure analysis, or evidence that the project has no weaknesses. Only the selected BOM CSV was analyzed by source rules. |

## Local report files

- Tasmota: [JSON](tasmota/findings.json), [text](tasmota/findings.txt), [SARIF](tasmota/findings.sarif)
- KiCad project: [JSON](arc-4/findings.json), [text](arc-4/findings.txt), [SARIF](arc-4/findings.sarif), [CycloneDX HBOM](arc-4/hardware-bom.cdx.json)
- Crawl4AI source index: [URL list and excerpts](crawl4ai-source-index.json)

The KiCad HBOM contains user-owned component metadata. Keep that file local unless the owner explicitly chooses to publish it.

## Reproduce the scan shape

```powershell
python -m vigil_fuse scan <tasmota-checkout> --output-dir reports/pilot-validation/tasmota --format json
python -m vigil_fuse scan <kicad-project> --hardware-bom <relative-bom.csv> --output-dir reports/pilot-validation/arc-4 --format json
```

## Tasmota signal triage

The 15 native results are code or configuration indicators with **unknown target applicability**. The report's high confidence describes the rule's match, not confidence that a vulnerable configuration ships in a product. The separate informational workflow result is a review candidate, not a device vulnerability.

- **FUSE001, 3 credential-like literals:** one is in an example sketch and two are in Berry FTP/SSH driver files. They may be example or default values. Whether the drivers are included and whether the values are changed or accepted was not established. Evidence is redacted in the generated report.
- **FUSE003, 10 TLS verification indicators:** matches occur in ESP-Mail-Client library code, a Powerwall integration, and the scripting driver. Static call/configuration markers are present, but the selected PlatformIO target and build reachability were not resolved.
- **FUSE004, 2 HTTP endpoint indicators:** one is in a PlatformIO helper and one in a Berry partition update extension. Build-time artifact retrieval and device update transport are different contexts. Neither match alone proves a product vulnerability.

The root `platformio.ini` lists five `extra_configs` entries. The updated bounded parser followed the four available configuration files and recovered 106 environments. It marks PlatformIO context partial because `platformio_override.ini` and `platformio_tasmota_cenv.ini` are absent from this checkout. It preserves declared `src_dir` and source-filter metadata, but does not evaluate interpolation or establish the effective compiled file set. The scan also had no `compile_commands.json`, so build reachability remains unknown.

Two selected source files exceeded the 2 MiB per-file cap: duplicate `viola.h` example assets under the ESP8266Audio library. The firmware candidate inventory separately lists 30 `.bin`, `.hex`, and `.ota` files, including files in common tool directories. It records their paths and sizes only. No firmware bytes were read, hashed, identified, or analyzed.

## Hardware pilot interpretation

The hardware inventory correctly detects filenames and the opt-in BOM importer successfully produces a CycloneDX hardware BOM. The selected BOM has reference, value, footprint, and quantity fields, but no manufacturer part number field. FUSE therefore lacks a dependable component identity for matching part-level advisories. No component names or values are copied into this summary.

## What to refine next

1. Resolve the remaining PlatformIO gap with a generated compile database or an explicitly selected target build. Keep unresolved interpolation and missing config files visible, and do not execute project scripts during static configuration analysis.
2. Add source-role and build-target evidence to findings. Keep example, vendor, helper, optional-driver, active-config, and compiled-target context visible without silently suppressing matches.
3. Expand the workflow analyzer only with structural YAML handling and paired fixtures for job-level permissions and event-controlled shell inputs.
4. Analyze firmware bytes only after a user selects an image, and continue to report format misses or unsupported files as unknown.
5. Keep hardware presence, BOM inventory, and netlist review as separate coverage stages. Mark part vulnerability matching unknown when stable identifiers are absent.

## Local package readiness

The current `vigil-fuse` 0.2.0 source distribution and wheel build locally. `twine check` passed for both archives, and the wheel contains the report schema and custom license file. No archive was uploaded. Before any TestPyPI trial, confirm the PyPI account email and mandatory two-factor authentication, then ask PyPI support whether a defensive static analyzer whose purpose includes vulnerability research fits the current Acceptable Use Policy. The policy describes PyPI as a runtime distribution service and says it is not for research. TestPyPI uses a separate account. Do not upload unless PyPI's answer and the release decision are clear.

The detailed research and implementation gates are in [the follow-up research memo](../../docs/research/fuse-field-follow-up-2026-10-28.md). The detailed scan artifacts, including the user-owned BOM output, remain local in this directory and should not be published as a website result.
