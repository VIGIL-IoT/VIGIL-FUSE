# Independent repository transfer cohort, 2 November 2026

FUSE 0.2.0 scanned four public embedded and IoT repositories that were not in the earlier scan manifests. Repository commits and scan scopes were pinned before analysis. FUSE source was clean at commit `2bff2e4df97d38f2aff103a3061dc850dabf8b7a`, with source tree SHA-256 `33cef04292cbc37bca76c7917bb765e216f86d63890285e4be115ee861fd0012`.

This is a purposive source-only transfer cohort. It is not representative, independently adjudicated, or an accuracy benchmark. A finding is a review lead and does not establish a shipped-product weakness or exploitability. No repository was built, its tests were not run, and no firmware image or physical device was analyzed.

## Results

| Measure | Result |
| --- | ---: |
| Pinned repositories | 4 |
| Selected scan scopes | 4 |
| Supported files discovered | 4,912 |
| Files selected by scope | 3,428 |
| Files scanned | 3,425 |
| Selected files skipped | 3 |
| Raw finding records | 16 |
| Informational GitHub Actions records | 16 |
| Native FUSE001 to FUSE007 records | 0 |
| Hardware filename matches | 0 |
| Firmware filename candidates | 121 |

All 16 findings are `FUSE-GHA-002` informational matches with high confidence. The confidence describes the static match to a floating branch reference. It does not represent confidence that a vulnerability is exploitable. Source review confirmed that each reported line uses `@main` or `@master`. No branch compromise, unsafe workflow execution, or downstream product impact was observed or tested.

| Repository and pinned commit | Selected scope | Scanned / selected | Status | Signals | Other coverage notes |
| --- | --- | ---: | --- | ---: | --- |
| [littlefs-project/littlefs](https://github.com/littlefs-project/littlefs/tree/6cb4e86540eca0d9ba62500a298385c9d863c8be), `6cb4e86540eca0d9ba62500a298385c9d863c8be` | Full repository within supported input formats | 63 / 63 | Complete | 0 | 6 unselected or unsupported inventory entries |
| [lvgl/lvgl](https://github.com/lvgl/lvgl/tree/1918a999d700ef195a53a73f8765a353e74dc07e), `1918a999d700ef195a53a73f8765a353e74dc07e` | `src`, `include`, `demos`, `examples`, and selected configuration templates | 1,777 / 1,780 | Partial | 7 | Three selected files exceeded the scanner size limit. 121 firmware filename candidates were inventoried without reading file contents. |
| [FreeRTOS/FreeRTOS-Plus-TCP](https://github.com/FreeRTOS/FreeRTOS-Plus-TCP/tree/b86ad086e9870099bb0ac18a75dcb7f6dd508cc7), `b86ad086e9870099bb0ac18a75dcb7f6dd508cc7` | `source/**`, root `CMakeLists.txt`, and `manifest.yml` | 236 / 236 | Complete | 9 | Workflow analysis reported nine floating branch references. |
| [espressif/esp-matter](https://github.com/espressif/esp-matter/tree/b9fc662976fc0af745a0e311cfd109bd0b7be413), `b9fc662976fc0af745a0e311cfd109bd0b7be413` | `components/**`, `device_hal/**`, `examples/**`, and selected ESP-IDF metadata | 1,349 / 1,349 | Complete | 0 | The `connectedhomeip` submodule was excluded. |

The three skipped LVGL files make its selected scope partial. A zero-finding result in the other scopes means only that no enabled check matched within the recorded scan. It does not establish full project coverage or security.

## Workflow reference review

FUSE reported action declarations that select a named Git branch instead of a commit SHA. The FreeRTOS-Plus-TCP matches are in [its pinned CI workflow](https://github.com/FreeRTOS/FreeRTOS-Plus-TCP/blob/b86ad086e9870099bb0ac18a75dcb7f6dd508cc7/.github/workflows/ci.yml#L114) at lines 114, 126, 136, 146, 166, 178, 449, and 469, plus [its pinned release workflow](https://github.com/FreeRTOS/FreeRTOS-Plus-TCP/blob/b86ad086e9870099bb0ac18a75dcb7f6dd508cc7/.github/workflows/release.yml#L24) at line 24. The references use `@main`.

The seven LVGL matches use `ammaraskar/gcc-problem-matcher@master`: [build_micropython.yml](https://github.com/lvgl/lvgl/blob/1918a999d700ef195a53a73f8765a353e74dc07e/.github/workflows/build_micropython.yml#L23), [ccpp.yml](https://github.com/lvgl/lvgl/blob/1918a999d700ef195a53a73f8765a353e74dc07e/.github/workflows/ccpp.yml#L32) at lines 32, 68, and 120, [makefiles.yml](https://github.com/lvgl/lvgl/blob/1918a999d700ef195a53a73f8765a353e74dc07e/.github/workflows/makefiles.yml#L22), [makefiles_uefi.yml](https://github.com/lvgl/lvgl/blob/1918a999d700ef195a53a73f8765a353e74dc07e/.github/workflows/makefiles_uefi.yml#L22), and [perf_tests.yml](https://github.com/lvgl/lvgl/blob/1918a999d700ef195a53a73f8765a353e74dc07e/.github/workflows/perf_tests.yml#L29).

These are valid matches for FUSE's documented rule definition, not confirmed security incidents. Pinning reviewed action revisions to full commit SHAs would improve workflow reproducibility. This review did not assess repository permissions, action implementation code, release protections, or owner intent. FUSE's static workflow analyzer did not execute workflow code.

## Coverage and limits

- Each scan used the `generic` profile with the seven available native rules and the static GitHub Actions analyzer. No build resolution, runtime analysis, device testing, or dependency advisory lookup was performed.
- The LVGL scope is partial because three selected files exceeded the configured size limit. Its report records 3,714 unselected or unsupported inventory entries. The other reports record 6 for littlefs, 114 for FreeRTOS-Plus-TCP, and 424 for ESP-Matter. Those inventory counts do not mean each file was selected for native rule analysis.
- FUSE recorded 121 LVGL firmware filename candidates. It did not open or validate their binary contents.
- FUSE's hardware inventory reported no filename matches in these selected project scopes. This does not mean the projects have no hardware support or that their hardware is secure.
- The native rules cover a narrow set of source and configuration indicators. Zero native findings do not cover unimplemented rule areas or infer the effective product build.
- Source lines for the 16 workflow signals were reviewed at the pinned revisions. No independent reviewer or repository owner confirmed applicability or workflow controls.

The chart shows exact `FUSE-GHA-002` counts. It is an informational signal count, not a vulnerability count: [workflow signal chart](../../../site/assets/independent-transfer-signals.svg).

## Reproduction

The pinned checkout manifest and raw JSON, text, and SARIF reports are stored beside this file. With those checkouts available as a sibling directory named `fuse-scan-targets-independent-2026-11-02`, rerun the scans from the FUSE repository root:

```powershell
py scripts\run_repository_scan_pilot.py ..\fuse-scan-targets-independent-2026-11-02 `
  --manifest reports\repository-scans\independent-2026-11-02\manifest.json `
  --report-root reports\repository-scans\independent-2026-11-02\reports
```

The runner verifies each checkout against the pinned commit and rejects dirty targets. The manifest records FUSE's scanner commit and source tree hash, the repository revisions, the scopes, and the selection protocol. The scan did not tune rules during the run.
