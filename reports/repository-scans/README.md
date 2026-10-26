# FUSE 0.2.0 repository scan pilot

FUSE 0.2.0 rescanned the same eight pinned public embedded and IoT repository snapshots on 2026-10-26. The manifest records exact source commits and scan scopes. Tasmota coverage expanded by 604 Berry `.be` scripts, increasing total files scanned from 8,856 to 9,460. All other scan scopes and their file counts match the 0.1.0 pilot.

The initial pilot reported 1,663 raw signals. After contextual noise reductions across all seven native rules, the refreshed pilot reports 20 raw signals, a 98.8% reduction in matches while covering more files. This is not a precision score: some findings remain unreviewed in build context, and tighter filters can miss indicators in excluded paths. Counts are raw per-file matches and include repeated OpenWrt source in IoTGoat and OpenWrt.

No repository build, repository test suite, firmware image, physical board, device endpoint, Syft, OSV-Scanner, or Binwalk analysis was run. FUSE unit tests ran separately in the FUSE repository.

## Aggregate coverage

| Measure | Result |
| --- | ---: |
| Repositories | 8 |
| Scan scopes | 9 |
| Supported files discovered | 9,590 |
| Files selected | 9,463 |
| Files scanned | 9,460 |
| Files skipped | 3 |
| Raw FUSE signals | 20 |
| Rule-assigned high severity | 13 |
| Rule-assigned medium severity | 7 |

The three skipped files were one non-UTF-8 file and two files above FUSE's 2 MiB default limit. Severity labels describe potential impact, not confirmed vulnerabilities. Confidence is reported separately in each finding.

| Repository | Profile | Files scanned | Raw signals | Scope |
| --- | --- | ---: | ---: | --- |
| [OWASP/IoTGoat](https://github.com/OWASP/IoTGoat) | `embedded-linux` | 1,651 | 1 | Selected OpenWrt 18.06.2 configuration, files, package, and target paths |
| [arendst/Tasmota](https://github.com/arendst/Tasmota) | `generic` | 6,800 | 15 | Full shallow checkout, including Berry source scripts |
| [espressif/esp-idf](https://github.com/espressif/esp-idf) | `esp-idf` | 73 | 0 | MQTT and OTA examples, reported as two scopes |
| [esphome/devices.esphome.io](https://github.com/esphome/devices.esphome.io) | `generic` | 73 | 0 | Full shallow checkout, supported source and configuration files |
| [arduino/arduino-examples](https://github.com/arduino/arduino-examples) | `generic` | 92 | 0 | Full shallow checkout, supported source and configuration files |
| [raspberrypi/pico-examples](https://github.com/raspberrypi/pico-examples) | `generic` | 373 | 3 | Full shallow checkout, supported source and configuration files |
| [zephyrproject-rtos/zephyr](https://github.com/zephyrproject-rtos/zephyr) | `zephyr` | 30 | 0 | MQTT publisher and secure MQTT sample directories |
| [openwrt/openwrt](https://github.com/openwrt/openwrt) | `embedded-linux` | 368 | 1 | Selected base-files, network services and utilities, system, and generic target paths |

The IoTGoat and OpenWrt snapshots share upstream OpenWrt files, so aggregate counts include duplicate source. Signals are not deduplicated across repositories.

## Rule comparison

| Rule | FUSE 0.1.0 | FUSE 0.2.0 | Main noise reduction or scope change |
| --- | ---: | ---: | --- |
| `FUSE001` | 218 | 5 | Excluded localization and test source, UI labels, path/characteristic constants, and computed token expressions |
| `FUSE002` | 12 | 3 | Excluded comment markers and recognized test-only paths |
| `FUSE003` | 11 | 10 | Excluded comments, strings, and recognized test-only paths |
| `FUSE004` | 1,422 | 2 | Required endpoint or network-call context; ignored comments, tests, loopback, and placeholder hosts |
| `FUSE005` | 0 | 0 | Required broker or endpoint context and ignored comments, tests, loopback, and placeholder hosts |
| `FUSE006` | 0 | 0 | Scoped matches to Kconfig-style input filenames and ignored comments and test-only paths |
| `FUSE007` | 0 | 0 | Scoped matches to Kconfig-style input filenames and ignored comments and test-only paths |

The large drop in `FUSE004` reflects that the old rule matched arbitrary HTTP strings, including comments and download metadata. The two remaining matches are Tasmota safeboot image URLs: one build-time download and one Berry OTA-related default. The build-time download is a source artifact transport signal, not proof of device runtime traffic.

`FUSE005`, `FUSE006`, and `FUSE007` had no matches in either pilot. These zero counts do not show that the projects are secure. The scopes do not resolve assembled MQTT settings or the effective release `sdkconfig`.

## Reports and charts

Each scan folder contains JSON, text, and SARIF reports. Report target names are normalized to repository and scope labels, and secret or private-key material is redacted in evidence.

- [`scan-manifest.json`](scan-manifest.json) records the pinned inputs, profiles, and reproducible include globs.
- [`summary.json`](summary.json) combines input metadata, coverage, rule counts, and per-repository findings.
- [`triage.md`](triage.md) notes the remaining findings, context, and coverage limits.
- [`plots/findings-by-repository.svg`](plots/findings-by-repository.svg) and [`plots/findings-by-rule.svg`](plots/findings-by-rule.svg) show raw counts with logarithmic bar lengths and exact labels.
- The website reads the same generated snapshot from [`site/data/repository-scan-results.json`](../../site/data/repository-scan-results.json).

Run the pinned scans with `py scripts\run_repository_scan_pilot.py`. Pass `--repository <id>` to rerun one repository, and repeat the option for more. The runner refuses checkouts whose commit does not match the manifest or whose working tree has local changes. Regenerate the summary, website data, and plots with `py scripts\build_repository_scan_dashboard.py`.
