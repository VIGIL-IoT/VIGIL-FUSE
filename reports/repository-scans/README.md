# FUSE repository scan pilot

FUSE 0.1.0 scanned eight public embedded and IoT repository snapshots on 2026-10-26. The exact source commits and scan scopes are recorded in [`scan-manifest.json`](scan-manifest.json). Large repositories were checked out sparsely and scanned only in the listed subtrees. The other repositories used shallow snapshots.

The native FUSE rules read selected source and configuration files. No repository build, test suite, firmware image, physical board, device endpoint, Syft, OSV-Scanner, or Binwalk analysis was run.

## Aggregate coverage

| Measure | Result |
| --- | ---: |
| Repositories | 8 |
| Scan scopes | 9 |
| Supported files discovered and selected | 8,859 |
| Files scanned | 8,856 |
| Files skipped | 3 |
| Raw FUSE signals | 1,663 |

The three skipped files were one non-UTF-8 file and two files above FUSE's 2 MiB default limit. Aggregate severity labels were 23 high and 1,640 medium. These are the rule-assigned labels for static signals, not a count of confirmed vulnerabilities.

| Repository | Profile | Files scanned | Raw signals | Scope |
| --- | --- | ---: | ---: | --- |
| [OWASP/IoTGoat](https://github.com/OWASP/IoTGoat) | `embedded-linux` | 1,651 | 30 | Selected OpenWrt 18.06.2 configuration, base-files, network service, system, and target Linux paths |
| [arendst/Tasmota](https://github.com/arendst/Tasmota) | `generic` | 6,196 | 1,592 | Full shallow checkout, supported source and configuration files |
| [espressif/esp-idf](https://github.com/espressif/esp-idf) | `esp-idf` | 73 | 10 | MQTT and OTA examples, reported as two scopes |
| [esphome/devices.esphome.io](https://github.com/esphome/devices.esphome.io) | `generic` | 73 | 8 | Full shallow checkout, supported source and configuration files |
| [arduino/arduino-examples](https://github.com/arduino/arduino-examples) | `generic` | 92 | 5 | Full shallow checkout, supported source and configuration files |
| [raspberrypi/pico-examples](https://github.com/raspberrypi/pico-examples) | `generic` | 373 | 6 | Full shallow checkout, supported source and configuration files |
| [zephyrproject-rtos/zephyr](https://github.com/zephyrproject-rtos/zephyr) | `zephyr` | 30 | 0 | MQTT publisher and secure MQTT sample directories |
| [openwrt/openwrt](https://github.com/openwrt/openwrt) | `embedded-linux` | 368 | 12 | Selected base-files, network services and utilities, system, and generic target paths |

The IoTGoat and OpenWrt snapshots share OpenWrt source, so aggregate totals include repeated upstream code. Tasmota also repeats localization strings across language files. Counts are raw per-file matches and are not deduplicated across repositories.

## Rule counts

| Rule | Raw signals |
| --- | ---: |
| `FUSE001` | 218 |
| `FUSE002` | 12 |
| `FUSE003` | 11 |
| `FUSE004` | 1,422 |
| `FUSE005` | 0 |
| `FUSE006` | 0 |
| `FUSE007` | 0 |

The zero counts for FUSE005, FUSE006, and FUSE007 do not establish that a repository is secure. FUSE005 currently recognizes plaintext MQTT broker URIs, while FUSE006 and FUSE007 look for specific explicit ESP-IDF settings.

## Report files and plots

Each scan folder contains FUSE JSON, text, and SARIF reports. Report target names were normalized to repository and scope labels so this public report set does not include the local checkout path. Evidence produced by FUSE retains its secret and private-key redaction.

- [`summary.json`](summary.json) combines the pinned source metadata, file coverage, rule counts, and per-repository groups.
- [`triage.md`](triage.md) records reviewed context patterns and current detection limits.
- [`plots/findings-by-repository.svg`](plots/findings-by-repository.svg) and [`plots/findings-by-rule.svg`](plots/findings-by-rule.svg) show raw signal counts with logarithmic bar lengths and exact labels.
- The website uses the same generated data from [`site/data/repository-scan-results.json`](../../site/data/repository-scan-results.json).

Regenerate the summary, site data, and plots after changing reports with `py scripts\build_repository_scan_dashboard.py`.
