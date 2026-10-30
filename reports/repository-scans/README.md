# FUSE repository scan corpus

## Current snapshot

On 2026-10-31, FUSE 0.2.0 scanned 14 pinned public repositories across 15 configured scopes at commit `2e50a6e`. The corpus includes selected component and example scopes as well as broad source/configuration scans. Each input commit and scope is recorded in [`scan-manifest.json`](scan-manifest.json).

These are raw static indicators, not confirmed vulnerabilities. Severity represents potential impact and confidence is a separate field on each finding. No repository was built, no project test suite was run, no firmware image or physical board was analyzed, and no external dependency or binary-analysis tools were invoked.

| Measure | Result |
| --- | ---: |
| Repositories | 14 |
| Scan scopes | 15 |
| Supported files discovered | 18,999 |
| Files selected by scope | 18,859 |
| Files scanned | 18,857 |
| Files skipped after selection | 2 |
| Raw FUSE signals | 38 |
| High severity signals | 19 |
| Medium severity signals | 17 |
| Informational GitHub Actions signals | 2 |
| Hardware filename matches | 28 |

Two selected Tasmota files exceeded FUSE's 2 MiB per-file limit, so that report is partial. Other scopes completed. A scan with zero signals means no enabled rule matched within the selected scope. It does not establish that the repository is secure.

| Repository | Profile | Files scanned | Signals | Status |
| --- | --- | ---: | ---: | --- |
| [OWASP/IoTGoat](https://github.com/OWASP/IoTGoat) | `embedded-linux` | 1,652 | 1 | Complete |
| [arendst/Tasmota](https://github.com/arendst/Tasmota) | `generic` | 6,800 | 15 | Partial |
| [espressif/esp-idf](https://github.com/espressif/esp-idf) | `esp-idf` | 73 | 0 | Complete, 2 scopes |
| [esphome/devices.esphome.io](https://github.com/esphome/devices.esphome.io) | `generic` | 73 | 0 | Complete |
| [arduino/arduino-examples](https://github.com/arduino/arduino-examples) | `generic` | 92 | 0 | Complete |
| [raspberrypi/pico-examples](https://github.com/raspberrypi/pico-examples) | `generic` | 373 | 3 | Complete |
| [zephyrproject-rtos/zephyr](https://github.com/zephyrproject-rtos/zephyr) | `zephyr` | 30 | 0 | Complete |
| [openwrt/openwrt](https://github.com/openwrt/openwrt) | `embedded-linux` | 368 | 1 | Complete |
| [raspberrypi/pico-sdk](https://github.com/raspberrypi/pico-sdk) | `generic` | 772 | 1 | Complete |
| [espressif/arduino-esp32](https://github.com/espressif/arduino-esp32) | `generic` | 1,778 | 16 | Complete |
| [buildroot/buildroot](https://github.com/buildroot/buildroot) | `embedded-linux` | 4,821 | 0 | Complete |
| [openembedded/openembedded-core](https://github.com/openembedded/openembedded-core) | `embedded-linux` | 819 | 0 | Complete |
| [openembedded/meta-openembedded](https://github.com/openembedded/meta-openembedded) | `embedded-linux` | 1,183 | 0 | Complete |
| [yoctoproject/meta-yocto](https://github.com/yoctoproject/meta-yocto) | `embedded-linux` | 19 | 0 | Complete |

The Yocto layer scope is intentionally small and is not representative of the entire Yocto ecosystem. IoTGoat includes selected vendored OpenWrt paths, so its source overlaps with the separate OpenWrt snapshot. Aggregate counts are not deduplicated by source identity.

## Current rule counts

| Rule | Signals | Interpretation |
| --- | ---: | --- |
| `FUSE001` | 15 | Credential-like literal assignments after filtering placeholders, tutorial hash inputs, computed values, BitBake metadata, disabled XML accounts, and filename or reserved-marker constants. |
| `FUSE002` | 4 | Private-key PEM markers. Some matches may be intentional sample keys. |
| `FUSE003` | 15 | TLS peer verification appears disabled. Matches include library and example code; no build reachability is established. |
| `FUSE004` | 2 | Non-loopback HTTP endpoints retained in Tasmota build and OTA contexts. Reserved test hosts, QA paths, and explicit HTTPS redirect probes are filtered. |
| `FUSE005` | 0 | No MQTT-related endpoint indicators matched in these scopes. |
| `FUSE006` | 0 | No insecure Kconfig indicators matched in these scopes. |
| `FUSE007` | 0 | No debug Kconfig indicators matched in these scopes. |

Two additional `FUSE-GHA-002` informational signals identify GitHub Action references that use floating branches. They are separate from the seven native rules above.

## Current source refresh, 2026-10-31

The previous 61-signal summary was produced at commit `b88f235` with `source_tree_dirty=true`. The current 38-signal summary uses a clean FUSE source snapshot at `2e50a6e`. The 23-signal difference reflects code and input-handling changes made between those snapshots. It is not an accuracy or precision measurement. In particular, 25 earlier FUSE001 matches in Arduino and Tasmota examples are now filtered by the existing common-example-placeholder check. The new [`2026-10-31 transfer cohort`](fresh-validation-20261031/README.md) separately documents the narrow filename and reserved-marker refinement and its two-match regression comparison.

Hardware inventory found 28 filename-matched artifacts: 27 hardware project files and one netlist. The inventory reports file presence and category only. It does not parse schematics or PCB design content and does not make a hardware security assessment.

See [`triage.md`](triage.md) for path-level context, false-positive candidates, and remaining precision limits. The latest rule changes were limited to contexts supported by pinned-source evidence and fixture coverage.

The four-repository validation corpus is stored separately in [`holdout/`](holdout/). Its first snapshot was held out from rule tuning; the later regression pass used those observations to refine rules. Neither pass is mixed into this training-corpus summary or the website dashboard, and the current corpus is not a blind accuracy benchmark.

The separate [2026-10-31 fresh transfer cohort](fresh-validation-20261031/README.md) covers four additional pinned scopes. Its initial snapshot and post-refinement regression reports remain outside this training summary and website dashboard. The before-and-after reduction from 5 to 3 raw signals is a qualitative regression comparison, not an accuracy score.

## Historical noise-reduction baseline

The 2026-10-26 pilot covered the first eight repositories and nine scopes. Its 0.1.0 run reported 1,663 raw signals. FUSE 0.2.0 reduced that same initial corpus to 20 signals while adding 604 Tasmota Berry files. This is a useful rule-noise comparison, not a precision score. The expanded 14-repository corpus initially had 78 signals; fixture-backed refinements first reduced it to 62, and a later FUSE001 refinement brought the current snapshot to 61 without changing the pinned scope.

| Rule | FUSE 0.1.0 initial corpus | FUSE 0.2.0 initial corpus | Main refinement |
| --- | ---: | ---: | --- |
| `FUSE001` | 218 | 5 | Excluded localization and test source, UI labels, path/characteristic constants, and computed token expressions |
| `FUSE002` | 12 | 3 | Excluded comment markers and recognized test-only paths |
| `FUSE003` | 11 | 10 | Excluded comments, strings, and recognized test-only paths |
| `FUSE004` | 1,422 | 2 | Required endpoint or network-call context; ignored comments, tests, loopback, and placeholder hosts |
| `FUSE005` | 0 | 0 | Required broker or endpoint context and ignored comments, tests, loopback, and placeholder hosts |
| `FUSE006` | 0 | 0 | Scoped matches to Kconfig-style input filenames and ignored comments and test-only paths |
| `FUSE007` | 0 | 0 | Scoped matches to Kconfig-style input filenames and ignored comments and test-only paths |

## Earlier refinement-stage snapshot

An earlier refinement-stage snapshot of the same 14 pinned repositories and 15 scopes covered 18,855 files, with four skipped files and 28 hardware filename matches. Four target-suffixed ESP-IDF defaults files were added to selected coverage; the signal count remained 61. The first fixture-backed stage reduced signals from 78 to 62: FUSE001 decreased from 49 to 41 and FUSE004 from 10 to 2. A later FUSE001 string-context filter reduced that rule from 41 to 40 and the aggregate from 62 to 61, with 19 high and 42 medium signals. That comparison measures changed matches in its pinned snapshot, not precision or general detection accuracy. The clean-source refresh above supersedes its summary counts.

- FUSE001 now ignores `Hello World` and its hex encoding only in MD5/SHA1 builder examples, shell/build expressions, BitBake metadata assignments, and accounts inside XML containers explicitly disabled with `enabled="no"` or an equivalent value. Positive fixtures retain ordinary hard-coded credentials and enabled XML accounts.
- FUSE004 ignores standard reserved example domains, reserved/private IPs only when used in example paths, recognized OpenEmbedded QA/self-test paths, and requests whose local code explicitly checks for an HTTPS redirect. Private network endpoints outside example paths and real non-test endpoints remain eligible.
- FUSE003 remains at 15 signals. Matches in library and example code need target/build reachability context before FUSE can decide whether they apply to a product. The rule does not claim those paths are enabled or invoked.

## Artifacts and reproduction

- [`scan-manifest.json`](scan-manifest.json) records pinned commits, profiles, and reproducible include scopes.
- [`summary.json`](summary.json) contains aggregate coverage, rule counts, hardware inventory, and per-repository findings.
- Each scope directory contains JSON, text, and SARIF reports. Secret-like evidence is redacted in reports.
- [`plots/findings-by-repository.svg`](plots/findings-by-repository.svg) and [`plots/findings-by-rule.svg`](plots/findings-by-rule.svg) show exact raw counts.
- The website reads the generated snapshot from [`site/data/repository-scan-results.json`](../../site/data/repository-scan-results.json).

Run all pinned scopes with:

```powershell
py scripts\run_repository_scan_pilot.py ..\fuse-scan-targets
```

Pass `--repository <id>` to scan one repository, and repeat the option for additional repositories. The runner checks that each checkout matches the manifest commit and has no local changes. Regenerate the aggregate summary, website data, and plots with:

```powershell
py scripts\build_repository_scan_dashboard.py
```

To regenerate only the checked-in report summary and plots without changing generated website data or assets, run:

```powershell
py scripts\build_repository_scan_dashboard.py --report-only
```
