# Initial triage notes

These notes describe patterns reviewed in the pilot. They are not a complete manual adjudication of all 1,663 signals. A FUSE finding remains a static signal until the affected code, build configuration, target, and release path are reviewed.

## Contextual false positives and review patterns

- **FUSE001 credential-like literals:** 193 of Tasmota's 205 FUSE001 signals are in `tasmota/language/` headers. They are localized UI labels such as password prompts, not credential values. All six ESPHome FUSE001 matches are in `scripts/review-made-for-esphome.test.ts`, where test cases intentionally contain password-shaped inputs. This demonstrates that name matching needs source context and better test and localization handling.
- **FUSE002 private-key markers:** the nine ESP-IDF OTA matches and three Pico matches are in example, test-certificate, or secure-boot sample paths. FUSE redacted private-key material in the reports. These paths need build and packaging context before any claim about a deployed device.
- **FUSE003 TLS bypass indicators:** the ESP-IDF MQTT match is in `pytest_mqtt_ssl.py`. Tasmota's ten matches are in optional driver or library code. The source contains explicit bypass indicators, but the scan does not establish that a product build includes or calls them.
- **FUSE004 HTTP strings:** this is the largest noise source, with 1,422 matches. The five Arduino matches include tutorial URLs in sketch comments. The ESPHome matches are in URL unit tests. OpenWrt and IoTGoat include package source URLs, device-tree schema identifiers, and upstream source comments. Tasmota's 1,377 matches cluster heavily in vendored libraries and PlatformIO environment files. These may be documentation, build-time source locations, or optional code, rather than a device runtime endpoint. Some build-time HTTP source URLs may merit a separate supply-chain check.
- **Overlapping sources:** IoTGoat contains an older OpenWrt source tree. Several source matches also occur in the OpenWrt scan. The raw aggregate counts both snapshots.

## Coverage gaps exposed by the run

- No FUSE005 result appeared, even in MQTT-focused examples. The current rule recognizes `mqtt://` URIs; it does not establish whether a broker assembled from a hostname, port, and separate TLS settings is encrypted.
- No FUSE006 or FUSE007 result appeared. These rules check two explicit ESP-IDF configuration settings. The scan does not resolve the effective configuration selected by a release build.
- The Zephyr MQTT sample scope returned no signals across 30 files. This is limited source coverage, not a security verdict.
- The intentionally insecure IoTGoat snapshot returned 30 signals, mostly FUSE004 URL matches. This pilot did not map every IoTGoat challenge to a FUSE rule, and the current seven rules do not assess many insecure defaults, web issues, debug exposure, or runtime behavior.
- Three files were skipped: one non-UTF-8 file and two files above the 2 MiB limit. Unsupported file types, binary firmware contents, dependency advisories, and effective build configuration were not analyzed.

## Refinements to consider before PyPI claims

1. Make FUSE004 distinguish runtime endpoint configuration from comments, documentation, schema identifiers, build downloads, and vendor code. Keep any source-download transport check separate and named for that scope.
2. Reduce FUSE001 matches on localization labels, test inputs, file paths, and credential-name constants without weakening real literal detection. Add paired fixtures for each context.
3. Add source and configuration context to FUSE002 and FUSE003, especially test certificates, sample signing keys, optional code, and release build inclusion.
4. Extend MQTT analysis beyond URI literals to supported framework configuration shapes, while reporting when host, port, or TLS context is incomplete.
5. Treat missing effective configuration, ignored paths, skipped files, and unsupported formats as explicit coverage states in the report.
6. Add a curated evaluation set with documented expected positives and secure controls. Do not use raw repository hit counts as a precision score.
