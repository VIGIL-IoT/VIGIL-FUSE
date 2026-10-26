# FUSE 0.2.0 scan triage

The 20 findings below are static signals, not confirmed vulnerabilities. Paths and evidence were reviewed, and representative source contexts were checked. Repository builds, dependency resolution, release configurations, and device behavior were not validated.

## Remaining signal groups

- **FUSE001 credential literals, 5 matches:** IoTGoat and OpenWrt each contain the same `DEFAULT_PASSWD` assignment in shared upstream code, so those are two reports for one source location copied into two repositories. Tasmota contains an example IR server password and Berry FTP/SSH default password assignments. The rule does not test whether values are accepted, active, or included in a product build. Secret-like values are redacted in all report formats.
- **FUSE002 private-key markers, 3 matches:** all are PEM files in Pico example paths under encrypted-boot, encrypted-hello, and Wi-Fi OTA samples. FUSE identifies the marker but does not establish how these sample keys are used or whether any product image includes them.
- **FUSE003 TLS verification bypasses, 10 matches:** six occur in Tasmota's ESP-Mail-Client and SSLClient library source; four occur in Tasmota Powerwall and scripter code. The matches are code, not comments or string literals. A source match does not prove the relevant component, build option, or execution path is enabled.
- **FUSE004 plaintext HTTP endpoints, 2 matches:** Tasmota contains a build helper that downloads a safeboot binary over HTTP and a Berry OTA-related default URL that uses HTTP. The first is a build-time download path, not a device runtime request. Both are worth checking for transport integrity and the expected server behavior.
- **FUSE005 plaintext MQTT URIs, 0 matches:** the current rule sees explicit `mqtt://` URI literals in broker or endpoint context. It does not resolve a broker assembled from host, port, framework defaults, and separate TLS settings.
- **FUSE006 and FUSE007 ESP-IDF validation settings, 0 matches:** the scanned ESP-IDF scopes were MQTT and OTA examples, not effective release configuration inputs. The scanner only matches explicit assignments in Kconfig-style filenames and does not resolve sdkconfig defaults, fragments, or build selection.

The 13 high and 7 medium labels are rule-assigned severity values. Severity and confidence remain separate fields. FUSE does not verify endpoint reachability, credential validity, firmware inclusion, or exploitability.

## What changed from 0.1.0

- `FUSE001` fell from 218 to 5 after excluding localization and test-only source, UI labels, path and characteristic constants, and computed string expressions. The remaining source evidence is much more specific, but weak defaults in examples can still be intentional teaching material or unused code.
- `FUSE002` fell from 12 to 3 after comment and test-path filtering. The remaining sample keys need build and packaging context before deciding whether a release artifact is affected.
- `FUSE003` fell from 11 to 10 after comment, string, and test filtering. Most remaining matches are in vendored or optional Tasmota code, so compile-path context remains a known gap.
- `FUSE004` fell from 1,422 to 2 after requiring endpoint or network-call context. One remaining URL is used by a build helper to download a firmware file, which shows that the rule can surface build-time transport risks as well as OTA-related source configuration.
- Tasmota scan coverage increased by 604 files when the generic profile added Berry `.be` source support. This exposed hardcoded FTP and SSH defaults and two HTTP safeboot URLs that were outside the old profile's coverage.

The raw match count fell from 1,663 to 20 while coverage expanded from 8,856 to 9,460 files. The 98.8% drop is not a measured precision rate: the match definitions changed, the new source extension added coverage, and findings have not all been adjudicated against actual product builds.

## Coverage limits and next refinements

- Three files were skipped: one non-UTF-8 file and two files above the 2 MiB limit. Unsupported formats and binary firmware contents were not scanned by native rules.
- These runs did not build or test the target repositories and did not run Syft, OSV-Scanner, or Binwalk.
- Test, localization, comments, loopback values, placeholder hosts, and non-Kconfig filenames are filtered by rules. An indicator in one of those contexts can be missed.
- The next evaluation should add controlled secure and insecure fixtures for framework-specific MQTT construction, firmware download integrity, release configuration selection, and supported embedded scripting languages. Keep expected findings tied to explicit source contexts and record skipped or unsupported coverage.
- Validate the retained findings against build manifests and generated artifacts before describing them as product vulnerabilities.
