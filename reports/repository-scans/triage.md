# FUSE 0.2.0 scan triage

The latest clean-source snapshot was produced by FUSE 0.2.0 at `fe6dfd2` on 2026-10-31. It covers 14 pinned repositories and 15 scopes, scans 18,857 of 18,859 selected files, and reports 35 static signals: 18 high, 15 medium, and two informational GitHub Actions signals. Two oversized Tasmota files were skipped, so that scope is partial. These are candidate indicators, not confirmed vulnerabilities. Source paths were reviewed, but repository builds, dependency resolution, release configurations, and device behavior were not validated. The 35-signal count is not an accuracy or precision estimate.

## Latest clean-source triage, 31 October 2026

- **FUSE001 credential-like literals, 13 matches:** eleven are in Arduino-ESP32 examples and two are Tasmota Berry FTP/SSH defaults. These are concrete credential-like source literals, but FUSE does not establish whether an example is selected, a default is active, or unchanged values reach a deployed device. A preceding scan's two duplicated TinySRP matches in IoTGoat and OpenWrt were removed after source review showed `DEFAULT_PASSWD "tpasswd"` names a password database file rather than a password value.
- **FUSE002 private-key markers, 4 matches:** three are in Pico examples and one in the Pico SDK example-key tools. The files contain private-key markers, with evidence redacted in reports. Their sample/tool paths are consistent with development keys; use in a product image or release is unknown.
- **FUSE003 TLS bypass indicators, 14 matches:** five are in Arduino-ESP32 and nine are in Tasmota. They include library fallback behavior, explicit insecure examples, Trust On First Use examples, and Tasmota mail/SSLClient and Powerwall source. They remain source indicators because selected builds, call reachability, and configuration are unknown. One Tasmota `.setInsecure()` match was removed after its source was confirmed to be inside a literal inactive `#else` under `#if 1`; a regression fixture preserves that behavior while symbolic preprocessor conditions remain findings.
- **FUSE004 plaintext HTTP endpoint indicators, 2 matches:** both are in Tasmota. One is in a build helper that downloads a safeboot image; the other is an HTTP URL in the Berry Partition Wizard. The first is a build-time path, not evidence of a device runtime request. Invocation, endpoint control, integrity checks, and product inclusion remain unverified.
- **FUSE-GHA-002 floating action references, 2 informational matches:** one each in Tasmota and Arduino examples. Pinning each third-party action to a reviewed full commit SHA would improve workflow reproducibility.
- **FUSE005, FUSE006, and FUSE007, 0 matches:** no enabled rule matched MQTT URI or the selected Kconfig indicators in these scopes. This says nothing about unselected files, assembled endpoints, effective build configuration, or other security weaknesses.

The hardware inventory identifies 28 filename-matched artifacts across the corpus, 27 hardware-project files and one netlist. It only reports file presence and category. It does not parse schematics or PCB content or assess hardware security. Overall, the corpus is a bounded source/configuration scan, not a representative accuracy benchmark. The source review is not independent adjudication.

## Initial pilot signal groups

- **FUSE001 credential literals, 5 matches:** IoTGoat and OpenWrt each contain the same `DEFAULT_PASSWD` assignment in shared upstream code, so those are two reports for one source location copied into two repositories. Tasmota contains an example IR server password and Berry FTP/SSH default password assignments. The rule does not test whether values are accepted, active, or included in a product build. Secret-like values are redacted in all report formats.
- **FUSE002 private-key markers, 3 matches:** all are PEM files in Pico example paths under encrypted-boot, encrypted-hello, and Wi-Fi OTA samples. FUSE identifies the marker but does not establish how these sample keys are used or whether any product image includes them.
- **FUSE003 TLS verification bypasses, 10 matches:** six occur in Tasmota's ESP-Mail-Client and SSLClient library source; four occur in Tasmota Powerwall and scripter code. The matches are code, not comments or string literals. A source match does not prove the relevant component, build option, or execution path is enabled.
- **FUSE004 plaintext HTTP endpoints, 2 matches:** Tasmota contains a build helper that downloads a safeboot binary over HTTP and a Berry OTA-related default URL that uses HTTP. The first is a build-time download path, not a device runtime request. Both are worth checking for transport integrity and the expected server behavior.
- **FUSE005 plaintext MQTT URIs, 0 matches:** the current rule sees explicit `mqtt://` URI literals in broker or endpoint context. It does not resolve a broker assembled from host, port, framework defaults, and separate TLS settings.
- **FUSE006 and FUSE007 ESP-IDF validation settings, 0 matches:** the scanned ESP-IDF scopes were MQTT and OTA examples, not effective release configuration inputs. The scanner only matches explicit assignments in Kconfig-style filenames and does not resolve sdkconfig defaults, fragments, or build selection.

In the initial pilot, 13 high and 7 medium labels were rule-assigned severity values. Severity and confidence remain separate fields. FUSE does not verify endpoint reachability, credential validity, firmware inclusion, or exploitability.

Evaluation provenance: the older 2026-10-28 reports at `b88f23565d3c6a9cb8d38b136c55813cd2aa2aa0` used a dirty source tree and are historical. The latest reports were regenerated on 2026-10-31 from clean FUSE source commit `fe6dfd2a5353a50ba126ff49c3bf204904e090ca`. The SHA-256 fingerprint and scope, plus every pinned checkout commit, are recorded in `scan-manifest.json` so results can be tied to the exact scanner and input snapshots.

## What changed from 0.1.0

- `FUSE001` fell from 218 to 5 after excluding localization and test-only source, UI labels, path and characteristic constants, and computed string expressions. The remaining source evidence is much more specific, but weak defaults in examples can still be intentional teaching material or unused code.
- `FUSE002` fell from 12 to 3 after comment and test-path filtering. The remaining sample keys need build and packaging context before deciding whether a release artifact is affected.
- `FUSE003` fell from 11 to 10 after comment, string, and test filtering. Most remaining matches are in vendored or optional Tasmota code, so compile-path context remains a known gap.
- `FUSE004` fell from 1,422 to 2 after requiring endpoint or network-call context. One remaining URL is used by a build helper to download a firmware file, which shows that the rule can surface build-time transport risks as well as OTA-related source configuration.
- Tasmota scan coverage increased by 604 files when the generic profile added Berry `.be` source support. This exposed hardcoded FTP and SSH defaults and two HTTP safeboot URLs that were outside the old profile's coverage.

The initial raw match count fell from 1,663 to 20 while coverage expanded from 8,856 to 9,460 files. The 98.8% drop is not a measured precision rate: the match definitions changed, the new source extension added coverage, and findings have not all been adjudicated against actual product builds.

## Initial pilot coverage limits and next refinements

- Three files were skipped: one non-UTF-8 file and two files above the 2 MiB limit. Unsupported formats and binary firmware contents were not scanned by native rules.
- These runs did not build or test the target repositories and did not run Syft, OSV-Scanner, or Binwalk.
- Test, localization, comments, loopback values, placeholder hosts, and non-Kconfig filenames are filtered by rules. An indicator in one of those contexts can be missed.
- The next evaluation should add controlled secure and insecure fixtures for framework-specific MQTT construction, firmware download integrity, release configuration selection, and supported embedded scripting languages. Keep expected findings tied to explicit source contexts and record skipped or unsupported coverage.
- Validate the retained findings against build manifests and generated artifacts before describing them as product vulnerabilities.

## Initial expanded corpus snapshot before rule refinements

This pre-refinement run used the same 14 repositories and 15 scan scopes as the current manifest. The six additions were Raspberry Pi Pico SDK, Arduino-ESP32, Buildroot, OpenEmbedded Core, Meta-OpenEmbedded, and Meta-Yocto. Coverage was 18,851 scanned files out of 18,855 selected. Four files were skipped: two non-UTF-8 files and two files over the 2 MiB per-file limit. Three scopes were partial because of skipped inputs. This historical pass produced 78 raw signals: 19 high and 59 medium by rule-assigned severity. The current manifest records the pinned repository commits, selected paths, target labels, and the later FUSE source snapshot. Hardware inventory separately found 28 filename-matched artifacts: 27 hardware projects and one netlist. It does not assess their security.

The 58 signals added by the six new scans comprise 44 FUSE001, one FUSE002, five FUSE003, and eight FUSE004 matches. Several contexts show why these are review signals rather than product verdicts:

- **Pico SDK:** the PEM marker is at `tools/example_keys/private.pem`. Its name and example location suggest a sample key; FUSE does not establish whether a product image includes it.
- **Arduino-ESP32:** 50 signals occur in library examples or core code. Forty FUSE001 matches include demo credentials and hash-example inputs. Five FUSE004 matches are example URLs, including a reserved placeholder domain and a private-network example address. Five FUSE003 matches include explicit insecure examples and one `setInsecure` method implementation, which is not itself a call site. These need example/build context; the method definition is not evidence that a product invokes the bypass.
- **Buildroot:** the Gerbera account entry is under `accounts enabled="no"`. The two root-password assignments are build-time variable or `mkpasswd` expressions, not hard-coded credentials. These are FUSE001 false positives for a credential-literal claim.
- **OpenEmbedded Core:** three FUSE004 matches are in QA code and use test or placeholder endpoints. The FUSE001 match is a BitBake `SUMMARY` field whose description contains the word "password", not a credential value. These are false positives for the current rule claims.
- **Meta-OpenEmbedded and Meta-Yocto:** the selected scopes produced no findings. Meta-Yocto's selected scope is only 19 scanned files, so this is limited evidence rather than broad framework coverage.

These observations drove the fixture-backed refinements below. Example and QA paths are not excluded globally because they can contain insecure defaults users may copy.

## Historical rule-noise refinement and expanded coverage, 28 October 2026

The same 14 pinned repositories and 15 scopes were rescanned. This historical snapshot covers 18,855 scanned files out of 18,859 selected, with four skipped files and 28 filename-matched hardware artifacts. The first fixture-backed stage reduced signals from 78 to 62: 19 high and 43 medium by rule-assigned severity. A later FUSE001 string-context filter reduced that snapshot from 62 to 61: 19 high and 42 medium. The change is limited to this qualitative corpus and does not measure precision.

- FUSE001 fell from 49 to 41 in the first fixture-backed stage. It ignores the `Hello World` plaintext and hex vectors only when they occur in MD5/SHA1 builder examples, non-literal shell/build expressions, BitBake package metadata such as `SUMMARY`, and credentials nested inside XML account containers explicitly disabled with `enabled="no"`, `false`, or `0`. The later filter ignores credential assignment patterns that occur only inside source-code strings, such as a Telnet `Password:` prompt. The current main-corpus FUSE001 count is 40. Ordinary credential literals and enabled XML accounts remain detectable.
- FUSE004 fell from 10 to 2. It now filters IANA-style reserved example domains, reserved/private addresses only inside `examples` paths, OpenEmbedded `oeqa` and `selftest` paths, and local requests that explicitly verify a 301 HTTPS redirect. Private IP endpoints outside example paths are still reported.
- FUSE003 had 15 signals in this snapshot. Vendored library calls and intentionally insecure examples remained visible because source-only evidence could not establish whether the component was selected or a call was reachable. One literal inactive branch was filtered in the later clean-source refinement; other build conditions remain unresolved.

The 16-signal reduction from 78 to 62 is not a precision rate. The rule versions changed for FUSE001 and FUSE004, and the scan scope is a small pinned corpus rather than a representative benchmark. Four target-suffixed ESP-IDF defaults files are now selected and included in coverage. The 61-signal snapshot is superseded by the later clean-source reports summarized above.
