# Manual triage for the second fresh validation snapshot

## Scope and provenance

This review covers the 23 raw signals in the pinned 2026-10-28 snapshot for Mynewt, Mbed TLS, OpenThread, and ESP-IoT-Solution. The repositories, commit IDs, scan scopes, and FUSE source provenance are recorded in [`manifest.json`](manifest.json) and [`summary.json`](summary.json). The source checkouts were verified clean at the manifest commits before review.

The review inspected the source context at each reported location. It did not build the projects, test configuration selection, verify credential validity, verify certificate use, or examine deployed firmware. Secret values and key material remain redacted in the scan reports and are not reproduced here. A no-finding repository is not evidence that it is secure.

This is a single manual source-context review, not independent adjudication or a benchmark. The cohort was selected before the scan, but it has since informed FUSE development and must not be described as an untouched holdout for changes guided by this review. The saved baseline and post-refinement reports are compared in the [artifact comparison record](../../../docs/experiments/validation-snapshot-artifact-comparison-2026-10-31.md). Both manifests mark the FUSE source tree dirty, and the exact source snapshots were not retained, so the reports cannot be reproduced as exact scans.

## Triage summary

| Signals | Locations | Disposition | Review note |
| ---: | --- | --- | --- |
| 5 | ESP-IoT-Solution `examples/esp_local_controller/sdkconfig.defaults:8`, `examples/mcp/mcp_client/sdkconfig.defaults:9,16`, `examples/mcp/mcp_server/sdkconfig.defaults:8`, `examples/network_provisioner/sdkconfig.defaults:9` | `review-required-candidate` | Credential-like literals occur in example configuration. Their validity and use are unknown. Keep the redacted signals for project-owner review. |
| 2 | ESP-IoT-Solution `examples/weaver/imu_gesture/sdkconfig.defaults:19`, `examples/weaver/led_light/sdkconfig.defaults:14` | `example-default-review` | Both values are obvious placeholders and have a nearby instruction to replace Wi-Fi credentials before building. They are not confirmed secrets. Retain them as candidates because an unchanged example default could still be built into a product. |
| 1 | OpenThread `src/cli/cli_tcp.hpp:222` | `review-required-candidate` | A password-like literal appears in CLI source. Its role, use, and product applicability were not established. |
| 1 | ESP-IoT-Solution `examples/bluetooth/ble_ota/rsa_key/private.pem:1` | `example-key-material-review` | A private-key PEM is present in an OTA example path. The report redacts key material. The review did not establish whether it is generated test material or used by a release build. |
| 4 | OpenThread `src/cli/cli_tcat.cpp:86,93`, `src/cli/cli_tcp.hpp:215`, `src/cli/x509_cert_key.hpp:78` | `example-key-material-review` | Private-key material is embedded in CLI or certificate-related source. It may support test or command-line flows. Production use and reuse were not established. |
| 6 | ESP-IoT-Solution `examples/ai/xiaozhi_chat/sdkconfig.defaults:6`, `examples/bluetooth/ble_adv/bthome/dimmer/sdkconfig.defaults:2`, `examples/camera/basic/sdkconfig.defaults:24`, `examples/camera/pic_server/sdkconfig.defaults:24`, `examples/camera/test_framerate/sdkconfig.defaults:24`, `examples/ulp/lp_cpu/lp_environment_sensor/sdkconfig.defaults:20` | `candidate-example-configuration` | The selected example defaults explicitly enable the setting that skips normal bootloader image validation. This is a valid configuration signal, but the review did not establish that any of these defaults are active in a release build. |
| 4 | ESP-IoT-Solution `examples/camera/basic/sdkconfig.defaults:22`, `examples/camera/pic_server/sdkconfig.defaults:22`, `examples/camera/test_framerate/sdkconfig.defaults:22`, `examples/ulp/lp_cpu/lp_environment_sensor/sdkconfig.defaults:18` | `candidate-example-configuration` | The selected example defaults explicitly enable the deep-sleep image-validation skip setting. The scan does not establish the required OTA and deep-sleep path or release applicability. |
| 0 | Mynewt and Mbed TLS selected scopes | `no-native-rule-signal` | No current native-rule findings were reported in these selected scopes. This is not a claim that either project is secure. |

The grouped rows account for 23 signals: eight FUSE001, five FUSE002, six FUSE006, and four FUSE007. No signal was confirmed as an exploitable vulnerability. The dispositions distinguish evidence in the scanned source from unknown build selection, runtime use, validity, and deployment.

## Interpretation

The two placeholder assignments were not discarded as false positives. Their comments identify them as values to replace before building, yet the corresponding config files could still influence an example build if left unchanged. This makes them useful default-review signals while leaving credential validity unknown. Other example credentials and embedded key material also remain candidate findings because source path alone cannot prove that a value is harmless or production-relevant.

The boot-validation settings are explicit configuration candidates rather than confirmed release defects. A downstream review should resolve the effective build configuration and device update path before assigning product impact. Any rule refinement prompted by this review requires new vulnerable and secure fixtures and a separate regression run.
