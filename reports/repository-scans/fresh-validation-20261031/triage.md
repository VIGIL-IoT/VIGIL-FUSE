# Manual source-context triage

This review covers the initial 5 signals and the 3 signals retained after the FUSE001 refinement. It inspected source context at each reported location in the pinned checkout. It did not build the projects, resolve effective configuration, validate credentials, inspect physical devices, or test deployed firmware. Values remain redacted in the scan artifacts and are not repeated here.

This is a single source-context review by the project maintainer. It is not independent adjudication, a precision estimate, or an accuracy benchmark. The initial scan was selected and recorded before rule tuning. After the observed false-positive patterns informed a rule change, this cohort became a regression-validation set.

## Triage summary

| Snapshot | Signals | Location | Disposition | Review note |
| --- | ---: | --- | --- | --- |
| Initial | 1 | Meshtastic `src/mesh/Default.h:79` | `review-required-candidate` | A default MQTT password literal is present. Its validity, whether it is a public service default, and whether a selected product build uses it were not established. |
| Initial | 1 | Meshtastic `src/mqtt/MQTT.cpp:544` | `conditional-transport-review` | The TLS client calls `setInsecure()` inside a branch guarded by the MQTT TLS setting. Effective configuration and release reachability were not checked. |
| Initial | 1 | RT-Thread `components/finsh/shell.h:47` | `conditional-default-credential-review` | A fallback value is assigned to `FINSH_DEFAULT_PASSWORD` inside the `FINSH_USING_AUTH` guard. The effective build configuration and downstream overrides are unknown. |
| Initial | 1 | Meshtastic `src/modules/AdminModule.cpp:92` | `false-positive-reserved-sentinel` | Nearby source comments describe this as a reserved marker used to preserve non-shareable strings. It is not a credential value. This signal is removed by the reserved-marker name filter. |
| Initial | 1 | Meshtastic `src/security/EncryptedStorage.cpp:35` | `false-positive-filename-constant` | `TOKEN_FILENAME` names an unlock-token file. The assigned value is a filename, not token material. This signal is removed by the filename suffix filter. |

ArduPilot and OpenBMC had no native-rule findings in their selected scopes. This does not establish that either repository is secure. After refinement, the two candidate password literals and the conditional TLS signal remain. Their severity and confidence fields remain separate in the FUSE reports.

## Coverage limitations

- RT-Thread has 2,127 selected files and 2,126 scanned files. One file exceeded the configured per-file size limit, so its report is partial.
- Meshtastic's bounded PlatformIO adapter found 22 environment declarations and 32 configuration files. Its `extra_configs` path match limit was reached, so inherited settings are incomplete. No PlatformIO commands or builds ran.
- The RT-Thread filename-only firmware inventory found six `.bin` files under lwIP fuzz-input paths. These are packet-test inputs, not firmware images. The scanner did not inspect their contents.
- No hardware design files were present in the selected scopes. The scopes do not cover each repository in full.
- The scans used the generic or embedded-Linux source profiles and the seven current native rules. They did not run external analyzers, query vulnerability databases, execute project code, or validate device behavior.

## Interpretation

The FUSE001 change is supported by two source-context examples and regression fixtures for the excluded filename and reserved-marker names. Its before-and-after result is 5 to 3 signals on these same four scopes. The cohort now serves as a regression set. Do not use the reduction as a claim about precision or field accuracy. New blind samples and independent adjudication are still needed for that.
