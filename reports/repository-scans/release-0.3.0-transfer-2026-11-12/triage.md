# Manual source review

This review covers only the three FUSE 0.3.0 findings in the pinned source scopes recorded in [`manifest.json`](manifest.json). Values that resemble secrets are redacted in FUSE reports and are not reproduced here.

| Finding | Source context | Review disposition |
| --- | --- | --- |
| RT-Thread `FUSE001`, medium severity, high confidence | [`components/finsh/shell.h:47`](https://github.com/RT-Thread/rt-thread/blob/cbc19778d0ae5ef2533a28c0f62c6a399858010a/components/finsh/shell.h#L47) defines a non-empty fallback value for the shell password. The implementation passes that value to `finsh_set_password` only under `FINSH_USING_AUTH`. | Keep as a review candidate. Check the selected product's authentication setting and effective Kconfig before deciding whether the fallback is active. The scan did not resolve a product build. |
| Meshtastic `FUSE001`, medium severity, high confidence | [`src/mesh/Default.h:79`](https://github.com/meshtastic/firmware/blob/332b5b0a2c4fec2896de3c5fa63f46d5cd05ea98/src/mesh/Default.h#L79) defines a non-empty MQTT password default. Source references copy this default into MQTT configuration. | Keep as a review candidate. Confirm whether the credential is an intentional shared public-broker default, how it is overridden, and which firmware configurations ship it. No credential validation or device test was performed. |
| Meshtastic `FUSE003`, high severity, high confidence | [`src/mqtt/MQTT.cpp:544`](https://github.com/meshtastic/firmware/blob/332b5b0a2c4fec2896de3c5fa63f46d5cd05ea98/src/mqtt/MQTT.cpp#L544) calls `setInsecure()` inside the branch used when MQTT TLS is enabled. | Keep as a review candidate. The call disables normal peer verification in the selected source path. Confirm release configuration and replace the bypass with reviewed certificate and hostname verification where that TLS path is used. |

## Noise and transfer notes

- No finding was confirmed as a false positive in this small source review. Both credential matches are defaults whose product applicability needs build and deployment context.
- ArduPilot and OpenBMC had no enabled-rule matches in the selected scopes. That is not evidence that either project is free of security issues.
- One RT-Thread source file was too large for the configured per-file limit. The report records partial native-rule coverage.
- Meshtastic's selected source scan completed, but its PlatformIO context is partial. FUSE hit the `extra_configs` path-match limit and could not resolve several inherited environment names. This is a concrete area to improve the metadata inspector and its tests.
- No ground-truth vulnerability set or project test suite was run, so missed checks cannot be counted. Dependency advisories, history secrets, firmware signatures, Ghidra analysis, and physical behavior were outside this scan.

Use these observations to propose fixture-backed refinements. Do not turn a source-context candidate into a confirmed vulnerability without validating the relevant build and runtime conditions.
