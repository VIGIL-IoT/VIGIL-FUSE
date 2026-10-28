# Fresh validation cohort triage

- **Reviewed:** 28 October 2026
- **Scanner source:** `12b2ccde23b0aad57104aabae8fe01deeecfcbbc0789256611aaaf8636b26176`
**Use:** the initial snapshot exposed an FUSE001 prompt-string false positive and was used to guide a narrowly scoped rule refinement.

FUSE scanned four pinned repositories and 5,885 selected files. It produced seven raw signals, skipped no files, and found no hardware-design filenames in the selected scopes. This is a small qualitative transfer check, not a precision or accuracy measurement.

| Repository | Rule | Observation | Triage |
| --- | --- | --- | --- |
| MicroPython | FUSE001 | `ports/cc3200/tools/update-wipy.py` checks for the literal Telnet prompt `Password:` before sending a separately supplied argument. | False positive. The prompt text is not a credential assignment. Preserve this example for future rule refinement. |
| MicroPython | FUSE003, 3 locations | `extmod/modtls_axtls.c` defines `CERT_NONE`, states that it is the only supported verification mode, and exposes it from the TLS module. | Conditional source signal. The selected code indicates that the AXTLS backend lacks certificate verification, but FUSE did not establish that a particular board enables this backend. Three locations appear to describe one behavior and may be noisy. |
| MCUboot | FUSE002, 2 locations | The PEM files are under `samples/zephyr/bad-keys/`; the directory README says they are alternate keys for testing. | Expected test material, not evidence that a production key is exposed. Keep the presence signal because accidentally packaging test keys can still matter. |
| NuttX apps | FUSE001 | `examples/pppd/pppd_main.c` assigns `user` and `pass` under the optional PAP example configuration. | Example default credentials. Treat as conditional on building and enabling that example, not as a deployed credential. |
| FreeRTOS Kernel | none | No native rule matched in the selected kernel and portable-layer scope. | No signal in this scope does not establish that the repository or products using it are secure. |

FUSE001 version 1.4.0 now ignores assignment-like patterns inside code string literals. The original reports remain unchanged under `reports/`; post-change reports are stored separately. This cohort is now a regression set, not a blind holdout. Keep it separate from the 14-repository tuning corpus and earlier regression set. Select and pin another independent cohort before evaluating future rule changes based on these observations.
