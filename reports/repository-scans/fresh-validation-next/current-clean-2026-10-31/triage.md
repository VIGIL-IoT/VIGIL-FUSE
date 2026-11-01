# Triage for the clean-source repeat

## Scope

This file reviews the three finding IDs present in the clean-source repeat but absent from the earlier post-refinement report. The comparison is between stored reports from FUSE schema 1.6 and 1.10. The older scanner source was dirty and not archived. These added IDs therefore do not establish that a detector improved or that the earlier scan would have produced different results with a recoverable source tree.

All three signals have candidate applicability and static, not-validated status. Confidence describes the observed pattern. It does not establish product exposure or exploitability.

## Review table

| Finding | Location | Severity and confidence | Disposition |
| --- | --- | --- | --- |
| `FUSE006:examples/bluetooth/ble_adv/bthome/dimmer/sdkconfig.defaults.esp32h4:2` | ESP-IoT-Solution, target-specific ESP32-H4 defaults | Medium severity, high confidence that the setting is explicitly enabled | `candidate-example-configuration` |
| `FUSE-GHA-002:.github/workflows/issue_comment.yml:17` | ESP-IoT-Solution, issue-comment workflow | Informational severity, high confidence that the action reference names a floating branch | `floating-ref-review` |
| `FUSE-GHA-002:.github/workflows/upload_component.yml:12` | ESP-IoT-Solution, component upload workflow | Informational severity, high confidence that the action reference names a floating branch | `floating-ref-review` |

## Finding notes

### ESP-IDF image validation setting

The target-specific defaults file sets `CONFIG_BOOTLOADER_SKIP_VALIDATE_ALWAYS=y`. FUSE reports the literal configuration and its documented security relevance. The file is an ESP32-H4-specific example default. This review did not establish that the example is built, that this defaults file is selected, that the effective Kconfig result retains the setting, or that a resulting image is released. Review the effective release `sdkconfig` and bootloader configuration before deciding whether remediation is needed. The signal is not evidence that a deployed product skips image validation.

### Floating action reference in an issue-comment workflow

The workflow is triggered by `issue_comment` and uses `espressif/github-actions/sync_issues_to_jira@master`. It passes Jira-related secrets to the action. A mutable branch reference weakens review and repeatability, so the reference and action permissions merit owner review. This scan did not inspect the action implementation, establish an unsafe behavior, or show that secrets were exposed. Pin a reviewed full commit SHA and assess the action's permissions and secret handling.

### Floating checkout reference in a component upload workflow

The workflow runs on pushes to its `master` branch and uses `actions/checkout@master`. The rule reports the mutable reference, not a confirmed compromise or an unsafe checkout result. Pin a verified full commit SHA and track updates through reviewed dependency changes.

## Limits

This is a single manual source-context review of the added signals. It does not analyze complete workflow reachability or permissions, execute actions, determine ESP-IDF configuration selection, build target projects, verify released artifacts, or validate physical devices. The finding JSON preserves the scanner's severity, confidence, applicability, validation status, location, and remediation context.
