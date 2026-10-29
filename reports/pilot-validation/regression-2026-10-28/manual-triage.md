# Manual signal triage

Reviewed 63 raw signals at their pinned source locations.

This is a static, source-context review. It does not confirm credential validity, release inclusion, reachability, or device behavior. Severity and confidence remain separate. The CSV contains no evidence values.

| Disposition | Signals |
| --- | ---: |
| `build-transport-review` | 1 |
| `conditional-default-review` | 4 |
| `conditional-example-review` | 11 |
| `conditional-insecure-example` | 4 |
| `conditional-integration-review` | 3 |
| `conditional-ota-transport-review` | 1 |
| `conditional-tls-review` | 7 |
| `direct-library-fallback` | 1 |
| `filtered-placeholder` | 25 |
| `sample-key-review` | 4 |
| `valid-workflow-policy-signal` | 2 |

The `filtered-placeholder` rows are the matches now excluded by the fixture-backed FUSE001 refinement. Other example, library, integration, and workflow signals remain visible until target configuration or build evidence resolves applicability.
