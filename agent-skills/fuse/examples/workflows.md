# Example requests

These are workflows, not fabricated results. Replace paths and review the actual plan and JSON report. Use a separate output directory for each scan.

- Python: “Scan this Python repository with FUSE and explain high-confidence findings.” Run doctor, plan and an offline scan. Report actual confidence and coverage, including unavailable tools.
- JavaScript/TypeScript: “Check this project before I push.” Inspect status and plan; scan the project without executing its scripts. Do not claim a clean bill of health for unsupported language analysis.
- Firmware: “Review this ESP-IDF project.” Plan with `--profile esp-idf`; select a build directory only when available and authorized. Distinguish selected build metadata from runtime execution.
- Hybrid: “Scan firmware and backend.” Plan the repository as a whole and report each domain's actual coverage. Do not infer hardware accessibility from source.
- PR review: “Did my changes introduce a finding?” Compare a compatible base report with the current report using `baseline create` and `baseline diff`. Do not equate a new fingerprint with confirmed exploitability.
- Fix and rescan: “Fix this finding and rerun FUSE.” Inspect the cited source, make a minimal authorized edit, rescan with the same options and compare against the saved baseline. Report unknown if the comparison is unreliable.
- Baseline: `vigil-fuse baseline create <old/findings.json> --output <baseline.json>` then `vigil-fuse baseline diff <new/findings.json> --baseline <baseline.json>`. Baseline creation can reject incomplete scans.
- Incomplete coverage: “What was not inspected?” Read the report coverage and analyzer statuses and name unavailable, failed, skipped and partial stages, limits and unknowns; do not infer coverage from a lack of findings.
