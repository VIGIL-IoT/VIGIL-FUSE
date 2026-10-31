# Changelog

## Unreleased

### Changed

- `FUSE001` also reports a non-placeholder literal compared with a password-like input, with positive, secure, placeholder, and prompt-name regression fixtures.
- `FUSE001` filters TinySRP's `DEFAULT_PASSWD` database filename in `tinysrp/t_pwd.h`, while retaining detection of ordinary literals in the same macro.
- `FUSE003` ignores bypass calls in literal inactive C preprocessor branches while retaining findings in unresolved symbolic branches.
- `FUSE001` ignores credential-named filename and reserved-marker constants, including camelCase names, while continuing to report credential-like default literals.
- Separate repository-scan summaries distinguish detected PlatformIO environments from selected environments, and generated plots now describe the metric they display.

### Added

- Added `FUSE-GHA-004` for a bounded allowlist of untrusted GitHub event expressions directly interpolated into step run scripts, with environment-variable and action-input controls.
- Added `FUSE-GHA-003` for an exact `pull_request_target` trigger combined with `actions/checkout` of the pull request head SHA or ref. It is a review candidate and does not claim that later steps execute the checked-out code.
- Deterministic synthetic scan-performance harness with a versioned JSON report schema and a clearly scoped local baseline. The benchmark is descriptive and has no timing gate.
- Pinned repository scans now capture sampled process-tree RSS for each measured run in report schema 1.1, with the sampling interval and completeness recorded separately from scan findings.
- CI renders Markdown Mermaid diagrams with a pinned renderer container and validates the generated SVG files.
- Added a manual Ubuntu and Windows workflow that builds upstream Binwalk v3.1.0 from a pinned commit and checks the FUSE adapter with positive and clean controls. Its Rust build does not promote upstream warnings to errors.
- Verified the Binwalk v3.1.0 adapter workflow on Ubuntu and native Windows: the synthetic gzip positive was identified, the clean control stayed clear, and neither run created extraction output.
- Repeated the pinned four-repository performance cohort across Ubuntu, Windows, and macOS, archived schema-validated reports, and documented same-day timing variability without setting a performance threshold.
- Optional analyzer timeouts and output-limit handling now attempt to terminate the analyzer and its child processes, with regression coverage for both paths.

## 0.2.0 - 2026-10-26

### Changed

- All seven native rules now report rule version `1.1.0`.
- Shared source handling removes line, block, HTML, and configuration comments before rules inspect code.
- `FUSE001` ignores localization paths, UI prompt labels, path and characteristic constants, computed string expressions, placeholders, and recognized test-only source while continuing to scan `.env.test` files.
- `FUSE002` ignores private-key markers in comments and recognized test-only paths.
- `FUSE003` checks code rather than comments or string literals and ignores recognized test-only paths.
- `FUSE004` requires endpoint-specific assignment context or a recognized network call, and ignores comments, test-only source, loopback hosts, and obvious template hosts.
- `FUSE005` requires broker or endpoint context and ignores comments, test-only source, loopback brokers, and obvious template hosts.
- `FUSE006` and `FUSE007` only inspect Kconfig-style filenames and ignore comments and test-only paths.
- The generic profile now scans Berry `.be` scripts used by embedded projects.
- The repository scan reports, aggregate plots, and landing page data are refreshed from the same eight pinned repository snapshots.

### Limits

- These filters reduce known noise but can exclude relevant indicators in localization, test, or nonstandard configuration paths.
- The scanners use lightweight source handling, not language-aware parsing or build-configuration resolution.
- Repository scan signals are not confirmed vulnerabilities and were not validated on hardware.
