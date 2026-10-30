# Changelog

## Unreleased

### Added

- Deterministic synthetic scan-performance harness with a versioned JSON report schema and a clearly scoped local baseline. The benchmark is descriptive and has no timing gate.
- Pinned repository scans now capture sampled process-tree RSS for each measured run in report schema 1.1, with the sampling interval and completeness recorded separately from scan findings.

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
