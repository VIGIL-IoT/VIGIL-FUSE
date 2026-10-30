# Public repository scan evaluation, October 2026

## Study type and question

This is a descriptive, observational engineering evaluation of FUSE's selected static checks on pinned public embedded and IoT repositories. It is not a controlled experiment and does not measure the prevalence of vulnerabilities.

**Question:** What candidate signals and coverage limits do the current FUSE rules report on a documented set of embedded repositories and scopes?

## Hypothesis

The study did not preregister a statistical hypothesis. The operational expectation was that pinned inputs and explicit scope settings would make scan output repeatable enough for manual triage and rule regression review.

## Setup

- FUSE version recorded by the report: `0.2.0`.
- Snapshot date: 2026-10-28.
- Dataset: 14 public repositories, 15 configured scopes, each pinned to a commit and profile in `reports/repository-scans/scan-manifest.json`.
- Hardware: no physical board used.
- Software: Python CLI, native rules, and the configured local profiles. The report states that optional external dependency and binary analyzers were not invoked for this corpus.
- Procedure: the repository runner validates checkout revision and cleanliness, then scans the configured scope and emits text, JSON, and SARIF results. Manual triage records context and candidate false positives.
- Repetitions: one scan per configured scope in this snapshot. Later snapshots are tracked as separate regression or holdout records, not repeated trials of an unchanged experiment.

## Variables and measurements

The observed inputs are repository commit, profile, include/exclude scope, FUSE rule version, file limits, and available selected metadata. Recorded outputs include files discovered, selected, scanned, or skipped; rule matches by severity and repository; hardware filename matches; and per-stage coverage.

The snapshot README reports 18,999 supported files discovered, 18,859 selected, 18,855 scanned, four skipped, 61 raw static signals, and 28 hardware filename matches. Three scopes are partial. The values are descriptive counts for these pinned inputs only.

## Interpretation

The scan demonstrates that FUSE can apply its configured rules across the documented snapshots and preserve coverage information. It does not prove any signal is exploitable or included in a released product. A zero-signal scope does not demonstrate that a repository is secure. Signal counts can change with rule versions, scopes, generated files, repository commits, and build context.

The later repository README documents the rule-level changes, counts, and triage limits. The holdout cohort is separately stored. Because later rule refinement used observed corpus examples, the refined corpus is regression evidence, not an untouched blind holdout.

## Statistical analysis

No inferential statistical analysis was performed. The number and selection of repositories are not representative enough for prevalence estimates. Repositories and scopes can overlap, including vendored or shared source.

## Failure cases and threats to validity

- Four selected files were skipped because of encoding or size limits.
- Three scopes were marked partial.
- Broad repositories were scanned with selected profiles and scopes, not full builds.
- Static rules cannot resolve all target selection, reachability, preprocessing, or deployment state.
- Manual triage can be incomplete or reviewer-dependent.
- Repository selection favors known embedded projects and is not random.
- Public repository contents and upstream commits change over time; the manifest pins the examined versions.
- The scan did not use hardware, execute project builds, or validate device behavior.

## Reproduction and evidence

See [repository scan report](../../reports/repository-scans/README.md), [manifest](../../reports/repository-scans/scan-manifest.json), [triage notes](../../reports/repository-scans/triage.md), and [scan runner](../../scripts/run_repository_scan_pilot.py). To reproduce, provide checkouts at the exact manifest commits and run the documented command in the report README.
