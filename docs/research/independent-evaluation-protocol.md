# FUSE independent evaluation protocol

**Status:** protocol prepared, independent review not started.

**Purpose:** keep future field evaluation reproducible and prevent scans used for rule tuning from being described as a blind accuracy study.

## Freeze before scanning

Record the following in a dated cohort manifest before running FUSE:

- FUSE release, Git commit, source-tree digest, Python version, operating system, profile, enabled and disabled rules, report schema, and CLI options.
- Candidate projects, official repository URLs, selected commit IDs, source license metadata, inclusion rationale, and selected directory scopes.
- Excluded repositories and files, submodules, generated source, unavailable dependencies, oversized files, and any permission or licensing concern.
- The expected project population and limitations of the selection method. A purposive set of public repositories is not a representative sample.
- Whether a product comparator will be run, its exact version and rules, and the rule categories where it overlaps with FUSE.

Do not tune rules, change configurations, or edit the report schema after seeing the frozen cohort results. If a safety or correctness defect forces a change, preserve the first reports, record the deviation, and treat later runs as regression validation.

## Source handling

- Scan clean, immutable checkouts and verify each recorded commit before analysis.
- Keep source checkouts outside the FUSE repository. Store only manifests, reports, hashes, and review decisions that the source license and project policy permit.
- Record every skipped path and reason. Mark a scope partial when the scanner skipped relevant content or the project could not be inspected as planned.
- Do not publish source excerpts, secrets, personal data, build credentials, or proprietary artifacts in reports.
- A repository's public availability or API license label alone is not a legal review of every file or dependency.

## Independent review

Use two reviewers who did not author or tune the rule being assessed. Give each reviewer the same frozen finding packet and source context. Keep their labels hidden from one another and from the maintainer's preliminary notes until both reviews are submitted. Record conflicts of interest and reviewer roles.

Each reviewer records one label per finding:

| Label | Meaning |
| --- | --- |
| Supported | The cited source evidence supports the exact title and category within the rule's stated scope. This does not mean the issue is exploitable or shipped. |
| Unsupported | The cited source evidence does not support the exact claim, or the match is clearly outside the rule's stated scope. |
| Uncertain | The available source, build selection, or product context is insufficient to decide. |

For every label, record whether the file is active, illustrative, generated, or unknown; whether the relevant build or configuration selects it; whether the affected value is reachable or used; whether the evidence and title match; and what context is missing. Do not infer runtime behavior from a source-only scan.

An adjudicator reviews disagreements only after both forms are complete. Preserve both original labels, the adjudicated result, rationale, and any unresolved uncertainty. Do not overwrite reviewer disagreement with one maintainer's preferred answer.

## Review findings and no-finding samples

Review all findings if the cohort is small enough. For a larger cohort, preregister a reproducible sampling method and random seed before results are inspected. Stratify by rule and project so one high-volume rule cannot hide results from other rules.

Also sample files that received no finding. Reviewers should record whether they found an in-scope weakness that FUSE missed, with evidence and a matching rule or explicitly unsupported category. A source review of a file without findings does not prove that the file or repository is secure.

Only calculate precision from adjudicated, applicable findings and clearly state how uncertain cases were handled. Calculate recall only when the evaluation has a defensible labeled set of positive cases, including known in-scope weaknesses that were not emitted. Repository scans without ground-truth labels do not support a recall estimate. Include per-rule denominators, review coverage, unresolved cases, a suitable uncertainty interval, and selection limitations.

## Comparator study

The [2026-11-14 packet](../../reports/evaluation/2026-11-14/review/README.md) operationalizes pinned-source selection, regression-hash checks, blank independent A/B forms and adjudication. Initial NetX Duo and TinyUSB samples emitted no findings; an emitted-candidate supplement and independent human decisions remain pending. No field precision or recall is claimed.

A second tool is a comparison point, not ground truth. Pin the tool version, ruleset digest, command, and exclusions. Compare only categories where both tools have an explicit, documented check. Preserve unmatched and conflicting results for adjudication. Do not collapse product differences into a single winner score.

## Required output

Publish or archive, subject to source permissions:

1. Frozen scan manifest and source-tree digest.
2. Original JSON, text, and SARIF reports with hashes and complete/partial status.
3. Independent reviewer forms, conflict notes, and adjudication log.
4. Per-rule evidence tables with denominators, uncertain cases, and no-finding sample results.
5. Limitations, exclusions, source permission status, and deviations from the protocol.

Until independent reviewers and adjudication are complete, label scan summaries as preliminary static signals. Do not report field precision, recall, or a universal security score.
