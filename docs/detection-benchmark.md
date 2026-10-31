# Native detection fixture benchmark

FUSE includes a small, deterministic benchmark for its seven native source rules. The dataset is the paired vulnerable and secure fixture set in [`tests/fixtures/rules/benchmark.json`](../tests/fixtures/rules/benchmark.json). It runs every native rule against every case, then counts case-level true positives, false positives, false negatives, and true negatives per rule.

Each sample records its source fixture, scanner-visible source path, expected rule IDs, expected disposition, rationale, category, split, and optional pinned commit. Current samples belong only to the synthetic development split. The framework does not yet include known vulnerable projects, independently labeled real repositories, or negative-control repositories.

Run it locally:

```powershell
python scripts/evaluate_rule_benchmark.py
python scripts/evaluate_rule_benchmark.py --json --output reports/benchmark/native-rule-fixtures.json
python scripts/evaluate_rule_benchmark.py --check
```

The evaluation unit is one rule on one fixture. A rule is considered positive for a fixture when it emits one or more findings. This makes the scorecard a check of whether the detector recognizes the labeled example, not a count of every finding line.

## Limits

This is a synthetic regression benchmark with 22 small examples. The fixture author knows the intended labels, and most rules have only a few positive examples. FUSE003 has one additional Python AST case. The results are useful for catching regressions in the fixture set. They do not estimate real-world precision or recall, measure missed vulnerabilities in arbitrary repositories, or validate applicability to a shipped product. The values must not be presented as field accuracy or independent validation.

The repository scans and manual triage under `reports/pilot-validation/` and [`reports/repository-scans/fresh-validation-next/triage.md`](../reports/repository-scans/fresh-validation-next/triage.md) remain separate evidence. They provide pinned examples and source-context dispositions, but they do not enumerate all true conditions in each repository. The 23-signal review is not independent adjudication and cannot establish recall. A future field benchmark needs independently selected snapshots, whole-scope labels or a documented sampling method, reviewer adjudication, and explicit unresolved or partial coverage accounting.

## Labeling rules

- A positive case contains the specific static condition described by its expected native rule, in a source path that rule supports.
- A negative case is intended to avoid all seven current native rule conditions.
- Findings are still static signals. Fixture labels do not establish that a condition is active, exploitable, reachable, or present in a released device image.
- Add or change a rule only with a vulnerable case and a secure case. Expand the labeled dataset when adding meaningful edge cases, especially cases based on previously observed false positives.
- Keep severity, confidence, and product applicability distinct from the benchmark label.

The `--check` mode is suitable for CI. It fails when the implemented detector disagrees with the fixture labels or when a rule has no positive example in the dataset.
