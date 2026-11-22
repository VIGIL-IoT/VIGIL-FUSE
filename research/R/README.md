# R research analysis

This optional, offline research layer analyzes prepared FUSE evaluation data. **Fixtures are synthetic and do not measure real-world accuracy.** R is not used by a scan or by security verdict generation. No external evaluation is run here.

## Requirements

R 4.4.3 is the intended reference version. Only base and recommended packages shipped with R are used: `stats`, `graphics`, `grDevices`, and `utils`. There is no CRAN installation or lockfile; use that R version for comparable results. Set a consistent environment and retain the input, R version, script commit, and outputs with each study. Normal FUSE users do not need R.

## Input and preparation

The scripts accept UTF-8 CSV, one row per independent evaluation unit and configuration. Prepare this normalized dataset from versioned `findings.json`, benchmark JSON/CSV, coverage records, manual-review labels and runtime/memory measurements. **Import and reconciliation are manual in this first layer**: raw FUSE JSON is not directly parsed. Retain source artifact hashes and the mapping decisions. A findings-only list cannot supply true negatives or missed positives: define and label the entire case universe or a defensible sample, including cases without findings, before interpreting recall, false-negative rate or coverage.

Common provenance columns, retained for downstream research, are `repository`, `commit`, `fuse_version`, `finding_id`, `rule_id`, `severity`, `confidence`, `applicability`, `validation`, `ground_truth`, `reviewer`, `analyzer`, and `execution_backend`. Use separate datasets where case and measurement units differ. Record whether multiple findings are collapsed to one case and use stable IDs. Missing values are blank or `NA`.

Accuracy requires:

| Column | Meaning |
| --- | --- |
| `case_id` | Stable, unique evaluation-unit ID shared across configurations; include repository and commit in the ID when needed. |
| `configuration` | Analysis variant, such as `native-only`, `native-plus-cpp`, `native-plus-binary`, or `native-plus-hardware`. |
| `prediction` | 1 if a case produces the defined finding, 0 if it does not, blank if unresolved. |
| `ground_truth` | Independently reviewed 1 or 0, blank if unresolved. Preserve reviewer and adjudication provenance. |
| `status` | `COMPLETE`, `PARTIAL`, or `UNKNOWN` for that case's analysis scope. |

Optional `severity` and `analyzer` fields produce finding-distribution and attributed-analyzer plots. These count positive case rows, not unique vulnerabilities or causal analyzer gains. For multiple findings per case, choose and document the aggregation before analysis.

Benchmark inputs require `case_id`, `configuration`, `runtime_ms`, and `memory_mb`; numeric measurements must be nonnegative, with missing values blank. Each row is one measurement and configuration. Encode repository, input snapshot, repetition, environment and hardware in the case ID or accompanying provenance; a case ID must match across comparable runs. Record whether memory is peak process or process-tree RSS and use the same method for every configuration. `execution_backend` can record local, Docker, or Kubernetes. Different backends are not assumed to produce different security conclusions; verify their output equivalence separately.

The scripts reject duplicate case/configuration pairs. They do not reconcile findings, infer labels, establish case independence, or validate experimental design. Conflicting nonmissing ground-truth labels for the same case are rejected; ensure paired cases also share the same scope. Coverage here is the fraction of supplied rows marked COMPLETE, not necessarily repository, code, or rule coverage. COMPLETE rows with missing prediction or ground truth are excluded from accuracy metrics but remain in the coverage denominator.

## Run

From the repository root in PowerShell:

```powershell
Rscript research\R\fixtures\test_analysis.R
Rscript research\R\accuracy\analyze_accuracy.R research\R\fixtures\accuracy.csv accuracy-output
Rscript research\R\benchmarks\compare_runtime.R research\R\fixtures\runtime.csv runtime-output
```

Replace fixture inputs with prepared CSVs. Optional second arguments choose output directories; existing output filenames are overwritten. `accuracy-summary.csv` contains counts, proportions, and percentile bootstrap 95% intervals; `paired-accuracy.csv` compares correctness for matched, complete, labeled cases. Benchmark outputs summarize count, mean, median, and 95th percentile and give paired absolute differences. PDFs show precision/recall, severity distribution, coverage, paired before/after accuracy, analyzer attribution, runtime and memory when data permit. The first configuration in alphabetical order is the baseline for every comparison; name configurations accordingly and interpret the sign as comparison minus baseline. The same machinery supports tuning, ablations and execution-backend comparisons, but does not prove causality.

The paired standardized effect is mean paired difference divided by the sample standard deviation of paired differences (Cohen's dz); it is undefined for fewer than two pairs or zero variance. Bootstrap resamples rows or matched pairs 2,000 times using a fixed seed. Intervals are omitted when fewer than 95% of replicates are defined; `*_bootstrap_valid` records the count. Ratios with zero denominators are undefined, not zero. Bootstrap intervals assume independent sampling units; use a study-specific clustered or hierarchical method for correlated findings, repositories, or repeated runs. Small fixtures are only implementation checks and their intervals have no empirical meaning. These summaries do not correct for multiple comparisons or selection bias.
