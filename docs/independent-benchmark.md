# Independent deep-engine benchmark program

This program evaluates externally supplied labels, including findings and non-findings.
Authored FUSE fixtures test contracts and regressions, not detector accuracy. The existing
[independent evaluation protocol](research/independent-evaluation-protocol.md) still governs
blind human field reviews. An official benchmark label is not a substitute for those reviews.

## Freeze and prepare

Freeze the analyzer commit, versions, configuration and rule bundle before reading evaluation
results. Do not tune on held-out labels. Record later corrections as protocol deviations and
preserve the original results. A corpus reused for tuning must move to the regression split.

The initial external corpus is [OWASP Benchmark Java](https://github.com/OWASP-Benchmark/BenchmarkJava),
revision `10dfcc54ad02dcfcb358b0ba4a0fef8c919a6d17`. All 2740 official Java 1.2 label rows are
included, without selection by scanner outcome. Its upstream GPL-2.0 license applies to
source material. Source remains in a separate checkout and is not redistributed here.

Create an external checkout, using LF text bytes for portable artifact hashes:

```text
git clone --no-checkout --filter=blob:none --config core.autocrlf=false --config core.eol=lf https://github.com/OWASP-Benchmark/BenchmarkJava.git OWASP-BenchmarkJava
git -C OWASP-BenchmarkJava sparse-checkout set src/main/java/org/owasp/benchmark/testcode
git -C OWASP-BenchmarkJava -c core.autocrlf=false -c core.eol=lf checkout 10dfcc54ad02dcfcb358b0ba4a0fef8c919a6d17
git -C OWASP-BenchmarkJava rev-parse HEAD
git -C OWASP-BenchmarkJava status --porcelain
```

Verify the exact revision and selected source bytes before scanning. The recorded ground
truth SHA-256 is `1809f6a690c6cf7dd6685df6ebe2eef8fe3ca93d19a7ca0ce45987ca4f5d78e1`.
Some Windows checkout environments override line endings. The initial measured snapshot
was materialized from pinned Git blobs through binary pipes to guarantee committed bytes.
If a checkout has different bytes, preparation records different hashes; never relabel a
different input as the published snapshot. Preserve the upstream license alongside inputs.

```text
python -m vigil_fuse.deep_evidence benchmark-prepare OWASP-BenchmarkJava --revision 10dfcc54ad02dcfcb358b0ba4a0fef8c919a6d17 --analysis-commit 3304e2656a018488994695fa4ddd46cc3243d14d --output manifest.json
python -m vigil_fuse.deep_evidence benchmark-transfer manifest.json OWASP-BenchmarkJava --output predictions.json
python -m vigil_fuse.deep_evidence benchmark-evaluate manifest.json predictions.json --output results.json
```

Preparation reads a local corpus; it does not download, compile or run target code. The
manifest records the revision, license, label digest, every source-file digest, selection,
split and frozen analyzer identity. The native fingerprint covers rule modules and the
model, normalizing only Python source line endings. The transfer runner rejects changed
analyzer or corpus bytes and bounds individual files, total bytes, repeats and elapsed time.
It runs existing native rules unchanged and retains their emitted fingerprints without
source snippets. It does not implement or simulate Java semantic analysis.

## Predictions and review

`independent_benchmark.evaluate(manifest, predictions)` accepts independent corpora using
the strict version 1.0 manifest and prediction envelopes. See the API and
`tests/test_independent_benchmark.py` for executable envelope examples. The corpus declares
its external label source and provenance; the evaluator validates that declaration and
hash binding, not the authenticity of an arbitrary third-party label provider.

Each case names its capability, metric, source digest, label reference and truth state:
POSITIVE, NEGATIVE, UNKNOWN or UNREVIEWED. Each prediction names a case, state and artifact
references. Missing predictions become UNKNOWN. Definitive predictions require a covered
analysis and evidence references. Negative predictions additionally require completed
coverage; partial, unsupported, unavailable or failed analysis cannot establish absence.
Every case remains in the output, including non-findings and unresolved cases.

TP, FP, TN and FN are computed only from resolved positive/negative labels and predictions.
UNKNOWN and UNREVIEWED never enter those counts. Whole-population precision, recall, F1,
FP/FN rates and accuracy remain null when any case in that metric is unresolved. Conditional
resolved-subset diagnostics are clearly named. Report review coverage and unknown rate
alongside every metric. Do not present conditional metrics as whole-population performance.

The following capability-specific label dimensions are supported:

| Capability | Independent label dimensions |
| --- | --- |
| Semantic SAST | Vulnerability detection, reviewed path validity |
| Dependency reachability | Package identity, symbol identification, call-path correctness |
| Firmware | Expected extraction entries, package identification |
| Cross-layer | Edge correctness, whether a claim is warranted, unknown-state preservation |
| Native SAST | In-scope native detector labels, separate from semantic analysis |

For path validity, label each reviewed path as correct or incorrect. For extraction
completeness, enumerate independently expected entries and compare their presence. For
cross-layer overclaim evaluation, POSITIVE means the claim is warranted and NEGATIVE means
it is unwarranted; FP divided by resolved positive predictions measures overclaim. For
unknown preservation, POSITIVE means an expected unknown was preserved. These labels must
come from external ground truth or independent adjudication, not the correlation rule itself.
Unpopulated capability metrics remain null and do not imply tested accuracy.

Run records retain capability, metric, unique run identity, status and artifact reference.
Failure/timeout rates use completed, partial, failed and timed-out attempts as their
denominator, excluding unavailable/unsupported engines. They describe submitted attempts,
not universal operational reliability. Keep actual engine errors and exclusions in artifacts.

## Performance and initial limitations

Performance records support wall time, peak process RSS, time to first finding, cache behavior
and an artifact reference. Missing measurements remain null. The native transfer runner
measures two passes with no application cache; it does not flush or claim control of OS
caches. RSS is the process lifetime high-water mark, including interpreter and harness
overhead. Time to first finding concerns any native signal, including unscored signals.
No emitted signal leaves that measurement null, not zero. Repeated outputs must match.

The initial [measured run](../reports/deep-engine/independent-2026-11-28/README.md) exercises
the complete external corpus, provenance checks and performance collection. Native FUSE
posture rules do not supply OWASP Java source-to-sink coverage, and optional CodeQL/Joern
were not run. Semantic predictions therefore remain UNKNOWN. This run establishes no
semantic precision, recall, path-validity or exploitability result. Other deep capabilities
have no independent labeled corpus result yet. Their adapters/rules are contract-tested,
not claimed accurate from authored fixtures.

Reusing the harness for Juliet/SARD, real CVE before/after revisions, package corpora,
firmware, RTL or open hardware requires pinned sources, terms, independently justified
labels, frozen producers and complete positive/non-finding populations. Previously tuned
SARD material in this repository remains regression evidence. Independent human field
review remains pending under the existing protocol.

Validation: `python -m pytest -q tests/test_independent_benchmark.py tests/test_deep_engine_integration.py`.
