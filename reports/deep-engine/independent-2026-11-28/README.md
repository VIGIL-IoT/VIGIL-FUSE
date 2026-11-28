# OWASP Java transfer measurement, 2026-11-28

This is an external-corpus transfer/performance run, not a Java semantic accuracy result.
All 2740 official OWASP Benchmark Java 1.2 labels were retained: 1415 positive and 1325
negative. No cases were selected by scanner outcome and no native detection rules changed.

| Input | Frozen identity |
| --- | --- |
| Corpus | [OWASP Benchmark Java](https://github.com/OWASP-Benchmark/BenchmarkJava/tree/10dfcc54ad02dcfcb358b0ba4a0fef8c919a6d17) |
| Corpus revision | `10dfcc54ad02dcfcb358b0ba4a0fef8c919a6d17` |
| Expected-results SHA-256 | `1809f6a690c6cf7dd6685df6ebe2eef8fe3ca93d19a7ca0ce45987ca4f5d78e1` |
| FUSE analysis freeze | `3304e2656a018488994695fa4ddd46cc3243d14d` |
| Native fingerprint | `b93bb9097e72023d27aa853fe1dbc21eb6a1e2efa6ccb05e030c317d376284b8` |
| Manifest digest | `85eeb4f0b92266510f4d58db487bbedccc645b14ec1f28b2d556d63f2223f938` |
| Environment | Python 3.14.7, Windows 11, AMD64, FUSE 0.4.1.dev0 |

The native-rule modules and model match the frozen analysis commit. The benchmark
harness itself was developed afterward. Sources were materialized from pinned Git blobs
through binary pipes, retained outside FUSE, and checked by per-file SHA-256. Upstream
source licensing is GPL-2.0; no upstream source snippets or secret values are included.

| Pass | Wall seconds | Peak process RSS bytes | Native signals | First finding |
| --- | ---: | ---: | ---: | --- |
| First | 45.5939521 | 43085824 | 0 | unknown, none emitted |
| Repeat | 47.5664453 | 43085824 | 0 | unknown, none emitted |

Native output matched across passes. There is no application cache in this runner.
The OS cache was neither flushed nor controlled; these are first/repeat passes, not
cold/warm cache claims. RSS is the process lifetime high-water mark including Python,
the evaluator and native rules. No target program, build, CodeQL query or Joern analysis ran.

Native posture rules do not implement OWASP Java semantic source-to-sink coverage.
Consequently the semantic detection result is UNKNOWN for all 2740 cases. TP, FP, TN
and FN are all zero because no case has a scored semantic prediction. Precision,
recall, F1, false-positive/negative rates and path validity remain null. Zero findings
does not establish that these known vulnerable cases are safe or absent. Other deep
capabilities have no independent accuracy result in this run. Independent human field
review and additional capability-specific corpora remain pending.

Artifacts:

- [Frozen corpus manifest](owasp-java-manifest.json), including all positive and negative labels.
- [Predictions, coverage and measurements](owasp-java-predictions.json).
- [Per-case outcomes and per-capability metrics](owasp-java-results.json).
- [Environment and native rule versions](environment.json).
- [Preparation and evaluation instructions](../../../docs/independent-benchmark.md).

The evaluator can rescore saved, provenance-bound outputs from external producers.
Unavailable analysis must stay UNKNOWN, and partial analysis cannot supply negative
predictions. These artifacts are not training data for detector changes in this task.
