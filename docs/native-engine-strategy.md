# Native engine strategy

Decision: `NO_RUST_NEEDED_YET`.

The existing Python benchmark is the starting point for measuring synthetic source
discovery and scanning, including sampled process-tree memory. A benchmark outcome
alone does not justify a rewrite: first isolate an algorithmic hot path and compare
equivalent bounded evidence outputs. No Rust runtime or build dependency is added.

Large netlists, SVD parsing (after cyber-physical integration), firmware metadata,
graph traversal, hashing and serialization remain candidates for later profiling.
Rust may own only a measured bottleneck. Security interpretation stays in Python.
Acceleration must gracefully fall back when absent and preserve evidence semantics.

See [benchmark record](experiments/native-engine-candidate-benchmark.md).
