# Native engine candidate benchmark

Decision: `NO_RUST_NEEDED_YET`.

Measured on Windows with Python 3.14.7 using the repository's existing synthetic scan
benchmark. Command from repository root:

```powershell
python scripts/benchmark_scan.py --files 128 --warmups 1 --repetitions 3 --output benchmark-polyglot.json
```

Observed input: 128 generated C files, 8,990 source bytes, zero findings. Three measured
scans after one discarded warmup yielded median wall time 1.384324 seconds, with range
1.235646 to 1.531353 seconds. Maximum sampled process-tree RSS was 62,324,736 bytes.
Reported throughput was 92.464 files/second. RSS sampling can miss short-lived peaks.

This small synthetic workload measures whole-scan overhead and source processing; it
does not isolate an algorithmic bottleneck or justify a native engine. Large netlists,
firmware metadata, graph traversal, hashing and serialization were not separately profiled.
SVD parsing belongs to the separate cyber-physical branch and was not merged to benchmark.
No Rust code is introduced based on these measurements. Larger workloads and profiling
are required before selecting any specific native acceleration task.
