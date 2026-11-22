# Rust native engine decision

Decision: **NO_RUST_NEEDED_YET**. The measurements do not establish that a Rust implementation would provide a meaningful end-to-end gain, nor that Python optimization is insufficient. No Rust code was added.

On Windows, Python 3.14.7, FUSE main b4a4eb7, the benchmark generated synthetic inputs and measured each existing operation three times in-process. Timing excludes input generation and result serialization; CPU time, individual runs, input sizes, output counts and digests, and process peak working set are in [results](rust-native-engine-results.json). Tracemalloc is run separately, so timing excludes its overhead. Traced allocation peaks exclude native allocations; process peak working set is cumulative across the process, not an isolated per-operation peak. Discovery uses 2,000 warm-cache small files; its 22-byte benchmark descriptor is not the total corpus size (44,000 bytes). Results depend on filesystem/cache and host load. This is a synthetic microbenchmark, not field performance or an accuracy assessment.

| Operation | Workload | Median wall seconds | Peak traced bytes | Decision |
| --- | --- | ---: | ---: | --- |
| Discovery | 2,000 files | 0.302 | 2,007,673 | PYTHON_SUFFICIENT for sampled input |
| SVD parsing | 4,000 registers, 296,275 bytes | 0.060 | 2,387,697 | PYTHON_SUFFICIENT for sampled input |
| Device-tree parsing | 4,000 nodes, 269,525 bytes | 0.147 | 4,755,735 | OPTIMIZE_PYTHON_FIRST if real profiles justify |
| KiCad topology | 4,000 nets, 256,765 bytes | 0.054 | 10,618,579 | OPTIMIZE_PYTHON_FIRST if memory becomes material |
| Text rule scans | 152,000 bytes | 0.093 | 348,320 | PYTHON_SUFFICIENT for sampled input |
| SHA-256 | 296,275 bytes | 0.00024 | 137 | PYTHON_SUFFICIENT |
| Evidence serialization | 4,001 nodes | 0.0071 | 621,691 | PYTHON_SUFFICIENT |

SVD returned `partial` as designed because schema and hardware behavior are not fully validated. Device-tree output contains the root plus 4,000 generated nodes. Netlist allocation peak includes the existing bounded read buffer. The synthetic inputs have no security findings and are not representative of all real projects. Output digests were checked across three repetitions and tracing, but do not establish Rust parity. A cProfile run of the largest DTS input identified the character lexer as the main Python cost, with `startswith`, `append`, and `len` frequent; profiling overhead changes absolute runtime. No alternative Python optimization or Rust parity experiment was measured, so neither may be claimed insufficient or faster. Firmware metadata and full graph traversal remain unmeasured. The bounded samples do not establish scaling to the maximum allowed size or production throughput.

Reproduce from the repository root with the existing development dependencies:

```powershell
.\.venv\Scripts\python.exe scripts\benchmark_rust_candidates.py --output "$env:TEMP\fuse-rust-candidates.json" --profile "$env:TEMP\fuse-rust-profile.txt"
```

Use independent process RSS measurement and actual project workloads before choosing a candidate. Existing Python policy remains authoritative; no native executable, optional fallback, Kubernetes worker, or Rust CI was introduced. The external accuracy campaign was not run.
