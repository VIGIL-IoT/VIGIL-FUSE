# Polyglot platform foundation

Python owns intelligence, findings, applicability, coverage, policies, RepoDNA, component
graphs, target models, analysis routing and serialization. The existing scanner remains
canonical. The new `execution_contract` and explicit `python -m vigil_fuse.execution`
handoff do not change scanner behavior or add runtime dependencies.

Go schedules disposable Kubernetes Jobs. It handles operational state and isolation;
it does not classify security evidence. Rust is reserved for demonstrated performance
bottlenecks. Java remains the existing Ghidra exporter. C/C++ remain firmware targets
and actual native adapters. Julia is numerical research and R is statistical validation.
The opt-in [Clang semantic stage](../cpp-semantic-analysis.md) now implements C++
LibTooling observations with strict Python validation and a controlled C/C++ corpus.
It does not add automatic security verdicts or a Kubernetes worker. Optional Julia experiment planning and R statistical scripts are implemented under `research/`; neither is imported by the scanner.

The initial worker is an identity probe. It echoes a target identifier and digest and
explicitly states that no target analysis occurred. It cannot emit findings or security
coverage. This proves message interchange without introducing arbitrary commands or
target mounts. Syft is the next analyzer after the probe passes live cluster validation.

The standalone cyber-physical foundation includes bounded DTS, SVD, reachability,
cFE, resilience and Renode export APIs. A future Python ModelDescription can be staged as a
bounded worker input, with observations returned to Python. Renode execution is deferred.
The interactive terminal and optional CLIUI presentation helpers are integrated. UI observes execution state;
it has no scheduling or authorization authority. Adaptive analysis is already in main.

See [execution backends](execution-backends.md), [operator](../kubernetes-operator.md),
and [native strategy](../native-engine-strategy.md).

## RTL analysis path

FUSE inventories `.v`, `.vh`, `.sv`, and `.svh` files separately from FPGA project and constraint files. It extracts bounded source structure and records candidate evidence under the normal `hardware_inventory.rtl_analysis` report object. Python assigns finding severity, confidence, applicability, and remediation. A debug, test, scan, or JTAG name by itself is an inventory observation, not a vulnerability.

The optional Verible syntax tool can provide structured tokens for source extraction. If it is absent or cannot parse a file, FUSE uses its built-in structural token parser. Neither backend elaborates a complete project. Literal Yosys `read_verilog` references can mark a present file `BUILD_INCLUDED`; otherwise the file remains `PRESENT`. The latter does not mean excluded.

This path does not perform formal verification, gate-level proof, timing analysis, physical FPGA validation, or runtime validation. It does not claim that a selected source was programmed into a device, is reachable, or is physically exposed. See the [RTL analysis guide](../rtl-security-analysis.md) for evidence categories and backend limits.

## Optional Julia research

FUSE's existing Python scanner remains authoritative for findings and policy. Julia is an optional, disconnected research environment, not a normal scan dependency. It explores optimization and experiment-selection strategies and does not generate production security verdicts. Its recommendations require Python policy validation before any future analysis router could act on them. No integration is implemented here.

The proposed division of responsibilities is Python for security intelligence and policy, Go for orchestration, C++ for semantic C/C++ analysis, C for firmware validation targets, Rust for optional measured acceleration, R for statistical validation, Julia for numerical research and experiment optimization, and Java for the Ghidra bridge. This describes architectural roles, not a claim that every proposed component currently exists.
