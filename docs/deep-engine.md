# Deep evidence engine

These research branches preserve findings as the security record. Evidence connections
never overwrite severity, confidence, applicability or validation. Presence, build
inclusion, reachability, runtime execution and physical accessibility remain separate.

## Evidence graph 1.0

Run `python -m vigil_fuse.deep_evidence graph findings.json --sbom components.cdx.json --output graph.json`.
This offline importer follows no artifact paths from the report and executes no targets.
The Python API also accepts validated Ghidra inventories, the existing bounded KiCad
topology parser, normalized build translation units and policy evidence references.
OSV findings retain package/advisory relationships and VEX assertions separately.
The report supplies RTL build candidates and hardware inventories. Unavailable artifact
contents remain unknown; a manifest reference is not an imported inventory.

`reporting.to_json(result, include_evidence_graph=True)` opts into report schema 1.14.
The default report remains 1.13, including existing baseline fingerprints and findings.
Both schemas are packaged. The graph also has its own 1.0 schema. Graph loading checks
referential integrity, deterministic identities, producer runs, duplicate keys, numeric
bounds, maximum 10000 nodes, 30000 edges and 16 MiB JSON. Exceeding limits rejects the
graph; it never silently truncates evidence. Duplicate assertions deduplicate, whereas
contradictions remain distinct. Confidence defaults to unknown, not a made-up score.

File identity includes relative path and digest when available. A missing digest is
explicitly `unknown`, scoped to the target manifest. Package identity includes PURL and
version. Firmware and binary identities use content digests. Design components, nets
and pins use design digest plus reference/name. Functions include producer namespace,
binary or source identity, and location. Node identities are target-scoped to prevent
accidental cross-project correlation. Assertion is independent of producer coverage.

Validate with `python -m pytest -q tests/test_evidence_graph.py`, `python -m ruff check
src tests scripts`, `python -m mypy`, and `python scripts/validate_docs.py`.

Branches start from the latest canonical main. Later branches cherry-pick explicit
prerequisites so they can be tested independently without merging any branch into main.
Authored fixtures verify contracts and regressions; they are not accuracy measurements.

## Semantic flow

`python -m vigil_fuse.deep_evidence semantic paths.sarif --language python --graph graph.json --output flows.json`
imports CodeQL SARIF 2.1.0 paths. CWE query tags identify the thirteen supported families;
unmapped results make coverage partial. Missing paths and failed invocations also make
coverage partial. Unsupported languages are explicit. All paths retain query identity,
locations, source, sink, sanitizer/barrier annotations and interprocedural evidence.
Feasibility always remains unknown. Sanitizers that suppress an alert are not normally
in SARIF: their absence is not proof that no sanitizer exists. Explicit call steps map
to `calls`; ordinary path steps map only to `flows_to`.

`--engine Joern` consumes the strict `fuse-joern-1.0` normalized adapter envelope. It is
an offline experimental adapter, not a bundled Joern installation or a new CPG engine.
Clang's existing source analyzer remains separate and does not gain taint semantics.

To query an existing database, use `python -m vigil_fuse.deep_evidence codeql DATABASE
QUERIES --image IMAGE@sha256:DIGEST --tool-version VERSION --authorize-query --output
paths.sarif`. The locally available image must include Python 3, CodeQL and installed
query packs. No image or query downloads are attempted. The shared `AnalyzerRequest`,
`AnalyzerResult`, `SandboxPolicy` contract denies network/devices, mounts inputs read-only,
copies the database into bounded tmpfs, and limits CPU, memory, PIDs, elapsed time,
diagnostics and artifact bytes. It removes containers after errors/timeouts. No host
fallback or database creation exists. Version supplied at invocation is an operator
assertion; the raw SARIF also records engine metadata. CodeQL licensing and tool/image
availability remain the operator's responsibility.

The invocation follows the official [CodeQL database analyze reference](https://docs.github.com/en/code-security/reference/code-scanning/codeql/codeql-cli-manual/database-analyze).
Tests: `python -m pytest -q tests/test_semantic_flow.py tests/test_evidence_graph.py`.
Live CodeQL/Joern runs require those optional engines; fixtures test import and failure
contracts without claiming live semantic accuracy.

## Dependency reachability

`python -m vigil_fuse.deep_evidence reachability graph.json request.json --calls
calls.json --advisory-symbols symbols.json --output reachability.json` combines exact
package/advisory identities, function-level metadata, build inclusion and external
CodeQL/Joern/Ghidra/Clang call evidence. All inputs are data; no dependency or target
code runs. `request.json` names graph node IDs in `package`, `advisory`, `symbols`,
`build_target`, and `entry_points`. The optional metadata adapter supplies vulnerable
symbol identities with a producer namespace and optional explicit function match.
It does not guess symbol identities from names or merge multiple package versions.

Package presence, build inclusion, symbol presence, references, static reachability,
and runtime reachability are separate states. Inclusion can be YES, NO, UNKNOWN or
CONTRADICTORY. A package-to-binary-to-function membership path establishes symbol
presence. Only direct `calls` edges establish a static entry-point path; `may_call`
remains a reference candidate. Build exclusion keeps inclusion NO even if an unused
binary contains a function. Runtime reachability remains UNKNOWN. Missing paths in
a partial graph never establish absence. Queries bound depth, path count and visits.

VEX assertions are scoped to the same package version and advisory. Conflicting VEX
and call/build evidence is reported for review. The applicability assessment is an
additional evidence statement and never rewrites existing finding verdicts.
Tests: `python -m pytest -q tests/test_dependency_reachability.py`.
