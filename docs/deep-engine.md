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

## Binary intelligence

`python -m vigil_fuse.deep_evidence binary metadata.json --graph graph.json --output
binary-graph.json` imports a strictly bounded LIEF metadata document. `--kind ghidra-calls`
imports the separate `fuse-ghidra-calls-1.0` artifact. Existing `graph --ghidra` imports
now retain API references and string-to-function references without emitting string
contents. Explicit source/binary matches use `--correspondence` with source and binary
function IDs, method and artifact reference. Names alone never establish a match.

`python -m vigil_fuse.deep_evidence binary-analyze image.elf --image IMAGE@sha256:DIGEST
--tool-version VERSION --authorize-analysis --output metadata.json` runs LIEF in the
shared sandbox. The image needs Python and LIEF. `--engine Ghidra` instead requires
Python and `analyzeHeadless` with compatible Java in the selected image. It runs the
packaged `FuseCallGraph.java` producer in a fresh, temporary Ghidra project. Direct call
references become `calls`; computed call targets become `may_call`. Unknown targets and
inventory/visit limits make coverage partial. All inputs are read-only, there is no
network, and no target program runs. Live optional engines are not bundled or downloaded.

ELF metadata covers NX, PIE, RELRO segment presence, canary imports and FORTIFY imports.
RELRO presence does not claim full RELRO. Missing canary/FORTIFY symbols remain unknown,
especially for static/stripped binaries. PE records ASLR/DEP/CFG flags and embedded
signature presence. Mach-O records PIE/signature presence; hardened runtime remains
unknown unless reliable external evidence is separately supplied. Missing controls are
posture observations, never automatically vulnerability findings. Signatures are not
cryptographically verified by metadata presence.

APIs: [LIEF ELF](https://lief.re/doc/latest/formats/elf/python.html),
[LIEF PE](https://lief.re/doc/latest/formats/pe/python.html),
[LIEF Mach-O](https://lief.re/doc/latest/formats/macho/python.html),
[Ghidra reference types](https://ghidra.re/ghidra_docs/api/ghidra/program/model/symbol/RefType.html).
Tests: `python -m pytest -q tests/test_binary_intelligence.py tests/test_ghidra_analyzer.py`.

## Firmware filesystems

`python -m vigil_fuse.deep_evidence firmware-extract firmware.bin --image
IMAGE@sha256:DIGEST --tool-version VERSION --authorize-extraction --output rootfs.json`
runs Binwalk and the packaged inventory script inside the shared sandbox. The image
must contain Python, Binwalk and its extraction helpers. Extraction is explicit,
temporary, network-denied and read-only on the input. `--recursive` opts into Binwalk's
recursive extraction; tmpfs, memory, PIDs, timeout, file, depth, aggregate-byte and
artifact limits remain enforced. FUSE does not extract archives itself or emulate code.

`python -m vigil_fuse.deep_evidence rootfs rootfs.json --graph graph.json --output
firmware-graph.json` imports the allow-listed inventory envelope. Binwalk is the initial
execution backend; offline EMBA/FACT adapters may emit the same strict envelope.
Filesystem entries, init/systemd services, hashed account identities, dpkg/opkg package
identities, certificate/key metadata, kernel security flags, binaries and libraries are
represented. Web package presence retains unknown network exposure. Password hashes,
key/certificate contents and arbitrary configuration values are not imported. Architecture
remains unknown when no reliable binary producer supplies it. No extraction-completeness
claim is made from a successful helper exit, so graph coverage is conservatively partial.

Inventory rejects escaping/cyclic symlinks, special files, hardlinks, more than 4000
entries, depth over 32, files over 16 MiB and aggregate file bytes over 64 MiB. Sparse
files are bounded by logical size. Container tmpfs also bounds writes before inventory.
External extractors must respect the container boundary; their output remains untrusted.
The Binwalk v3 output directory is explicit and its input alias cleanup is enabled,
as documented in the [upstream CLI](https://github.com/ReFirmLabs/binwalk/blob/master/src/cliparser.rs)
and [driver](https://github.com/ReFirmLabs/binwalk/blob/master/src/main.rs).
Tests: `python -m pytest -q tests/test_firmware_rootfs.py`.
