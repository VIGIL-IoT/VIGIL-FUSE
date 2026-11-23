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
