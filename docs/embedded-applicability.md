# Embedded applicability

**Status:** experimental, partial, and not part of the published 0.4.0 release.

## Initial repository audit

The audit found these existing extension points on `main` at `2e9453a`:

| Capability | Status | Current boundary |
| --- | --- | --- |
| SBOM and advisory findings | IMPLEMENTED | Optional Syft and OSV-Scanner adapters report package identities and advisory matches. |
| Build and configuration context | PARTIALLY IMPLEMENTED | ESP-IDF, Zephyr, PlatformIO, and compilation database metadata are inspected without running build commands. This does not prove what was compiled. |
| Hardware and firmware evidence | PARTIALLY IMPLEMENTED | BOM, selected netlist, firmware candidates, and optional binary analysis provide bounded observations, not physical exposure or runtime proof. |
| CycloneDX VEX review import | IMPLEMENTED | Review metadata is attached only to exact product, advisory, and component matches. Signatures are not verified. |
| Cross-layer applicability assessment | PROPOSED | Findings remain independent of configured target, artifact, reachability, and physical exposure. |
| Evidence bundles, security delta, trust continuity, and physical reachability | PROPOSED | These tracks are not implemented in the inspected `main` commit. |

The implementation below composes current report evidence without changing `scan`, its report schema, or finding severity. It does not add a generic graph database or infer missing evidence.

## Analyze an existing scan

For an ESP-IDF project, write a FUSE JSON report with the build directory selected and dependency analysis enabled:

```sh
vigil-fuse scan . --profile esp-idf --build-dir build --vulnerabilities --output-dir .fuse-results
vigil-fuse applicability analyze --report .fuse-results/findings.json --output .fuse-results/applicability.json
```

For other projects, use the matching scan profile and selected metadata options.

The analyzer reads a bounded FUSE JSON report and emits stable JSON, including source discovery completeness and dependency-analyzer status. It does not rerun a scan or invoke external tools. Without `--output`, JSON is written to stdout.

Each dependency finding has separate states for dependency presence, upstream version match, ESP-IDF component resolution against the configured target, build inclusion, feature and device enablement, binary presence, runtime reachability, and physical exposure. The first three can contain evidence when the input report supports them. The later states remain `UNKNOWN` until directly linked evidence exists.

`COMPONENT_RESOLVED_FOR_CONFIGURED_TARGET` requires an exact ESP-IDF component name and version match and a lock target that matches the generated configuration target. This is lock resolution only. It does not establish compiled, released, or deployed contents. A same-name version disagreement remains `CONTRADICTORY`.

The overall assessment remains `UNDER_INVESTIGATION` for an OSV advisory match unless an exact imported VEX review records `exploitable` or `not_affected`. `NOT_AFFECTED` requires a supported VEX justification. These are imported reviewer assertions, not conclusions independently verified by FUSE. An unsupported advisory provider yields `UNKNOWN` unless an exact VEX review supplies a state.

## Evidence contract, version 1.0

An evidence claim preserves one observation without promoting it into later product states:

| Field | Meaning |
| --- | --- |
| `claim_id` | Stable SHA-256 identity for this claim in the source report. |
| `subject` | Component PURL, or the component name and version when no PURL exists. |
| `predicate`, `value` | One claim and its explicit state. |
| `source`, `source_version` | FUSE finding, analyzer, lock file, or VEX review that supplied it. |
| `artifact_digest`, `location` | Digest and report-relative evidence reference. Local source paths are omitted. |
| `target_identity` | Available framework, target, board, and version metadata. |
| `extraction_method`, `confidence`, `coverage`, `observation_context` | How the claim was obtained and its evidence boundary. |
| `limitations` | What the observation does not establish. |
| `justification`, `detail` | Optional VEX reviewer explanation. |

Claims retain independent provenance. The current output uses `STATIC` for scan metadata and `REVIEWED` for imported VEX. It omits timestamps so identical input bytes produce identical output. Missing evidence is `UNKNOWN`; conflicting lock evidence remains visible. No claim is inferred from a preceding layer.

The output is defined by [applicability-1.0.schema.json](../src/vigil_fuse/schemas/applicability-1.0.schema.json).

## Known limits

- Current input is an existing FUSE scan report. A clean scan with no dependency finding produces no applicability record for that package.
- The dependency-to-compiled-object relation is not available in current report metadata. Compilation database summaries do not contain component mappings.
- There is no advisory-to-feature, peripheral, binary, runtime, or physical-exposure mapping.
- The engine does not export VEX, resolve arbitrary dependency ecosystems against target locks, or claim `AFFECTED` or `NOT_AFFECTED` from static and lock metadata alone.
- Imported VEX is not authenticated. Review authority, provenance freshness, and correctness remain unverified.

The next useful increment is to add bounded component-to-build evidence with a controlled fixture that distinguishes a resolved dependency from an included object. Dynamic, lab, and field observations need separate explicit providers and must remain separate evidence contexts.
