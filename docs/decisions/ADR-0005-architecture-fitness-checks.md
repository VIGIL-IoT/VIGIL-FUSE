# ADR-0005: Enforce module boundaries with architecture fitness tests

## Status

Accepted, retrospective.

## Context

FUSE has distinct model, rule, context, execution, reporting, and CLI modules. Their intended dependency directions were described in architecture documentation, but no automated check prevented import cycles or accidental dependencies from foundational modules, rule implementations, or reporters into orchestration code.

Individual unit tests also did not prove that one embedded-project scan could connect source rules, selected generated build metadata, hardware inventory, a KiCad netlist, a BOM artifact, and a serialized report through the public CLI.

## Decision

Keep the current package layout and add standard-library AST-based architecture fitness tests. The tests enforce an acyclic internal import graph, a dependency-light foundation, narrow native-rule dependencies, registry coverage, and reporting independence from scan and analyzer orchestration.

Add a paired CLI integration test using synthetic ESP-IDF and hardware-project inputs. The vulnerable control should produce the documented scoped findings and evidence fields. The secure control should not produce those specific findings. Both should complete with local report outputs and hardware inventory metadata.

## Alternatives

- Rely on architecture diagrams and code review alone.
- Introduce a runtime architecture framework or a new mandatory dependency.
- Test each helper in isolation without exercising the user-facing scan path.

## Rationale

Python's AST is sufficient for import-boundary checks and is already part of the runtime. The current package can gain enforceable boundaries without changing the public API or adding dependencies. A paired synthetic CLI run covers integration that unit tests cannot establish while retaining deterministic inputs.

## Consequences and tradeoffs

- Intentional dependency changes must update the architecture contract and its tests.
- The synthetic project proves only that the selected modules are connected for the tested paths.
- It does not prove physical-board behavior, general parser correctness, field accuracy, or security certification.
- The standards-oriented evaluation guidance is summarized in [`docs/research/architecture-and-testing-guidance-2026-11-01.md`](../research/architecture-and-testing-guidance-2026-11-01.md).

## Evidence

`tests/test_architecture_contracts.py`, `tests/test_cli_embedded_project_integration.py`, `docs/architecture.md`, and `docs/traceability.md`.
