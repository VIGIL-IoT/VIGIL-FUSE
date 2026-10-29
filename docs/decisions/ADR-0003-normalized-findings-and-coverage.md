# ADR-0003: Normalize findings and keep coverage explicit

## Status

Accepted, retrospective.

## Context

FUSE combines native rules, selected platform and hardware context, and optional external analyzers. These stages produce different evidence strengths and can be skipped, unavailable, partial, or failed.

## Decision

Normalize outputs into a shared finding and scan-report model. Keep severity, confidence, applicability, and validation status as separate fields. Report analyzer status and coverage alongside findings, and version the JSON contract.

## Alternatives

- Let each analyzer emit unrelated output formats only.
- Convert confidence into severity or suppress signals when build reachability is unknown.
- Treat unavailable stages as clean results.

## Rationale

The shared report model provides a stable review and integration boundary and prevents missing coverage from looking like a negative result. This is a retrospective interpretation based on current repository evidence.

## Consequences and tradeoffs

- Text, JSON, SARIF, and baseline review share normalized records.
- The schema requires compatibility review when adding fields or changing semantics.
- More explicit report state can make reports larger and more complex.
- Separate uncertainty fields do not eliminate false positives or prove applicability.

## Evidence

`src/vigil_fuse/model.py`, `src/vigil_fuse/reporting.py`, `src/vigil_fuse/sarif.py`, `src/vigil_fuse/schemas/fuse-report-1.10.schema.json`, and report tests.
