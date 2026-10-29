# ADR-0004: Isolate optional analyzers behind explicit adapters

## Status

Accepted, retrospective.

## Context

Dependency vulnerability matching, firmware signature identification, and Git-history scanning require separate tools with their own data, parsers, versioning, and network behavior.

## Decision

Keep these tools optional, invoked only when selected, behind adapter modules. Record versions, artifacts, status, timeouts, and failures. Do not treat a missing tool or failed stage as a clean result.

## Alternatives

- Add all analyzers as mandatory Python dependencies.
- Run external tools automatically on every project.
- Hide tool output and report only normalized findings.

## Rationale

Optional adapters preserve a small core install while allowing focused capabilities. This is a retrospective interpretation based on the current module boundaries and CLI options.

## Consequences and tradeoffs

- Users must install, update, and review external tools separately.
- Reports can identify stage availability and artifacts.
- The core cannot guarantee external tool behavior, safety, accuracy, or network policy.

## Evidence

`src/vigil_fuse/analyzer_runtime.py`, `dependency_analyzers.py`, `firmware_analyzer.py`, `history_analyzer.py`, `docs/integrations.md`, and analyzer tests.
