# ADR-0002: Bound analysis and do not execute project inputs

## Status

Accepted, retrospective.

## Context

FUSE reads source, configuration, build metadata, hardware exports, and selected firmware artifacts. These may be untrusted or proprietary. Some parsers and external analyzers can consume complex inputs.

## Decision

Keep native analysis read-only, apply explicit input and time limits, avoid running project build logic, and invoke external tools only as opt-in adapters with bounded subprocess handling. Describe the native worker as timeout control, not a security sandbox.

## Alternatives

- Run the project's own build and scripts automatically to resolve target reachability.
- Treat all inputs as trusted and rely on one global timeout.
- Make external analysis mandatory in the core install.

## Rationale

The existing call paths and tests reflect a deliberate separation between source inspection and project execution. This rationale is a retrospective interpretation based on current repository evidence.

## Consequences and tradeoffs

- Default scans avoid arbitrary project-code execution and keep runtime dependencies low.
- FUSE cannot claim full build reachability or runtime behavior.
- External analyzers retain their own parser, privilege, and network risks.
- Bounded parsing reduces resource exposure but does not prove safety.

## Evidence

`docs/threat-model.md`, `docs/architecture.md`, `src/vigil_fuse/scanner.py`, `src/vigil_fuse/analyzer_runtime.py`, and their tests.
