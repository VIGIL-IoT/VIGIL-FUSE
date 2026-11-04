# ADR-0001: Keep FUSE as a local CLI-first Python package

## Status

Accepted, retrospective.

## Context

The repository contains a Python `src/` package, the `vigil-fuse` console entry point, local configuration, and no required server or hosted backend. The website is a separate static output.

## Decision

Keep the analysis engine usable as a local CLI and Python package. Treat hosted dashboards and editor integrations as separate future clients.

## Alternatives

- Make a hosted service the primary analysis path.
- Couple analysis to the static website.
- Require a plugin or editor host to run scans.

## Rationale

The local CLI matches the package metadata and lets users inspect proprietary project trees without uploading them to a service. This is a retrospective interpretation based on current repository evidence, not a claim about the original author's historical reasoning.

## Consequences and tradeoffs

- Core use does not require an account, server, or runtime dependency.
- Users manage local installation and optional executables.
- A local CLI has no shared report database or team dashboard.
- The custom VIGIL-FUSE Restricted Use License permits installation, execution, commercial use, and private modification. Version 1.1 adds a narrow permission for unmodified official packages distributed through PyPI and compatible mirrors; other redistribution and publication of modifications remain restricted. CLI-first design does not grant additional publication rights. Review the terms of any distribution channel before publishing packages or release assets.

## Evidence

`pyproject.toml`, `src/vigil_fuse/cli.py`, `README.md`, and `vercel.json`.
