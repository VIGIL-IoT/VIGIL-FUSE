# Architecture and testing guidance from Crawl4AI source review

**Review date:** 2026-11-01
**Crawler:** Crawl4AI 0.9.5
**Purpose:** identify practical architecture and evaluation changes for FUSE without treating a reference catalogue as certification.

## Sources and method

The pages below were fetched and read with the locally installed Crawl4AI browser crawler. NIST's IoT technical-capability catalogue returned HTTP 200 in the current pass. The NIST SATE overview was successfully extracted in an earlier Crawl4AI pass in this review thread. A later repeat request to that SATE URL ended with a connection reset, so this note records the source's stated method and preserves the retrieval limitation instead of treating every repeat as available.

1. [NIST Static Analysis Tool Exposition (SATE)](https://www.nist.gov/itl/csd/secure-systems-and-applications/samate/static-analysis-tool-exposition-sate)
2. [NIST IoT Device Cybersecurity Technical Capabilities Catalog](https://pages.nist.gov/IoT-Device-Cybersecurity-Requirement-Catalogs/technical/)

The SATE overview describes a recurring, noncompetitive evaluation in which tool makers run analyzers on a shared program set, researchers analyze the outputs, and participants share results and experience. The IoT catalog groups device capabilities into areas including identification, configuration, data protection, logical access to interfaces, software update, cybersecurity state awareness, and device security. The catalog is context-tailored and is not a product certification.

## Implications for FUSE architecture

- Keep analyzer output, human review, and evaluation evidence as distinct layers. A static signal is a candidate observation; it does not establish whether a device is deployed, a path is reachable, or an attack succeeds.
- Map each capability to explicit FUSE evidence, a selected metadata input, or an unimplemented gap. Do not imply that filename inventory or a configuration candidate proves a physical device capability.
- Keep boundaries around rule definitions, the registry, scanning, optional analyzers, report serialization, and the CLI composition root. Enforce those boundaries with import-graph checks rather than relying on diagrams alone.
- Exercise a complete user-visible workflow with paired positive and secure synthetic controls. Keep these wiring tests separate from per-rule fixtures and external known-case evaluations.

## Changes made from this review

- Added AST architecture tests for an acyclic package import graph, foundation independence, rule-module dependencies, rule registry completeness, and reporter isolation.
- Added a paired end-to-end CLI scan for an ESP-IDF source/configuration sample with hardware inventory, selected KiCad netlist, BOM import, and JSON artifact reporting.
- Recorded the limits of the synthetic test. It does not estimate field accuracy, test a physical board, validate firmware behavior, or claim NIST conformance.

## Remaining evaluation work

SATE's shared-corpus and analyst-review model supports an independent evaluation plan, but this repository's synthetic and pinned known-case results do not substitute for independent adjudication. A representative, permission-cleared corpus, a documented triage protocol, and independent reviewers are still needed before publishing a field-accuracy estimate. Physical interface exposure remains outside the current FUSE CLI scope and needs a separate controlled lab method if that claim is pursued.
