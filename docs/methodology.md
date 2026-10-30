# Methodology

This document describes the implemented analysis and validation path. It does not describe planned behavior as if it existed.

## Design approach

FUSE uses a local CLI with a small dependency-free Python core. The design prioritizes bounded reads, explicit analysis coverage, a normalized finding model, and adapters for capabilities that require separate tools. Inputs and analyzer output are treated as untrusted. The native rules run in a worker process for timeout control, but that worker is not an operating-system sandbox.

## Analysis pipeline

1. **Request and configuration:** The CLI validates the target, profile, selected build context, output options, limits, and opt-in analysis stages.
2. **Discovery:** The scanner applies profile filters, exclusions, path and directory limits, and supported file types. It records discovered, selected, skipped, and unsupported counts.
3. **Input handling:** Selected text inputs are size-bounded, hashed, decoded with disclosed fallback behavior, and represented by scan-root-relative paths. Binary candidates are inventoried separately.
4. **Native rules:** Each enabled rule receives decoded text and a relative path in a killable worker process. Rules report explicit findings; source is not imported, compiled, or executed.
5. **Context adapters:** Selected adapters read bounded known metadata such as platform configuration, compilation databases, KiCad netlists, hardware BOMs, VEX records, or provenance subjects. They do not run project build tools.
6. **Optional external analyzers:** When explicitly enabled, FUSE invokes Syft, OSV-Scanner, Binwalk, or Gitleaks through argument arrays with time and output bounds. Their absence and failure status are represented in the report.
7. **Finding normalization:** Findings retain separate severity, confidence, applicability, validation method, and validation status. Evidence is redacted where applicable and associated with stable identifiers and fingerprints.
8. **Reporting:** The CLI writes text, schema-versioned JSON, and SARIF outputs. Requested inventory artifacts are stored in the selected output directory. Coverage and analyzer status accompany findings.

## Inputs and outputs

Inputs include local source/configuration trees, optional selected build directories, explicit firmware files, optional SBOM/VEX/provenance files, and selected hardware netlist/BOM files. Outputs include findings, scan coverage, stage status, inventories, and artifact hashes. By default, output is written under `.fuse-results/` in the scanned target.

## Failure states

Invalid settings stop before analysis. Unsupported or over-limit inputs are recorded as unsupported or skipped. Missing optional executables are unavailable. Timeouts and parser failures are surfaced as failed or partial coverage. A partial scan is not represented as a complete clean scan. See `docs/finding-schema.md` and `docs/threat-model.md` for report and trust details.

## Rule development and validation method

Each native rule has a stable ID and metadata, a vulnerable fixture expected to produce a finding, a secure fixture expected not to produce one, and automated tests. `scripts/evaluate_rule_benchmark.py --check` checks all labeled cases against current rule behavior. It is a synthetic regression suite; its scores do not estimate real-world precision or recall. Rule changes based on repository observations should be separately reviewed and tested on a cohort not used for tuning where possible.

## Repository-scan evaluation method

Repository studies use pinned commits, profiles, and include/exclude scopes recorded in manifests under `reports/`. The runner checks checkout identity and local cleanliness before scanning. It does not build target projects or run their tests. Manual triage records candidate matches and interpretation. Counts describe one tool version and scope, not a population estimate. The current evaluation limitations are recorded in `docs/experiments/pilot-scan-2026-10.md` and `docs/benchmarks.md`.

## Reproduction

Install and execute with Python 3.11 or later:

```powershell
python -m pip install -e ".[dev]"
python -m vigil_fuse doctor
python -m vigil_fuse scan path\to\embedded-project --format json --output findings.json
python -m pytest -q
python scripts/evaluate_rule_benchmark.py --check
python scripts/benchmark_scan.py --files 128 --warmups 1 --repetitions 5 --output reports/benchmark/scan-performance.json
```

The package has no core runtime dependencies. The performance harness uses the development-only psutil dependency to sample process-tree RSS. Optional analysis stages require the corresponding external executable and may use the network as documented in `docs/integrations.md`.
