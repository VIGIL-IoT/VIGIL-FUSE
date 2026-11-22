# Reasoning context

FUSE can prepare a bounded context packet for a single finding from its canonical JSON report. This makes the scanner's evidence easier for a separate reasoning tool to review without giving that tool the entire repository or letting it rewrite scanner conclusions.

```sh
vigil-fuse reasoning-context .fuse-results/findings.json --finding FUSE-001-1 --output .fuse-results/context.json --pretty
```

Packet bounds can be tuned without changing scan behavior:

```sh
vigil-fuse reasoning-context .fuse-results/findings.json \
  --finding FUSE-001-1 \
  --max-context-chars 12000 \
  --max-text-chars 800 \
  --max-snippet-chars 1200 \
  --max-items 16
```

The command accepts FUSE report schema 1.11, requires an exact finding ID, and writes deterministic JSON to standard output or `--output`. It includes the selected finding, source location and bounded evidence, provenance, coverage limitations, and exact-path build, firmware, hardware, or VEX metadata present in that report. Absolute source paths are reduced to their file name. Sensitive values in included text are redacted. `--pretty` changes only JSON formatting.

The packet includes explicit `confirmed`, `supported`, `unknown`, and `contradicted` evidence groups. A FUSE validation status is preserved as scanner validation evidence; a reported finding is labeled as scanner-supported, not independently proven. Missing applicability, incomplete discovery, skipped files, and analyzer limits remain visible. Firmware inventory, project settings, BOM entries, and netlist candidates do not prove that an image was built, linked, run, physically populated, or reachable. Those deployment stages remain separate and unknown unless the report directly supports a stage.

The context contract fixes `may_change_finding`, `may_change_severity`, and `may_invent_evidence` to `false`. A separate output schema documents the limited shape for a possible future explanation, missing-evidence list, checks, remediation, and limitations. FUSE does not currently call an LLM, Ollama, or any provider; it does not install model packages, transmit report content, change severity or policy, or apply generated patches. The output schema rejects extra fields such as a replacement severity.

The current report does not contain source-level semantic evidence beyond each finding's emitted evidence. The packet therefore leaves `semantic_evidence` empty and never infers control flow, linkage, runtime behavior, hardware population, or network reachability from filenames or neighboring findings.

## Future provider boundary

The command above is inspection only. These future interfaces are documented but are not registered or implemented:

```sh
vigil-fuse scan TARGET --reason
vigil-fuse reason .fuse-results/findings.json --finding FUSE-001-1
```

If a local provider is added, its input will be the selected `reasoning_context_v1` packet plus a short instruction to explain that finding using only the supplied evidence, retain unknowns, and suggest checks or remediation. It will not receive the whole report, repository, SARIF, PDF, Ghidra output, AST, KiCad file, or unrelated findings. FUSE will validate provider output against `reasoning-output-v1.schema.json` and present it as optional enrichment alongside the unchanged deterministic finding.

Provider output may contain a plain-language summary, reasoning, ranked missing evidence, recommended checks, remediation suggestions, and limitations. It cannot set finding existence, severity, deterministic confidence, policy outcome, evidence provenance, coverage, or physical reachability. FUSE will reject unexpected fields. V1 does not apply patches.

`pip install vigil-fuse` installs no model and performs no model download. FUSE has no reasoning setup or recommended setup command that installs a model. A future provider may detect Ollama and a separately installed model, but model installation must be a separate, explicit action. No provider, model, GPU, or network access is needed for `reasoning-context`.

Provider settings such as context limit, timeout, temperature, and unload/keep-alive behavior are future integration work. An approximately 8K-token context, low temperature, and unloading after each explanation are starting points to benchmark, not current defaults or guarantees.
