# FUSE architecture

FUSE is a [VIGIL](https://github.com/VIGIL-IoT) Project in the [VIGIL-IoT suite](https://github.com/VIGIL-IoT). The initial implementation is a small Python package with a CLI boundary and no runtime dependencies.

```text
CLI
 ├─ validates target, profile, config, and output options
 ├─ scanner discovers selected text/code files, hashes, and decodes UTF-8
 ├─ rule registry runs independent native checks
 ├─ optional Syft / OSV-Scanner / Binwalk adapters run as bounded subprocesses
 ├─ common Finding model carries severity, confidence, evidence, and provenance
 └─ reporters emit text, JSON, SARIF, SBOMs, and explicit coverage/artifact hashes
```

## Module responsibilities

- `cli.py`: command-line arguments, output selection, and CI exit threshold.
- `config.py` and `profiles.py`: validated TOML configuration and file-discovery profiles.
- `input_types.py`: recognized existing CycloneDX/SPDX documents and routes them to the inventory/advisory stage.
- `scanner.py`: deterministic file discovery, path filtering, generated-directory exclusions, hashes, size limits, and text decoding.
- `model.py`: shared source, finding, analyzer-status, and scan-result data structures.
- `rules/`: one module per rule plus the explicit rule registry. Rule scanners receive source text and emit common findings.
- `reporting.py` and `sarif.py`: text, schema-versioned JSON, and SARIF serialization.
- `analyzers.py`: optional Syft inventory, OSV vulnerability matching, and Binwalk signature identification. Each adapter is isolated from native rules and writes artifact hashes into the report.
- `schemas/`: machine-readable report schema shipped with the Python package.
- `tests/fixtures/rules/`: vulnerable and secure inputs for each enabled rule.

## Rule contract

Each rule has a stable ID, title, severity, confidence, category, explanation, potential impact, remediation, optional references, and a scanner function. Rules should match explicit evidence and avoid extrapolating exploitability. A finding's evidence must be useful and must not disclose literal credentials or private-key material.

Every rule change should include a vulnerable fixture that produces the intended finding and a secure fixture that produces no finding for that rule. The automated tests load fixtures and exercise the rule directly. Scanner and reporter tests cover end-to-end path handling and output shape.

## Deliberate boundaries

Native rules analyze selected source/configuration text only. Optional Syft inventories local directory/file inputs; OSV-Scanner matches generated or supplied CycloneDX/SPDX SBOMs or project manifests to known advisories; Binwalk identifies firmware signatures without extraction. FUSE does not contact device services, validate credentials, extract or execute firmware, or infer runtime reachability. OSV uses the network unless the user selects its offline database. The executable adapters have explicit timeouts, output limits, statuses, versions, and output hashes; firmware parsing is still performed by the selected external tool and should be isolated for hostile input.

Profiles currently control file discovery only. They are not claims that platform-specific rules already exist. The result records profile, selected/skipped files, active rules, analyzer status, an input-manifest digest, and artifact paths/hashes. The canonical JSON report is schema-versioned; new adapters must report missing tools, partial coverage, and failures explicitly instead of returning an empty result as if analysis completed. SARIF exports normalized findings for code-scanning tools; CycloneDX remains the component-inventory format.

FUSE and SPECTRA-32 have complementary roles in the [VIGIL-IoT suite](https://github.com/VIGIL-IoT): FUSE inspects candidate weaknesses, while SPECTRA-32 can reproduce selected cases in a controlled lab and measure mitigation overhead.
