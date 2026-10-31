# FUSE finding format

FUSE JSON reports use `schema_version: "1.10"`, defined in the packaged [JSON Schema](../src/vigil_fuse/schemas/fuse-report-1.10.schema.json). A report contains tool metadata, a privacy-preserving target label, profile and timestamps, a deterministic scanned-input manifest digest, summary, coverage, hardware and build-context inventories, optional product-context evidence, unsupported file-type counts, findings, and generated artifacts. Counts distinguish discovered, selected, filtered, scanned, skipped, and unsupported files so an unsupported or filtered target is not presented as a clean scan.

The top-level `target` value is a shareable label. By default, it is the target basename. Pass `--target-label organization/repository` or set `scan.target_label` in TOML to give reports and baselines a stable identity when different repositories have the same folder name. Labels cannot be absolute paths or contain traversal segments. Local target paths are not included in reports.

## Finding fields

The fields are separate judgments. The [interactive finding model](../site/diagrams/fuse-finding-model.html) lets you adjust severity and confidence independently. The static figure below uses the illustrative `FUSE001` example in this document. It is a teaching model, not a scan result or a physical FUSE device.

![Conceptual model of independent FUSE finding fields](figures/fuse-finding-model.svg)

| Field | Meaning |
| --- | --- |
| `id` | Stable location-based identifier: `rule_id:file:line` |
| `fingerprint` | SHA-256 identity over rule, path, line, and redacted evidence for comparison across runs |
| `rule_id` | Stable detection rule identifier such as `FUSE003` |
| `rule_version` | Version of the rule logic that emitted this finding |
| `analyzer` | Producer name, such as `fuse-native` or a future adapter |
| `title` | Short description of the observed signal |
| `severity` | Potential impact rating: `critical`, `high`, `medium`, `low`, `info`, or `unknown` |
| `severity_basis` | Whether severity came from a native rule, upstream advisory label, numeric CVSS score, or an unscored CVSS vector |
| `severity_score` | Numeric CVSS score from 0 to 10 when supplied or calculable; otherwise `null` |
| `severity_vector` | Original CVSS vector, including CVSS v4 vectors that FUSE does not score locally |
| `severity_version` | CVSS version when available, such as `3.1` or `4.0` |
| `confidence` | Strength of evidence supporting this specific detection: `high`, `medium`, or `low` |
| `applicability` | Whether the signal is known to apply to the shipped product; defaults to `unknown` until build or product evidence resolves it |
| `validation_method` | Evidence source: static rule, generated build configuration, advisory match, external tool, lab validation, or operator-guided check |
| `validation_status` | Whether the reported condition has been independently validated; static and advisory matches default to `not-validated` |
| `category` | Security topic, such as `secrets` or `transport-security` |
| `location` | Scan-root-relative file and inclusive start/end lines |
| `evidence` | Short supporting excerpt; secret values and key material must be redacted |
| `explanation` | What the rule observed and the limits of that observation |
| `potential_impact` | Conditional consequence if the configuration is active and applicable |
| `remediation` | Practical next step to remove or verify the risk |
| `references` | Optional primary weakness references, such as CWE entries |
| `component` | Optional dependency identity with ecosystem, name, version, and package URL; populated for normalized advisory findings |
| `vex_review` | Optional CycloneDX VEX review state, justification, and detail; this context does not replace the underlying finding |

Line numbers are `null` for findings such as dependency advisories when the inventory identifies a manifest or SBOM but cannot identify a source line. Dependency severity uses an upstream qualitative label or a CVSS v3.0/v3.1 base vector when present. `severity: "unknown"` means FUSE could not derive a supported advisory severity; it does not manufacture one from confidence.

## Scan metadata and coverage

The `scan` object identifies the target kind and profile, records the network policy and UTC start/completion times, and gives `input_manifest_sha256`. The network policy is `not-requested`, `network-allowed`, `offline-vulnerabilities`, or `no-network`. That digest covers selected source paths and file hashes, or their skip reasons. It is **not** a digest of every file in the target: unsupported files and files filtered by policy are excluded and counted separately.

The summary includes `source_bytes_read`, the number of bytes read while processing selected source files. Defaults cap discovery at 100,000 file paths or 20,000 directories, native source reads at 512 MiB, and native scanning at 10 minutes. CLI switches or the matching `[scan]` TOML fields can adjust these limits up to hard ceilings of 1,000,000 paths, 200,000 directories, 8 GiB of source, and 60 minutes. Optional external analyzers have separate timeouts. Native rules run in a worker subprocess with a configurable per-rule, per-input limit of 0.1 to 30 seconds, defaulting to 2 seconds. A timed-out rule is terminated and disabled for the rest of the scan. Its `coverage.analyzers` entry has a `native-rule:<ID>` name and `partial` status; a rule exception has `failed` status. The aggregate native analyzer reports `partial` and the CLI returns a nonzero status when a rule is incomplete. `coverage.discovery_complete`, `coverage.limits_reached`, and analyzer statuses make coverage limits visible. An empty finding list alone is never proof that all relevant content was analyzed.

The `coverage` object lists all available and enabled rules, analyzer status/version, file skip reasons, and the applicable support label from the packaged [support matrix](../src/vigil_fuse/support-matrix.json). Support labels describe the documented scope, while `status` reports what happened in this scan. Each native rule has a `native-rule:<ID>` entry. A `skipped` status means no selected input was passed to the rule, either because none matched its supported scope or because the scan had no applicable source inputs. This intentional rule-level skip does not by itself make the native scan partial. Rule-owned prefilters may also exclude individual inputs with no required markers; reports include that count in the rule detail when the rule ran on other inputs.

`coverage.input_inventory` counts regular files not selected by the active source profile during bounded directory discovery. For firmware-image and supplied-SBOM inputs, the field states that source-profile inventory does not apply. Directory scope excludes symbolic links, configured/generated directories, and explicit exclude patterns. Include patterns limit selected source files but do not hide other types from this inventory. A file listed here may still be recognized by a separate inventory stage, such as hardware filename recognition. `complete` is false if discovery stopped at a resource limit, and `unsupported_file_types` uses lowercase extensions or `<no-extension>` as keys. These counts are a routing summary, not a claim that every file on disk was examined.

The `hardware_inventory` object reports recognizable schematics, PCB design and fabrication artifacts, BOMs, CAD models, netlists, and HDL files. Detection uses filenames only and is independent of the source profile. `scope` is either the full directory target or a single file. `complete` is false if directory discovery stopped at a resource limit. Its entries are presence metadata, not vulnerability findings, and FUSE does not claim to validate hardware contents or security.

The `firmware_candidates` object records candidate paths, extensions, sizes, and counts across bounded source and common build-output directories. This is filename metadata only: candidate files are not opened, hashed, or validated as firmware. The path list is capped separately from the extension counts, and `omitted_count` shows when the displayed list was shortened.

The `github_actions` object records workflow paths and hashes plus coverage for narrow static checks. FUSE reports exact workflow-level and job-level `permissions: write-all` scalars, counts recognized non-SHA action references, and creates findings for obvious floating branches such as `@main` or `@master`. It also reports the exact combination of a `pull_request_target` trigger and an `actions/checkout` `ref` set to `github.event.pull_request.head.sha` or `.head.ref`. `FUSE-GHA-004` reports selected untrusted event fields directly interpolated into a step `run` scalar or block script. These findings do not establish whether a later step executes checked-out code or whether a workflow script is exploitable. Normal version tags are counted but are not findings. Structured permission mappings, permission inheritance, complete event field coverage, expression flow, shell semantics, sanitization, and general workflow analysis are outside this check.

The `hardware_netlist` object records metadata from one selected or uniquely detected KiCad XML netlist. FUSE rejects DTD and entity declarations, and reports a debug-net candidate only when a named debug/programming signal connects to a connector-designator or connector-like part. The result does not establish PCB routing, physical access, population state, or whether device debug access is enabled.

The `build_context.platformio` object records selected metadata from `platformio.ini` and its bounded `extra_configs` include graph, including declared environments, allow-listed board and platform fields, default environment names, source directories, ordered `build_src_filter` lines, and per-file digests. It does not expand interpolation, resolve filters into an effective compiled file set, run PlatformIO, or build each environment. Missing or unsafe includes produce partial coverage. `build_context.compilation_database` records bounded entry counts, source paths classified as in-target or external, compiler families, and a digest. FUSE treats compilation commands as data and never executes them. This inventory does not imply semantic C or C++ analysis.

The `hardware_bom` object is present-only unless `--hardware-bom` explicitly selects a CSV or TSV. It records the source digest, imported row count, listed quantity, normalized part fields, and parse limitations. FUSE also writes `hardware-bom.cdx.json`, a CycloneDX hardware inventory, and lists its digest in `artifacts`. Imported part names and manufacturer metadata may reveal board composition. Neither the imported BOM nor the generated HBOM is a hardware security assessment.

The `product_context` object can include a product PURL and the metadata for an explicitly imported CycloneDX VEX document. FUSE binds the VEX product PURL to `--product-purl`, then applies review metadata only when both the vulnerability ID and affected component PURL exactly match a FUSE dependency finding. Unmatched records remain visible in the import summary. The underlying finding, severity, and `--fail-on` result are preserved. VEX review is not signature-authenticated by FUSE.

The `provenance` object records fields selected from an in-toto SLSA statement and whether a subject SHA-256 matches the selected firmware image. `subject-match` means only that the supplied statement contains the image digest. `signature_verified` remains false because FUSE does not verify the envelope signature, trusted builder identity, or build policy. A mismatch is an explicit nonzero scan status.

The `project_context` object records ESP-IDF or Zephyr project markers and, only when `--build-dir` is supplied, a small set of files from that selected build directory. Those generated files are hashed and bounded to 4 MiB each. ESP-IDF context records the selected `sdkconfig` path and whether it came from `CMakeCache.txt` or the conventional project default. It records defaults candidates in processing order, target-specific variants, hashes, and missing or unreadable inputs. An explicit `SDKCONFIG_DEFAULTS` value is taken from the selected build's cache; without that evidence, conventional defaults are candidates only because project CMake or environment settings may override them. The order follows Espressif's documented rule: each target-specific variant is tried immediately after its base entry. FUSE does not interpret Kconfig dependencies or claim that a selected build was released. Boot-validation settings found in selected generated configuration can produce findings with `applicability: "candidate"` and `validation_method: "generated-config"`. ESP-IDF scans also inventory a root `dependencies.lock` when present, using the optional `vigil-fuse[esp-idf]` extra. The lock summary preserves the file hash, lock version, target, manifest hash, and resolved component names, versions, source types, compatibility targets, and dependency edges. It does not expose raw source URLs or local paths. The manifest hash is not recomputed, so `manifest_freshness` remains `unverified`. A resolved lock entry is not proof that a component was built into or shipped in a firmware image. Zephyr scans can import the selected build's JSON hardening report with `--zephyr-hardening-report`. The report is hashed, limited to 4 MiB, and must be inside the selected build directory. FUSE preserves the Zephyr profile and rationale, and maps each upstream `FAIL` to a finding with unknown severity, high confidence in the reported configuration deviation, candidate applicability, and external-tool validation provenance. Passing and non-applicable check counts appear in the analyzer coverage detail. FUSE does not run `west` or the build. Both platform adapters are experimental.

The `artifacts` array records each generated SBOM or analyzer output by relative path, media type, and SHA-256. The report itself is not listed as an artifact because it contains the artifact manifest.

SARIF 2.1.0 uses `%SRCROOT%` for relative source locations and limits serialized output to 9 MiB. Its run properties include `resultsAvailable`, `resultsIncluded`, and `resultsOmitted`; consumers can detect a capped export without mistaking it for the complete JSON finding list.

For SARIF alert matching, FUSE includes GitHub's `primaryLocationLineHash`. It hashes normalized, already-redacted finding evidence and adds an occurrence counter for repeated same-rule evidence in one file. This remains stable when a finding moves because unrelated lines were inserted, while preserving distinct repeated matches. The JSON report's `fingerprint` remains location-sensitive, and the baseline diff uses its own line-insensitive comparison identity.

Severity, its source, confidence, applicability, and validation are separate dimensions. A rule can have high confidence that a risky setting exists while its applicability to the shipped product is unknown. Static and advisory matches are not lab validation. FUSE preserves an advisory's original CVSS vector. It derives a score only for supported CVSS v3 vectors; an unscored CVSS v4 vector remains attached to the finding while severity stays `unknown` unless the advisory supplies a qualitative label. FUSE should not raise severity merely because evidence is strong, or raise confidence because the potential impact is severe.

## Example

```json
{
  "schema_version": "1.10",
  "tool": {"name": "FUSE", "version": "0.2.0"},
  "target": "device-project",
  "scan": {
    "target_kind": "directory",
    "profile": "generic",
    "network_policy": "not-requested",
    "started_at": "2026-10-26T12:00:00Z",
    "completed_at": "2026-10-26T12:00:01Z",
    "input_manifest_sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
  },
  "summary": {
    "files_discovered": 12,
    "files_selected": 12,
    "files_filtered": 0,
    "files_scanned": 12,
    "source_bytes_read": 6400,
    "files_skipped": 0,
    "analysis_performed": true,
    "finding_count": 1,
    "severity_counts": {"critical": 0, "high": 0, "medium": 1, "low": 0, "info": 0, "unknown": 0}
  },
  "coverage": {
    "files_skipped_by_reason": {},
    "discovery_complete": true,
    "limits_reached": [],
    "input_inventory": {
      "scope": "Regular non-symbolic files encountered under traversed target paths, excluding configured and generated directories and explicit excludes; include patterns affect selected source files only.",
      "complete": true,
      "unsupported_file_count": 2,
      "unsupported_file_types": {".md": 1, ".txt": 1}
    },
    "support": {
      "capability_id": "source.generic",
      "label": "basic",
      "status": "completed",
      "scope": "Seven native rules over selected source and configuration files.",
      "limitations": ["No build resolution", "No runtime or device validation"]
    },
    "rules_available": ["FUSE001"],
    "rules_enabled": ["FUSE001"],
    "analyzers": [
      {"name": "fuse-native", "status": "completed", "version": "0.2.0", "detail": "Native rules completed.", "findings": 1}
    ]
  },
  "hardware_inventory": {
    "scope": "directory",
    "complete": true,
    "present": true,
    "file_count": 1,
    "category_counts": {"schematic": 1},
    "artifacts": [
      {"path": "hardware/controller.kicad_sch", "category": "schematic", "format": "KiCad schematic"}
    ]
  },
  "build_context": {
    "platformio": {
      "status": "not-detected",
      "path": null,
      "sha256": null,
      "byte_size": 0,
      "default_environments": [],
      "selected_environments": [],
      "environments": [],
      "limitations": []
    },
    "compilation_database": {
      "status": "not-detected",
      "path": null,
      "sha256": null,
      "byte_size": 0,
      "entry_count": 0,
      "unique_translation_units": 0,
      "in_target_source_count": 0,
      "external_source_count": 0,
      "compiler_families": {},
      "malformed_entries": 0,
      "limitations": []
    }
  },
  "hardware_bom": {
    "status": "not-requested",
    "source_path": null,
    "sha256": null,
    "byte_size": 0,
    "format": null,
    "component_count": 0,
    "quantity_total": 0,
    "components": [],
    "limitations": []
  },
  "product_context": {
    "product_purl": null,
    "vex_import": {
      "status": "not-requested",
      "source_path": null,
      "sha256": null,
      "byte_size": 0,
      "product_purl": null,
      "record_count": 0,
      "matched_findings": 0,
      "unmatched_records": 0,
      "limitations": []
    }
  },
  "provenance": {
    "status": "not-requested",
    "source_path": null,
    "sha256": null,
    "byte_size": 0,
    "predicate_type": null,
    "builder_id": null,
    "build_type": null,
    "subject_name": null,
    "subject_sha256": null,
    "signature_verified": false,
    "limitations": []
  },
  "project_context": {
    "framework": null,
    "status": "not-detected",
    "project_detected": false,
    "build_dir": null,
    "target": null,
    "board": null,
    "framework_version": null,
    "adapter_capability_id": null,
    "adapter_support_label": "planned",
    "evidence": [],
    "configuration_files": [],
    "settings": [],
    "configuration_origin": {
      "status": "not-inspected",
      "selected_sdkconfig": null,
      "selected_sdkconfig_source": "none",
      "defaults_source": "not-applicable",
      "defaults_order_resolved": false,
      "default_files": [],
      "limitations": []
    },
    "component_lock": {
      "status": "not-detected",
      "path": null,
      "sha256": null,
      "byte_size": 0,
      "lock_version": null,
      "target": null,
      "selected_target_match": null,
      "manifest_hash": null,
      "manifest_freshness": "unverified",
      "direct_dependencies": [],
      "components": [],
      "limitations": []
    },
    "limitations": []
  },
  "findings": [
    {
      "id": "FUSE001:src/network.cpp:18",
      "fingerprint": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
      "rule_id": "FUSE001",
      "rule_version": "1.8.0",
      "analyzer": "fuse-native",
      "title": "Credential-like literal in source",
      "severity": "medium",
      "severity_basis": "rule",
      "severity_score": null,
      "severity_vector": null,
      "severity_version": null,
      "confidence": "high",
      "applicability": "unknown",
      "validation_method": "static",
      "validation_status": "not-validated",
      "category": "secrets",
      "location": {"file": "src/network.cpp", "start_line": 18, "end_line": 18},
      "evidence": "const char* mqtt_password = \"[REDACTED]\";",
      "explanation": "A credential-related name is assigned a literal value. This is a static indicator.",
      "potential_impact": "If active and distributed, the value may permit access to a service or device.",
      "remediation": "Remove and rotate the value; provision it through a protected device process.",
      "references": ["https://cwe.mitre.org/data/definitions/798.html"],
      "component": null,
      "vex_review": null
    }
  ],
  "artifacts": []
}
```

Finding fingerprints stay stable when only a secret value changes because the evidence is redacted before hashing. A path or line move changes the report fingerprint. The separate baseline workflow derives a line-insensitive comparison identity from the rule, path, category, title, and redacted evidence. It handles harmless line insertion and uses an occurrence identity to let teams suppress repeated identical matches independently. Baseline format 1.1 also stores a path-independent identity for native findings. A move is reported only when exactly one unmatched old finding and one unmatched current finding agree; ambiguous matches remain new and resolved for review. OSV findings remain path-sensitive, and suppressions do not follow moved findings.
