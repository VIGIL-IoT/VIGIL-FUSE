# FUSE finding format

FUSE JSON reports use `schema_version: "1.2"`, defined in the packaged [JSON Schema](../src/vigil_fuse/schemas/fuse-report-1.2.schema.json). A report contains tool metadata, target/profile and timestamps, a deterministic scanned-input manifest digest, summary, coverage, findings, and generated artifacts. Counts distinguish discovered, selected, filtered, scanned, and skipped files so an unsupported or filtered target is not presented as a clean scan.

## Finding fields

| Field | Meaning |
| --- | --- |
| `id` | Stable location-based identifier: `rule_id:file:line` |
| `fingerprint` | SHA-256 identity over rule, path, line, and redacted evidence for comparison across runs |
| `rule_id` | Stable detection rule identifier such as `FUSE003` |
| `rule_version` | Version of the rule logic that emitted this finding |
| `analyzer` | Producer name, such as `fuse-native` or a future adapter |
| `title` | Short description of the observed signal |
| `severity` | Potential impact rating: `critical`, `high`, `medium`, `low`, `info`, or `unknown` |
| `confidence` | Strength of evidence supporting this specific detection: `high`, `medium`, or `low` |
| `category` | Security topic, such as `secrets` or `transport-security` |
| `location` | Scan-root-relative file and inclusive start/end lines |
| `evidence` | Short supporting excerpt; secret values and key material must be redacted |
| `explanation` | What the rule observed and the limits of that observation |
| `potential_impact` | Conditional consequence if the configuration is active and applicable |
| `remediation` | Practical next step to remove or verify the risk |
| `references` | Optional primary weakness references, such as CWE entries |

Line numbers are `null` for findings such as dependency advisories when the inventory identifies a manifest or SBOM but cannot identify a source line. Dependency severity uses an upstream qualitative label or a CVSS v3.0/v3.1 base vector when present. `severity: "unknown"` means FUSE could not derive a supported advisory severity; it does not manufacture one from confidence.

## Scan metadata and coverage

The `scan` object identifies the target kind and profile, records UTC start/completion times, and gives `input_manifest_sha256`. That digest covers selected source paths and file hashes, or their skip reasons. It is **not** a digest of every file in the target: unsupported files and files filtered by policy are excluded and counted separately.

The `coverage` object lists all available and enabled rules, analyzer status/version, and file skip reasons. Analyzer states distinguish completed, partial, unavailable, skipped, and failed. An empty finding list alone is never proof that all relevant content was analyzed.

The `artifacts` array records each generated SBOM or analyzer output by relative path, media type, and SHA-256. The report itself is not listed as an artifact because it contains the artifact manifest.

Severity and confidence are separate dimensions. A rule can have high confidence that a risky setting exists while the real-world impact remains uncertain. FUSE should not raise severity merely because evidence is strong, or raise confidence because the potential impact is severe.

## Example

```json
{
  "schema_version": "1.2",
  "tool": {"name": "FUSE", "version": "0.2.0"},
  "target": "device-project",
  "scan": {
    "target_kind": "directory",
    "profile": "generic",
    "started_at": "2026-10-26T12:00:00Z",
    "completed_at": "2026-10-26T12:00:01Z",
    "input_manifest_sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
  },
  "summary": {
    "files_discovered": 12,
    "files_selected": 12,
    "files_filtered": 0,
    "files_scanned": 12,
    "files_skipped": 0,
    "analysis_performed": true,
    "finding_count": 1,
    "severity_counts": {"critical": 0, "high": 0, "medium": 1, "low": 0, "info": 0, "unknown": 0}
  },
  "coverage": {
    "files_skipped_by_reason": {},
    "rules_available": ["FUSE001"],
    "rules_enabled": ["FUSE001"],
    "analyzers": [
      {"name": "fuse-native", "status": "completed", "version": "0.2.0", "detail": "Native rules completed.", "findings": 1}
    ]
  },
  "findings": [
    {
      "id": "FUSE001:src/network.cpp:18",
      "fingerprint": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
      "rule_id": "FUSE001",
      "rule_version": "1.1.0",
      "analyzer": "fuse-native",
      "title": "Credential-like literal assigned in source",
      "severity": "medium",
      "confidence": "high",
      "category": "secrets",
      "location": {"file": "src/network.cpp", "start_line": 18, "end_line": 18},
      "evidence": "const char* mqtt_password = \"[REDACTED]\";",
      "explanation": "A credential-related name is assigned a literal value. This is a static indicator.",
      "potential_impact": "If active and distributed, the value may permit access to a service or device.",
      "remediation": "Remove and rotate the value; provision it through a protected device process.",
      "references": ["https://cwe.mitre.org/data/definitions/798.html"]
    }
  ],
  "artifacts": []
}
```

Finding fingerprints stay stable when only a secret value changes because the evidence is redacted before hashing. A path or line move changes the fingerprint; later schema versions may add content-independent baseline identity for adapters that can provide stable source ranges.
