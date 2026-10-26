from __future__ import annotations

import json
from urllib.parse import quote

from . import __version__
from .model import Finding, ScanResult

_LEVEL = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "warning",
    "info": "note",
    "unknown": "note",
}


def to_sarif(result: ScanResult) -> str:
    """Serialize FUSE findings as SARIF 2.1.0 for CI and code-scanning tools."""
    definitions: dict[str, dict[str, object]] = {}
    for finding in result.findings:
        definitions.setdefault(
            finding.rule_id,
            {
                "id": finding.rule_id,
                "shortDescription": {"text": finding.title},
                "fullDescription": {"text": finding.explanation},
                "defaultConfiguration": {"level": _LEVEL[finding.severity]},
                "properties": {
                    "severity": finding.severity,
                    "confidence": finding.confidence,
                    "category": finding.category,
                    "version": finding.rule_version,
                },
                **(
                    {"helpUri": finding.references[0]}
                    if finding.references
                    else {}
                ),
            },
        )

    results: list[dict[str, object]] = []
    for finding in result.findings:
        physical_location: dict[str, object] = {
            "artifactLocation": {"uri": quote(finding.file, safe="/._-")}
        }
        if finding.start_line is not None:
            region: dict[str, int] = {"startLine": finding.start_line}
            if finding.end_line is not None:
                region["endLine"] = finding.end_line
            physical_location["region"] = region
        location = {"physicalLocation": physical_location}

        results.append(
            {
                "ruleId": finding.rule_id,
                "level": _LEVEL[finding.severity],
                "message": {
                    "text": f"{finding.title}. {finding.explanation} Evidence: {finding.evidence}"
                },
                "locations": [location],
                "partialFingerprints": {
                    "vigilIoTFingerprint/v1": finding.fingerprint,
                },
                "properties": {
                    "fuseId": finding.id,
                    "severity": finding.severity,
                    "confidence": finding.confidence,
                    "category": finding.category,
                    "analyzer": finding.analyzer,
                    "potentialImpact": finding.potential_impact,
                    "remediation": finding.remediation,
                    "evidence": finding.evidence,
                    "references": list(finding.references),
                },
            }
        )

    report = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "FUSE",
                        "semanticVersion": __version__,
                        "rules": list(definitions.values()),
                    }
                },
                "artifacts": [
                    {
                        "location": {"uri": quote(artifact.path, safe="/._-")},
                        "mimeType": artifact.media_type,
                        "hashes": {"sha-256": artifact.sha256},
                    }
                    for artifact in result.artifacts
                ],
                "results": results,
                "properties": {
                    "target": result.target,
                    "profile": result.profile,
                    "inputManifestSha256": result.input_manifest_sha256,
                    "analysisPerformed": result.analysis_performed,
                    "analyzers": [
                        {
                            "name": analyzer.name,
                            "status": analyzer.status,
                            "version": analyzer.version,
                        }
                        for analyzer in result.analyzers
                    ],
                },
            }
        ],
    }
    return json.dumps(report, indent=2, ensure_ascii=False) + "\n"
