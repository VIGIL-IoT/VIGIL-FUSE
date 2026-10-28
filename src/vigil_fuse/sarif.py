from __future__ import annotations

import hashlib
import json
from collections import defaultdict
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
MAX_SARIF_BYTES = 9 * 1024 * 1024


def _primary_location_fingerprints(findings: tuple[Finding, ...]) -> dict[int, str]:
    """Build line-shift-stable GitHub fingerprints without exposing raw secrets.

    FUSE evidence is already redacted before it reaches the report model. Hashing
    that normalized evidence keeps identities stable when a finding moves, while
    an occurrence counter distinguishes repeated matches in one file.
    """
    ordered = sorted(
        enumerate(findings),
        key=lambda item: (
            item[1].file.replace("\\", "/"),
            item[1].start_line or 0,
            item[1].rule_id,
            item[1].id,
            item[0],
        ),
    )
    seen: defaultdict[tuple[str, str, str], int] = defaultdict(int)
    fingerprints: dict[int, str] = {}
    for index, finding in ordered:
        evidence = " ".join(finding.evidence.split())
        if not evidence:
            evidence = "\0".join(
                (finding.analyzer, finding.rule_id, finding.category, finding.title)
            )
        evidence_hash = hashlib.sha256(evidence.encode("utf-8")).hexdigest()
        occurrence_key = (finding.file.replace("\\", "/"), finding.rule_id, evidence_hash)
        seen[occurrence_key] += 1
        fingerprints[index] = f"{evidence_hash}:{seen[occurrence_key]}"
    return fingerprints


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
                    "severityBasis": finding.severity_basis,
                    "severityScore": finding.severity_score,
                    "severityVector": finding.severity_vector,
                    "severityVersion": finding.severity_version,
                    "confidence": finding.confidence,
                    "applicability": finding.applicability,
                    "validationMethod": finding.validation_method,
                    "validationStatus": finding.validation_status,
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
    primary_fingerprints = _primary_location_fingerprints(result.findings)
    for index, finding in enumerate(result.findings):
        physical_location: dict[str, object] = {
            "artifactLocation": {
                "uri": quote(finding.file, safe="/._-"),
                "uriBaseId": "%SRCROOT%",
            }
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
                    "primaryLocationLineHash": primary_fingerprints[index],
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
                    "component": (
                        {
                            "name": finding.component.name,
                            "version": finding.component.version,
                            "ecosystem": finding.component.ecosystem,
                            "purl": finding.component.purl,
                        }
                        if finding.component
                        else None
                    ),
                    "vexReview": (
                        {
                            "state": finding.vex_review.state,
                            "justification": finding.vex_review.justification,
                            "detail": finding.vex_review.detail,
                        }
                        if finding.vex_review
                        else None
                    ),
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
                "originalUriBaseIds": {
                    "%SRCROOT%": {"uri": "./"},
                },
                "results": results,
                "properties": {
                    "target": result.target,
                    "profile": result.profile,
                    "networkPolicy": result.network_policy,
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
                    "sarifExport": {
                        "resultsAvailable": len(results),
                        "resultsIncluded": len(results),
                        "resultsOmitted": 0,
                        "maxBytes": MAX_SARIF_BYTES,
                    },
                },
            }
        ],
    }
    serialized = json.dumps(report, indent=2, ensure_ascii=False) + "\n"
    if len(serialized.encode("utf-8")) <= MAX_SARIF_BYTES:
        return serialized

    run = report["runs"][0]
    left, right = 0, len(results)
    while left < right:
        included = (left + right + 1) // 2
        run["results"] = results[:included]
        run["properties"]["sarifExport"] = {
            "resultsAvailable": len(results),
            "resultsIncluded": included,
            "resultsOmitted": len(results) - included,
            "maxBytes": MAX_SARIF_BYTES,
        }
        candidate = json.dumps(report, indent=2, ensure_ascii=False) + "\n"
        if len(candidate.encode("utf-8")) <= MAX_SARIF_BYTES:
            left = included
        else:
            right = included - 1

    run["results"] = results[:left]
    run["properties"]["sarifExport"] = {
        "resultsAvailable": len(results),
        "resultsIncluded": left,
        "resultsOmitted": len(results) - left,
        "maxBytes": MAX_SARIF_BYTES,
    }
    serialized = json.dumps(report, indent=2, ensure_ascii=False) + "\n"
    return serialized
