from __future__ import annotations

import json
from collections import Counter

from . import __version__
from .model import ScanResult


def to_json(result: ScanResult) -> str:
    counts = Counter(finding.severity for finding in result.findings)
    report = {
        "schema_version": "1.2",
        "tool": {"name": "FUSE", "version": __version__},
        "target": result.target,
        "scan": {
            "target_kind": result.target_kind,
            "profile": result.profile,
            "started_at": result.started_at,
            "completed_at": result.completed_at,
            "input_manifest_sha256": result.input_manifest_sha256,
        },
        "summary": {
            "files_discovered": result.files_discovered,
            "files_selected": result.files_selected,
            "files_filtered": result.files_filtered,
            "files_scanned": result.files_scanned,
            "files_skipped": result.files_skipped,
            "analysis_performed": result.analysis_performed,
            "finding_count": len(result.findings),
            "severity_counts": {
                severity: counts.get(severity, 0)
                for severity in ("critical", "high", "medium", "low", "info", "unknown")
            },
        },
        "coverage": {
            "files_skipped_by_reason": result.files_skipped_by_reason,
            "rules_available": list(result.rules_available),
            "rules_enabled": list(result.rules_enabled),
            "analyzers": [
                {
                    "name": item.name,
                    "status": item.status,
                    "version": item.version,
                    "detail": item.detail,
                    "findings": item.findings,
                }
                for item in result.analyzers
            ],
        },
        "findings": [finding.to_dict() for finding in result.findings],
        "artifacts": [
            {
                "path": artifact.path,
                "media_type": artifact.media_type,
                "sha256": artifact.sha256,
            }
            for artifact in result.artifacts
        ],
    }
    return json.dumps(report, indent=2, ensure_ascii=False) + "\n"


def to_text(result: ScanResult) -> str:
    lines = [
        f"FUSE scan: {result.target}",
        f"Target kind: {result.target_kind}",
        f"Profile: {result.profile}",
        f"Scanned manifest SHA-256: {result.input_manifest_sha256}",
        f"Files discovered/selected: {result.files_discovered}/{result.files_selected}",
        f"Files filtered by path policy: {result.files_filtered}",
        f"Files scanned: {result.files_scanned}",
        f"Files skipped: {result.files_skipped}",
        f"Findings: {len(result.findings)}",
    ]
    if result.analyzers:
        lines.append("Analyzers:")
        lines.extend(
            f"  {item.name}: {item.status}"
            + (f" ({item.detail})" if item.detail else "")
            for item in result.analyzers
        )
    if result.artifacts:
        lines.append("Artifacts:")
        lines.extend(f"  {artifact.path} [{artifact.media_type}]" for artifact in result.artifacts)
    if result.files_skipped_by_reason:
        reasons = ", ".join(
            f"{reason}={count}"
            for reason, count in result.files_skipped_by_reason.items()
        )
        lines.append(f"Skip reasons: {reasons}")
    if not result.rules_enabled:
        lines.append(
            "No native rules are enabled; see analyzer coverage for any other analysis stages."
            if result.analysis_performed
            else "No rules are enabled; no security analysis was performed."
        )
        return "\n".join(lines) + "\n"
    if result.target_kind == "sbom" and not result.analysis_performed:
        lines.append("SBOM recognized; use --vulnerabilities to match its components against OSV advisories.")
        return "\n".join(lines) + "\n"
    if result.files_scanned == 0:
        if result.files_filtered and result.analysis_performed:
            lines.append(
                "All supported source/configuration files were filtered out; review analyzer coverage for other analysis stages."
            )
        elif result.files_filtered:
            lines.append("All supported files were filtered out; no analysis was performed.")
        elif result.analysis_performed:
            lines.append(
                "No native source/configuration files were analyzed. Review analyzer coverage and artifacts for other analysis stages."
            )
        else:
            lines.append(f"No supported source/configuration files were analyzed for profile '{result.profile}'.")
        return "\n".join(lines) + "\n"
    if not result.findings:
        lines.append("No findings from the enabled rules.")
        return "\n".join(lines) + "\n"

    lines.append("")
    for finding in result.findings:
        lines.extend(
            [
                f"[{finding.severity.upper()}] {finding.rule_id} - {finding.title}",
                f"  Confidence: {finding.confidence}",
                "  Location: " + finding.file + (
                    f":{finding.start_line}"
                    if finding.start_line is not None
                    else ""
                ),
                f"  Evidence: {finding.evidence}",
                f"  Explanation: {finding.explanation}",
                f"  Potential impact: {finding.potential_impact}",
                f"  Remediation: {finding.remediation}",
            ]
        )
        if finding.references:
            lines.append(f"  References: {', '.join(finding.references)}")
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"
