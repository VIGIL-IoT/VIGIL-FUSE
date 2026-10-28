from __future__ import annotations

import json
from collections import Counter

from . import __version__
from .model import ScanResult
from .support import capability_for_scan


def _input_inventory_scope(result: ScanResult) -> str:
    if result.target_kind == "firmware-image":
        return "Not applicable to a firmware-image input; the selected firmware stage handles this input."
    if result.target_kind == "sbom":
        return "Not applicable to a supplied SBOM; selected inventory or advisory stages handle this input."
    if result.target_kind != "directory":
        return "The single target file classified against the active source profile; separate inventory stages may still classify it."
    return (
        "Regular non-symbolic files encountered under traversed target paths that are not selected by the active source profile. "
        "Configured and generated directories and explicit excludes are omitted; include patterns affect selected source files only. "
        "Separate inventory stages may still classify a file type."
    )


def to_json(result: ScanResult) -> str:
    counts = Counter(finding.severity for finding in result.findings)
    report = {
        "schema_version": "1.8",
        "tool": {"name": "FUSE", "version": __version__},
        "target": result.target,
        "scan": {
            "target_kind": result.target_kind,
            "profile": result.profile,
            "network_policy": result.network_policy,
            "started_at": result.started_at,
            "completed_at": result.completed_at,
            "input_manifest_sha256": result.input_manifest_sha256,
        },
        "summary": {
            "files_discovered": result.files_discovered,
            "files_selected": result.files_selected,
            "files_filtered": result.files_filtered,
            "files_scanned": result.files_scanned,
            "source_bytes_read": result.source_bytes_read,
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
            "discovery_complete": result.discovery_complete,
            "limits_reached": list(result.limits_reached),
            "input_inventory": {
                "scope": _input_inventory_scope(result),
                "complete": result.discovery_complete,
                "unsupported_file_count": sum(result.unsupported_file_types.values()),
                "unsupported_file_types": result.unsupported_file_types,
            },
            "support": capability_for_scan(result),
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
        "hardware_inventory": {
            "scope": result.hardware_inventory.scope,
            "complete": result.hardware_inventory.complete,
            "present": bool(result.hardware_inventory.artifacts),
            "file_count": len(result.hardware_inventory.artifacts),
            "category_counts": result.hardware_inventory.category_counts,
            "artifacts": [
                {
                    "path": item.path,
                    "category": item.category,
                    "format": item.format,
                }
                for item in result.hardware_inventory.artifacts
            ],
        },
        "build_context": {
            "platformio": {
                "status": result.platformio_inventory.status,
                "path": result.platformio_inventory.path,
                "sha256": result.platformio_inventory.sha256,
                "byte_size": result.platformio_inventory.byte_size,
                "default_environments": list(result.platformio_inventory.default_environments),
                "selected_environments": list(result.platformio_inventory.selected_environments),
                "environments": [
                    {
                        "name": item.name,
                        "platform": item.platform,
                        "board": item.board,
                        "frameworks": list(item.frameworks),
                        "build_type": item.build_type,
                        "upload_protocol": item.upload_protocol,
                        "debug_tool": item.debug_tool,
                        "extends": item.extends,
                    }
                    for item in result.platformio_inventory.environments
                ],
                "limitations": list(result.platformio_inventory.limitations),
            },
            "compilation_database": {
                "status": result.compilation_database.status,
                "path": result.compilation_database.path,
                "sha256": result.compilation_database.sha256,
                "byte_size": result.compilation_database.byte_size,
                "entry_count": result.compilation_database.entry_count,
                "unique_translation_units": result.compilation_database.unique_translation_units,
                "in_target_source_count": result.compilation_database.in_target_source_count,
                "external_source_count": result.compilation_database.external_source_count,
                "compiler_families": result.compilation_database.compiler_families,
                "malformed_entries": result.compilation_database.malformed_entries,
                "limitations": list(result.compilation_database.limitations),
            },
        },
        "hardware_bom": {
            "status": result.hardware_bom.status,
            "source_path": result.hardware_bom.source_path,
            "sha256": result.hardware_bom.sha256,
            "byte_size": result.hardware_bom.byte_size,
            "format": result.hardware_bom.format,
            "component_count": result.hardware_bom.component_count,
            "quantity_total": result.hardware_bom.quantity_total,
            "components": [
                {
                    "reference": item.reference,
                    "name": item.name,
                    "quantity": item.quantity,
                    "footprint": item.footprint,
                    "manufacturer": item.manufacturer,
                    "part_number": item.part_number,
                    "description": item.description,
                }
                for item in result.hardware_bom.components
            ],
            "limitations": list(result.hardware_bom.limitations),
        },
        "product_context": {
            "product_purl": result.product_purl,
            "vex_import": {
                "status": result.vex_import.status,
                "source_path": result.vex_import.source_path,
                "sha256": result.vex_import.sha256,
                "byte_size": result.vex_import.byte_size,
                "product_purl": result.vex_import.product_purl,
                "record_count": result.vex_import.record_count,
                "matched_findings": result.vex_import.matched_findings,
                "unmatched_records": result.vex_import.unmatched_records,
                "limitations": list(result.vex_import.limitations),
            },
        },
        "provenance": {
            "status": result.provenance.status,
            "source_path": result.provenance.source_path,
            "sha256": result.provenance.sha256,
            "byte_size": result.provenance.byte_size,
            "predicate_type": result.provenance.predicate_type,
            "builder_id": result.provenance.builder_id,
            "build_type": result.provenance.build_type,
            "subject_name": result.provenance.subject_name,
            "subject_sha256": result.provenance.subject_sha256,
            "signature_verified": result.provenance.signature_verified,
            "limitations": list(result.provenance.limitations),
        },
        "project_context": {
            "framework": result.project_context.framework,
            "status": result.project_context.status,
            "project_detected": result.project_context.project_detected,
            "build_dir": result.project_context.build_dir,
            "target": result.project_context.target,
            "board": result.project_context.board,
            "framework_version": result.project_context.framework_version,
            "adapter_capability_id": (
                f"build-context.{result.project_context.framework}"
                if result.project_context.framework
                else None
            ),
            "adapter_support_label": (
                "experimental" if result.project_context.framework else "planned"
            ),
            "evidence": list(result.project_context.evidence),
            "configuration_files": [
                {
                    "path": item.path,
                    "role": item.role,
                    "sha256": item.sha256,
                    "byte_size": item.byte_size,
                }
                for item in result.project_context.configuration_files
            ],
            "settings": [
                {
                    "name": item.name,
                    "value": item.value,
                    "path": item.path,
                    "line": item.line,
                }
                for item in result.project_context.settings
            ],
            "configuration_origin": {
                "status": result.project_context.configuration_origin.status,
                "selected_sdkconfig": result.project_context.configuration_origin.selected_sdkconfig,
                "selected_sdkconfig_source": result.project_context.configuration_origin.selected_sdkconfig_source,
                "defaults_source": result.project_context.configuration_origin.defaults_source,
                "defaults_order_resolved": result.project_context.configuration_origin.defaults_order_resolved,
                "default_files": [
                    {
                        "path": item.path,
                        "order": item.order,
                        "target_specific": item.target_specific,
                        "state": item.state,
                        "sha256": item.sha256,
                        "byte_size": item.byte_size,
                    }
                    for item in result.project_context.configuration_origin.default_files
                ],
                "limitations": list(result.project_context.configuration_origin.limitations),
            },
            "component_lock": {
                "status": result.project_context.component_lock.status,
                "path": result.project_context.component_lock.path,
                "sha256": result.project_context.component_lock.sha256,
                "byte_size": result.project_context.component_lock.byte_size,
                "lock_version": result.project_context.component_lock.lock_version,
                "target": result.project_context.component_lock.target,
                "selected_target_match": result.project_context.component_lock.selected_target_match,
                "manifest_hash": result.project_context.component_lock.manifest_hash,
                "manifest_freshness": result.project_context.component_lock.manifest_freshness,
                "direct_dependencies": list(result.project_context.component_lock.direct_dependencies),
                "components": [
                    {
                        "name": item.name,
                        "version": item.version,
                        "source_type": item.source_type,
                        "direct": item.direct,
                        "component_hash": item.component_hash,
                        "compatible_targets": list(item.compatible_targets),
                        "dependencies": list(item.dependencies),
                    }
                    for item in result.project_context.component_lock.components
                ],
                "limitations": list(result.project_context.component_lock.limitations),
            },
            "limitations": list(result.project_context.limitations),
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
    support = capability_for_scan(result)
    lines = [
        f"FUSE scan: {result.target}",
        f"Target kind: {result.target_kind}",
        f"Profile: {result.profile}",
        f"Support: {support['label']} / {support['status']}",
        f"Network policy: {result.network_policy}",
        f"Scanned manifest SHA-256: {result.input_manifest_sha256}",
        f"Files discovered/selected: {result.files_discovered}/{result.files_selected}",
        f"Files filtered by path policy: {result.files_filtered}",
        f"Files scanned: {result.files_scanned}",
        f"Source bytes read: {result.source_bytes_read}",
        f"Files skipped: {result.files_skipped}",
        f"Discovery complete: {'yes' if result.discovery_complete else 'no'}",
        f"Findings: {len(result.findings)}",
        f"Hardware artifacts: {len(result.hardware_inventory.artifacts)}",
    ]
    pio = result.platformio_inventory
    if pio.status != "not-detected":
        lines.append(
            f"PlatformIO: {pio.status}; {len(pio.environments)} environment(s), "
            f"selected: {', '.join(pio.selected_environments) or 'none'}"
        )
        for item in pio.environments:
            details = ", ".join(value for value in (item.platform, item.board, ",".join(item.frameworks)) if value)
            lines.append(f"  {item.name}" + (f" [{details}]" if details else ""))
        lines.extend(f"  PlatformIO limit: {item}" for item in pio.limitations)
    database = result.compilation_database
    if database.status != "not-detected":
        lines.append(
            f"Compilation database: {database.status}; {database.unique_translation_units} unique "
            f"translation unit(s), {database.in_target_source_count} in target, "
            f"{database.external_source_count} external"
        )
        lines.append("  Commands were indexed as data and were not executed.")
        lines.extend(f"  Compilation database limit: {item}" for item in database.limitations)
    bom = result.hardware_bom
    if bom.status != "not-requested":
        lines.append(
            f"Hardware BOM: {bom.status}; {bom.component_count} line item(s), "
            f"{bom.quantity_total} listed part(s)"
        )
        lines.extend(f"  BOM limit: {item}" for item in bom.limitations)
    if result.product_purl:
        lines.append(f"Product PURL: {result.product_purl}")
    if result.vex_import.status != "not-requested":
        lines.append(
            f"CycloneDX VEX: {result.vex_import.status}; "
            f"{result.vex_import.matched_findings} finding(s) annotated; base findings remain unchanged"
        )
        lines.extend(f"  VEX limit: {item}" for item in result.vex_import.limitations)
    provenance = result.provenance
    if provenance.status != "not-requested":
        lines.append(
            f"SLSA provenance: {provenance.status}; signature verified: "
            f"{'yes' if provenance.signature_verified else 'no'}"
        )
        if provenance.builder_id:
            lines.append(f"  Claimed builder: {provenance.builder_id}")
        lines.extend(f"  Provenance limit: {item}" for item in provenance.limitations)
    if result.target_kind in {"firmware-image", "sbom"}:
        lines.append("Source-profile file inventory: not applicable to this specialized input.")
    else:
        lines.append(
            f"Files not selected by the source profile: {sum(result.unsupported_file_types.values())}"
        )
    if result.unsupported_file_types:
        lines.extend(
            f"  {file_type}: {count}"
            for file_type, count in result.unsupported_file_types.items()
        )
    if not result.discovery_complete:
        lines.append("Input inventory is incomplete because discovery stopped at a resource limit.")
    context = result.project_context
    if context.framework:
        lines.append(
            f"Project context: {context.framework} / {context.status} "
            f"(adapter support: experimental)"
        )
        if context.build_dir:
            lines.append(f"Selected build directory: {context.build_dir}")
        if context.target:
            lines.append(f"Build target: {context.target}")
        if context.board:
            lines.append(f"Build board: {context.board}")
        if context.framework_version:
            lines.append(f"Framework version: {context.framework_version}")
        if context.configuration_files:
            lines.append("Build context files:")
            lines.extend(
                f"  {item.path} [{item.role}]"
                + (f" sha256:{item.sha256}" if item.sha256 else " (not read)")
                for item in context.configuration_files
            )
        if context.settings:
            lines.append("Selected generated security settings:")
            lines.extend(
                f"  {item.name}={item.value} ({item.path}:{item.line})"
                for item in context.settings
            )
        origin = context.configuration_origin
        if origin.status != "not-inspected":
            lines.append(f"ESP-IDF configuration origin: {origin.status}")
            if origin.selected_sdkconfig:
                lines.append(
                    f"  Selected sdkconfig: {origin.selected_sdkconfig} [{origin.selected_sdkconfig_source}]"
                )
            if origin.default_files:
                lines.append("  Defaults candidates in processing order:")
                lines.extend(
                    f"    {item.order}. {item.path} [{item.state}]"
                    + (" target-specific" if item.target_specific else "")
                    for item in origin.default_files
                )
            lines.extend(f"  Configuration origin limit: {item}" for item in origin.limitations)
        lock = context.component_lock
        if lock.path:
            lines.append(
                f"ESP-IDF resolved dependencies: {len(lock.components)} component(s) / {lock.status}"
            )
            lines.append(f"  Lockfile: {lock.path} (sha256:{lock.sha256})" if lock.sha256 else f"  Lockfile: {lock.path} (not hashed)")
            if lock.target:
                lines.append(f"  Lock target: {lock.target}")
            if lock.selected_target_match is not None:
                lines.append(f"  Selected build target match: {'yes' if lock.selected_target_match else 'no'}")
            lines.extend(
                f"  {item.name}@{item.version} [{item.source_type}, {'direct' if item.direct else 'transitive'}]"
                for item in lock.components
            )
            lines.extend(f"  Dependency inventory limit: {item}" for item in lock.limitations)
        if context.limitations:
            lines.extend(f"  Context limit: {item}" for item in context.limitations)
    if result.hardware_inventory.artifacts:
        lines.append("Hardware inventory:")
        for category, count in result.hardware_inventory.category_counts.items():
            lines.append(f"  {category}: {count}")
        lines.extend(
            f"  {item.path} [{item.format}]"
            for item in result.hardware_inventory.artifacts
        )
    else:
        lines.append("Hardware inventory: no recognized hardware artifacts in target scope.")
    if result.limits_reached:
        lines.append(f"Resource limits reached: {', '.join(result.limits_reached)}")
    if not result.hardware_inventory.complete:
        lines.append("Hardware inventory is incomplete because discovery stopped at a resource limit.")
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
                f"  Severity basis: {finding.severity_basis}"
                + (f" ({finding.severity_score:g})" if finding.severity_score is not None else ""),
                f"  Confidence: {finding.confidence}",
                f"  Applicability: {finding.applicability}",
                f"  Validation: {finding.validation_method} ({finding.validation_status})",
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
        if finding.severity_vector:
            lines.append(
                f"  Severity vector: {finding.severity_vector}"
                + (f" (CVSS {finding.severity_version})" if finding.severity_version else "")
            )
        if finding.component:
            lines.append(
                f"  Component: {finding.component.ecosystem} {finding.component.name}@{finding.component.version}"
            )
            if finding.component.purl:
                lines.append(f"  Component PURL: {finding.component.purl}")
        if finding.vex_review:
            lines.append(
                f"  Product review: CycloneDX VEX state {finding.vex_review.state}; "
                "this context does not remove or downgrade the finding"
            )
            if finding.vex_review.justification:
                lines.append(f"  Review justification: {finding.vex_review.justification}")
            if finding.vex_review.detail:
                lines.append(f"  Review detail: {finding.vex_review.detail}")
        if finding.references:
            lines.append(f"  References: {', '.join(finding.references)}")
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"
