from __future__ import annotations

import hashlib
import json
import os
import re
import tempfile
from pathlib import Path
from typing import Any

from . import __version__
from .text_safety import safe_report_text

MAX_APPLICABILITY_INPUT_BYTES = 50 * 1024 * 1024
MAX_APPLICABILITY_FINDINGS = 100_000
_SHA256 = re.compile(r"^[a-f0-9]{64}$")
_VEX_JUSTIFICATIONS = {
    "code_not_present",
    "code_not_reachable",
    "requires_configuration",
    "requires_dependency",
    "requires_environment",
    "protected_by_compiler",
    "protected_at_runtime",
    "protected_at_perimeter",
    "protected_by_mitigating_control",
}
_ANALYZER_STATUSES = {
    "completed",
    "partial",
    "unavailable",
    "incompatible",
    "timeout",
    "unsupported",
    "skipped",
    "failed",
}


def _read_report(path: Path) -> tuple[dict[str, Any], str]:
    if path.is_symlink():
        raise ValueError(f"Refusing to read a symbolic-link report: {path}")
    if not path.is_file():
        raise ValueError(f"Applicability input is not a regular file: {path}")
    if path.stat().st_size > MAX_APPLICABILITY_INPUT_BYTES:
        raise ValueError(
            f"Applicability input exceeds the {MAX_APPLICABILITY_INPUT_BYTES // (1024 * 1024)} MiB limit: {path}"
        )
    with path.open("rb") as stream:
        data = stream.read(MAX_APPLICABILITY_INPUT_BYTES + 1)
    if len(data) > MAX_APPLICABILITY_INPUT_BYTES:
        raise ValueError(
            f"Applicability input exceeds the {MAX_APPLICABILITY_INPUT_BYTES // (1024 * 1024)} MiB limit: {path}"
        )
    try:
        report = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as error:
        raise ValueError(f"Applicability input is not valid UTF-8 JSON: {path}") from error
    if not isinstance(report, dict):
        raise ValueError("Applicability input must contain a FUSE report object")
    tool = report.get("tool")
    if not isinstance(tool, dict) or tool.get("name") != "FUSE":
        raise ValueError("Applicability input is not a FUSE report")
    if not isinstance(report.get("schema_version"), str):
        raise ValueError("FUSE report is missing its schema version")
    if not isinstance(report.get("findings"), list):
        raise ValueError("FUSE report is missing its findings array")
    if len(report["findings"]) > MAX_APPLICABILITY_FINDINGS:
        raise ValueError(f"FUSE report exceeds the {MAX_APPLICABILITY_FINDINGS}-finding limit")
    return report, hashlib.sha256(data).hexdigest()


def _text(value: object, label: str, *, limit: int = 1000) -> str:
    cleaned = safe_report_text(value, limit=limit)
    if not cleaned:
        raise ValueError(f"FUSE report contains invalid {label}")
    return cleaned


def _claim(
    *,
    fingerprint: str,
    subject: str,
    predicate: str,
    value: str,
    source: str,
    artifact_digest: str,
    location: str,
    extraction_method: str,
    confidence: str,
    target_identity: dict[str, str],
    limitations: tuple[str, ...],
    source_version: str | None = None,
    justification: str | None = None,
    detail: str | None = None,
    observation_context: str = "STATIC",
) -> dict[str, Any]:
    identity = "\0".join((fingerprint, predicate, value, source, artifact_digest))
    result: dict[str, Any] = {
        "claim_id": hashlib.sha256(identity.encode("utf-8")).hexdigest(),
        "subject": subject,
        "predicate": predicate,
        "value": value,
        "source": source,
        "source_version": source_version,
        "artifact_digest": artifact_digest,
        "target_identity": target_identity,
        "location": location,
        "extraction_method": extraction_method,
        "confidence": confidence,
        "coverage": "observed",
        "observation_context": observation_context,
        "limitations": list(limitations),
    }
    if justification is not None:
        result["justification"] = justification
    if detail is not None:
        result["detail"] = detail
    return result


def _state(
    value: str,
    *,
    claim_ids: tuple[str, ...] = (),
    confidence: str = "low",
    limitations: tuple[str, ...] = (),
) -> dict[str, Any]:
    return {
        "value": value,
        "confidence": confidence,
        "claim_ids": list(claim_ids),
        "limitations": list(limitations),
    }


def _analyzer_version(report: dict[str, Any], name: str) -> str | None:
    coverage = report.get("coverage")
    analyzers = coverage.get("analyzers") if isinstance(coverage, dict) else None
    if not isinstance(analyzers, list):
        return None
    for analyzer in analyzers:
        if isinstance(analyzer, dict) and analyzer.get("name") == name:
            value = safe_report_text(analyzer.get("version"), limit=100)
            return value
    return None


def _analyzer_status(report: dict[str, Any], name: str) -> str:
    coverage = report.get("coverage")
    analyzers = coverage.get("analyzers") if isinstance(coverage, dict) else None
    if isinstance(analyzers, list):
        for analyzer in analyzers:
            status = analyzer.get("status") if isinstance(analyzer, dict) else None
            if (
                isinstance(analyzer, dict)
                and analyzer.get("name") == name
                and isinstance(status, str)
                and status in _ANALYZER_STATUSES
            ):
                return status
    return "not-reported"


def _target_identity(project: dict[str, Any]) -> dict[str, str]:
    identity: dict[str, str] = {}
    for key in ("framework", "target", "board", "framework_version"):
        value = safe_report_text(project.get(key), limit=240)
        if value:
            identity[key] = value
    return identity


def _component_resolution(
    component: dict[str, str], project: dict[str, Any]
) -> tuple[str, str | None, str | None]:
    if project.get("framework") != "esp-idf" or "esp-idf" not in component["ecosystem"].casefold():
        return "UNKNOWN", None, None
    lock = project.get("component_lock")
    if not isinstance(lock, dict):
        return "UNKNOWN", None, None
    components = lock.get("components")
    if not isinstance(components, list) or len(components) > MAX_APPLICABILITY_FINDINGS:
        return "UNKNOWN", None, None
    matching_names = [
        item
        for item in components
        if isinstance(item, dict)
        and isinstance(item.get("name"), str)
        and item["name"].casefold() == component["name"].casefold()
    ]
    if not matching_names:
        return "UNKNOWN", None, None
    digest_value = lock.get("sha256")
    digest = digest_value.casefold() if isinstance(digest_value, str) else ""
    if not _SHA256.fullmatch(digest):
        return "UNKNOWN", None, None
    location = "project_context.component_lock"
    exact = [item for item in matching_names if item.get("version") == component["version"]]
    if lock.get("selected_target_match") is False:
        return "CONTRADICTORY", location, digest
    if (
        len(exact) == 1
        and lock.get("status") == "target-matches"
        and lock.get("selected_target_match") is True
    ):
        return "TRUE", location, digest
    if (
        len(exact) == 1
        and lock.get("status") == "partial"
        and lock.get("selected_target_match") is True
    ):
        return "PARTIAL", location, digest
    if (
        not exact
        and lock.get("status") == "target-matches"
        and lock.get("selected_target_match") is True
    ):
        return "CONTRADICTORY", location, digest
    return "UNKNOWN", None, None


def analyze_report(path: Path) -> dict[str, Any]:
    """Compose dependency, configured-target, and exact VEX evidence from a FUSE report."""
    report, report_digest = _read_report(path)
    raw_findings = report["findings"]
    if not all(isinstance(item, dict) for item in raw_findings):
        raise ValueError("FUSE report contains a malformed finding")
    project = report.get("project_context")
    project = project if isinstance(project, dict) else {}
    target_identity = _target_identity(project)
    product_context = report.get("product_context")
    product_context = product_context if isinstance(product_context, dict) else {}
    vex_import = product_context.get("vex_import")
    vex_import = vex_import if isinstance(vex_import, dict) else {}
    analyzer_version = _analyzer_version(report, "osv-scanner")
    source_coverage = report.get("coverage")

    claims: list[dict[str, Any]] = []
    assessments: list[dict[str, Any]] = []
    seen_fingerprints: set[str] = set()
    for finding in raw_findings:
        if finding.get("category") != "dependency-vulnerability":
            continue
        component_data = finding.get("component")
        if not isinstance(component_data, dict):
            raise ValueError("Dependency finding is missing its component identity")
        component = {
            key: _text(component_data.get(key), f"component {key}", limit=1000)
            for key in ("name", "version", "ecosystem")
        }
        purl = safe_report_text(component_data.get("purl"), limit=2048)
        if purl:
            component["purl"] = purl
        rule_id = _text(finding.get("rule_id"), "finding rule ID", limit=500)
        analyzer = _text(finding.get("analyzer"), "finding analyzer", limit=100)
        raw_fingerprint = finding.get("fingerprint")
        if not isinstance(raw_fingerprint, str) or not _SHA256.fullmatch(raw_fingerprint):
            raise ValueError("FUSE report contains an invalid finding fingerprint")
        fingerprint = raw_fingerprint
        if fingerprint in seen_fingerprints:
            raise ValueError("FUSE report contains duplicate dependency finding fingerprints")
        seen_fingerprints.add(fingerprint)
        subject = component.get("purl") or f"{component['name']}@{component['version']}"
        location = f"finding:{fingerprint}"
        finding_confidence = finding.get("confidence")
        confidence = (
            finding_confidence
            if isinstance(finding_confidence, str)
            and finding_confidence in {"high", "medium", "low"}
            else "low"
        )

        finding_claim = _claim(
            fingerprint=fingerprint,
            subject=subject,
            predicate="DEPENDENCY_PRESENT",
            value="TRUE",
            source="FUSE finding",
            source_version=analyzer_version if analyzer == "osv-scanner" else None,
            artifact_digest=report_digest,
            location=location,
            extraction_method="normalized-fuse-report",
            confidence=confidence,
            target_identity=target_identity,
            limitations=("A dependency finding does not establish build inclusion or deployment.",),
        )
        claims.append(finding_claim)
        dependency_state = _state(
            "TRUE", claim_ids=(finding_claim["claim_id"],), confidence=confidence
        )

        advisory_match = (
            analyzer == "osv-scanner"
            and finding.get("validation_method") == "advisory-match"
            and rule_id.startswith("OSV-")
        )
        version_claim: dict[str, Any] | None = None
        if advisory_match:
            version_claim = _claim(
                fingerprint=fingerprint,
                subject=subject,
                predicate="VERSION_AFFECTED",
                value="TRUE",
                source="OSV-Scanner advisory match",
                source_version=analyzer_version,
                artifact_digest=report_digest,
                location=location,
                extraction_method="osv-finding-exact-component-version",
                confidence=confidence,
                target_identity=target_identity,
                limitations=(
                    "This preserves the upstream advisory match; FUSE does not independently verify advisory version ranges.",
                ),
            )
            claims.append(version_claim)
        version_state = (
            _state("TRUE", claim_ids=(version_claim["claim_id"],), confidence=confidence)
            if version_claim
            else _state(
                "UNKNOWN",
                limitations=("No supported OSV advisory match was recorded for this finding.",),
            )
        )

        resolution, resolution_location, resolution_digest = _component_resolution(
            component, project
        )
        resolution_claim: dict[str, Any] | None = None
        if resolution_location and resolution_digest:
            resolution_claim = _claim(
                fingerprint=fingerprint,
                subject=subject,
                predicate="COMPONENT_RESOLVED_FOR_CONFIGURED_TARGET",
                value=resolution,
                source="ESP-IDF dependencies.lock",
                artifact_digest=resolution_digest,
                location=resolution_location,
                extraction_method="exact-component-name-version-match",
                confidence="high" if resolution == "TRUE" else "medium",
                target_identity=target_identity,
                limitations=(
                    "Lock resolution does not prove that the component was compiled into or shipped in a firmware image.",
                ),
            )
            claims.append(resolution_claim)
        resolution_state = _state(
            resolution,
            claim_ids=(resolution_claim["claim_id"],) if resolution_claim else (),
            confidence="high" if resolution == "TRUE" else "medium" if resolution_claim else "low",
            limitations=("Only exact ESP-IDF component name and version matches are correlated.",),
        )

        vex_review = finding.get("vex_review")
        vex_digest_value = vex_import.get("sha256")
        vex_digest = (
            vex_digest_value.casefold()
            if isinstance(vex_digest_value, str) and _SHA256.fullmatch(vex_digest_value.casefold())
            else None
        )
        vex_review_valid = (
            isinstance(vex_review, dict)
            and vex_import.get("status") in {"imported", "partial"}
            and vex_digest is not None
            and isinstance(vex_import.get("product_purl"), str)
            and vex_import.get("product_purl") == product_context.get("product_purl")
            and bool(component.get("purl"))
        )
        vex_claim: dict[str, Any] | None = None
        assessment = "UNDER_INVESTIGATION" if advisory_match else "UNKNOWN"
        assessment_source = "evidence-gap" if advisory_match else "unsupported-advisory-provider"
        if vex_review_valid and isinstance(vex_review, dict) and vex_digest is not None:
            vex_state = vex_review.get("state")
            justification = safe_report_text(vex_review.get("justification"), limit=240)
            detail = safe_report_text(vex_review.get("detail"), limit=1000)
            if vex_state in {"exploitable", "not_affected"} and (
                vex_state != "not_affected" or justification in _VEX_JUSTIFICATIONS
            ):
                assessment = "AFFECTED" if vex_state == "exploitable" else "NOT_AFFECTED"
                assessment_source = "reviewed-vex"
                vex_claim = _claim(
                    fingerprint=fingerprint,
                    subject=subject,
                    predicate="REVIEWED_VEX_ASSESSMENT",
                    value=assessment,
                    source="CycloneDX VEX review",
                    artifact_digest=vex_digest,
                    location=location,
                    extraction_method="exact-product-component-advisory-match",
                    confidence="medium",
                    target_identity=target_identity,
                    limitations=(
                        "Imported VEX is review metadata; its signature is not verified by FUSE.",
                    ),
                    justification=justification,
                    detail=detail,
                    observation_context="REVIEWED",
                )
                claims.append(vex_claim)

        assessment_claims = (
            (vex_claim["claim_id"],)
            if vex_claim
            else ((version_claim["claim_id"],) if version_claim else (finding_claim["claim_id"],))
        )
        states = {
            "DEPENDENCY_PRESENT": dependency_state,
            "VERSION_AFFECTED": version_state,
            "COMPONENT_RESOLVED_FOR_CONFIGURED_TARGET": resolution_state,
            "BUILD_INCLUDED": _state(
                "UNKNOWN",
                limitations=("The report has no component-to-compiled-object evidence.",),
            ),
            "FEATURE_ENABLED": _state(
                "UNKNOWN", limitations=("No advisory-to-configuration mapping is available.",)
            ),
            "DEVICE_ENABLED": _state(
                "UNKNOWN", limitations=("No device instantiation evidence is correlated.",)
            ),
            "BINARY_PRESENT": _state(
                "UNKNOWN",
                limitations=(
                    "The scan report does not link this component to a firmware artifact.",
                ),
            ),
            "RUNTIME_REACHABLE": _state(
                "UNKNOWN", limitations=("No runtime reachability evidence was supplied.",)
            ),
            "PHYSICALLY_EXPOSED": _state(
                "UNKNOWN",
                limitations=("No physical interface evidence is correlated to this finding.",),
            ),
        }
        vulnerability_id = rule_id.removeprefix("OSV-") if rule_id.startswith("OSV-") else rule_id
        assessments.append(
            {
                "finding_fingerprint": fingerprint,
                "vulnerability_id": vulnerability_id,
                "component": component,
                "assessment": assessment,
                "assessment_source": assessment_source,
                "assessment_claim_ids": list(assessment_claims),
                "states": states,
            }
        )

    assessments.sort(key=lambda item: item["finding_fingerprint"])
    claims.sort(key=lambda item: item["claim_id"])
    counts = {name: 0 for name in ("AFFECTED", "NOT_AFFECTED", "UNDER_INVESTIGATION", "UNKNOWN")}
    for item in assessments:
        counts[item["assessment"]] += 1
    return {
        "schema_version": "1.0",
        "tool": {"name": "FUSE", "version": __version__},
        "source_report": {
            "schema_version": report["schema_version"],
            "sha256": report_digest,
        },
        "summary": {"assessment_count": len(assessments), "assessment_states": counts},
        "coverage": {
            "source_discovery_complete": (
                source_coverage.get("discovery_complete")
                if isinstance(source_coverage, dict)
                and isinstance(source_coverage.get("discovery_complete"), bool)
                else None
            ),
            "dependency_analyzer_status": _analyzer_status(report, "osv-scanner"),
            "findings_assessed": len(assessments),
        },
        "claims": claims,
        "assessments": assessments,
        "limitations": [
            "FUSE does not infer AFFECTED or NOT_AFFECTED from inventory, lock, build, configuration, binary, or hardware metadata alone.",
            "AFFECTED and NOT_AFFECTED are emitted only when an exact imported VEX review explicitly records that state.",
            "Imported VEX signatures, reviewers, and authorities are not authenticated.",
        ],
    }


def write_report(input_path: Path, output_path: Path, report: dict[str, Any]) -> None:
    if output_path.is_symlink():
        raise ValueError(f"Refusing to write through a symbolic link: {output_path}")
    if output_path.exists() and not output_path.is_file():
        raise ValueError(f"Applicability output must be a regular file: {output_path}")
    input_resolved = input_path.resolve(strict=True)
    output_resolved = output_path.resolve(strict=False)
    if os.path.normcase(str(input_resolved)) == os.path.normcase(str(output_resolved)):
        raise ValueError("Applicability output cannot overwrite its source FUSE report")
    output_path.parent.mkdir(parents=True, exist_ok=True)
    temporary_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            newline="\n",
            prefix=f".{output_path.name}.",
            suffix=".tmp",
            dir=output_path.parent,
            delete=False,
        ) as temporary:
            temporary.write(json.dumps(report, indent=2, ensure_ascii=False) + "\n")
            temporary_path = Path(temporary.name)
        os.replace(temporary_path, output_path)
    finally:
        if temporary_path is not None and temporary_path.exists():
            temporary_path.unlink()
