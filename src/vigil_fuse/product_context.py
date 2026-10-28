from __future__ import annotations

import hashlib
import json
import os
import re
from dataclasses import replace
from pathlib import Path
from urllib.parse import quote
from typing import Any

from .build_context import _read_bounded, _select_project_file
from .model import (
    DependencyComponent,
    Finding,
    ProvenanceRecord,
    VexImport,
    VexReview,
)
from .text_safety import safe_report_text

MAX_PRODUCT_CONTEXT_BYTES = 10 * 1024 * 1024
_SHA256 = re.compile(r"^[a-f0-9]{64}$")
_PURL_TYPE = re.compile(r"^[a-z][a-z0-9.+-]*$")
_VULNERABILITY_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$")
_VEX_STATES = {
    "resolved",
    "resolved_with_pedigree",
    "exploitable",
    "in_triage",
    "false_positive",
    "not_affected",
}
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


def _encoded(value: str) -> str:
    return quote(value, safe="-._~")


def validate_package_purl(value: str) -> str:
    """Validate the structural parts of a package URL used as product identity."""
    if not isinstance(value, str) or not value.startswith("pkg:"):
        raise ValueError("--product-purl must be a valid package URL beginning with pkg:")
    if any(character.isspace() for character in value) or safe_report_text(value, limit=len(value)) != value:
        raise ValueError("--product-purl cannot contain whitespace or control characters")
    if re.search(r"%(?![A-Fa-f0-9]{2})", value):
        raise ValueError("--product-purl contains an invalid percent escape")
    package_type, separator, package_path = value[4:].partition("/")
    if not separator or not _PURL_TYPE.fullmatch(package_type):
        raise ValueError("--product-purl must include a package type and name")
    identity_path = package_path.split("?", 1)[0].split("#", 1)[0]
    segments = identity_path.split("/")
    if not identity_path or any(not item for item in segments):
        raise ValueError("--product-purl must include a package name")
    if not segments[-1].rsplit("@", 1)[0]:
        raise ValueError("--product-purl must include a package name")
    if any(character in identity_path for character in "[]\\"):
        raise ValueError("--product-purl contains an unsupported path character")
    return value


def package_purl(ecosystem: str, name: str, version: str) -> str | None:
    """Build package URLs for common OSV ecosystems when the package identity is unambiguous."""
    ecosystem_key = ecosystem.casefold()
    package_type = {
        "pypi": "pypi",
        "npm": "npm",
        "maven": "maven",
        "go": "golang",
        "golang": "golang",
        "cargo": "cargo",
        "crates.io": "cargo",
        "nuget": "nuget",
        "rubygems": "gem",
        "gem": "gem",
        "packagist": "composer",
        "composer": "composer",
        "debian": "deb",
        "alpine": "apk",
    }.get(ecosystem_key)
    if package_type is None or not name.strip() or not version.strip():
        return None

    normalized = name.strip()
    if package_type == "maven":
        group, separator, artifact = normalized.partition(":")
        if not separator or not group or not artifact:
            return None
        path = f"{_encoded(group)}/{_encoded(artifact)}"
    elif package_type == "npm" and normalized.startswith("@") and "/" in normalized:
        namespace, artifact = normalized[1:].split("/", 1)
        if not namespace or not artifact:
            return None
        path = f"%40{_encoded(namespace)}/{_encoded(artifact)}"
    elif package_type == "golang":
        path = "/".join(_encoded(part) for part in normalized.split("/") if part)
    else:
        if "/" in normalized and package_type not in {"composer", "gem"}:
            return None
        path = _encoded(normalized.casefold() if package_type == "pypi" else normalized)
    if not path:
        return None
    return f"pkg:{package_type}/{path}@{quote(version.strip(), safe='-._~+')}"


def dependency_component(
    name: str,
    version: str,
    ecosystem: str,
    supplied_purl: object = None,
) -> DependencyComponent:
    purl = supplied_purl.strip() if isinstance(supplied_purl, str) else ""
    if not purl.startswith("pkg:") or any(char.isspace() for char in purl):
        purl = package_purl(ecosystem, name, version) or ""
    return DependencyComponent(
        name=name,
        version=version,
        ecosystem=ecosystem,
        purl=purl or None,
    )


def _read_json(root: Path, path: Path, option: str) -> tuple[dict[str, Any] | None, str, bytes, str | None]:
    selected, display = _select_project_file(root, path, option)
    data = _read_bounded(selected, MAX_PRODUCT_CONTEXT_BYTES, option)
    digest = hashlib.sha256(data).hexdigest()
    try:
        document = json.loads(data)
    except (json.JSONDecodeError, UnicodeDecodeError, RecursionError):
        return None, display, data, digest
    return (document if isinstance(document, dict) else None), display, data, digest


def _vex_reference_map(document: dict[str, Any]) -> dict[str, str]:
    result: dict[str, str] = {}
    components = document.get("components", [])
    if not isinstance(components, list):
        return result
    pending = list(components)
    while pending and len(result) < 100_000:
        component = pending.pop()
        if not isinstance(component, dict):
            continue
        reference = component.get("bom-ref")
        purl = component.get("purl")
        if isinstance(reference, str) and isinstance(purl, str) and purl.startswith("pkg:"):
            result[reference] = purl
        nested = component.get("components")
        if isinstance(nested, list):
            pending.extend(nested)
    return result


def import_vex(
    root: Path,
    supplied: str | Path,
    *,
    product_purl: str,
    findings: tuple[Finding, ...],
) -> tuple[tuple[Finding, ...], VexImport]:
    validate_package_purl(product_purl)
    document, display, data, digest = _read_json(root, Path(supplied), "--vex")
    if document is None:
        return findings, VexImport(
            status="invalid",
            source_path=display,
            sha256=digest,
            byte_size=len(data),
            product_purl=product_purl,
            limitations=("VEX input is not a JSON object.",),
        )
    if document.get("bomFormat") != "CycloneDX" or document.get("specVersion") not in {"1.5", "1.6"}:
        return findings, VexImport(
            status="invalid",
            source_path=display,
            sha256=digest,
            byte_size=len(data),
            product_purl=product_purl,
            limitations=("VEX input must be CycloneDX JSON with specVersion 1.5 or 1.6.",),
        )
    metadata = document.get("metadata")
    product = metadata.get("component") if isinstance(metadata, dict) else None
    if not isinstance(product, dict) or product.get("purl") != product_purl:
        return findings, VexImport(
            status="invalid",
            source_path=display,
            sha256=digest,
            byte_size=len(data),
            product_purl=product_purl,
            limitations=("VEX product PURL does not exactly match --product-purl.",),
        )
    records = document.get("vulnerabilities", [])
    if not isinstance(records, list):
        return findings, VexImport(
            status="invalid",
            source_path=display,
            sha256=digest,
            byte_size=len(data),
            product_purl=product_purl,
            limitations=("VEX vulnerabilities member must be an array.",),
        )

    references = _vex_reference_map(document)
    pending: dict[str, list[VexReview]] = {}
    limitations: list[str] = []
    unmatched = 0
    invalid_records = 0
    conflicting_reviews = False
    for record in records[:100_000]:
        if not isinstance(record, dict):
            unmatched += 1
            invalid_records += 1
            continue
        vulnerability_id = record.get("id")
        analysis = record.get("analysis")
        state = analysis.get("state") if isinstance(analysis, dict) else None
        if (
            not isinstance(vulnerability_id, str)
            or not _VULNERABILITY_ID.fullmatch(vulnerability_id)
            or not isinstance(state, str)
            or state not in _VEX_STATES
        ):
            unmatched += 1
            invalid_records += 1
            continue
        justification = analysis.get("justification") if isinstance(analysis, dict) else None
        detail = analysis.get("detail") if isinstance(analysis, dict) else None
        justification_valid = (
            justification is None
            or isinstance(justification, str) and justification in _VEX_JUSTIFICATIONS
        )
        if not justification_valid or state == "not_affected" and justification is None:
            limitations.append(f"VEX record {vulnerability_id} has a missing or unsupported justification.")
            unmatched += 1
            invalid_records += 1
            continue
        affected = record.get("affects", [])
        affected_purls: set[str] = set()
        if isinstance(affected, list):
            for item in affected:
                if not isinstance(item, dict) or not isinstance(item.get("ref"), str):
                    continue
                reference = item["ref"]
                purl = references.get(reference, reference)
                if purl.startswith("pkg:"):
                    affected_purls.add(purl)
        if not affected_purls:
            unmatched += 1
            invalid_records += 1
            continue
        review = VexReview(
            state=state,
            justification=justification[:240] if isinstance(justification, str) else None,
            detail=safe_report_text(detail, limit=1000),
        )
        canonical_id = vulnerability_id.upper()
        for finding in findings:
            if finding.category != "dependency-vulnerability" or finding.component is None:
                continue
            component_purl = finding.component.purl
            finding_id = finding.rule_id.removeprefix("OSV-").upper()
            if component_purl in affected_purls and finding_id == canonical_id:
                pending.setdefault(finding.fingerprint, []).append(review)

    imported: list[Finding] = []
    matched_findings = 0
    for finding in findings:
        reviews = pending.get(finding.fingerprint, [])
        distinct_reviews = {
            (item.state, item.justification, item.detail): item
            for item in reviews
        }
        if len(distinct_reviews) == 1:
            imported.append(replace(finding, vex_review=next(iter(distinct_reviews.values()))))
            matched_findings += 1
        elif len(distinct_reviews) > 1:
            imported.append(finding)
            limitations.append(
                f"Conflicting VEX records matched finding {finding.rule_id}; no review state was applied."
            )
            unmatched += len(reviews)
            conflicting_reviews = True
        else:
            imported.append(finding)

    if len(records) > 100_000:
        limitations.append("VEX record count exceeded the 100000-record parsing limit.")
    if unmatched:
        limitations.append(f"{unmatched} VEX record(s) did not match an exact FUSE advisory and package PURL.")
    limitations.append("Imported VEX is review context, not signature verification; base findings and fail thresholds remain unchanged.")
    return tuple(imported), VexImport(
        status="partial" if invalid_records or conflicting_reviews or len(records) > 100_000 else "imported",
        source_path=display,
        sha256=digest,
        byte_size=len(data),
        product_purl=product_purl,
        record_count=min(len(records), 100_000),
        matched_findings=matched_findings,
        unmatched_records=unmatched,
        limitations=tuple(dict.fromkeys(limitations)),
    )


def inspect_provenance(
    root: Path,
    supplied: str | Path,
    *,
    firmware_path: Path,
    max_firmware_bytes: int,
) -> ProvenanceRecord:
    statement, display, data, digest = _read_json(root, Path(supplied), "--provenance")
    base = {
        "source_path": display,
        "sha256": digest,
        "byte_size": len(data),
    }
    limitation = (
        "FUSE compares the attested subject digest only. It does not authenticate a signature, "
        "establish a trusted builder, or validate the SLSA predicate policy.",
    )
    if statement is None:
        return ProvenanceRecord(
            status="invalid",
            **base,
            limitations=("Provenance input is not an in-toto statement JSON object.", *limitation),
        )
    statement_type = statement.get("_type")
    predicate_type = statement.get("predicateType")
    subjects = statement.get("subject")
    predicate = statement.get("predicate")
    if (
        not isinstance(statement_type, str)
        or statement_type not in {"https://in-toto.io/Statement/v1", "https://in-toto.io/Statement/v0.1"}
        or not isinstance(predicate_type, str)
        or predicate_type not in {"https://slsa.dev/provenance/v1", "https://slsa.dev/provenance/v0.2"}
        or not isinstance(subjects, list)
        or not isinstance(predicate, dict)
    ):
        return ProvenanceRecord(
            status="invalid",
            **base,
            predicate_type=safe_report_text(predicate_type, limit=500),
            limitations=("Input is not a supported in-toto SLSA provenance statement or lacks subject data.", *limitation),
        )

    build_definition = predicate.get("buildDefinition")
    run_details = predicate.get("runDetails")
    builder = run_details.get("builder") if isinstance(run_details, dict) else None
    if not isinstance(builder, dict):
        builder = predicate.get("builder")
    builder_id = builder.get("id") if isinstance(builder, dict) else None
    build_type = build_definition.get("buildType") if isinstance(build_definition, dict) else predicate.get("buildType")
    actual_hash: str | None = None
    try:
        size = firmware_path.stat().st_size
        if size > max_firmware_bytes:
            raise ValueError("Firmware image exceeds the configured scan size limit.")
        digest_builder = hashlib.sha256()
        with firmware_path.open("rb") as stream:
            while chunk := stream.read(1024 * 1024):
                digest_builder.update(chunk)
        actual_hash = digest_builder.hexdigest()
    except (OSError, ValueError) as error:
        return ProvenanceRecord(
            status="invalid",
            **base,
            predicate_type=safe_report_text(predicate_type, limit=500),
            builder_id=safe_report_text(builder_id, limit=500),
            build_type=safe_report_text(build_type, limit=500),
            limitations=(f"Firmware digest could not be checked ({type(error).__name__}).", *limitation),
        )

    matched_name: str | None = None
    matched_digest: str | None = None
    first_subject_name: str | None = None
    first_subject_digest: str | None = None
    for subject in subjects[:100_000]:
        if not isinstance(subject, dict):
            continue
        name = subject.get("name")
        safe_name = safe_report_text(Path(name.replace("\\", "/")).name, limit=200) if isinstance(name, str) else None
        digests = subject.get("digest")
        sha256 = digests.get("sha256") if isinstance(digests, dict) else None
        if not isinstance(sha256, str) or not _SHA256.fullmatch(sha256.casefold()):
            continue
        sha256 = sha256.casefold()
        if first_subject_digest is None:
            first_subject_name, first_subject_digest = safe_name, sha256
        if sha256 == actual_hash:
            matched_name, matched_digest = safe_name, sha256
            break
    status = "subject-match" if matched_digest else "subject-mismatch" if first_subject_digest else "unverified"
    return ProvenanceRecord(
        status=status,
        **base,
        predicate_type=safe_report_text(predicate_type, limit=500),
        builder_id=safe_report_text(builder_id, limit=500),
        build_type=safe_report_text(build_type, limit=500),
        subject_name=matched_name or first_subject_name,
        subject_sha256=matched_digest or first_subject_digest,
        signature_verified=False,
        limitations=limitation,
    )
