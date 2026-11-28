from __future__ import annotations

import hashlib
import json
import re
import shutil
import subprocess
from typing import Any
from urllib.parse import urlsplit

from .analyzer_runtime import (
    MAX_ANALYZER_OUTPUT_BYTES,
    AdapterResult,
    AnalyzerOutputLimitError,
    _run,
    _tool_version,
    analyzer_sandbox_active,
    analyzer_unavailable_detail,
    resolve_analyzer_executable,
)
from .model import (
    AnalyzerStatus,
    DependencyComponent,
    Finding,
    SoftwareComponent,
)

_IMAGE_REFERENCE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/@+-]{0,511}\Z")
_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,199}\Z")
_PACKAGE_NAME = re.compile(r"[A-Za-z0-9@._/+:-]{1,256}\Z")
_VERSION = re.compile(r"[A-Za-z0-9._+~:-]{1,256}\Z")
_CWE = re.compile(r"CWE-[0-9]{1,6}\Z")
_SEVERITIES = {"critical", "high", "medium", "low", "unknown"}
_ECOSYSTEMS = {
    "npm": "npm",
    "pypi": "Python",
    "python": "Python",
    "gomod": "Go",
    "golang": "Go",
    "maven": "Maven",
    "java": "Maven",
    "nuget": "NuGet",
    "composer": "Composer",
    "gem": "Bundler",
    "cargo": "Cargo",
}


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON object key")
        result[key] = value
    return result


def _text(value: object, pattern: re.Pattern[str], *, maximum: int = 256) -> str | None:
    if not isinstance(value, str) or len(value) > maximum or not pattern.fullmatch(value):
        return None
    return value


def _reference_url(value: object) -> str | None:
    if not isinstance(value, str) or len(value) > 2048 or any(ord(c) < 32 for c in value):
        return None
    parsed = urlsplit(value)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
        return None
    return value


def _parse_report(
    document: object, image_sha256: str
) -> tuple[tuple[Finding, ...], tuple[SoftwareComponent, ...], bool]:
    if not isinstance(document, dict) or document.get("ArtifactType") != "container_image":
        raise ValueError("Trivy JSON is not a container image report")
    results = document.get("Results")
    if not isinstance(results, list) or len(results) > 10_000:
        raise ValueError("Trivy JSON has no results array")
    findings: list[Finding] = []
    components: dict[tuple[str, str, str], SoftwareComponent] = {}
    complete = True
    packages_seen = 0
    for result in results:
        if not isinstance(result, dict):
            complete = False
            continue
        packages = result.get("Packages")
        if isinstance(packages, list):
            for package in packages:
                packages_seen += 1
                if packages_seen > 10_000:
                    complete = False
                    break
                component = _component(package)
                if component is None:
                    complete = False
                    continue
                key = (
                    component.ecosystem.casefold(),
                    component.name.casefold(),
                    component.version.casefold(),
                )
                components.setdefault(key, component)
        elif "Packages" in result:
            complete = False
        else:
            complete = False

        vulnerabilities = result.get("Vulnerabilities", [])
        if vulnerabilities is None:
            continue
        if not isinstance(vulnerabilities, list):
            complete = False
            continue
        for vulnerability in vulnerabilities:
            finding = _finding(vulnerability, image_sha256)
            if finding is None:
                complete = False
                continue
            findings.append(finding)
            if len(findings) >= 10_000:
                complete = False
                break
        if len(findings) >= 10_000:
            break
    return (
        tuple(sorted(findings, key=lambda item: (item.id, item.file))),
        tuple(components[key] for key in sorted(components)),
        complete,
    )


def _component(value: object) -> SoftwareComponent | None:
    if not isinstance(value, dict):
        return None
    name = _text(value.get("Name"), _PACKAGE_NAME)
    version = _text(value.get("Version"), _VERSION)
    if name is None or version is None:
        return None
    identifier = value.get("Identifier")
    purl = identifier.get("PURL") if isinstance(identifier, dict) else None
    if (
        not isinstance(purl, str)
        or len(purl) > 2048
        or not purl.startswith("pkg:")
        or any(ord(char) < 32 for char in purl)
    ):
        purl = None
    package_type = value.get("Type")
    if not isinstance(package_type, str) or len(package_type) > 64:
        package_type = "unknown"
    purl_type = purl[4:].split("/", 1)[0].split("@", 1)[0].casefold() if purl else ""
    ecosystem = _ECOSYSTEMS.get(purl_type, _ECOSYSTEMS.get(package_type.casefold(), "unknown"))
    return SoftwareComponent(
        name=name,
        version=version,
        ecosystem=ecosystem,
        purl=purl,
        source="Trivy local image report",
    )


def _finding(value: object, image_sha256: str) -> Finding | None:
    if not isinstance(value, dict):
        return None
    advisory = _text(value.get("VulnerabilityID"), _IDENTIFIER)
    package = _text(value.get("PkgName"), _PACKAGE_NAME)
    version = _text(value.get("InstalledVersion"), _VERSION)
    if advisory is None or package is None or version is None:
        return None
    external_severity = value.get("Severity")
    if not isinstance(external_severity, str):
        external_severity = "UNKNOWN"
    external_severity = external_severity.upper()
    if external_severity.lower() not in _SEVERITIES:
        external_severity = "UNKNOWN"
    severity = external_severity.casefold()
    if severity not in _SEVERITIES:
        severity = "unknown"
    identifier = value.get("PkgIdentifier")
    purl = identifier.get("PURL") if isinstance(identifier, dict) else None
    if (
        not isinstance(purl, str)
        or len(purl) > 2048
        or not purl.startswith("pkg:")
        or any(ord(char) < 32 for char in purl)
    ):
        purl = None
    package_type = value.get("PkgType")
    purl_type = purl[4:].split("/", 1)[0].split("@", 1)[0].casefold() if purl else ""
    ecosystem = _ECOSYSTEMS.get(
        purl_type,
        _ECOSYSTEMS.get(package_type.casefold(), "unknown")
        if isinstance(package_type, str)
        else "unknown",
    )
    cwe_values = value.get("CweIDs", [])
    cwe = (
        tuple(
            sorted({item for item in cwe_values if isinstance(item, str) and _CWE.fullmatch(item)})
        )
        if isinstance(cwe_values, list)
        else ()
    )
    cwe = cwe[:8]
    references: list[str] = []
    primary_url = _reference_url(value.get("PrimaryURL"))
    if primary_url:
        references.append(primary_url)
    aliases = value.get("References", [])
    if isinstance(aliases, list):
        for reference in aliases:
            safe = _reference_url(reference)
            if safe and safe not in references:
                references.append(safe)
            if len(references) >= 6:
                break
    key = "\0".join((image_sha256, advisory, package, version))
    fingerprint = hashlib.sha256(key.encode("utf-8")).hexdigest()
    fixed = value.get("FixedVersion")
    fixed_version = _text(fixed, re.compile(r"[A-Za-z0-9._+~,: -]{1,256}\Z"))
    remediation = (
        f"Review advisory {advisory} and update {package} to a vendor-supported version outside the affected range."
        + (f" Trivy reports a fixed version: {fixed_version}." if fixed_version else "")
    )
    return Finding(
        id=f"TRIVY:{advisory}:{package}@{version}:{image_sha256}",
        fingerprint=fingerprint,
        rule_id=f"TRIVY-{advisory}",
        rule_version="1",
        analyzer="trivy",
        title=f"Container image advisory match: {package}@{version} ({advisory})",
        severity=severity,  # type: ignore[arg-type]
        confidence="high",
        category="dependency-vulnerability",
        file="container-image",
        start_line=None,
        end_line=None,
        evidence=(
            f"Trivy matched {ecosystem} package {package}@{version} with advisory {advisory}; "
            "reachability is unknown."
        ),
        explanation=(
            "The selected local container image contains a package/version that matches a Trivy "
            "vulnerability record. This inventory match does not establish runtime reachability."
        ),
        potential_impact=(
            "If vulnerable behavior is reachable in a running container, it may expose the "
            "container or host to the impact described by the advisory."
        ),
        remediation=remediation,
        references=tuple(references),
        applicability="unknown",
        validation_method="advisory-match",
        validation_status="not-validated",
        severity_basis="upstream-label",
        component=DependencyComponent(package, version, ecosystem, purl),
        engine_rule_id=advisory,
        cwe=cwe,
        external_severity=external_severity[:32],
    )


def run_trivy_image(image: str) -> AdapterResult:
    """Scan one already-present Docker image without registry access or database updates."""
    if not isinstance(image, str) or not _IMAGE_REFERENCE.fullmatch(image):
        return AdapterResult(
            AnalyzerStatus(
                "trivy-image", "failed", detail="Image reference has unsupported syntax."
            )
        )
    if analyzer_sandbox_active():
        return AdapterResult(
            AnalyzerStatus(
                "trivy-image",
                "skipped",
                detail="Image scanning uses the host Docker engine and is unavailable inside the analyzer sandbox.",
            )
        )
    executable = resolve_analyzer_executable("trivy", host_lookup=shutil.which)
    if executable is None:
        return AdapterResult(
            AnalyzerStatus(
                "trivy-image",
                "unavailable",
                detail=analyzer_unavailable_detail("trivy", "Install Trivy to scan a local image."),
            )
        )
    version = _tool_version(executable)
    command = [
        executable,
        "image",
        "--image-src",
        "docker",
        "--scanners",
        "vuln",
        "--list-all-pkgs",
        "--format",
        "json",
        "--no-progress",
        "--skip-version-check",
        "--disable-telemetry",
        "--offline-scan",
        "--skip-db-update",
        "--skip-java-db-update",
        "--skip-check-update",
        "--skip-vex-repo-update",
        image,
    ]
    try:
        completed = _run(command, output_limit_bytes=MAX_ANALYZER_OUTPUT_BYTES)
    except subprocess.TimeoutExpired:
        return AdapterResult(
            AnalyzerStatus(
                "trivy-image", "timeout", version=version, detail="Timed out after 180 seconds."
            )
        )
    except AnalyzerOutputLimitError:
        return AdapterResult(
            AnalyzerStatus(
                "trivy-image", "failed", version=version, detail="Trivy output exceeded 10 MiB."
            )
        )
    except OSError as error:
        return AdapterResult(
            AnalyzerStatus(
                "trivy-image",
                "failed",
                version=version,
                detail=f"Could not start Trivy ({type(error).__name__}).",
            )
        )
    if completed.returncode != 0:
        return AdapterResult(
            AnalyzerStatus(
                "trivy-image",
                "failed",
                version=version,
                detail=f"Trivy could not scan the requested local image (exit {completed.returncode}); output was omitted.",
            )
        )
    try:
        document = json.loads(
            completed.stdout,
            object_pairs_hook=_unique_object,
            parse_constant=lambda _: (_ for _ in ()).throw(ValueError("invalid number")),
        )
        image_digest = hashlib.sha256(image.encode("utf-8")).hexdigest()
        findings, components, complete = _parse_report(document, image_digest)
    except (json.JSONDecodeError, ValueError, RecursionError):
        return AdapterResult(
            AnalyzerStatus(
                "trivy-image",
                "failed",
                version=version,
                detail="Trivy did not emit a valid bounded container image report.",
            )
        )
    return AdapterResult(
        AnalyzerStatus(
            "trivy-image",
            "completed" if complete else "partial",
            version=version,
            detail=(
                f"Scanned an explicitly selected local Docker image; recorded {len(components)} packages and {len(findings)} advisory match(es)."
                if complete
                else "Scanned the explicitly selected local Docker image, but its bounded report omitted or malformed entries."
            ),
            findings=len(findings),
        ),
        findings=findings,
        software_components=components,
        component_inventory_complete=complete,
    )
