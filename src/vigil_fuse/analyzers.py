from __future__ import annotations

import hashlib
import json
import math
import re
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .model import AnalysisArtifact, AnalyzerStatus, Finding

ANALYZER_TIMEOUT_SECONDS = 180
TOOL_VERSION_TIMEOUT_SECONDS = 5
MAX_ANALYZER_OUTPUT_BYTES = 10 * 1024 * 1024
MAX_SBOM_BYTES = 50 * 1024 * 1024
MAX_BINWALK_REPORT_BYTES = 1024 * 1024


@dataclass(frozen=True)
class AdapterResult:
    status: AnalyzerStatus
    findings: tuple[Finding, ...] = ()
    artifacts: tuple[AnalysisArtifact, ...] = ()


def _artifact(path: Path, media_type: str, output_dir: Path) -> AnalysisArtifact:
    data = path.read_bytes()
    return AnalysisArtifact(
        path=path.relative_to(output_dir).as_posix(),
        media_type=media_type,
        sha256=hashlib.sha256(data).hexdigest(),
    )


def _artifact_destination(output_dir: Path, filename: str) -> Path:
    path = output_dir / filename
    if path.is_symlink():
        raise OSError(f"Refusing to write analyzer output through symbolic link: {path.name}")
    if path.exists() and not path.is_file():
        raise OSError(f"Analyzer output path is not a regular file: {path.name}")
    return path


def _run(command: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=ANALYZER_TIMEOUT_SECONDS,
        check=False,
    )


def _tool_version(executable: str) -> str | None:
    try:
        completed = subprocess.run(
            [executable, "--version"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=TOOL_VERSION_TIMEOUT_SECONDS,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if completed.returncode != 0:
        return None
    lines = (completed.stdout or completed.stderr).strip().splitlines()
    return lines[0][:120] if lines else None


def _output_exclude_pattern(target: Path, output_dir: Path) -> str | None:
    if not target.is_dir():
        return None
    try:
        relative = output_dir.resolve().relative_to(target.resolve())
    except ValueError:
        return None
    if relative == Path("."):
        return None
    return relative.as_posix().rstrip("/") + "/**"


def generate_sbom(target: Path, output_dir: Path) -> AdapterResult:
    """Generate a local CycloneDX inventory with Syft; never resolve image names."""
    executable = shutil.which("syft")
    if executable is None:
        return AdapterResult(
            AnalyzerStatus(
                "syft",
                "unavailable",
                detail="Install Syft and rerun with --sbom or --vulnerabilities.",
            )
        )

    version = _tool_version(executable)
    output_dir.mkdir(parents=True, exist_ok=True)
    try:
        sbom_path = _artifact_destination(output_dir, "components.cdx.json")
    except OSError as error:
        return AdapterResult(AnalyzerStatus("syft", "failed", version=version, detail=str(error)))
    source = f"{'dir' if target.is_dir() else 'file'}:{target.resolve()}"
    command = [executable, "scan", source]
    exclude_pattern = _output_exclude_pattern(target, output_dir)
    if exclude_pattern:
        command.extend(["--exclude", exclude_pattern])
    command.extend(["--output", f"cyclonedx-json={sbom_path}"])
    try:
        completed = _run(command)
    except subprocess.TimeoutExpired:
        return AdapterResult(
            AnalyzerStatus("syft", "failed", version=version, detail="Timed out after 180 seconds.")
        )
    except OSError as error:
        return AdapterResult(AnalyzerStatus("syft", "failed", version=version, detail=f"Could not start Syft ({type(error).__name__})."))

    output_size = len(completed.stdout.encode("utf-8")) + len(completed.stderr.encode("utf-8"))
    if output_size > MAX_ANALYZER_OUTPUT_BYTES:
        return AdapterResult(
            AnalyzerStatus("syft", "failed", version=version, detail="Syft diagnostics exceeded 10 MiB limit.")
        )

    if completed.returncode != 0 or not sbom_path.is_file():
        return AdapterResult(
            AnalyzerStatus(
                "syft",
                "failed",
                version=version,
                detail=f"Syft could not create the requested CycloneDX inventory (exit {completed.returncode}). Diagnostics were omitted from the report.",
            )
        )
    if sbom_path.stat().st_size > MAX_SBOM_BYTES:
        return AdapterResult(
            AnalyzerStatus("syft", "failed", version=version, detail="Generated SBOM exceeded 50 MiB limit.")
        )
    try:
        artifact = _artifact(sbom_path, "application/vnd.cyclonedx+json", output_dir)
        document = json.loads(sbom_path.read_text(encoding="utf-8"))
    except (OSError, ValueError, TypeError):
        return AdapterResult(
            AnalyzerStatus("syft", "failed", version=version, detail="Syft did not emit readable CycloneDX JSON.")
        )
    if not isinstance(document, dict) or document.get("bomFormat") != "CycloneDX":
        return AdapterResult(
            AnalyzerStatus("syft", "failed", version=version, detail="Syft output was not a CycloneDX document.")
        )
    components = document.get("components", [])
    component_count = len(components) if isinstance(components, list) else 0
    return AdapterResult(
        AnalyzerStatus(
            "syft",
            "completed",
            version=version,
            detail=f"Generated CycloneDX component inventory ({component_count} components).",
        ),
        artifacts=(artifact,),
    )


def _source_location(source_path: str, target: Path) -> str:
    source = Path(source_path)
    if not source.is_absolute():
        base = target if target.is_dir() else target.parent
        source = base / source
    try:
        return source.resolve().relative_to(target.resolve()).as_posix()
    except (OSError, ValueError):
        return source.name or source_path


def _severity(vulnerability: dict[str, Any]) -> str:
    database_specific = vulnerability.get("database_specific")
    if isinstance(database_specific, dict):
        label = database_specific.get("severity")
        if isinstance(label, str):
            normalized = label.casefold()
            if normalized in {"critical", "high", "medium", "low"}:
                return normalized

    severity_items = vulnerability.get("severity", [])
    if not isinstance(severity_items, list):
        severity_items = []
    for item in severity_items:
        if not isinstance(item, dict):
            continue
        score = item.get("score")
        if isinstance(score, (int, float)):
            value = float(score)
        elif isinstance(score, str) and re.fullmatch(r"\d+(?:\.\d+)?", score.strip()):
            value = float(score)
        elif isinstance(score, str):
            value = _cvss_v3_score(score)
            if value is None:
                continue
        else:
            continue
        if value >= 9.0:
            return "critical"
        if value >= 7.0:
            return "high"
        if value >= 4.0:
            return "medium"
        if value > 0:
            return "low"
    return "unknown"


def _cvss_v3_score(vector: str) -> float | None:
    """Calculate a CVSS v3.0/v3.1 base score from its standard vector string."""
    parts = vector.strip().split("/")
    if not parts or parts[0] not in {"CVSS:3.0", "CVSS:3.1"}:
        return None
    metrics: dict[str, str] = {}
    for part in parts[1:]:
        if ":" not in part:
            continue
        key, value = part.split(":", 1)
        metrics[key] = value
    required = {"AV", "AC", "PR", "UI", "S", "C", "I", "A"}
    if not required.issubset(metrics):
        return None
    if metrics["S"] not in {"U", "C"}:
        return None

    attack_vector = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}.get(metrics["AV"])
    attack_complexity = {"L": 0.77, "H": 0.44}.get(metrics["AC"])
    user_interaction = {"N": 0.85, "R": 0.62}.get(metrics["UI"])
    impact_value = {"H": 0.56, "L": 0.22, "N": 0.0}
    confidentiality = impact_value.get(metrics["C"])
    integrity = impact_value.get(metrics["I"])
    availability = impact_value.get(metrics["A"])
    if None in {
        attack_vector,
        attack_complexity,
        user_interaction,
        confidentiality,
        integrity,
        availability,
    }:
        return None

    scope_changed = metrics["S"] == "C"
    privileges = (
        {"N": 0.85, "L": 0.68, "H": 0.50}
        if scope_changed
        else {"N": 0.85, "L": 0.62, "H": 0.27}
    ).get(metrics["PR"])
    if privileges is None:
        return None

    impact_subscore = 1 - (
        (1 - confidentiality) * (1 - integrity) * (1 - availability)
    )
    if scope_changed:
        impact = 7.52 * (impact_subscore - 0.029) - 3.25 * (impact_subscore - 0.02) ** 15
    else:
        impact = 6.42 * impact_subscore
    if impact <= 0:
        return 0.0
    exploitability = (
        8.22
        * attack_vector
        * attack_complexity
        * privileges
        * user_interaction
    )
    raw_score = min(impact + exploitability, 10.0)
    if scope_changed:
        raw_score = min(1.08 * (impact + exploitability), 10.0)
    return math.ceil(raw_score * 10 - 1e-8) / 10


def _canonical_id(ids: set[str]) -> str:
    return min(ids, key=lambda value: (not value.upper().startswith("CVE-"), value))


def osv_findings(document: dict[str, Any], target: Path, version: str | None) -> tuple[Finding, ...]:
    findings: list[Finding] = []
    seen: set[tuple[str, str, str, str]] = set()
    source_results = document.get("results", [])
    if not isinstance(source_results, list):
        return ()
    for result in source_results:
        if not isinstance(result, dict):
            continue
        source = result.get("source")
        source_path = source.get("path", "unknown") if isinstance(source, dict) else "unknown"
        location = _source_location(str(source_path), target)
        package_results = result.get("packages", [])
        if not isinstance(package_results, list):
            continue
        for package_result in package_results:
            if not isinstance(package_result, dict):
                continue
            package = package_result.get("package")
            if not isinstance(package, dict):
                continue
            name = str(package.get("name") or "unknown-package")
            package_version = str(package.get("version") or "unknown-version")
            ecosystem = str(package.get("ecosystem") or "unknown ecosystem")
            group_by_id: dict[str, set[str]] = {}
            groups = package_result.get("groups", [])
            if not isinstance(groups, list):
                groups = []
            for group in groups:
                if not isinstance(group, dict):
                    continue
                ids = group.get("ids", [])
                if not isinstance(ids, list):
                    continue
                group_ids = {str(item) for item in ids if item}
                for advisory_id in group_ids:
                    group_by_id[advisory_id] = group_ids

            vulnerabilities = package_result.get("vulnerabilities", [])
            if not isinstance(vulnerabilities, list):
                vulnerabilities = []
            for vulnerability in vulnerabilities:
                if not isinstance(vulnerability, dict):
                    continue
                advisory_id = str(vulnerability.get("id") or "OSV-UNKNOWN")
                alias_items = vulnerability.get("aliases", [])
                aliases = {str(item) for item in alias_items if item} if isinstance(alias_items, list) else set()
                ids = group_by_id.get(advisory_id, {advisory_id, *aliases})
                canonical = _canonical_id(ids)
                dedup_key = (canonical, name, package_version, location)
                if dedup_key in seen:
                    continue
                seen.add(dedup_key)

                summary = str(vulnerability.get("summary") or "").strip()
                title = f"Known vulnerable dependency: {name}@{package_version} ({canonical})"
                evidence = f"{ecosystem} package {name}@{package_version}; advisory {canonical}; source {location}"
                if not summary and _severity(vulnerability) == "unknown":
                    evidence += "; no advisory severity score was supplied"
                references = [f"https://osv.dev/vulnerability/{canonical}"]
                advisory_references = vulnerability.get("references", [])
                if not isinstance(advisory_references, list):
                    advisory_references = []
                for reference in advisory_references:
                    if isinstance(reference, dict) and isinstance(reference.get("url"), str):
                        url = reference["url"]
                        if url.startswith("https://") and url not in references:
                            references.append(url)
                fingerprint_source = "\0".join(
                    (canonical, ecosystem, name, package_version, location)
                )
                fingerprint = hashlib.sha256(fingerprint_source.encode("utf-8")).hexdigest()
                short_summary = summary.replace("\n", " ")[:240]
                findings.append(
                    Finding(
                        id=f"OSV:{canonical}:{name}@{package_version}:{location}",
                        fingerprint=fingerprint,
                        rule_id=f"OSV-{canonical}",
                        rule_version=version or "unknown",
                        analyzer="osv-scanner",
                        title=title,
                        severity=_severity(vulnerability),  # type: ignore[arg-type]
                        confidence="high",
                        category="dependency-vulnerability",
                        file=location,
                        start_line=None,
                        end_line=None,
                        evidence=evidence,
                        explanation=(
                            f"OSV-Scanner matched the identified {ecosystem} package and version "
                            f"to advisory {canonical}. This inventory match does not establish "
                            "that vulnerable code is reachable or active in the device."
                            + (f" Advisory summary: {short_summary}" if short_summary else "")
                        ),
                        potential_impact=(
                            "If the affected component is present in the deployed artifact and "
                            "the vulnerable behavior is reachable, it may expose the device or "
                            "service to the impact described by the advisory."
                        ),
                        remediation=(
                            "Review the linked advisory and update to a vendor-supported version "
                            "outside the affected range; rebuild the firmware and rescan its inventory."
                        ),
                        references=tuple(references),
                    )
                )
    return tuple(findings)


def scan_vulnerabilities(
    target: Path,
    output_dir: Path,
    *,
    sbom_path: Path | None = None,
    offline: bool = False,
) -> AdapterResult:
    executable = shutil.which("osv-scanner")
    if executable is None:
        return AdapterResult(
            AnalyzerStatus(
                "osv-scanner",
                "unavailable",
                detail="Install OSV-Scanner and rerun with --vulnerabilities.",
            )
        )

    version = _tool_version(executable)
    command = [executable]
    if offline:
        command.append("--offline-vulnerabilities")
    command.extend(["scan", "source", "--format", "json"])
    inventory_path = sbom_path
    if inventory_path is not None:
        command.extend(["-L", str(inventory_path.resolve())])
    elif target.is_dir():
        exclude_pattern = _output_exclude_pattern(target, output_dir) if output_dir else None
        if exclude_pattern:
            command.extend(["--x-exclude", f"g:{exclude_pattern}"])
        command.extend(["--recursive", str(target.resolve())])
    else:
        command.extend(["-L", str(target.resolve())])

    try:
        completed = _run(command)
    except subprocess.TimeoutExpired:
        return AdapterResult(
            AnalyzerStatus("osv-scanner", "failed", version=version, detail="Timed out after 180 seconds.")
        )
    except OSError as error:
        return AdapterResult(AnalyzerStatus("osv-scanner", "failed", version=version, detail=f"Could not start OSV-Scanner ({type(error).__name__})."))

    encoded_size = len(completed.stdout.encode("utf-8")) + len(completed.stderr.encode("utf-8"))
    if encoded_size > MAX_ANALYZER_OUTPUT_BYTES:
        return AdapterResult(
            AnalyzerStatus("osv-scanner", "failed", detail="Analyzer output exceeded 10 MiB limit.")
        )
    try:
        document = json.loads(completed.stdout)
        if not isinstance(document, dict) or not isinstance(document.get("results", []), list):
            raise ValueError("JSON does not contain an OSV results array")
    except (json.JSONDecodeError, ValueError):
        return AdapterResult(
            AnalyzerStatus(
                "osv-scanner",
                "failed",
                version=version,
                detail="OSV-Scanner did not emit valid JSON results; diagnostics were omitted from the report.",
            )
        )

    output_dir.mkdir(parents=True, exist_ok=True)
    try:
        result_path = _artifact_destination(output_dir, "osv-results.json")
        result_path.write_text(json.dumps(document, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    except OSError as error:
        return AdapterResult(AnalyzerStatus("osv-scanner", "failed", version=version, detail=str(error)))
    status_name = "completed" if completed.returncode in (0, 1) else "partial"
    detail = (
        "Matched the generated CycloneDX inventory against OSV advisories."
        if inventory_path
        else "Checked source manifests/lockfiles against OSV advisories."
    )
    if completed.returncode == 128:
        detail += " No packages were recognized by OSV-Scanner."
    elif completed.returncode not in (0, 1):
        detail += f" OSV-Scanner exited with code {completed.returncode}."
    findings = osv_findings(document, target, version)
    try:
        artifact = _artifact(result_path, "application/json", output_dir)
    except OSError as error:
        return AdapterResult(AnalyzerStatus("osv-scanner", "failed", detail=str(error)))
    return AdapterResult(
        AnalyzerStatus(
            "osv-scanner",
            status_name,  # type: ignore[arg-type]
            version=version,
            detail=detail,
            findings=len(findings),
        ),
        findings=findings,
        artifacts=(artifact,),
    )


def identify_firmware(target: Path, output_dir: Path) -> AdapterResult:
    """Run Binwalk signature identification only. No extraction option is invoked."""
    executable = shutil.which("binwalk")
    if executable is None:
        return AdapterResult(
            AnalyzerStatus(
                "binwalk",
                "unavailable",
                detail="Install Binwalk and rerun with --firmware; extraction is not performed.",
            )
        )
    try:
        completed = _run([executable, str(target.resolve())])
    except subprocess.TimeoutExpired:
        return AdapterResult(
            AnalyzerStatus("binwalk", "failed", version=version, detail="Timed out after 180 seconds.")
        )
    except OSError as error:
        return AdapterResult(AnalyzerStatus("binwalk", "failed", version=version, detail=f"Could not start Binwalk ({type(error).__name__})."))

    output_size = len(completed.stdout.encode("utf-8")) + len(completed.stderr.encode("utf-8"))
    if output_size > MAX_ANALYZER_OUTPUT_BYTES:
        return AdapterResult(
            AnalyzerStatus("binwalk", "failed", version=version, detail="Binwalk diagnostics exceeded 10 MiB limit.")
        )

    output_dir.mkdir(parents=True, exist_ok=True)
    try:
        report_path = _artifact_destination(output_dir, "firmware-identification.txt")
    except OSError as error:
        return AdapterResult(AnalyzerStatus("binwalk", "failed", version=version, detail=str(error)))
    content = (completed.stdout + ("\n" + completed.stderr if completed.stderr else "")).strip()
    if not content:
        content = "Binwalk produced no signature output."
    report_path.write_text(content[:MAX_BINWALK_REPORT_BYTES], encoding="utf-8")
    status = "partial" if completed.returncode == 0 else "failed"
    detail = (
        "Signature identification only; no extraction or firmware execution was attempted. "
        "A successful signature scan is not a complete firmware security assessment."
        if completed.returncode == 0
        else f"Binwalk exited with code {completed.returncode}."
    )
    try:
        artifact = _artifact(report_path, "text/plain", output_dir)
    except OSError as error:
        return AdapterResult(AnalyzerStatus("binwalk", "failed", detail=str(error)))
    return AdapterResult(
        AnalyzerStatus("binwalk", status, detail=detail),  # type: ignore[arg-type]
        artifacts=(artifact,),
    )
