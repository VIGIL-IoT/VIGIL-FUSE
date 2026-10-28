from __future__ import annotations

import hashlib
import json
import math
import re
import shutil
import subprocess
import tempfile
import threading
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any

from .model import AnalysisArtifact, AnalyzerStatus, Finding
from .product_context import dependency_component

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


def inspect_tools() -> tuple[tuple[str, str | None, str | None], ...]:
    """Return optional tool availability, executable path, and version for doctor."""
    tools = []
    for name, executable_name in (
        ("Syft", "syft"),
        ("OSV-Scanner", "osv-scanner"),
        ("Binwalk", "binwalk"),
        ("Gitleaks", "gitleaks"),
    ):
        executable = shutil.which(executable_name)
        version = _tool_version(executable) if executable else None
        tools.append((name, executable, version))
    return tuple(tools)


class AnalyzerOutputLimitError(RuntimeError):
    """Raised when a child process exceeds FUSE's combined diagnostic limit."""


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


def _run(
    command: list[str], *, timeout: int = ANALYZER_TIMEOUT_SECONDS, cwd: Path | None = None
) -> subprocess.CompletedProcess[str]:
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=cwd)
    captured = {"stdout": bytearray(), "stderr": bytearray()}
    total = 0
    lock = threading.Lock()
    exceeded = threading.Event()

    def drain(name: str, stream) -> None:
        nonlocal total
        while True:
            chunk = stream.read(64 * 1024)
            if not chunk:
                return
            with lock:
                remaining = max(0, MAX_ANALYZER_OUTPUT_BYTES - total)
                keep = min(len(chunk), remaining)
                captured[name].extend(chunk[:keep])
                total += len(chunk)
                if len(chunk) > remaining:
                    exceeded.set()
                    try:
                        process.terminate()
                    except OSError:
                        pass

    assert process.stdout is not None and process.stderr is not None
    readers = [
        threading.Thread(target=drain, args=("stdout", process.stdout), daemon=True),
        threading.Thread(target=drain, args=("stderr", process.stderr), daemon=True),
    ]
    for reader in readers:
        reader.start()
    try:
        returncode = process.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        try:
            process.kill()
        except OSError:
            pass
        process.wait()
        for reader in readers:
            reader.join()
        process.stdout.close()
        process.stderr.close()
        raise
    for reader in readers:
        reader.join()
    process.stdout.close()
    process.stderr.close()
    if exceeded.is_set():
        raise AnalyzerOutputLimitError("Analyzer output exceeded the configured limit")
    return subprocess.CompletedProcess(
        command,
        returncode,
        stdout=bytes(captured["stdout"]).decode("utf-8", errors="replace"),
        stderr=bytes(captured["stderr"]).decode("utf-8", errors="replace"),
    )


def _tool_version(executable: str) -> str | None:
    try:
        completed = _run([executable, "--version"], timeout=TOOL_VERSION_TIMEOUT_SECONDS)
    except (OSError, subprocess.TimeoutExpired, AnalyzerOutputLimitError):
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
    except AnalyzerOutputLimitError:
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
    return _severity_details(vulnerability)[0]


def _severity_label(score: float | None) -> str:
    if score is None:
        return "unknown"
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0:
        return "low"
    return "unknown"


def _severity_details(
    vulnerability: dict[str, Any],
) -> tuple[str, str, float | None, str | None, str | None]:
    """Return severity label, basis, score, vector, and CVSS version."""
    database_specific = vulnerability.get("database_specific")
    advisory_label: str | None = None
    if isinstance(database_specific, dict):
        label = database_specific.get("severity")
        if isinstance(label, str):
            normalized = label.casefold()
            if normalized in {"critical", "high", "medium", "low"}:
                advisory_label = normalized

    severity_items = vulnerability.get("severity", [])
    if not isinstance(severity_items, list):
        severity_items = []
    score_value: float | None = None
    vector: str | None = None
    cvss_version: str | None = None
    basis = "unknown"
    for item in severity_items:
        if not isinstance(item, dict):
            continue
        severity_type = item.get("type")
        severity_type = severity_type if isinstance(severity_type, str) else ""
        if severity_type == "CVSS_V4":
            cvss_version = "4.0"
        elif severity_type == "CVSS_V3":
            cvss_version = "3.x"
        score = item.get("score")
        if isinstance(score, (int, float)) and not isinstance(score, bool):
            value = float(score)
        elif isinstance(score, str) and re.fullmatch(r"\d+(?:\.\d+)?", score.strip()):
            value = float(score)
        elif isinstance(score, str):
            vector = score.strip()
            value = _cvss_v3_score(vector)
            if vector.startswith("CVSS:"):
                cvss_version = vector.split("/", 1)[0].removeprefix("CVSS:")
            elif severity_type.endswith("_V4"):
                cvss_version = "4.0"
            elif severity_type.endswith("_V3"):
                cvss_version = "3.x"
        else:
            continue
        if value is not None and (not math.isfinite(value) or not 0 <= value <= 10):
            continue
        if value is None:
            if vector is not None:
                basis = "cvss-vector"
            continue
        score_value = value
        basis = "cvss-score"
        break

    if advisory_label is not None:
        return advisory_label, "upstream-label", score_value, vector, cvss_version
    if score_value is not None:
        return _severity_label(score_value), "cvss-score", score_value, vector, cvss_version
    if vector is not None:
        return "unknown", "cvss-vector", None, vector, cvss_version
    return "unknown", basis, None, None, cvss_version


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
                severity, severity_basis, severity_score, severity_vector, severity_version = (
                    _severity_details(vulnerability)
                )
                title = f"Known vulnerable dependency: {name}@{package_version} ({canonical})"
                evidence = f"{ecosystem} package {name}@{package_version}; advisory {canonical}; source {location}"
                if not summary and severity == "unknown":
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
                        severity=severity,  # type: ignore[arg-type]
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
                        applicability="unknown",
                        validation_method="advisory-match",
                        validation_status="not-validated",
                        severity_basis=severity_basis,  # type: ignore[arg-type]
                        severity_score=severity_score,
                        severity_vector=severity_vector,
                        severity_version=severity_version,
                        component=dependency_component(
                            name,
                            package_version,
                            ecosystem,
                            package.get("purl") or package_result.get("purl"),
                        ),
                    )
                )
    return tuple(findings)


def scan_vulnerabilities(
    target: Path,
    output_dir: Path,
    *,
    sbom_path: Path | None = None,
    offline: bool = False,
    no_network: bool = False,
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
    if no_network:
        command.append("--offline")
    elif offline:
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
    except AnalyzerOutputLimitError:
        return AdapterResult(
            AnalyzerStatus(
                "osv-scanner",
                "failed",
                version=version,
                detail="Analyzer output exceeded 10 MiB limit.",
            )
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
        result_path.write_text(
            json.dumps(document, ensure_ascii=False, separators=(",", ":")) + "\n",
            encoding="utf-8",
        )
    except OSError as error:
        return AdapterResult(AnalyzerStatus("osv-scanner", "failed", version=version, detail=str(error)))
    status_name = "completed" if completed.returncode in (0, 1) else "partial"
    detail = (
        "Matched the generated CycloneDX inventory against OSV advisories."
        if inventory_path
        else "Checked source manifests/lockfiles against OSV advisories."
    )
    if completed.returncode == 128:
        status_name = "partial"
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


def _git_command(target: Path, *arguments: str) -> subprocess.CompletedProcess[str] | None:
    git = shutil.which("git")
    if git is None:
        return None
    try:
        return _run([git, *arguments], timeout=TOOL_VERSION_TIMEOUT_SECONDS, cwd=target)
    except (OSError, subprocess.TimeoutExpired, AnalyzerOutputLimitError):
        return None


def _history_path(raw_path: object, target: Path) -> str:
    """Return a safe repository-relative path, never an absolute local path."""
    if not isinstance(raw_path, str) or not raw_path or any(ord(char) < 32 for char in raw_path):
        return "[path unavailable]"
    normalized = raw_path.replace("\\", "/")
    root = target.resolve()
    try:
        candidate = Path(raw_path)
        if candidate.is_absolute():
            return candidate.resolve(strict=False).relative_to(root).as_posix()
        if re.match(r"^[A-Za-z]:", normalized) or normalized.startswith("/"):
            return "[path unavailable]"
        parts = PurePosixPath(normalized).parts
        if not parts or any(part in {"", ".", ".."} for part in parts):
            return "[path unavailable]"
        return PurePosixPath(*parts).as_posix()
    except (OSError, ValueError):
        return "[path unavailable]"


def _safe_line(value: object) -> int | None:
    if isinstance(value, int) and not isinstance(value, bool) and 1 <= value <= 2**31 - 1:
        return value
    if isinstance(value, str) and value.isdecimal():
        number = int(value)
        return number if 1 <= number <= 2**31 - 1 else None
    return None


def _gitleaks_findings(
    document: object, target: Path, version: str | None
) -> tuple[Finding, ...]:
    if not isinstance(document, list):
        raise ValueError("Gitleaks report is not a JSON findings array")
    findings: list[Finding] = []
    seen: set[str] = set()
    for item in document:
        if not isinstance(item, dict):
            raise ValueError("Gitleaks report contains an invalid finding")
        raw_rule = item.get("RuleID")
        rule = re.sub(r"[^A-Za-z0-9_.-]", "_", raw_rule[:80]) if isinstance(raw_rule, str) else "unknown"
        file = _history_path(item.get("File"), target)
        line = _safe_line(item.get("StartLine", item.get("Line")))
        commit_raw = item.get("Commit")
        commit = commit_raw.lower() if isinstance(commit_raw, str) and re.fullmatch(r"[0-9a-fA-F]{7,64}", commit_raw) else "unknown"
        date_raw = item.get("Date")
        date = date_raw[:32] if isinstance(date_raw, str) and re.fullmatch(
            r"\d{4}-\d{2}-\d{2}(?:T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)?",
            date_raw,
        ) else None
        identity = "\0".join((commit, file, rule, str(line or "")))
        fingerprint = hashlib.sha256(identity.encode("utf-8")).hexdigest()
        if fingerprint in seen:
            continue
        seen.add(fingerprint)
        evidence = f"Secret-like pattern reported at {file}"
        if line is not None:
            evidence += f":{line}"
        evidence += f" in commit {commit}; secret value redacted."
        if date:
            evidence += f" Commit date: {date}."
        findings.append(
            Finding(
                id=f"GITLEAKS:{fingerprint[:20]}",
                fingerprint=fingerprint,
                rule_id=f"GITLEAKS:{rule}",
                rule_version=version or "unknown",
                analyzer="gitleaks-history",
                title="Possible secret pattern in Git history",
                severity="unknown",
                confidence="medium",
                category="historical-secret-exposure",
                file=file,
                start_line=line,
                end_line=line,
                evidence=evidence,
                explanation=(
                    "Gitleaks matched a default secret-detection pattern in repository history. "
                    "This historical indicator does not establish that the value is valid or "
                    "present in the current working tree. The matched value is intentionally omitted."
                ),
                potential_impact=(
                    "If the historical value was genuine and usable, it may have been exposed to "
                    "anyone with access to repository history. Removing it from the current files "
                    "does not remove copies from existing clones or cached history."
                ),
                remediation=(
                    "Verify the finding without copying the value into another report. If genuine, "
                    "revoke or rotate the credential, review its access logs, and coordinate any "
                    "history rewrite with repository collaborators."
                ),
                references=("https://github.com/gitleaks/gitleaks",),
                applicability="candidate",
                validation_method="external-tool",
                validation_status="not-validated",
                severity_basis="unknown",
            )
        )
    return tuple(findings)


def scan_git_history(target: Path, output_dir: Path) -> AdapterResult:
    """Optionally scan commits reachable from HEAD without persisting secret values."""
    if not target.is_dir() or target.is_symlink():
        return AdapterResult(
            AnalyzerStatus("gitleaks-history", "skipped", detail="Git-history scanning requires a repository-root directory target.")
        )
    git = shutil.which("git")
    if git is None:
        return AdapterResult(AnalyzerStatus("gitleaks-history", "unavailable", detail="Install Git to inspect repository history."))
    executable = shutil.which("gitleaks")
    if executable is None:
        return AdapterResult(AnalyzerStatus("gitleaks-history", "unavailable", detail="Install Gitleaks and rerun with --git-history."))
    version = _tool_version(executable)

    top = _git_command(target, "rev-parse", "--show-toplevel")
    if top is None or top.returncode != 0:
        return AdapterResult(AnalyzerStatus("gitleaks-history", "skipped", version=version, detail="The selected target is not a Git repository."))
    try:
        repository_root = Path(top.stdout.strip()).resolve()
        selected_target = target.resolve()
    except OSError:
        return AdapterResult(AnalyzerStatus("gitleaks-history", "failed", version=version, detail="Could not resolve the selected Git repository root."))
    if repository_root != selected_target:
        return AdapterResult(AnalyzerStatus("gitleaks-history", "skipped", version=version, detail="Git-history scanning requires the repository root, not a subdirectory."))

    head_result = _git_command(target, "rev-parse", "HEAD")
    count_result = _git_command(target, "rev-list", "--count", "HEAD")
    shallow_result = _git_command(target, "rev-parse", "--is-shallow-repository")
    if any(result is None or result.returncode != 0 for result in (head_result, count_result, shallow_result)):
        return AdapterResult(AnalyzerStatus("gitleaks-history", "skipped", version=version, detail="No readable commit history is available at HEAD."))
    head = head_result.stdout.strip().lower()
    try:
        commit_count = int(count_result.stdout.strip())
    except ValueError:
        commit_count = 0
    if not re.fullmatch(r"[0-9a-f]{7,64}", head) or commit_count < 1:
        return AdapterResult(AnalyzerStatus("gitleaks-history", "skipped", version=version, detail="The repository has no commits reachable from HEAD."))
    shallow_state = shallow_result.stdout.strip().casefold()
    shallow = shallow_state == "true"
    history_state = "shallow" if shallow else "complete" if shallow_state == "false" else "unknown"

    try:
        with tempfile.TemporaryDirectory(prefix="vigil-fuse-gitleaks-") as temporary:
            temporary_dir = Path(temporary)
            config_path = temporary_dir / "gitleaks.toml"
            config_path.write_text("[extend]\nuseDefault = true\n", encoding="utf-8")
            command = [
                executable, "git", "--config", str(config_path), "--redact=100",
                "--report-format=json", "--report-path=-", "--exit-code=0",
                "--timeout", str(ANALYZER_TIMEOUT_SECONDS), "--no-banner", "--no-color",
                "--log-level=fatal", "--log-opts=HEAD", "--gitleaks-ignore-path", str(temporary_dir),
                str(selected_target),
            ]
            completed = _run(command, timeout=ANALYZER_TIMEOUT_SECONDS + 5, cwd=selected_target)
    except subprocess.TimeoutExpired:
        return AdapterResult(AnalyzerStatus("gitleaks-history", "failed", version=version, detail="Timed out after 180 seconds; no raw report was saved."))
    except OSError as error:
        return AdapterResult(AnalyzerStatus("gitleaks-history", "failed", version=version, detail=f"Could not start Gitleaks ({type(error).__name__}); no raw report was saved."))
    except AnalyzerOutputLimitError:
        return AdapterResult(AnalyzerStatus("gitleaks-history", "failed", version=version, detail="Gitleaks output exceeded 10 MiB; no raw report was saved."))

    if completed.returncode != 0:
        return AdapterResult(AnalyzerStatus("gitleaks-history", "failed", version=version, detail=f"Gitleaks exited with status {completed.returncode}; diagnostics were omitted."))
    try:
        document = json.loads(completed.stdout or "[]")
        findings = _gitleaks_findings(document, selected_target, version)
    except (ValueError, TypeError):
        return AdapterResult(AnalyzerStatus("gitleaks-history", "failed", version=version, detail="Gitleaks did not emit a readable JSON report; raw output was omitted."))

    status = "completed" if history_state == "complete" else "partial"
    detail = f"Scanned {commit_count} commit(s) reachable from HEAD {head[:12]}; secret values were not retained."
    if shallow:
        detail += " The repository is shallow, so older history was not available."
    elif history_state == "unknown":
        detail += " The repository's shallow-history state could not be confirmed."
    artifacts: tuple[AnalysisArtifact, ...] = ()
    try:
        output_dir.mkdir(parents=True, exist_ok=True)
        artifact_path = _artifact_destination(output_dir, "git-history-findings.json")
        safe_report = {
            "schema_version": "1.0",
            "analyzer": "gitleaks-history",
            "tool_version": version,
            "scope": "commits reachable from current HEAD",
            "head_commit": head,
            "commit_count": commit_count,
            "history_shallow": shallow,
            "history_completeness": history_state,
            "secrets_redacted": True,
            "findings": [
                {
                    "fingerprint": finding.fingerprint,
                    "rule_id": finding.rule_id,
                    "path": finding.file,
                    "line": finding.start_line,
                    "evidence": finding.evidence,
                }
                for finding in findings
            ],
        }
        artifact_path.write_text(json.dumps(safe_report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        artifacts = (_artifact(artifact_path, "application/json", output_dir),)
    except (OSError, ValueError, TypeError) as error:
        return AdapterResult(AnalyzerStatus("gitleaks-history", "failed", version=version, detail=f"Could not write the redacted Git-history report ({type(error).__name__})."), findings=findings)
    return AdapterResult(
        AnalyzerStatus("gitleaks-history", status, version=version, detail=detail, findings=len(findings)),
        findings=findings,
        artifacts=artifacts,
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
    version = _tool_version(executable)
    try:
        completed = _run([executable, str(target.resolve())])
    except subprocess.TimeoutExpired:
        return AdapterResult(
            AnalyzerStatus("binwalk", "failed", version=version, detail="Timed out after 180 seconds.")
        )
    except OSError as error:
        return AdapterResult(AnalyzerStatus("binwalk", "failed", version=version, detail=f"Could not start Binwalk ({type(error).__name__})."))
    except AnalyzerOutputLimitError:
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
    content_bytes = content.encode("utf-8")
    output_truncated = len(content_bytes) > MAX_BINWALK_REPORT_BYTES
    report_path.write_bytes(content_bytes[:MAX_BINWALK_REPORT_BYTES])
    status = (
        "failed"
        if completed.returncode != 0
        else "partial"
        if output_truncated
        else "completed"
    )
    detail = (
        f"Binwalk exited with code {completed.returncode}."
        if completed.returncode != 0
        else "Signature identification only; no extraction or firmware execution was attempted. "
        "A successful signature scan is not a complete firmware security assessment."
    )
    if output_truncated:
        detail += f" The saved signature report was truncated at the {MAX_BINWALK_REPORT_BYTES}-byte limit."
    try:
        artifact = _artifact(report_path, "text/plain", output_dir)
    except OSError as error:
        return AdapterResult(AnalyzerStatus("binwalk", "failed", detail=str(error)))
    return AdapterResult(
        AnalyzerStatus("binwalk", status, version=version, detail=detail),  # type: ignore[arg-type]
        artifacts=(artifact,),
    )
