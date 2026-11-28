from __future__ import annotations

import hashlib
import json
import re
import subprocess
from pathlib import Path

from .analyzer_runtime import (
    MAX_ANALYZER_OUTPUT_BYTES,
    AdapterResult,
    AnalyzerOutputLimitError,
    _run,
    _tool_version,
    analyzer_sandbox_active,
    resolve_analyzer_executable,
)
from .path_safety import assert_no_path_aliases
from .model import AnalyzerStatus, Finding, Severity
from .software_semgrep import _pairs

_ID = re.compile(r"^[A-Za-z0-9_.-]{1,200}$")


def parse_trivy(data: str, target: Path, version: str | None) -> tuple[Finding, ...]:
    if len(data.encode("utf-8")) > MAX_ANALYZER_OUTPUT_BYTES:
        raise ValueError("Analyzer report exceeds byte limit")
    doc = json.loads(
        data,
        object_pairs_hook=_pairs,
        parse_constant=lambda _: (_ for _ in ()).throw(ValueError("invalid number")),
    )
    if (
        not isinstance(doc, dict)
        or doc.get("SchemaVersion") != 2
        or not isinstance(doc.get("Results"), list)
        or len(doc["Results"]) > 10000
    ):
        raise ValueError("invalid Trivy document")
    findings: list[Finding] = []
    for result in doc["Results"]:
        if not isinstance(result, dict) or not isinstance(result.get("Target"), str):
            raise ValueError("invalid Trivy result")
        path = result["Target"]
        if path.startswith("/fuse/input/"):
            path = path[len("/fuse/input/") :]
        if (
            not path
            or len(path) > 4096
            or ":" in path
            or any(ord(c) < 32 or ord(c) == 127 for c in path)
            or "\\" in path
            or Path(path).is_absolute()
        ):
            raise ValueError("unsafe result path")
        try:
            assert_no_path_aliases(target / path, allow_missing=True)
            relative = (target.resolve() / path).resolve().relative_to(target.resolve()).as_posix()
        except (OSError, ValueError):
            raise ValueError("result path outside target") from None
        checks = result.get("Misconfigurations", [])
        if checks is None:
            checks = []
        if not isinstance(checks, list):
            raise ValueError("invalid misconfigurations")
        for check in checks:
            if not isinstance(check, dict) or len(findings) >= 10000:
                raise ValueError("invalid or excessive checks")
            status = check.get("Status")
            if status not in ("FAIL", "PASS", "EXCEPTION"):
                raise ValueError("invalid check status")
            if status != "FAIL":
                continue
            rule, external = check.get("ID"), check.get("Severity")
            if (
                not isinstance(rule, str)
                or not _ID.fullmatch(rule)
                or not isinstance(external, str)
                or external.upper() not in {"CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"}
            ):
                raise ValueError("invalid check metadata")
            cause = check.get("CauseMetadata", {})
            if not isinstance(cause, dict):
                raise ValueError("invalid location")
            line, end = cause.get("StartLine"), cause.get("EndLine")
            if line is not None and (type(line) is not int or not 1 <= line <= 10000000):
                raise ValueError("invalid start line")
            if end is not None and (
                type(end) is not int or line is None or not line <= end <= 10000000
            ):
                raise ValueError("invalid end line")
            severity: Severity = {
                "CRITICAL": "critical",
                "HIGH": "high",
                "MEDIUM": "medium",
                "LOW": "low",
                "UNKNOWN": "unknown",
            }.get(external.upper(), "unknown")  # type: ignore[assignment]
            digest = hashlib.sha256(
                f"trivy\0{rule}\0{relative}\0{line}\0{end}".encode()
            ).hexdigest()
            findings.append(
                Finding(
                    id=f"TRIVY:{digest}",
                    fingerprint=digest,
                    rule_id=f"TRIVY:{rule}",
                    rule_version=version or "unknown",
                    analyzer="trivy",
                    title="Trivy configuration candidate",
                    severity=severity,
                    confidence="medium",
                    category="iac-configuration",
                    file=relative,
                    start_line=line,
                    end_line=end,
                    evidence="External configuration check failed; source text omitted.",
                    explanation=f"Trivy check {rule}; upstream severity {external.upper()}.",
                    potential_impact="Impact and deployment applicability require review.",
                    remediation="Review the configuration against the referenced check.",
                    applicability="candidate",
                    validation_method="external-tool",
                    severity_basis="upstream-label",
                    engine_rule_id=rule,
                    external_severity=external.upper(),
                )
            )
    return tuple(findings)


def run_trivy_config(target: Path) -> AdapterResult:
    if not analyzer_sandbox_active():
        return AdapterResult(
            AnalyzerStatus(
                "trivy-config",
                "skipped",
                detail="IaC scanning requires the no-network Docker sandbox; Terraform modules can otherwise trigger downloads.",
            )
        )
    if not target.is_dir():
        return AdapterResult(
            AnalyzerStatus("trivy-config", "unsupported", detail="A project directory is required.")
        )
    executable = resolve_analyzer_executable("trivy")
    if executable is None:
        return AdapterResult(
            AnalyzerStatus(
                "trivy-config",
                "unavailable",
                detail="Configure a locally available digest-pinned Trivy sandbox image.",
            )
        )
    version = _tool_version(executable)
    try:
        result = _run(
            [
                executable,
                "config",
                "--config=",
                "--ignorefile=",
                "--format",
                "json",
                "--skip-check-update",
                "--skip-version-check",
                "--disable-telemetry",
                str(target.resolve()),
            ],
            timeout=180,
            output_limit_bytes=MAX_ANALYZER_OUTPUT_BYTES,
        )
        if result.returncode != 0:
            return AdapterResult(
                AnalyzerStatus(
                    "trivy-config",
                    "failed",
                    version=version,
                    detail=f"Trivy exited {result.returncode}; diagnostics omitted.",
                )
            )
        findings = parse_trivy(result.stdout, target, version)
    except subprocess.TimeoutExpired:
        return AdapterResult(
            AnalyzerStatus("trivy-config", "timeout", version=version, detail="Trivy timed out.")
        )
    except (OSError, AnalyzerOutputLimitError, ValueError, RecursionError):
        return AdapterResult(
            AnalyzerStatus(
                "trivy-config",
                "failed",
                version=version,
                detail="Trivy output was invalid, exceeded limits, or could not be read.",
            )
        )
    return AdapterResult(
        AnalyzerStatus(
            "trivy-config",
            "partial",
            version=version,
            detail="Offline configuration checks ran; remote modules and file coverage are not verified.",
            findings=len(findings),
        ),
        findings=findings,
    )
