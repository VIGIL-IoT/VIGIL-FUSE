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
    analyzer_unavailable_detail,
    resolve_analyzer_executable,
)
from .path_safety import assert_no_path_aliases
from .model import AnalyzerStatus, Finding, Severity
from .software_semgrep import _pairs

_IDENTIFIER = re.compile(r"[A-Za-z0-9_.:-]{1,200}\Z")
_MAX_ITEMS = 10000
_SEVERITIES = {"CRITICAL": "critical", "HIGH": "high", "MEDIUM": "medium", "LOW": "low"}


def _path_from_target(value: object, target: Path) -> str:
    if not isinstance(value, str) or not value or len(value) > 4096 or "\\" in value:
        raise ValueError("invalid Trivy secret path")
    prefix = "/fuse/input/"
    if value.startswith(prefix):
        value = value[len(prefix) :]
    if value.startswith("/") or ":" in value:
        raise ValueError("unsafe Trivy secret path")
    parts = value.split("/")
    if any(part in {"", ".", ".."} for part in parts):
        raise ValueError("unsafe Trivy secret path")
    try:
        assert_no_path_aliases(target / Path(*parts), allow_missing=True)
        resolved = (target.resolve() / Path(*parts)).resolve()
        return resolved.relative_to(target.resolve()).as_posix()
    except (OSError, ValueError):
        raise ValueError("Trivy secret path escaped the target") from None


def parse_trivy_secrets(data: str, target: Path, version: str | None) -> tuple[Finding, ...]:
    if len(data.encode("utf-8")) > MAX_ANALYZER_OUTPUT_BYTES:
        raise ValueError("Analyzer report exceeds byte limit")
    document = json.loads(
        data,
        object_pairs_hook=_pairs,
        parse_constant=lambda _: (_ for _ in ()).throw(ValueError("invalid number")),
    )
    if (
        not isinstance(document, dict)
        or document.get("SchemaVersion") != 2
        or not isinstance(document.get("Results"), list)
        or len(document["Results"]) > _MAX_ITEMS
    ):
        raise ValueError("invalid Trivy secret report")

    findings: list[Finding] = []
    seen = 0
    for result in document["Results"]:
        if not isinstance(result, dict):
            raise ValueError("invalid Trivy result")
        secrets = result.get("Secrets", [])
        if secrets is None:
            continue
        if not isinstance(secrets, list):
            raise ValueError("invalid Trivy secret list")
        if secrets:
            relative = _path_from_target(result.get("Target"), target)
        for secret in secrets:
            seen += 1
            if seen > _MAX_ITEMS or not isinstance(secret, dict):
                raise ValueError("invalid or excessive Trivy secret results")
            rule = secret.get("RuleID")
            external = secret.get("Severity")
            start = secret.get("StartLine")
            end = secret.get("EndLine", start)
            if (
                not isinstance(rule, str)
                or not _IDENTIFIER.fullmatch(rule)
                or not isinstance(external, str)
                or external.upper() not in {*_SEVERITIES, "UNKNOWN"}
                or type(start) is not int
                or not 1 <= start <= 10_000_000
                or type(end) is not int
                or not start <= end <= 10_000_000
            ):
                raise ValueError("invalid Trivy secret metadata")
            normalized: Severity = _SEVERITIES.get(external.upper(), "unknown")  # type: ignore[assignment]
            digest = hashlib.sha256(
                f"trivy-secret\0{rule}\0{relative}\0{start}\0{end}".encode("utf-8")
            ).hexdigest()
            findings.append(
                Finding(
                    id=f"TRIVY-SECRET:{digest}",
                    fingerprint=digest,
                    rule_id=f"TRIVY-SECRET:{rule}",
                    rule_version=version or "unknown",
                    analyzer="trivy-secrets",
                    title="Possible secret exposure",
                    severity=normalized,
                    confidence="medium",
                    category="secrets",
                    file=relative,
                    start_line=start,
                    end_line=end,
                    evidence=f"Trivy secret rule {rule} matched this location; matched content was redacted.",
                    explanation="An external local secret scanner reported a candidate at this source location.",
                    potential_impact="A committed credential may allow unauthorized access if it remains valid.",
                    remediation="Revoke or rotate any confirmed credential, remove it from active source, and review repository history.",
                    applicability="candidate",
                    validation_method="external-tool",
                    severity_basis="upstream-label",
                    engine_rule_id=rule,
                    external_severity=external.upper(),
                )
            )
    return tuple(findings)


def run_trivy_secrets(target: Path) -> AdapterResult:
    """Scan one project directory with Trivy secret rules in the offline Docker sandbox."""
    if not analyzer_sandbox_active():
        return AdapterResult(
            AnalyzerStatus(
                "trivy-secrets",
                "skipped",
                detail="Secret scanning requires the no-network Docker analyzer sandbox; host execution is disabled.",
            )
        )
    if not target.is_dir():
        return AdapterResult(
            AnalyzerStatus(
                "trivy-secrets", "unsupported", detail="A project directory is required."
            )
        )
    executable = resolve_analyzer_executable("trivy")
    if executable is None:
        return AdapterResult(
            AnalyzerStatus(
                "trivy-secrets",
                "unavailable",
                detail=analyzer_unavailable_detail("trivy", "Install Trivy."),
            )
        )
    version = _tool_version(executable)
    command = [
        executable,
        "fs",
        "--scanners",
        "secret",
        "--format",
        "json",
        "--no-progress",
        "--config=",
        "--ignorefile=",
        "--secret-config=",
        "--skip-version-check",
        "--disable-telemetry",
        "--skip-db-update",
        "--skip-check-update",
        str(target.resolve()),
    ]
    try:
        completed = _run(
            command,
            timeout=180,
            output_limit_bytes=MAX_ANALYZER_OUTPUT_BYTES,
        )
    except subprocess.TimeoutExpired:
        return AdapterResult(
            AnalyzerStatus("trivy-secrets", "timeout", version=version, detail="Trivy timed out.")
        )
    except (OSError, AnalyzerOutputLimitError):
        return AdapterResult(
            AnalyzerStatus(
                "trivy-secrets",
                "failed",
                version=version,
                detail="Trivy could not complete the bounded scan.",
            )
        )
    if completed.returncode != 0:
        return AdapterResult(
            AnalyzerStatus(
                "trivy-secrets",
                "failed",
                version=version,
                detail=f"Trivy exited {completed.returncode}; diagnostics omitted.",
            )
        )
    try:
        findings = parse_trivy_secrets(completed.stdout, target, version)
    except (ValueError, RecursionError):
        return AdapterResult(
            AnalyzerStatus(
                "trivy-secrets",
                "failed",
                version=version,
                detail="Trivy did not emit a valid bounded secret report.",
            )
        )
    return AdapterResult(
        AnalyzerStatus(
            "trivy-secrets",
            "partial",
            version=version,
            findings=len(findings),
            detail="Offline secret rules ran; Trivy JSON contains findings only and does not prove file-level scan coverage.",
        ),
        findings=findings,
    )
