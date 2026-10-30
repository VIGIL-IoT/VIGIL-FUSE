from __future__ import annotations

import hashlib
import json
import re
import shutil
import subprocess
import tempfile
from pathlib import Path, PurePosixPath
from typing import Literal

from .analyzer_runtime import (
    ANALYZER_TIMEOUT_SECONDS,
    TOOL_VERSION_TIMEOUT_SECONDS,
    AdapterResult,
    AnalyzerOutputLimitError,
    _artifact,
    _artifact_destination,
    _run,
    _tool_version,
)
from .model import AnalysisArtifact, AnalyzerStatus, Finding


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


def _gitleaks_findings(document: object, target: Path, version: str | None) -> tuple[Finding, ...]:
    if not isinstance(document, list):
        raise ValueError("Gitleaks report is not a JSON findings array")
    findings: list[Finding] = []
    seen: set[str] = set()
    for item in document:
        if not isinstance(item, dict):
            raise ValueError("Gitleaks report contains an invalid finding")
        raw_rule = item.get("RuleID")
        rule = (
            re.sub(r"[^A-Za-z0-9_.-]", "_", raw_rule[:80])
            if isinstance(raw_rule, str)
            else "unknown"
        )
        file = _history_path(item.get("File"), target)
        line = _safe_line(item.get("StartLine", item.get("Line")))
        commit_raw = item.get("Commit")
        commit = (
            commit_raw.lower()
            if isinstance(commit_raw, str) and re.fullmatch(r"[0-9a-fA-F]{7,64}", commit_raw)
            else "unknown"
        )
        date_raw = item.get("Date")
        date = (
            date_raw[:32]
            if isinstance(date_raw, str)
            and re.fullmatch(
                r"\d{4}-\d{2}-\d{2}(?:T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)?",
                date_raw,
            )
            else None
        )
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
            AnalyzerStatus(
                "gitleaks-history",
                "skipped",
                detail="Git-history scanning requires a repository-root directory target.",
            )
        )
    git = shutil.which("git")
    if git is None:
        return AdapterResult(
            AnalyzerStatus(
                "gitleaks-history",
                "unavailable",
                detail="Install Git to inspect repository history.",
            )
        )
    executable = shutil.which("gitleaks")
    if executable is None:
        return AdapterResult(
            AnalyzerStatus(
                "gitleaks-history",
                "unavailable",
                detail="Install Gitleaks and rerun with --git-history.",
            )
        )
    version = _tool_version(executable)

    top = _git_command(target, "rev-parse", "--show-toplevel")
    if top is None or top.returncode != 0:
        return AdapterResult(
            AnalyzerStatus(
                "gitleaks-history",
                "skipped",
                version=version,
                detail="The selected target is not a Git repository.",
            )
        )
    try:
        repository_root = Path(top.stdout.strip()).resolve()
        selected_target = target.resolve()
    except OSError:
        return AdapterResult(
            AnalyzerStatus(
                "gitleaks-history",
                "failed",
                version=version,
                detail="Could not resolve the selected Git repository root.",
            )
        )
    if repository_root != selected_target:
        return AdapterResult(
            AnalyzerStatus(
                "gitleaks-history",
                "skipped",
                version=version,
                detail="Git-history scanning requires the repository root, not a subdirectory.",
            )
        )

    head_result = _git_command(target, "rev-parse", "HEAD")
    count_result = _git_command(target, "rev-list", "--count", "HEAD")
    shallow_result = _git_command(target, "rev-parse", "--is-shallow-repository")
    if (
        head_result is None
        or head_result.returncode != 0
        or count_result is None
        or count_result.returncode != 0
        or shallow_result is None
        or shallow_result.returncode != 0
    ):
        return AdapterResult(
            AnalyzerStatus(
                "gitleaks-history",
                "skipped",
                version=version,
                detail="No readable commit history is available at HEAD.",
            )
        )
    head = head_result.stdout.strip().lower()
    try:
        commit_count = int(count_result.stdout.strip())
    except ValueError:
        commit_count = 0
    if not re.fullmatch(r"[0-9a-f]{7,64}", head) or commit_count < 1:
        return AdapterResult(
            AnalyzerStatus(
                "gitleaks-history",
                "skipped",
                version=version,
                detail="The repository has no commits reachable from HEAD.",
            )
        )
    shallow_state = shallow_result.stdout.strip().casefold()
    shallow = shallow_state == "true"
    history_state = "shallow" if shallow else "complete" if shallow_state == "false" else "unknown"

    try:
        with tempfile.TemporaryDirectory(prefix="vigil-fuse-gitleaks-") as temporary:
            temporary_dir = Path(temporary)
            config_path = temporary_dir / "gitleaks.toml"
            config_path.write_text("[extend]\nuseDefault = true\n", encoding="utf-8")
            command = [
                executable,
                "git",
                "--config",
                str(config_path),
                "--redact=100",
                "--report-format=json",
                "--report-path=-",
                "--exit-code=0",
                "--timeout",
                str(ANALYZER_TIMEOUT_SECONDS),
                "--no-banner",
                "--no-color",
                "--log-level=fatal",
                "--log-opts=HEAD",
                "--gitleaks-ignore-path",
                str(temporary_dir),
                str(selected_target),
            ]
            completed = _run(command, timeout=ANALYZER_TIMEOUT_SECONDS + 5, cwd=selected_target)
    except subprocess.TimeoutExpired:
        return AdapterResult(
            AnalyzerStatus(
                "gitleaks-history",
                "failed",
                version=version,
                detail="Timed out after 180 seconds; no raw report was saved.",
            )
        )
    except OSError as error:
        return AdapterResult(
            AnalyzerStatus(
                "gitleaks-history",
                "failed",
                version=version,
                detail=f"Could not start Gitleaks ({type(error).__name__}); no raw report was saved.",
            )
        )
    except AnalyzerOutputLimitError:
        return AdapterResult(
            AnalyzerStatus(
                "gitleaks-history",
                "failed",
                version=version,
                detail="Gitleaks output exceeded 10 MiB; no raw report was saved.",
            )
        )

    if completed.returncode != 0:
        return AdapterResult(
            AnalyzerStatus(
                "gitleaks-history",
                "failed",
                version=version,
                detail=f"Gitleaks exited with status {completed.returncode}; diagnostics were omitted.",
            )
        )
    try:
        document = json.loads(completed.stdout or "[]")
        findings = _gitleaks_findings(document, selected_target, version)
    except (ValueError, TypeError):
        return AdapterResult(
            AnalyzerStatus(
                "gitleaks-history",
                "failed",
                version=version,
                detail="Gitleaks did not emit a readable JSON report; raw output was omitted.",
            )
        )

    status: Literal["completed", "partial"] = (
        "completed" if history_state == "complete" else "partial"
    )
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
        artifact_path.write_text(
            json.dumps(safe_report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
        )
        artifacts = (_artifact(artifact_path, "application/json", output_dir),)
    except (OSError, ValueError, TypeError) as error:
        return AdapterResult(
            AnalyzerStatus(
                "gitleaks-history",
                "failed",
                version=version,
                detail=f"Could not write the redacted Git-history report ({type(error).__name__}).",
            ),
            findings=findings,
        )
    return AdapterResult(
        AnalyzerStatus(
            "gitleaks-history", status, version=version, detail=detail, findings=len(findings)
        ),
        findings=findings,
        artifacts=artifacts,
    )
