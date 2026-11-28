from __future__ import annotations

import hashlib
import json
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any

from .analyzer_runtime import (
    MAX_ANALYZER_OUTPUT_BYTES,
    AdapterResult,
    AnalyzerOutputLimitError,
    inspect_tool_version,
    run_bounded_host_tool,
)
from .path_safety import assert_no_path_aliases
from .model import AnalyzerStatus, Finding, Severity

_RULE = re.compile(r"^[A-Za-z0-9_.-]{1,200}$")
_CWE = re.compile(r"^CWE-(\d+)(?:\b|:)")


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def config_digest(path: Path) -> str:
    assert_no_path_aliases(path)
    if not path.is_file():
        raise ValueError("configuration is not a regular file")
    with path.open("rb") as stream:
        raw = stream.read(1024 * 1024 + 1)
    if len(raw) > 1024 * 1024:
        raise ValueError("configuration exceeds 1 MiB")
    return hashlib.sha256(raw).hexdigest()


def validate_local_rules_config(path: Path) -> str:
    """Accept a bounded local rules file without Semgrep registry inheritance."""
    digest = config_digest(path)
    with path.open("rb") as stream:
        raw = stream.read(1024 * 1024 + 1)
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        raise ValueError("configuration must be UTF-8") from None
    if len(raw) > 1024 * 1024 or re.search(r"\bextends\b", text, re.IGNORECASE):
        raise ValueError("configuration exceeds the limit or references inherited rules")
    return digest


def parse_semgrep(data: str, target: Path, version: str | None) -> tuple[tuple[Finding, ...], bool]:
    if len(data.encode("utf-8")) > MAX_ANALYZER_OUTPUT_BYTES:
        raise ValueError("Analyzer report exceeds byte limit")
    document = json.loads(
        data,
        object_pairs_hook=_pairs,
        parse_constant=lambda _: (_ for _ in ()).throw(ValueError("invalid number")),
    )
    if (
        not isinstance(document, dict)
        or not isinstance(document.get("results"), list)
        or not isinstance(document.get("errors"), list)
    ):
        raise ValueError("invalid Semgrep document")
    if len(document["results"]) > 10000:
        raise ValueError("too many findings")
    findings: list[Finding] = []
    root = target.resolve()
    for row in document["results"]:
        if not isinstance(row, dict):
            raise ValueError("invalid result")
        rule, path, start, end, extra = (
            row.get(k) for k in ("check_id", "path", "start", "end", "extra")
        )
        if (
            not isinstance(rule, str)
            or not _RULE.fullmatch(rule)
            or not isinstance(path, str)
            or not path
            or len(path) > 4096
            or not isinstance(start, dict)
            or not isinstance(end, dict)
            or not isinstance(extra, dict)
        ):
            raise ValueError("invalid result fields")
        line, end_line = start.get("line"), end.get("line")
        if (
            type(line) is not int
            or type(end_line) is not int
            or not 1 <= line <= end_line <= 10000000
        ):
            raise ValueError("invalid location")
        if any(ord(c) < 32 or ord(c) == 127 for c in path) or ":" in path.replace(
            str(root.drive), "", 1
        ):
            raise ValueError("unsafe location")
        resolved = Path(path)
        if not resolved.is_absolute():
            resolved = root / resolved
        try:
            assert_no_path_aliases(resolved, allow_missing=True)
            relative = resolved.resolve().relative_to(root).as_posix()
        except (ValueError, OSError):
            raise ValueError("location outside target") from None
        if not relative or relative == ".":
            raise ValueError("invalid location")
        external = extra.get("severity")
        if not isinstance(external, str) or not re.fullmatch(r"[A-Za-z_-]{1,32}", external):
            raise ValueError("invalid severity")
        severity: Severity = {"ERROR": "high", "WARNING": "medium", "INFO": "low"}.get(
            external.upper(), "unknown"
        )  # type: ignore[assignment]
        metadata = extra.get("metadata", {})
        if not isinstance(metadata, dict):
            raise ValueError("invalid metadata")
        cwes = metadata.get("cwe", [])
        if isinstance(cwes, str):
            cwes = [cwes]
        if (
            not isinstance(cwes, list)
            or len(cwes) > 50
            or not all(isinstance(c, str) for c in cwes)
        ):
            raise ValueError("invalid CWE metadata")
        refs = tuple(
            sorted(
                {
                    f"https://cwe.mitre.org/data/definitions/{match.group(1)}.html"
                    for c in cwes
                    if (match := _CWE.match(c))
                }
            )
        )
        identity = f"semgrep\0{rule}\0{relative}\0{line}\0{end_line}"
        digest = hashlib.sha256(identity.encode()).hexdigest()
        findings.append(
            Finding(
                id=f"SEMGREP:{digest}",
                fingerprint=digest,
                rule_id=f"SEMGREP:{rule}",
                rule_version=version or "unknown",
                analyzer="semgrep",
                title="Semgrep static candidate",
                severity=severity,
                confidence="medium",
                category="software-source",
                file=relative,
                start_line=line,
                end_line=end_line,
                evidence="External rule matched; source and tool messages omitted.",
                explanation=f"Semgrep rule {rule}; external severity {external.upper()}. FUSE maps ERROR to high, WARNING to medium and INFO to low.",
                potential_impact="Impact and runtime reachability require independent review.",
                remediation="Review the referenced rule and source location.",
                references=refs,
                applicability="candidate",
                validation_method="external-tool",
                severity_basis="upstream-label",
                engine_rule_id=rule,
                cwe=tuple(f"CWE-{match.group(1)}" for c in cwes if (match := _CWE.match(c))),
                external_severity=external.upper(),
            )
        )
    return tuple(findings), bool(document["errors"])


def run_semgrep(
    target: Path, config: Path, *, no_network: bool, output_dir: Path | None = None
) -> AdapterResult:
    if no_network:
        return AdapterResult(
            AnalyzerStatus(
                "semgrep",
                "skipped",
                detail="Host network isolation is not available for this adapter; strict no-network mode does not launch it.",
            )
        )
    executable = shutil.which("semgrep")
    if not executable:
        return AdapterResult(
            AnalyzerStatus("semgrep", "unavailable", detail="Install Semgrep manually.")
        )
    if not target.is_dir() or config.is_symlink() or not config.is_file():
        return AdapterResult(
            AnalyzerStatus(
                "semgrep",
                "failed",
                detail="A directory target and regular local rule file are required.",
            )
        )
    version = inspect_tool_version(executable)
    try:
        digest = validate_local_rules_config(config)
        exclude: list[str] = []
        if output_dir is not None:
            try:
                output_relative = output_dir.resolve().relative_to(target.resolve()).as_posix()
            except ValueError:
                pass
            else:
                if output_relative == ".":
                    raise ValueError("output directory is target")
                exclude = ["--exclude", output_relative]
        result = run_bounded_host_tool(
            [
                executable,
                "scan",
                "--config",
                str(config.resolve()),
                "--json",
                "--metrics=off",
                "--disable-version-check",
                *exclude,
                str(target.resolve()),
            ],
            timeout=180,
            output_limit_bytes=MAX_ANALYZER_OUTPUT_BYTES,
        )
        if result.returncode != 0:
            return AdapterResult(
                AnalyzerStatus(
                    "semgrep",
                    "failed",
                    version=version,
                    detail=f"Semgrep exited {result.returncode}; diagnostics omitted.",
                )
            )
        if config_digest(config) != digest:
            raise ValueError("configuration changed during scan")
        findings, partial = parse_semgrep(result.stdout, target, version)
    except subprocess.TimeoutExpired:
        return AdapterResult(
            AnalyzerStatus("semgrep", "timeout", version=version, detail="Semgrep timed out.")
        )
    except (OSError, AnalyzerOutputLimitError, ValueError, RecursionError):
        return AdapterResult(
            AnalyzerStatus(
                "semgrep",
                "failed",
                version=version,
                detail="Semgrep output was invalid, exceeded limits, or could not be read.",
            )
        )
    return AdapterResult(
        AnalyzerStatus(
            "semgrep",
            "partial",
            version=version,
            detail=(
                "Semgrep reported analysis errors; diagnostics omitted."
                if partial
                else "Local rules were evaluated; file coverage was not independently verified. Source text and diagnostics omitted."
            ),
            findings=len(findings),
            configuration_sha256=digest,
        ),
        findings=findings,
    )
