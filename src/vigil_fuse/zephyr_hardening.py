from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any

from .model import AnalyzerStatus, ContextArtifact, Finding
from .path_safety import resolve_inside_directory
from .platform_context import MAX_CONTEXT_FILE_BYTES, resolve_build_dir

_SAFE_SYMBOL = re.compile(r"^(?:CONFIG_)?[A-Z0-9_]{1,160}$")
_SAFE_PROFILE = re.compile(r"^[A-Za-z0-9_.+-]{1,120}$")
_CWE = re.compile(r"^CWE-(\d{1,6})$")
_CVE = re.compile(r"^CVE-(\d{4})-(\d{4,})$", re.IGNORECASE)
_MAX_OPTIONS = 10000
_MAX_FIELD_LENGTH = 4000


def resolve_hardening_report_path(
    target: str | Path,
    build_dir: str | Path,
    report_path: str | Path,
) -> tuple[Path, str]:
    """Resolve a report only when it is a regular file inside the selected build directory."""
    root = Path(target).expanduser().resolve(strict=True)
    build_root, _ = resolve_build_dir(root, build_dir)
    supplied = Path(report_path).expanduser()
    candidate = supplied if supplied.is_absolute() else root / supplied
    try:
        resolved, _ = resolve_inside_directory(build_root, candidate)
    except ValueError as error:
        if "symbolic link" in str(error):
            raise ValueError(
                "--zephyr-hardening-report cannot pass through a symbolic link"
            ) from error
        raise ValueError(
            "--zephyr-hardening-report must resolve inside the selected --build-dir"
        ) from error
    if not resolved.is_file():
        raise ValueError("--zephyr-hardening-report must be an existing file inside --build-dir")
    return resolved, resolved.relative_to(root).as_posix()


def _compact(value: str, limit: int = 240) -> str:
    text = " ".join("".join(character for character in value if character.isprintable()).split())
    return text if len(text) <= limit else text[: limit - 3] + "..."


def _references(values: list[str]) -> tuple[str, ...]:
    links = ["https://docs.zephyrproject.org/latest/security/hardening-tool.html"]
    for value in values:
        cwe = _CWE.fullmatch(value)
        cve = _CVE.fullmatch(value)
        if cwe:
            links.append(f"https://cwe.mitre.org/data/definitions/{cwe.group(1)}.html")
        elif cve:
            links.append(f"https://nvd.nist.gov/vuln/detail/{value.upper()}")
    return tuple(dict.fromkeys(links))


def _validate_report(document: Any) -> tuple[str, list[dict[str, Any]], dict[str, int]]:
    if not isinstance(document, dict):
        raise ValueError("JSON root must be an object")
    profile = document.get("profile")
    options = document.get("options")
    fail_count = document.get("fail_count")
    if not isinstance(profile, str) or not _SAFE_PROFILE.fullmatch(profile):
        raise ValueError("profile is missing or malformed")
    if not isinstance(options, list) or len(options) > _MAX_OPTIONS:
        raise ValueError(f"options must be an array of at most {_MAX_OPTIONS} entries")
    if not isinstance(fail_count, int) or isinstance(fail_count, bool) or fail_count < 0:
        raise ValueError("fail_count must be a non-negative integer")

    validated: list[dict[str, Any]] = []
    seen_symbols: set[str] = set()
    counts = {"FAIL": 0, "PASS": 0, "NA": 0}
    for index, option in enumerate(options):
        if not isinstance(option, dict):
            raise ValueError(f"option {index} must be an object")
        name = option.get("name")
        recommended = option.get("recommended")
        rationale = option.get("rationale")
        result = option.get("result")
        current = option.get("current")
        references = option.get("references", [])
        if not isinstance(name, str) or not _SAFE_SYMBOL.fullmatch(name):
            raise ValueError(f"option {index} has an invalid Kconfig symbol")
        symbol = name if name.startswith("CONFIG_") else f"CONFIG_{name}"
        if symbol in seen_symbols:
            raise ValueError(f"duplicate Kconfig symbol in hardening report: {symbol}")
        seen_symbols.add(symbol)
        if (
            not isinstance(recommended, str)
            or not recommended.strip()
            or len(recommended) > _MAX_FIELD_LENGTH
        ):
            raise ValueError(f"option {symbol} has an invalid recommended value")
        if (
            not isinstance(rationale, str)
            or not rationale.strip()
            or len(rationale) > _MAX_FIELD_LENGTH
        ):
            raise ValueError(f"option {symbol} has an invalid rationale")
        if not isinstance(result, str) or result not in counts:
            raise ValueError(f"option {symbol} has an unsupported result")
        if current is not None and (
            not isinstance(current, str) or len(current) > _MAX_FIELD_LENGTH
        ):
            raise ValueError(f"option {symbol} has an invalid current value")
        if (
            not isinstance(references, list)
            or len(references) > 100
            or any(not isinstance(value, str) or len(value) > 200 for value in references)
        ):
            raise ValueError(f"option {symbol} has invalid references")
        counts[result] += 1
        validated.append(
            {
                "symbol": symbol,
                "recommended": recommended,
                "current": current,
                "rationale": rationale,
                "result": result,
                "references": references,
            }
        )

    if counts["FAIL"] != fail_count:
        raise ValueError("fail_count does not match the FAIL options")
    return profile, validated, counts


def inspect_hardening_report(
    target: str | Path,
    build_dir: str | Path,
    report_path: str | Path,
) -> tuple[ContextArtifact, tuple[Finding, ...], AnalyzerStatus]:
    path, relative_path = resolve_hardening_report_path(target, build_dir, report_path)
    try:
        size = path.stat().st_size
        if size > MAX_CONTEXT_FILE_BYTES:
            artifact = ContextArtifact(relative_path, "Zephyr hardenconfig JSON report", None, size)
            return (
                artifact,
                (),
                AnalyzerStatus(
                    "zephyr-hardenconfig",
                    "partial",
                    detail="The selected Zephyr hardening report exceeds the 4 MiB input limit.",
                ),
            )
        with path.open("rb") as source:
            data = source.read(MAX_CONTEXT_FILE_BYTES + 1)
    except OSError as error:
        artifact = ContextArtifact(relative_path, "Zephyr hardenconfig JSON report", None, 0)
        return (
            artifact,
            (),
            AnalyzerStatus(
                "zephyr-hardenconfig",
                "partial",
                detail=f"The selected report could not be read: {type(error).__name__}.",
            ),
        )
    if len(data) > MAX_CONTEXT_FILE_BYTES:
        artifact = ContextArtifact(
            relative_path, "Zephyr hardenconfig JSON report", None, len(data)
        )
        return (
            artifact,
            (),
            AnalyzerStatus(
                "zephyr-hardenconfig",
                "partial",
                detail="The selected Zephyr hardening report exceeds the 4 MiB input limit.",
            ),
        )

    digest = hashlib.sha256(data).hexdigest()
    artifact = ContextArtifact(relative_path, "Zephyr hardenconfig JSON report", digest, len(data))
    try:
        document = json.loads(data.decode("utf-8"))
        profile, options, counts = _validate_report(document)
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError, ValueError) as error:
        detail = str(error) if isinstance(error, ValueError) else "invalid UTF-8 JSON"
        return (
            artifact,
            (),
            AnalyzerStatus(
                "zephyr-hardenconfig",
                "failed",
                detail=f"The selected Zephyr hardening report is invalid: {_compact(detail, 300)}",
            ),
        )

    findings: list[Finding] = []
    for option in options:
        if option["result"] != "FAIL":
            continue
        symbol = option["symbol"]
        current = (
            "unset or unavailable"
            if option["current"] is None
            else _compact(option["current"], 120)
        )
        recommended = _compact(option["recommended"], 120)
        rationale = (
            _compact(option["rationale"], 800)
            or "Zephyr reports that this option differs from its recommendation."
        )
        evidence = _compact(
            f"{symbol}: current={current}; recommended={recommended}; profile={profile}; result=FAIL",
            240,
        )
        fingerprint_material = "\0".join(
            ("zephyr-hardenconfig", relative_path, profile, symbol, current, recommended)
        )
        findings.append(
            Finding(
                id=f"ZEPHYR-HARDENCONFIG:{profile}:{symbol}",
                fingerprint=hashlib.sha256(fingerprint_material.encode("utf-8")).hexdigest(),
                rule_id="ZEPHYR-HARDENCONFIG",
                rule_version="1.0.0",
                analyzer="zephyr-hardenconfig",
                title=f"Zephyr hardening recommendation not met: {symbol}",
                severity="unknown",
                confidence="high",
                category="hardening-configuration",
                file=relative_path,
                start_line=None,
                end_line=None,
                evidence=evidence,
                explanation=(
                    f"Zephyr's {profile} hardening profile marked {symbol} as FAIL. {rationale} "
                    "This is a selected-build configuration signal, not proof that the setting is present in a released image."
                ),
                potential_impact=(
                    f"The selected Zephyr build does not meet this upstream hardening recommendation. {rationale}"
                ),
                remediation=(
                    f"Review the Zephyr recommendation and set {symbol} to {recommended} if appropriate for this target. "
                    "Rebuild and verify the configuration and artifact selected for release."
                ),
                references=_references(option["references"]),
                applicability="candidate",
                validation_method="external-tool",
                validation_status="not-validated",
            )
        )

    detail = (
        f"Imported Zephyr hardenconfig profile '{profile}': {counts['FAIL']} FAIL, "
        f"{counts['PASS']} PASS, {counts['NA']} not applicable; "
        "Zephyr supplied the recommendation database and evaluation."
    )
    return (
        artifact,
        tuple(findings),
        AnalyzerStatus("zephyr-hardenconfig", "completed", detail=detail, findings=len(findings)),
    )
