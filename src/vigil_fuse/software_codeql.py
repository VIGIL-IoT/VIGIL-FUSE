from __future__ import annotations

import hashlib
import json
import re
import shutil
import subprocess
import tempfile
from pathlib import Path
from urllib.parse import unquote, urlsplit
from urllib.request import url2pathname

from .analyzer_runtime import (
    MAX_ANALYZER_OUTPUT_BYTES,
    AdapterResult,
    AnalyzerOutputLimitError,
    inspect_tool_version,
    run_bounded_host_tool,
)
from .path_safety import assert_no_path_aliases
from .model import AnalyzerStatus, CodeFlowLocation, Finding, Severity
from .software_semgrep import _pairs, config_digest

_RULE = re.compile(r"^[A-Za-z0-9_./-]{1,200}$")
_CWE = re.compile(r"^external/cwe/cwe-([0-9]+)$", re.IGNORECASE)


def _location(value: object, target: Path, allowed_bases: set[str]) -> CodeFlowLocation:
    if not isinstance(value, dict):
        raise ValueError("invalid location")
    physical = value.get("physicalLocation")
    if not isinstance(physical, dict):
        raise ValueError("invalid physical location")
    artifact, region = physical.get("artifactLocation"), physical.get("region")
    if not isinstance(artifact, dict) or not isinstance(region, dict):
        raise ValueError("invalid location fields")
    base = artifact.get("uriBaseId")
    if base is not None and (not isinstance(base, str) or base not in allowed_bases):
        raise ValueError("unverified location base")
    uri, line = artifact.get("uri"), region.get("startLine")
    if (
        not isinstance(uri, str)
        or not uri
        or len(uri) > 4096
        or type(line) is not int
        or not 1 <= line <= 10000000
    ):
        raise ValueError("invalid location data")
    parts = urlsplit(uri)
    if parts.scheme or parts.netloc or parts.query or parts.fragment:
        raise ValueError("external location")
    name = unquote(parts.path)
    if (
        "\\" in name
        or ":" in name
        or any(ord(c) < 32 or ord(c) == 127 for c in name)
        or name.startswith("/")
    ):
        raise ValueError("absolute location")
    root = target.resolve()
    try:
        assert_no_path_aliases(root / name, allow_missing=True)
        rel = (root / name).resolve().relative_to(root).as_posix()
    except (OSError, ValueError):
        raise ValueError("location outside target") from None
    if rel == ".":
        raise ValueError("invalid target location")
    return CodeFlowLocation(rel, line)


def parse_codeql(data: str, target: Path, version: str | None) -> tuple[Finding, ...]:
    if len(data.encode("utf-8")) > MAX_ANALYZER_OUTPUT_BYTES:
        raise ValueError("Analyzer report exceeds byte limit")
    document = json.loads(
        data,
        object_pairs_hook=_pairs,
        parse_constant=lambda _: (_ for _ in ()).throw(ValueError("invalid number")),
    )
    if (
        not isinstance(document, dict)
        or document.get("version") != "2.1.0"
        or not isinstance(document.get("runs"), list)
        or len(document["runs"]) > 20
    ):
        raise ValueError("invalid SARIF")
    findings: list[Finding] = []
    for run in document["runs"]:
        if not isinstance(run, dict) or not isinstance(run.get("results"), list):
            raise ValueError("invalid SARIF run")
        allowed_bases: set[str] = set()
        bases = run.get("originalUriBaseIds", {})
        if not isinstance(bases, dict):
            raise ValueError("invalid URI bases")
        for name, entry in bases.items():
            if not isinstance(name, str) or not isinstance(entry, dict):
                raise ValueError("invalid URI base")
            uri = entry.get("uri")
            if not isinstance(uri, str):
                continue
            parts = urlsplit(uri)
            if (
                parts.scheme == "file"
                and not parts.netloc
                and not parts.query
                and not parts.fragment
            ):
                if Path(url2pathname(unquote(parts.path))).resolve() == target.resolve():
                    allowed_bases.add(name)
        tool = run.get("tool")
        if not isinstance(tool, dict) or not isinstance(tool.get("driver"), dict):
            raise ValueError("invalid driver")
        rules = tool["driver"].get("rules", [])
        if not isinstance(rules, list) or len(rules) > 10000:
            raise ValueError("invalid rules")
        definitions = {
            row["id"]: row
            for row in rules
            if isinstance(row, dict) and isinstance(row.get("id"), str)
        }
        for result in run["results"]:
            if len(findings) >= 10000 or not isinstance(result, dict):
                raise ValueError("too many or invalid results")
            rule = result.get("ruleId")
            locations = result.get("locations")
            if (
                not isinstance(rule, str)
                or not _RULE.fullmatch(rule)
                or not isinstance(locations, list)
                or len(locations) != 1
            ):
                raise ValueError("invalid result identity")
            primary = _location(locations[0], target, allowed_bases)
            level = result.get("level", "warning")
            if not isinstance(level, str) or level not in {"error", "warning", "note", "none"}:
                raise ValueError("invalid level")
            severity: Severity = {
                "error": "high",
                "warning": "medium",
                "note": "low",
                "none": "unknown",
            }.get(level, "unknown")  # type: ignore[assignment]
            definition = definitions.get(rule, {})
            query_name = definition.get("name")
            if (
                not isinstance(query_name, str)
                or len(query_name) > 256
                or any(ord(character) < 32 or ord(character) == 127 for character in query_name)
            ):
                query_name = None
            metadata = definition.get("properties", {})
            if not isinstance(metadata, dict):
                raise ValueError("invalid metadata")
            tags = metadata.get("tags", [])
            if (
                not isinstance(tags, list)
                or len(tags) > 100
                or not all(isinstance(tag, str) for tag in tags)
            ):
                raise ValueError("invalid tags")
            cwes = tuple(
                sorted(
                    {f"CWE-{int(match.group(1))}" for tag in tags if (match := _CWE.fullmatch(tag))}
                )
            )
            precision = metadata.get("precision")
            if precision is not None and (
                not isinstance(precision, str)
                or precision not in {"low", "medium", "high", "very-high"}
            ):
                raise ValueError("invalid precision")
            flow: list[tuple[CodeFlowLocation, ...]] = []
            step_count = 0
            flows = result.get("codeFlows", [])
            if not isinstance(flows, list) or len(flows) > 20:
                raise ValueError("invalid code flows")
            for code_flow in flows:
                if not isinstance(code_flow, dict) or not isinstance(
                    code_flow.get("threadFlows"), list
                ):
                    raise ValueError("invalid thread flows")
                if len(code_flow["threadFlows"]) > 20:
                    raise ValueError("too many code-flow paths")
                for thread in code_flow["threadFlows"]:
                    if not isinstance(thread, dict) or not isinstance(
                        thread.get("locations"), list
                    ):
                        raise ValueError("invalid thread locations")
                    path: list[CodeFlowLocation] = []
                    for step in thread["locations"]:
                        if not isinstance(step, dict) or step_count >= 1000:
                            raise ValueError("invalid code flow step")
                        kinds = step.get("kinds", [])
                        if (
                            not isinstance(kinds, list)
                            or len(kinds) > 16
                            or not all(isinstance(kind, str) and len(kind) <= 100 for kind in kinds)
                        ):
                            raise ValueError("invalid code flow kinds")
                        source_sink = tuple(sorted(set(kinds) & {"source", "sink"}))
                        location = _location(step.get("location"), target, allowed_bases)
                        path.append(CodeFlowLocation(location.file, location.line, source_sink))
                        step_count += 1
                    flow.append(tuple(path))
            digest = hashlib.sha256(
                f"codeql\0{rule}\0{primary.file}\0{primary.line}".encode()
            ).hexdigest()
            findings.append(
                Finding(
                    id=f"CODEQL:{digest}",
                    fingerprint=digest,
                    rule_id=f"CODEQL:{rule}",
                    rule_version=version or "unknown",
                    analyzer="codeql",
                    title="CodeQL static candidate",
                    severity=severity,
                    confidence="medium",
                    category="software-source",
                    file=primary.file,
                    start_line=primary.line,
                    end_line=primary.line,
                    evidence="External query matched; messages and source snippets omitted.",
                    explanation=f"CodeQL query {rule}; SARIF level {level}.",
                    potential_impact="Impact and runtime reachability require independent review.",
                    remediation="Review the query and source locations.",
                    references=tuple(
                        f"https://cwe.mitre.org/data/definitions/{c[4:]}.html" for c in cwes
                    ),
                    applicability="candidate",
                    validation_method="external-tool",
                    severity_basis="upstream-label",
                    engine_rule_id=rule,
                    engine_rule_name=query_name,
                    cwe=cwes,
                    external_severity=level,
                    precision=precision,
                    code_flow=tuple(flow),
                )
            )
    return tuple(findings)


def run_codeql(target: Path, database: Path, queries: Path, *, no_network: bool) -> AdapterResult:
    if no_network:
        return AdapterResult(
            AnalyzerStatus(
                "codeql",
                "skipped",
                detail="Host network isolation is not available for this adapter; strict no-network mode does not launch it.",
            )
        )
    executable = shutil.which("codeql")
    if not executable:
        return AdapterResult(
            AnalyzerStatus(
                "codeql", "unavailable", detail="Install CodeQL manually, subject to its license."
            )
        )
    if (
        not target.is_dir()
        or database.is_symlink()
        or not database.is_dir()
        or queries.is_symlink()
        or not queries.is_file()
        or queries.suffix not in {".ql", ".qls"}
    ):
        return AdapterResult(
            AnalyzerStatus(
                "codeql",
                "failed",
                detail="A source directory, existing database, and local query or suite are required.",
            )
        )
    try:
        database.resolve().relative_to(target.resolve())
    except ValueError:
        pass
    else:
        return AdapterResult(
            AnalyzerStatus(
                "codeql",
                "failed",
                detail="The CodeQL database must be outside the scan target because analysis can write to it.",
            )
        )
    version = inspect_tool_version(executable)
    try:
        assert_no_path_aliases(database)
        digest = config_digest(queries)
        with tempfile.TemporaryDirectory(prefix="fuse-codeql-") as temporary:
            output = Path(temporary) / "results.sarif"
            result = run_bounded_host_tool(
                [
                    executable,
                    "database",
                    "analyze",
                    "--no-download",
                    "--format=sarifv2.1.0",
                    "--no-sarif-add-file-contents",
                    "--no-sarif-add-snippets",
                    "--output",
                    str(output),
                    "--",
                    str(database.resolve()),
                    str(queries.resolve()),
                ],
                timeout=180,
                output_limit_bytes=MAX_ANALYZER_OUTPUT_BYTES,
            )
            if result.returncode != 0 or output.is_symlink() or not output.is_file():
                return AdapterResult(
                    AnalyzerStatus(
                        "codeql",
                        "failed",
                        version=version,
                        detail=f"CodeQL did not produce SARIF (exit {result.returncode}); diagnostics omitted.",
                    )
                )
            with output.open("rb") as stream:
                raw = stream.read(MAX_ANALYZER_OUTPUT_BYTES + 1)
            if len(raw) > MAX_ANALYZER_OUTPUT_BYTES:
                raise ValueError("SARIF too large")
            if config_digest(queries) != digest:
                raise ValueError("query changed during analysis")
            findings = parse_codeql(raw.decode("utf-8"), target, version)
    except subprocess.TimeoutExpired:
        return AdapterResult(
            AnalyzerStatus(
                "codeql", "timeout", version=version, detail="CodeQL analysis timed out."
            )
        )
    except (OSError, AnalyzerOutputLimitError, ValueError, RecursionError):
        return AdapterResult(
            AnalyzerStatus(
                "codeql",
                "failed",
                version=version,
                detail="CodeQL output was invalid, exceeded limits, or could not be read.",
            )
        )
    return AdapterResult(
        AnalyzerStatus(
            "codeql",
            "partial",
            version=version,
            detail="Existing database and local query analyzed; database source coverage is not independently verified.",
            findings=len(findings),
            configuration_sha256=digest,
        ),
        findings=findings,
    )
