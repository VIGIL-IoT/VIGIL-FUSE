"""Bounded, deterministic model-ready context from canonical FUSE JSON reports."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
import json
from pathlib import Path, PurePath, PureWindowsPath
import re

from .text_safety import safe_report_text

REASONING_CONTEXT_SCHEMA_VERSION = "reasoning_context_v1"
MAX_SCAN_REPORT_BYTES = 32 * 1024 * 1024

_SEVERITIES = {"critical", "high", "medium", "low", "info", "unknown"}
_CONFIDENCE = {"high", "medium", "low"}
_APPLICABILITY = {"unknown", "candidate", "applicable", "not_applicable"}
_VALIDATION_METHODS = {
    "static",
    "generated-config",
    "advisory-match",
    "external-tool",
    "lab",
    "operator-guided",
}
_VALIDATION_STATUSES = {"not-validated", "validated", "not-applicable"}
_INCOMPLETE_ANALYZER_STATES = {
    "partial",
    "failed",
    "timeout",
    "unavailable",
    "incompatible",
    "unsupported",
    "skipped",
}
_SECRET_ASSIGNMENT = re.compile(
    r"(?i)(?P<name>password|passwd|pwd|secret|token|api[_-]?key|access[_-]?token|"
    r"auth[_-]?token|private[_-]?key|client[_-]?secret)(?P<separator>\s*[:=]\s*)"
    r"(?:\"[^\"\r\n]*\"|'[^'\r\n]*'|[^\s,;]+)"
)
_PRIVATE_KEY = re.compile(
    r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----",
    re.DOTALL,
)
_BEARER_TOKEN = re.compile(r"(?i)(\bBearer\s+)[A-Za-z0-9._~+/=-]{8,}")
_URL_CREDENTIALS = re.compile(r"(?i)(https?://)[^/@\s:]+:[^/@\s]+@")


@dataclass(frozen=True)
class ReasoningContextLimits:
    """Character and item bounds for one finding context packet."""

    max_context_chars: int = 12_000
    max_text_chars: int = 800
    max_snippet_chars: int = 1_200
    max_items: int = 16

    def __post_init__(self) -> None:
        if self.max_context_chars < 2_048:
            raise ValueError("max_context_chars must be at least 2048")
        if self.max_context_chars > 100_000:
            raise ValueError("max_context_chars must not exceed 100000")
        if self.max_text_chars < 32:
            raise ValueError("max_text_chars must be at least 32")
        if self.max_text_chars > 10_000:
            raise ValueError("max_text_chars must not exceed 10000")
        if self.max_snippet_chars < 32:
            raise ValueError("max_snippet_chars must be at least 32")
        if self.max_snippet_chars > 20_000:
            raise ValueError("max_snippet_chars must not exceed 20000")
        if not 1 <= self.max_items <= 100:
            raise ValueError("max_items must be between 1 and 100")


def _mapping(value: object, label: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping) or any(not isinstance(key, str) for key in value):
        raise ValueError(f"{label} must be a JSON object")
    return value


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def load_scan_report(path: Path) -> Mapping[str, object]:
    """Load a bounded UTF-8 FUSE report and reject duplicate JSON keys."""
    if path.stat().st_size > MAX_SCAN_REPORT_BYTES:
        raise ValueError(f"FUSE report exceeds the {MAX_SCAN_REPORT_BYTES}-byte input limit")
    with path.open("rb") as stream:
        raw = stream.read(MAX_SCAN_REPORT_BYTES + 1)
    if len(raw) > MAX_SCAN_REPORT_BYTES:
        raise ValueError(f"FUSE report exceeds the {MAX_SCAN_REPORT_BYTES}-byte input limit")
    try:
        document = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_object)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError(f"invalid FUSE report JSON: {error}") from error
    return _validate_report(document)


def _validate_report(document: object) -> Mapping[str, object]:
    report = _mapping(document, "FUSE report")
    if report.get("schema_version") != "1.11":
        raise ValueError("reasoning context requires a FUSE report with schema_version 1.11")
    tool = _mapping(report.get("tool"), "report.tool")
    if tool.get("name") != "FUSE":
        raise ValueError("report.tool.name must be FUSE")
    _mapping(report.get("summary"), "report.summary")
    _mapping(report.get("coverage"), "report.coverage")
    findings = report.get("findings")
    if not isinstance(findings, list):
        raise ValueError("report.findings must be an array")
    for index, finding in enumerate(findings):
        item = _mapping(finding, f"report.findings[{index}]")
        if not isinstance(item.get("id"), str) or not item["id"]:
            raise ValueError(f"report.findings[{index}].id must be a non-empty string")
    return report


def _clean_text(
    value: object,
    *,
    limit: int,
    category: str,
    truncated: set[str],
) -> str:
    if not isinstance(value, str):
        return ""
    cleaned = safe_report_text(value, limit=max(limit * 8, limit + 1)) or ""
    cleaned = _PRIVATE_KEY.sub("[PRIVATE KEY REDACTED]", cleaned)
    cleaned = _SECRET_ASSIGNMENT.sub(
        lambda match: match.group("name") + match.group("separator") + "[REDACTED]", cleaned
    )
    cleaned = _BEARER_TOKEN.sub(r"\1[REDACTED]", cleaned)
    cleaned = _URL_CREDENTIALS.sub(r"\1[REDACTED]@", cleaned)
    if len(cleaned) > limit:
        truncated.add(category)
        marker = " [truncated]"
        cleaned = cleaned[: max(0, limit - len(marker))].rstrip() + marker
    return cleaned


def _path_text(value: object, limits: ReasoningContextLimits, truncated: set[str]) -> str:
    if not isinstance(value, str) or not value:
        return ""
    windows_path = PureWindowsPath(value)
    posix_path = PurePath(value)
    path = windows_path if windows_path.is_absolute() or "\\" in value else posix_path
    if windows_path.is_absolute() or posix_path.is_absolute():
        value = path.name or "[absolute path omitted]"
    return _clean_text(
        value,
        limit=limits.max_text_chars,
        category="source.files",
        truncated=truncated,
    )


def _same_path(left: object, right: object) -> bool:
    if not isinstance(left, str) or not isinstance(right, str):
        return False
    return left.replace("\\", "/").casefold() == right.replace("\\", "/").casefold()


def _line(value: object, label: str) -> int | None:
    if value is None:
        return None
    if not isinstance(value, int) or isinstance(value, bool) or value < 1:
        raise ValueError(f"{label} must be a positive integer or null")
    return value


def _provenance(
    finding_id: str,
    rule_id: str,
    file_path: str,
    start_line: int | None,
    source_field: str,
) -> dict[str, object]:
    return {
        "source_field": source_field,
        "finding_id": finding_id,
        "rule_id": rule_id,
        "file": file_path,
        "start_line": start_line,
    }


def _evidence(kind: str, summary: str, provenance: dict[str, object]) -> dict[str, object]:
    return {"kind": kind, "summary": summary, "provenance": provenance}


def _stable_unique(items: list[dict[str, object]]) -> list[dict[str, object]]:
    unique = {json.dumps(item, sort_keys=True, ensure_ascii=False): item for item in items}
    return [unique[key] for key in sorted(unique)]


def _cap_items(
    items: list[dict[str, object]], category: str, limits: ReasoningContextLimits, truncated: set[str]
) -> list[dict[str, object]]:
    unique = _stable_unique(items)
    if len(unique) > limits.max_items:
        truncated.add(category)
        return unique[: limits.max_items]
    return unique


def _hardware_finding(category: str, rule_id: str) -> bool:
    lowered = category.casefold()
    return "hardware" in lowered or "cyber-physical" in lowered or rule_id.upper().startswith("FUSE-HW")


def _matching_context(
    report: Mapping[str, object],
    finding_path: str,
    display_path: str,
    start_line: int | None,
    end_line: int | None,
    limits: ReasoningContextLimits,
    truncated: set[str],
) -> tuple[list[dict[str, object]], list[dict[str, object]], list[dict[str, object]]]:
    build: list[dict[str, object]] = []
    firmware: list[dict[str, object]] = []
    hardware: list[dict[str, object]] = []
    context = report.get("project_context")
    if isinstance(context, Mapping):
        for item in context.get("configuration_files", []) if isinstance(context.get("configuration_files", []), list) else []:
            if not isinstance(item, Mapping) or not _same_path(item.get("path"), finding_path):
                continue
            role = _clean_text(item.get("role"), limit=limits.max_text_chars, category="build_evidence", truncated=truncated)
            build.append(_evidence("configuration_file", f"FUSE recorded this file as {role or 'project configuration'}.", _provenance("", "", display_path, None, "project_context.configuration_files")))
        settings = context.get("settings", [])
        if isinstance(settings, list):
            for item in settings:
                if not isinstance(item, Mapping) or not _same_path(item.get("path"), finding_path):
                    continue
                setting_line = _line(item.get("line"), "project_context.settings.line")
                if setting_line is None or (start_line is None and end_line is None):
                    continue
                if start_line is not None and setting_line < start_line:
                    continue
                if end_line is not None and setting_line > end_line:
                    continue
                name = _clean_text(item.get("name"), limit=limits.max_text_chars, category="build_evidence", truncated=truncated)
                value = _clean_text(item.get("value"), limit=limits.max_text_chars, category="build_evidence", truncated=truncated)
                build.append(_evidence("configured_setting", f"{name}={value}", _provenance("", "", display_path, setting_line, "project_context.settings")))
    candidates = report.get("firmware_candidates")
    if isinstance(candidates, Mapping):
        entries = candidates.get("candidates", [])
        if isinstance(entries, list):
            for item in entries:
                if not isinstance(item, Mapping) or not _same_path(item.get("path"), finding_path):
                    continue
                format_name = _clean_text(item.get("format"), limit=limits.max_text_chars, category="firmware_evidence", truncated=truncated)
                size = item.get("byte_size")
                if not isinstance(size, int) or isinstance(size, bool) or size < 0:
                    raise ValueError("firmware candidate byte_size must be a non-negative integer")
                firmware.append(_evidence("firmware_candidate", f"FUSE cataloged a {format_name or 'firmware-like'} file ({size} bytes).", _provenance("", "", display_path, None, "firmware_candidates.candidates")))
    inventory = report.get("hardware_inventory")
    if isinstance(inventory, Mapping):
        artifacts = inventory.get("artifacts", [])
        if isinstance(artifacts, list):
            for item in artifacts:
                if not isinstance(item, Mapping) or not _same_path(item.get("path"), finding_path):
                    continue
                detail = f"{item.get('category', 'hardware artifact')} / {item.get('format', 'unknown format')}"
                hardware.append(_evidence("hardware_artifact", _clean_text(detail, limit=limits.max_text_chars, category="hardware_evidence", truncated=truncated), _provenance("", "", display_path, None, "hardware_inventory.artifacts")))
    netlist = report.get("hardware_netlist")
    if isinstance(netlist, Mapping) and _same_path(netlist.get("path"), finding_path):
        status = _clean_text(netlist.get("status"), limit=limits.max_text_chars, category="hardware_evidence", truncated=truncated)
        candidate_nets = netlist.get("debug_net_candidates", [])
        if isinstance(candidate_nets, list):
            for candidate in candidate_nets[: limits.max_items]:
                summary = _clean_text(candidate, limit=limits.max_text_chars, category="hardware_evidence", truncated=truncated)
                if summary:
                    hardware.append(_evidence("netlist_candidate", f"{status}: {summary}", _provenance("", "", display_path, None, "hardware_netlist.debug_net_candidates")))
            if len(candidate_nets) > limits.max_items:
                truncated.add("hardware_evidence")
    bom = report.get("hardware_bom")
    if isinstance(bom, Mapping) and _same_path(bom.get("source_path"), finding_path):
        status = _clean_text(bom.get("status"), limit=limits.max_text_chars, category="hardware_evidence", truncated=truncated)
        count = bom.get("component_count")
        if not isinstance(count, int) or isinstance(count, bool) or count < 0:
            raise ValueError("hardware_bom.component_count must be a non-negative integer")
        hardware.append(_evidence("bom_inventory", f"FUSE recorded BOM status {status or 'unknown'} with {count} line items; physical population is not verified.", _provenance("", "", display_path, None, "hardware_bom")))
    return build, firmware, hardware


def _truncatable_strings(value: object, path: tuple[str, ...] = ()) -> list[tuple[int, str, str]]:
    candidates: list[tuple[int, str, str]] = []
    if isinstance(value, dict):
        for key in sorted(key for key in value if isinstance(key, str)):
            child = value[key]
            child_path = (*path, key)
            if isinstance(child, str) and child_path[0] not in {"schema_version"} and key not in {
                "id", "rule_id", "severity", "confidence", "category", "file", "start_line",
                "end_line", "state", "stage", "kind", "status", "validation_method",
                "validation_status", "applicability", "source_field", "finding_id",
            }:
                category = ".".join(child_path[:2]) if len(child_path) > 1 else child_path[0]
                candidates.append((len(child), ".".join(child_path), category))
            else:
                candidates.extend(_truncatable_strings(child, child_path))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            candidates.extend(_truncatable_strings(child, (*path, str(index))))
    return candidates


def _compact_length(context: dict[str, object]) -> int:
    return len(json.dumps(context, sort_keys=True, ensure_ascii=False, separators=(",", ":")))


def build_reasoning_context(
    scan_result: Mapping[str, object],
    finding_id: str,
    limits: ReasoningContextLimits = ReasoningContextLimits(),
) -> dict[str, object]:
    """Build one bounded packet from one finding in a canonical FUSE JSON report."""
    report = _validate_report(scan_result)
    if not finding_id:
        raise ValueError("finding ID must not be empty")
    findings = report["findings"]
    assert isinstance(findings, list)
    selected = [item for item in findings if isinstance(item, Mapping) and item.get("id") == finding_id]
    if not selected:
        raise ValueError(f"finding ID not found in report: {finding_id}")
    if len(selected) != 1:
        raise ValueError(f"finding ID is duplicated in report: {finding_id}")
    finding = _mapping(selected[0], "selected finding")
    truncated: set[str] = set()

    rule_id = finding.get("rule_id")
    if not isinstance(rule_id, str) or not rule_id:
        raise ValueError("selected finding.rule_id must be a non-empty string")
    title = finding.get("title")
    severity = finding.get("severity")
    confidence = finding.get("confidence")
    category = finding.get("category")
    if not isinstance(title, str) or not isinstance(category, str):
        raise ValueError("selected finding.title and finding.category must be strings")
    if (
        not isinstance(severity, str)
        or severity not in _SEVERITIES
        or not isinstance(confidence, str)
        or confidence not in _CONFIDENCE
    ):
        raise ValueError("selected finding has an invalid severity or confidence")
    applicability = finding.get("applicability")
    validation_status = finding.get("validation_status")
    validation_method = finding.get("validation_method")
    if (
        not isinstance(applicability, str)
        or applicability not in _APPLICABILITY
        or not isinstance(validation_status, str)
        or validation_status not in _VALIDATION_STATUSES
    ):
        raise ValueError("selected finding has invalid applicability or validation status")
    if not isinstance(validation_method, str) or validation_method not in _VALIDATION_METHODS:
        raise ValueError("selected finding has an invalid validation method")
    location = _mapping(finding.get("location"), "selected finding.location")
    raw_path = location.get("file")
    if not isinstance(raw_path, str):
        raise ValueError("selected finding.location.file must be a string")
    file_path = _path_text(raw_path, limits, truncated)
    start_line = _line(location.get("start_line"), "selected finding.location.start_line")
    end_line = _line(location.get("end_line"), "selected finding.location.end_line")
    finding_key = _clean_text(finding_id, limit=limits.max_text_chars, category="finding.id", truncated=truncated)
    safe_rule_id = _clean_text(rule_id, limit=limits.max_text_chars, category="finding.rule_id", truncated=truncated)
    evidence_text = _clean_text(
        finding.get("evidence"),
        limit=limits.max_snippet_chars,
        category="source.snippets",
        truncated=truncated,
    )
    finding_context: dict[str, object] = {
        "id": finding_key,
        "rule_id": safe_rule_id,
        "analyzer": _clean_text(finding.get("analyzer"), limit=limits.max_text_chars, category="finding.analyzer", truncated=truncated),
        "title": _clean_text(title, limit=limits.max_text_chars, category="finding.title", truncated=truncated),
        "severity": severity,
        "confidence": confidence,
        "category": _clean_text(category, limit=limits.max_text_chars, category="finding.category", truncated=truncated),
        "applicability": applicability,
        "validation_method": validation_method,
        "validation_status": validation_status,
        "location": {"file": file_path, "start_line": start_line, "end_line": end_line},
        "explanation": _clean_text(finding.get("explanation"), limit=limits.max_text_chars, category="finding.explanation", truncated=truncated),
        "potential_impact": _clean_text(finding.get("potential_impact"), limit=limits.max_text_chars, category="finding.potential_impact", truncated=truncated),
        "remediation": _clean_text(finding.get("remediation"), limit=limits.max_text_chars, category="finding.remediation", truncated=truncated),
    }

    source_files = [{"file": file_path, "start_line": start_line, "end_line": end_line}] if file_path else []
    snippets = [{"file": file_path, "start_line": start_line, "text": evidence_text}] if file_path and evidence_text else []
    support_summary = evidence_text or finding_context["explanation"] or finding_context["title"]
    supported = [_evidence("scanner_finding", str(support_summary), _provenance(finding_key, safe_rule_id, file_path, start_line, "findings.evidence"))]
    confirmed = []
    if validation_status == "validated":
        confirmed.append(_evidence("fuse_validation", f"FUSE marked this finding validated using {validation_method}.", _provenance(finding_key, safe_rule_id, file_path, start_line, "findings.validation_status")))
    unknown: list[dict[str, object]] = []
    if applicability == "unknown":
        unknown.append(_evidence("applicability", "FUSE has not established this finding's applicability.", _provenance(finding_key, safe_rule_id, file_path, start_line, "findings.applicability")))

    coverage = _mapping(report.get("coverage"), "report.coverage")
    summary = _mapping(report.get("summary"), "report.summary")
    discovery_complete = coverage.get("discovery_complete")
    if not isinstance(discovery_complete, bool):
        raise ValueError("report.coverage.discovery_complete must be a boolean")
    files_skipped = summary.get("files_skipped")
    if not isinstance(files_skipped, int) or isinstance(files_skipped, bool) or files_skipped < 0:
        raise ValueError("report.summary.files_skipped must be a non-negative integer")
    limits_reached = coverage.get("limits_reached", [])
    if not isinstance(limits_reached, list) or any(not isinstance(item, str) for item in limits_reached):
        raise ValueError("report.coverage.limits_reached must be an array of strings")
    analyzers = coverage.get("analyzers", [])
    if not isinstance(analyzers, list):
        raise ValueError("report.coverage.analyzers must be an array")
    relevant_analyzers = [
        item for item in analyzers
        if isinstance(item, Mapping) and item.get("name") == finding.get("analyzer")
    ]
    if len(relevant_analyzers) > 1:
        raise ValueError("report.coverage contains duplicate status entries for the finding analyzer")
    analyzer_status = relevant_analyzers[0].get("status") if relevant_analyzers else None
    limitations: list[str] = []
    if not discovery_complete:
        limitations.append("Input discovery was incomplete.")
        unknown.append(_evidence("coverage", "Input discovery was incomplete.", _provenance(finding_key, safe_rule_id, file_path, start_line, "coverage.discovery_complete")))
    if files_skipped:
        limitations.append(f"The scan skipped {files_skipped} file(s).")
    for item in limits_reached:
        limitations.append(_clean_text(item, limit=limits.max_text_chars, category="coverage.limitations", truncated=truncated))
    if isinstance(analyzer_status, str) and analyzer_status in _INCOMPLETE_ANALYZER_STATES:
        limitations.append(f"Finding analyzer status: {analyzer_status}.")
        unknown.append(_evidence("analyzer_coverage", f"The finding analyzer status is {analyzer_status}.", _provenance(finding_key, safe_rule_id, file_path, start_line, "coverage.analyzers")))
    support = coverage.get("support")
    support_status = support.get("status") if isinstance(support, Mapping) else None
    if not discovery_complete or files_skipped or limits_reached or analyzer_status in _INCOMPLETE_ANALYZER_STATES:
        coverage_status = "partial"
    else:
        coverage_status = "complete"

    build_evidence, firmware_evidence, hardware_evidence = _matching_context(
        report, raw_path, file_path, start_line, end_line, limits, truncated
    )
    policy_context: list[dict[str, object]] = []
    vex_review = finding.get("vex_review")
    if vex_review is not None:
        review = _mapping(vex_review, "selected finding.vex_review")
        state = _clean_text(review.get("state"), limit=limits.max_text_chars, category="policy_context", truncated=truncated)
        justification = _clean_text(review.get("justification"), limit=limits.max_text_chars, category="policy_context", truncated=truncated)
        detail = _clean_text(review.get("detail"), limit=limits.max_text_chars, category="policy_context", truncated=truncated)
        policy_context.append(_evidence("vex_review", f"VEX state={state}; justification={justification}; detail={detail}", _provenance(finding_key, safe_rule_id, file_path, start_line, "findings.vex_review")))

    deployment_stages: list[dict[str, object]] = []
    if _hardware_finding(category, rule_id):
        configured = "SUPPORTED" if any(item.get("kind") == "configured_setting" for item in build_evidence) else "UNKNOWN"
        for stage in ("configured", "build_included", "linked", "runtime_executed", "physically_populated", "externally_accessible"):
            state = configured if stage == "configured" else "UNKNOWN"
            stage_evidence = [item for item in build_evidence if item.get("kind") == "configured_setting"] if stage == "configured" and state == "SUPPORTED" else []
            deployment_stages.append({"stage": stage, "state": state, "evidence": stage_evidence})
            if state == "UNKNOWN":
                unknown.append(_evidence("deployment_stage", f"{stage} is not established by this report.", _provenance(finding_key, safe_rule_id, file_path, start_line, "report coverage")))

    item_categories = {
        "confirmed": _cap_items(confirmed, "evidence_state.confirmed", limits, truncated),
        "supported": _cap_items(supported, "evidence_state.supported", limits, truncated),
        "unknown": _cap_items(unknown, "evidence_state.unknown", limits, truncated),
        "contradicted": [],
    }
    build_evidence = _cap_items(build_evidence, "build_evidence", limits, truncated)
    firmware_evidence = _cap_items(firmware_evidence, "firmware_evidence", limits, truncated)
    hardware_evidence = _cap_items(hardware_evidence, "hardware_evidence", limits, truncated)
    policy_context = _cap_items(policy_context, "policy_context", limits, truncated)
    limitations = sorted(set(item for item in limitations if item))
    if len(limitations) > limits.max_items:
        limitations = limitations[: limits.max_items]
        truncated.add("coverage.limitations")

    context: dict[str, object] = {
        "schema_version": REASONING_CONTEXT_SCHEMA_VERSION,
        "finding": finding_context,
        "evidence_state": item_categories,
        "source": {"files": source_files, "snippets": snippets},
        "semantic_evidence": [],
        "build_evidence": build_evidence,
        "firmware_evidence": firmware_evidence,
        "hardware_evidence": hardware_evidence,
        "policy_context": policy_context,
        "deployment_stages": deployment_stages,
        "coverage": {
            "status": coverage_status,
            "discovery_complete": discovery_complete,
            "files_skipped": files_skipped,
            "support_status": _clean_text(
                support_status,
                limit=limits.max_text_chars,
                category="coverage.support_status",
                truncated=truncated,
            ) or None,
            "limitations": limitations,
        },
        "allowed_symbols": [],
        "context_truncated": bool(truncated),
        "truncated_categories": sorted(truncated),
        "constraints": {
            "may_change_finding": False,
            "may_change_severity": False,
            "may_invent_evidence": False,
        },
    }
    while _compact_length(context) > limits.max_context_chars:
        candidates = [item for item in _truncatable_strings(context) if item[0] > 48]
        if not candidates:
            raise ValueError("max_context_chars is too small for the required context fields")
        selected_text = sorted(candidates, key=lambda item: (-item[0], item[1]))[0]
        length, path, category_name = selected_text
        excess = _compact_length(context) - limits.max_context_chars
        marker = " [truncated]"
        keep = max(32, length - excess - len(marker) - 8)
        # Resolve the value by its path so the cap remains stable across runs.
        value = _get_text_path(context, path)
        _set_text_path(context, path, value[: max(0, keep - len(marker))].rstrip() + marker)
        truncated.add(category_name)
        context["context_truncated"] = True
        context["truncated_categories"] = sorted(truncated)
    context["context_truncated"] = bool(truncated)
    context["truncated_categories"] = sorted(truncated)
    return context


def _get_text_path(context: dict[str, object], dotted_path: str) -> str:
    current: object = context
    for part in dotted_path.split("."):
        if isinstance(current, dict):
            current = current.get(part)
        elif isinstance(current, list):
            current = current[int(part)]
        else:
            return ""
    return current if isinstance(current, str) else ""


def _set_text_path(context: dict[str, object], dotted_path: str, value: str) -> None:
    parts = dotted_path.split(".")
    current: object = context
    for part in parts[:-1]:
        if isinstance(current, dict):
            current = current[part]
        elif isinstance(current, list):
            current = current[int(part)]
        else:
            return
    key = parts[-1]
    if isinstance(current, dict):
        current[key] = value
    elif isinstance(current, list):
        current[int(key)] = value
