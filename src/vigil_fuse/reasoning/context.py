from __future__ import annotations

import hashlib
import json
import re
import unicodedata
from pathlib import Path
from typing import Any

from ..text_safety import safe_report_text
from .validation import strict_json

CONTEXT_SCHEMA = "reasoning_context_v1"
MAX_REPORT_BYTES = 50 * 1024 * 1024
MAX_STRING = 700
MAX_SOURCE_LINES = 8
MAX_EVIDENCE = 8
MAX_PATH_DEPTH = 8
MAX_OBSERVATIONS = 6
MAX_POLICY = 2

_PRIVATE = re.compile(
    r"-----BEGIN [^-]*(?:PRIVATE KEY|CERTIFICATE)-----.*?(?:-----END [^-]+-----|$)"
    r"|(?i:\b(?:password|passwd|secret|token|api[_-]?key)\w*\s*[=:]\s*"
    r"(?:\"[^\"\r\n]*\"|'[^'\r\n]*'|[^\s,;]+))"
    r"|(?i:Bearer\s+\S+)"
    r"|\b(?:gh[pousr]_[A-Za-z0-9_]+|sk-[A-Za-z0-9_-]+|AKIA[A-Z0-9]{16})\b"
    r"|\b[A-Za-z0-9+/=_-]{32,}\b"
    r"|(?i:[A-Z]:[\\/](?:Users|Documents and Settings)[\\/][^\s\"<>]+)"
    r"|/(?:home|Users)/[^\s\"<>]+",
    re.DOTALL,
)


def load_report(raw: bytes) -> dict[str, Any]:
    """Check the canonical report boundary; never accept TXT, SARIF, PDF or context JSON."""
    report = strict_json(raw, MAX_REPORT_BYTES)
    if report.get("schema_version") not in ("1.11", "1.12"):
        raise ValueError("Unsupported canonical FUSE report schema")
    if not isinstance(report.get("tool"), dict) or report["tool"].get("name") != "FUSE":
        raise ValueError("Expected a canonical FUSE report")
    if not isinstance(report.get("coverage"), dict) or not isinstance(report.get("scan"), dict):
        raise ValueError("FUSE report must include scan and coverage")
    coverage = report["coverage"]
    if (
        type(coverage.get("discovery_complete")) is not bool
        or not isinstance(coverage.get("limits_reached"), list)
        or any(not isinstance(item, str) for item in coverage["limits_reached"])
    ):
        raise ValueError("Invalid FUSE coverage states")
    findings = report.get("findings")
    if not isinstance(findings, list) or len(findings) > 100_000:
        raise ValueError("Invalid FUSE findings array")
    seen: set[str] = set()
    for finding in findings:
        if not isinstance(finding, dict):
            raise ValueError("Invalid FUSE finding")
        for key in (
            "id",
            "fingerprint",
            "rule_id",
            "title",
            "evidence",
            "explanation",
            "remediation",
            "analyzer",
            "category",
        ):
            if not isinstance(finding.get(key), str) or len(finding[key]) > 100_000:
                raise ValueError(f"Invalid finding {key}")
        if not finding["id"] or finding["id"] in seen:
            raise ValueError("Missing or duplicate finding ID")
        seen.add(finding["id"])
        for key, choices in (
            ("severity", {"critical", "high", "medium", "low", "info", "unknown"}),
            ("confidence", {"high", "medium", "low"}),
            ("applicability", {"unknown", "candidate", "applicable", "not_applicable"}),
            ("validation_status", {"not-validated", "validated", "not-applicable"}),
        ):
            if not isinstance(finding.get(key), str) or finding[key] not in choices:
                raise ValueError(f"Invalid finding {key}")
        location = finding.get("location")
        if not isinstance(location, dict) or not isinstance(location.get("file"), str):
            raise ValueError("Invalid finding location")
        for key in ("start_line", "end_line"):
            if location.get(key) is not None and (
                type(location[key]) is not int or location[key] < 1
            ):
                raise ValueError("Invalid finding line")
    return report


def read_report(path: Path) -> bytes:
    if path.is_symlink() or not path.is_file():
        raise ValueError("Reasoning input must be a regular canonical JSON file")
    with path.open("rb") as source:
        raw = source.read(MAX_REPORT_BYTES + 1)
    if len(raw) > MAX_REPORT_BYTES:
        raise ValueError("FUSE report exceeds 50 MiB")
    return raw


def select_findings(report: dict[str, Any], finding_id: str | None) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = report["findings"]
    if finding_id is None:
        return findings
    # Exact instance ID wins. A rule ID may select several instances, explicitly.
    selected = [item for item in findings if item["id"] == finding_id]
    selected = selected or [item for item in findings if item["rule_id"] == finding_id]
    if not selected:
        raise ValueError("Selected finding does not exist in the report")
    return selected


def build_context(
    report: dict[str, Any],
    finding: dict[str, Any],
    context_tokens: int = 8192,
) -> dict[str, Any]:
    truncated: set[str] = set()
    redacted: set[str] = set()

    def text(value: Any, category: str, *, path: bool = False) -> str:
        if not isinstance(value, str):
            return ""
        if path and len(re.split(r"[/\\]", value)) > MAX_PATH_DEPTH:
            truncated.add(category)
            return "[path depth exceeded]"
        clean = _PRIVATE.sub("[redacted]", value)
        clean = "".join(char for char in clean if unicodedata.category(char) not in {"Cf", "Cs"})
        if clean != value:
            redacted.add(category)
        if path and (clean.startswith(("/", "\\")) or re.match(r"^[A-Za-z]:", clean)):
            redacted.add(category)
            return "[absolute path withheld]"
        lines = clean.splitlines()
        if len(lines) > MAX_SOURCE_LINES:
            truncated.add(category)
            clean = "\n".join(lines[:MAX_SOURCE_LINES])
        if len(clean) > MAX_STRING:
            truncated.add(category)
        return safe_report_text(clean, limit=MAX_STRING) or ""

    def rows(items: Any, category: str, keys: tuple[str, ...], limit: int) -> list[dict[str, Any]]:
        if not isinstance(items, list):
            return []
        if len(items) > limit:
            truncated.add(category)
        result = []
        for item in items[:limit]:
            if not isinstance(item, dict):
                continue
            values: dict[str, Any] = {
                key: item[key]
                if type(item.get(key)) in {bool, int}
                else text(item.get(key), category, path=key in {"path", "file"})
                for key in keys
            }
            name = item.get("name")
            if (
                "value" in keys
                and isinstance(name, str)
                and re.search(r"(?i)password|passwd|secret|token|api[_-]?key|private[_-]?key", name)
            ):
                values["value"] = "[redacted]"
                redacted.add(category)
            result.append(values)
        return result

    location = finding["location"]
    evidence: dict[str, list[dict[str, str]]] = {
        "confirmed": [],
        "supported": [],
        "unknown": [],
        "contradicted": [],
    }
    # The current canonical schema has no per-observation truth states. Do not infer them.
    evidence["supported"].append({"id": "E1", "text": text(finding["evidence"], "evidence")})
    unknowns = [
        "No structured runtime execution state is available; do not infer it from source or configuration.",
        "No structured physical population or external accessibility states are available; do not infer them from schematic routing.",
    ]
    if finding["applicability"] == "unknown":
        unknowns.append("Finding applicability is unknown.")
    if finding["validation_status"] == "not-validated":
        unknowns.append("The finding has not been independently validated.")
    evidence["unknown"] = [
        {"id": f"E{index + 2}", "text": value} for index, value in enumerate(unknowns)
    ][: MAX_EVIDENCE - 1]
    project = report.get("project_context", {})
    project = project if isinstance(project, dict) else {}
    settings = project.get("settings", [])
    settings = settings if isinstance(settings, list) else []
    relevant_settings = [
        item for item in settings if isinstance(item, dict) and item.get("path") == location["file"]
    ]
    hardware = report.get("hardware_inventory", {})
    hardware = hardware if isinstance(hardware, dict) else {}
    artifacts = hardware.get("artifacts", [])
    artifacts = artifacts if isinstance(artifacts, list) else []
    firmware_inventory = report.get("firmware_candidates", {})
    firmware_inventory = firmware_inventory if isinstance(firmware_inventory, dict) else {}
    firmware_candidates = firmware_inventory.get("candidates", [])
    relevant_firmware: list[dict[str, Any]] = []
    if isinstance(firmware_candidates, list):
        for item in firmware_candidates:
            if not isinstance(item, dict) or item.get("path") != location["file"]:
                continue
            if not isinstance(item.get("format"), str) or type(item.get("byte_size")) is not int:
                raise ValueError("Invalid matching firmware candidate")
            if item["byte_size"] < 0:
                raise ValueError("Invalid matching firmware candidate size")
            relevant_firmware.append(item)
    relevant_hardware = [
        item for item in artifacts if isinstance(item, dict) and item.get("path") == location["file"]
    ]
    netlist = report.get("hardware_netlist", {})
    if isinstance(netlist, dict) and netlist.get("path") == location["file"]:
        candidates = netlist.get("debug_net_candidates", [])
        if isinstance(candidates, list):
            relevant_hardware.extend(
                {
                    "path": location["file"],
                    "category": "netlist debug candidate",
                    "format": candidate,
                }
                for candidate in candidates
                if isinstance(candidate, str)
            )
    bom = report.get("hardware_bom", {})
    if isinstance(bom, dict) and bom.get("source_path") == location["file"]:
        status = bom.get("status") if isinstance(bom.get("status"), str) else "unknown"
        count = bom.get("component_count")
        if type(count) is not int or count < 0:
            raise ValueError("Invalid matching BOM component count")
        relevant_hardware.append(
            {
                "path": location["file"],
                "category": "BOM inventory",
                "format": f"{status}; {count} line items; physical population unverified",
            }
        )
    rtl = hardware.get("rtl_analysis", {})
    rtl = rtl if isinstance(rtl, dict) else {}
    rtl_files = rtl.get("files", [])
    rtl_events = rtl.get("evidence", [])
    relevant_rtl = (
        [
            item
            for item in rtl_files
            if isinstance(item, dict) and item.get("path") == location["file"]
        ]
        if isinstance(rtl_files, list)
        else []
    )
    if isinstance(rtl_events, list):
        for item in rtl_events:
            if not isinstance(item, dict) or item.get("file") != location["file"]:
                continue
            if (
                location.get("start_line") is not None
                and item.get("line") != location["start_line"]
            ):
                continue
            detail = item.get("evidence", {})
            detail = detail if isinstance(detail, dict) else {}
            relevant_rtl.append(
                {**item, "source": detail.get("source"), "conditional": detail.get("conditional")}
            )
    coverage = report["coverage"]
    coverage_view = {
        "discovery_complete": coverage.get("discovery_complete"),
        "limits_reached": [
            text(item, "coverage") for item in coverage.get("limits_reached", [])[:8]
        ]
        if isinstance(coverage.get("limits_reached"), list)
        else [],
        "limitations": [
            "Only report evidence is supplied; inventories do not prove build inclusion, linking, runtime execution, population or accessibility.",
            "Semantic observations are unavailable. RTL observations, if supplied, are static structure only.",
        ],
        "analyzers": rows(
            [
                item
                for item in coverage.get("analyzers", [])
                if isinstance(item, dict) and item.get("name") == finding["analyzer"]
            ]
            if isinstance(coverage.get("analyzers"), list)
            else [],
            "coverage",
            ("name", "status", "detail"),
            MAX_OBSERVATIONS,
        ),
    }
    if len(coverage.get("limits_reached", [])) > 8:
        truncated.add("coverage")
    packet: dict[str, Any] = {
        "schema_version": CONTEXT_SCHEMA,
        "finding": {
            **{
                key: text(finding[key], "finding")
                for key in (
                    "id",
                    "rule_id",
                    "title",
                    "severity",
                    "confidence",
                    "applicability",
                    "validation_status",
                    "analyzer",
                    "category",
                    "explanation",
                    "remediation",
                )
            },
        },
        "evidence": evidence,
        "source": [
            {
                "file": text(location["file"], "source", path=True),
                "start_line": location.get("start_line"),
                "end_line": location.get("end_line"),
            }
        ],
        "semantic": [],
        "build": rows(relevant_settings, "build", ("name", "value", "path"), MAX_OBSERVATIONS),
        "firmware": rows(
            relevant_firmware,
            "firmware",
            ("path", "format", "byte_size"),
            MAX_OBSERVATIONS,
        ),
        "hardware": rows(
            relevant_hardware,
            "hardware",
            ("path", "category", "format"),
            MAX_OBSERVATIONS,
        ),
        "rtl": rows(
            relevant_rtl,
            "rtl",
            (
                "path",
                "presence",
                "build_status",
                "parse_status",
                "kind",
                "module",
                "signal",
                "file",
                "line",
                "source",
                "conditional",
            ),
            MAX_OBSERVATIONS,
        ),
        "policy_context": rows(
            [finding["vex_review"]] if isinstance(finding.get("vex_review"), dict) else [],
            "policy_context",
            ("state", "justification", "detail"),
            MAX_POLICY,
        ),
        "coverage": coverage_view,
        "constraints": {
            "finding_authoritative": True,
            "severity_authoritative": True,
            "confidence_authoritative": True,
            "applicability_authoritative": True,
            "coverage_authoritative": True,
            "policy_authoritative": True,
            "model_may_invent_evidence": False,
            "evidence_distinctions": [
                "PRESENT",
                "BUILD_INCLUDED",
                "LINKED",
                "RUNTIME_EXECUTED",
                "PHYSICALLY_POPULATED",
                "EXTERNALLY_ACCESSIBLE",
            ],
        },
        "context_truncated": False,
        "truncated_categories": [],
        "redacted_categories": sorted(redacted),
    }
    # A byte cap is conservative, tokenizer-independent input accounting. Output has a reserve.
    byte_budget = min(12_000, context_tokens - 2300)
    for category in ("build", "firmware", "hardware", "rtl", "policy_context"):
        if len(encode_context(packet)) <= byte_budget:
            break
        if packet[category]:
            packet[category] = []
            truncated.add(category)
    if len(encode_context(packet)) > byte_budget:
        raise ValueError("Finding exceeds configured reasoning context budget")
    packet["context_truncated"] = bool(truncated)
    packet["truncated_categories"] = sorted(truncated)
    packet["redacted_categories"] = sorted(redacted)
    if len(encode_context(packet)) > byte_budget:
        raise ValueError("Finding exceeds configured reasoning context budget")
    return packet


def encode_context(context: dict[str, Any]) -> bytes:
    return json.dumps(context, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode(
        "utf-8"
    )


def report_hash(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()
