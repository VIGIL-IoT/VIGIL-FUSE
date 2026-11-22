"""Bounded OPA/Rego evaluation over normalized FUSE evidence."""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .analyzer_runtime import (
    AnalyzerOutputLimitError,
    _analyzer_environment,
    _run_with_environment,
)
from .model import Finding, ScanResult

POLICY_INPUT_SCHEMA_VERSION = "1.0"
POLICY_RESULT_SCHEMA_VERSION = "1.0"
BUILTIN_POLICY = "reference:production-iot"
MAX_POLICY_FILE_BYTES = 256 * 1024
MAX_POLICY_TOTAL_BYTES = 1024 * 1024
MAX_POLICY_FILES = 16
MAX_POLICY_DIRECTORY_ENTRIES = 4096
MAX_POLICY_DIRECTORIES = 256
MAX_POLICY_INPUT_BYTES = 2 * 1024 * 1024
MAX_POLICY_OUTPUT_BYTES = 256 * 1024
MAX_POLICY_RESULT_BYTES = 8 * 1024 * 1024
MAX_POLICY_ITEMS = 128
MAX_EVIDENCE_REFS = 64
MAX_POLICY_EVALUATION_SECONDS = 30
OPA_TIMEOUT_SECONDS = 5
OPA_EVAL_TIMEOUT = "3s"
_POLICY_ID = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}$")
_DISABLED_CAPABILITIES = frozenset(
    {
        "http.send",
        "net.lookup_ip_addr",
        "opa.runtime",
        "print",
        "rand.intn",
        "time.now_ns",
        "uuid.rfc4122",
    }
)


@dataclass(frozen=True)
class OpaInfo:
    executable: str | None
    version: str | None

    @property
    def available(self) -> bool:
        return self.executable is not None and self.version is not None


def inspect_opa() -> OpaInfo:
    """Inspect OPA without installing or changing the caller's environment."""
    executable = shutil.which("opa")
    if executable is None:
        return OpaInfo(None, None)
    command = [executable, "version"]
    try:
        completed = _run_opa(command, timeout=OPA_TIMEOUT_SECONDS)
    except (OSError, subprocess.TimeoutExpired, AnalyzerOutputLimitError):
        return OpaInfo(executable, None)
    if completed.returncode != 0:
        return OpaInfo(executable, None)
    output = (completed.stdout or completed.stderr).strip().splitlines()
    if not output:
        return OpaInfo(executable, None)
    version = re.search(r"\b\d+\.\d+\.\d+(?:[-+][A-Za-z0-9.-]+)?\b", output[0])
    return OpaInfo(executable, version.group(0) if version else output[0][:120])


def resolve_policy_files(policy: str | Path) -> tuple[Path, ...]:
    """Resolve one explicit Rego module or a bounded directory of modules."""
    supplied = str(policy)
    path = Path(supplied).expanduser()
    if not path.exists() and supplied == BUILTIN_POLICY:
        path = Path(__file__).parent / "policies" / "production_iot.rego"
    if path.is_symlink():
        raise ValueError("Policy path must not be a symbolic link")
    if path.is_file():
        if path.suffix.casefold() != ".rego":
            raise ValueError("Policy file must use the .rego extension")
        candidates = [path]
    elif path.is_dir():
        candidates = _policy_directory_files(path)
    else:
        raise ValueError("Policy path does not exist or is not a regular file or directory")
    if not candidates:
        raise ValueError("Policy directory contains no .rego files")
    if len(candidates) > MAX_POLICY_FILES:
        raise ValueError(f"Policy directory exceeds the {MAX_POLICY_FILES}-file limit")

    total_bytes = 0
    for candidate in candidates:
        if candidate.is_symlink() or not candidate.is_file():
            raise ValueError("Policy modules must be regular, non-symbolic files")
        size = candidate.stat().st_size
        if size > MAX_POLICY_FILE_BYTES:
            raise ValueError(
                f"Policy module exceeds the {MAX_POLICY_FILE_BYTES}-byte per-file limit"
            )
        total_bytes += size
    if total_bytes > MAX_POLICY_TOTAL_BYTES:
        raise ValueError(f"Policy directory exceeds the {MAX_POLICY_TOTAL_BYTES}-byte total limit")
    return tuple(candidates)


def policy_input(result: ScanResult) -> dict[str, object]:
    """Return the versioned, allow-listed policy view of a scan result."""
    findings = sorted(result.findings, key=lambda item: (item.fingerprint, item.rule_id))
    omitted_findings = max(0, len(findings) - 5000)
    findings = findings[:5000]

    mqtt = _findings_for_rule(result, "FUSE005")
    tls = _findings_for_rule(result, "FUSE003")
    private_keys = _findings_for_rule(result, "FUSE002")
    high_findings = [
        finding for finding in result.findings if finding.severity in {"high", "critical"}
    ]
    unresolved_high = [
        finding
        for finding in high_findings
        if finding.applicability == "applicable"
        and finding.validation_status != "validated"
        and not _vex_not_affected(finding)
    ]
    uncertain_high = [
        finding
        for finding in high_findings
        if (finding.applicability in {"unknown", "candidate"} or _vex_not_affected(finding))
        and finding.validation_status != "validated"
    ]
    lock_components = [
        {
            "name": item.name[:256],
            "version": item.version[:128],
            "ecosystem": "esp-idf",
            "source_type": item.source_type[:128],
        }
        for item in result.project_context.component_lock.components
    ]
    finding_components = [
        {
            "name": item.component.name[:256],
            "version": item.component.version[:128],
            "ecosystem": item.component.ecosystem[:128],
            **({"purl": item.component.purl[:512]} if item.component.purl else {}),
        }
        for item in result.findings
        if item.component is not None
    ]
    component_by_key = {
        json.dumps(item, sort_keys=True, separators=(",", ":")): item
        for item in (*lock_components, *finding_components)
    }
    all_components = [component_by_key[key] for key in sorted(component_by_key)]
    omitted_components = max(0, len(all_components) - 1000)
    components = all_components[:1000]

    native_status = next(
        (item.status for item in result.analyzers if item.name == "fuse-native"),
        "skipped",
    )
    incomplete_analyzers = any(
        item.status
        in {"partial", "unavailable", "incompatible", "timeout", "unsupported", "failed"}
        for item in result.analyzers
    )
    scan_complete = (
        native_status == "completed"
        and result.files_scanned > 0
        and result.discovery_complete
        and not result.files_skipped
        and not result.limits_reached
        and not incomplete_analyzers
    )
    high_findings_status = (
        "unresolved"
        if unresolved_high
        else "uncertain"
        if uncertain_high
        else "none"
        if scan_complete
        else "unknown"
    )
    rule_statuses = {
        item.name.removeprefix("native-rule:"): item.status
        for item in result.analyzers
        if item.name.startswith("native-rule:")
    }
    policy_input_complete = not omitted_findings and not omitted_components

    netlist_status = result.netlist_inventory.status
    if result.netlist_inventory.debug_net_candidates:
        debug_status = "candidate"
    elif netlist_status == "parsed":
        debug_status = "no_candidate"
    else:
        debug_status = "unknown"

    signature_status = (
        "verified"
        if result.provenance.signature_verified
        else "not_verified"
        if result.provenance.status != "not-requested"
        else "unknown"
    )
    analyzer_statuses = {
        item.name: item.status for item in sorted(result.analyzers, key=lambda item: item.name)
    }

    return {
        "schema_version": POLICY_INPUT_SCHEMA_VERSION,
        "target": {"kind": result.target_kind, "profile": result.profile},
        "components": components,
        "findings": [
            {
                "ref": item.fingerprint,
                "rule_id": item.rule_id[:128],
                "severity": item.severity,
                "applicability": item.applicability,
                "validation_status": item.validation_status,
                "vex_state": item.vex_review.state if item.vex_review else None,
                **(
                    {"component_purl": item.component.purl[:512]}
                    if item.component and item.component.purl
                    else {}
                ),
            }
            for item in findings
        ],
        "evidence": {
            "plaintext_mqtt": _finding_signal(
                mqtt,
                "observed"
                if mqtt
                else "not_observed"
                if _rule_absence_supported(result, "FUSE005")
                else "unknown",
            ),
            "tls_verification": _finding_signal(
                tls,
                "bypass_observed"
                if tls
                else "no_bypass_observed"
                if _rule_absence_supported(result, "FUSE003")
                else "unknown",
            ),
            "private_key_material": _finding_signal(
                private_keys,
                "observed"
                if private_keys
                else "not_observed"
                if _rule_absence_supported(result, "FUSE002")
                else "unknown",
            ),
            "debug_interface_exposure": {
                "status": debug_status,
                "evidence_refs": _digest_ref(result.netlist_inventory.sha256, "netlist"),
                "candidate_count": len(result.netlist_inventory.debug_net_candidates),
            },
            "unresolved_high_findings": _finding_signal(
                unresolved_high if high_findings_status == "unresolved" else uncertain_high,
                high_findings_status,
            ),
        },
        "coverage": {
            "scan_complete": scan_complete,
            "policy_input_complete": policy_input_complete,
            "files_scanned": result.files_scanned,
            "files_skipped": result.files_skipped,
            "limits_reached": sorted(result.limits_reached),
            "rules_enabled": sorted(set(result.rules_enabled)),
            "rule_statuses": dict(sorted(rule_statuses.items())),
            "finding_count": len(result.findings),
            "omitted_findings": omitted_findings,
            "omitted_components": omitted_components,
        },
        "firmware": {
            "candidate_status": result.firmware_candidates.status,
            "candidate_count": result.firmware_candidates.candidate_count,
            "signature_status": signature_status,
            "provenance_status": result.provenance.status,
        },
        "hardware": {
            "netlist_status": netlist_status,
            "debug_interface_status": debug_status,
            "debug_net_candidate_count": len(result.netlist_inventory.debug_net_candidates),
        },
        "supply_chain": {
            "component_lock_status": result.project_context.component_lock.status,
            "vex_status": result.vex_import.status,
            "analyzers": analyzer_statuses,
        },
    }


def serialize_policy_input(document: dict[str, object]) -> str:
    encoded = json.dumps(document, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    if len(encoded.encode("utf-8")) > MAX_POLICY_INPUT_BYTES:
        raise ValueError("Normalized policy input exceeds the configured byte limit")
    return encoded


def evaluate_policies(policy: str | Path, result: ScanResult) -> dict[str, object]:
    """Evaluate explicit Rego modules and normalize their decisions for reporting."""
    modules = resolve_policy_files(policy)
    normalized_input = policy_input(result)
    try:
        input_json = serialize_policy_input(normalized_input)
    except ValueError:
        info = inspect_opa()
        return _document(
            info,
            [_unknown_policy(_fallback_policy_id(path), "input_limit") for path in modules],
        )

    info = inspect_opa()
    if not info.available or info.executable is None:
        return _document(
            info,
            [_unknown_policy(_fallback_policy_id(path), "opa_unavailable") for path in modules],
        )
    known_refs = _evidence_refs(normalized_input)

    try:
        capabilities = _restricted_capabilities(info.executable)
    except (OSError, subprocess.TimeoutExpired, AnalyzerOutputLimitError, ValueError):
        return _document(
            info,
            [
                _unknown_policy(_fallback_policy_id(path), "capabilities_unavailable")
                for path in modules
            ],
        )

    evaluations: list[dict[str, object]] = []
    with tempfile.TemporaryDirectory(prefix="vigil-fuse-policy-") as temporary:
        root = Path(temporary)
        input_path = root / "input.json"
        capabilities_path = root / "capabilities.json"
        input_path.write_text(input_json, encoding="utf-8")
        capabilities_path.write_text(
            json.dumps(capabilities, separators=(",", ":")), encoding="utf-8"
        )
        deadline = time.monotonic() + MAX_POLICY_EVALUATION_SECONDS
        for module in modules:
            fallback_id = _fallback_policy_id(module)
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                evaluations.append(_unknown_policy(fallback_id, "evaluation_timeout"))
                continue
            timeout = max(1, min(OPA_TIMEOUT_SECONDS, int(remaining)))
            command = [
                info.executable,
                "eval",
                "--format=json",
                "--strict-builtin-errors",
                f"--timeout={OPA_EVAL_TIMEOUT}",
                "--capabilities",
                str(capabilities_path),
                "--input",
                str(input_path),
                "--data",
                str(module),
                "data.fuse.policy.result",
            ]
            try:
                completed = _run_opa(command, timeout=timeout, cwd=root)
            except subprocess.TimeoutExpired:
                evaluations.append(_unknown_policy(fallback_id, "evaluation_timeout"))
                continue
            except AnalyzerOutputLimitError:
                evaluations.append(_unknown_policy(fallback_id, "output_limit"))
                continue
            except OSError:
                evaluations.append(_unknown_policy(fallback_id, "evaluation_error"))
                continue
            if completed.returncode != 0:
                evaluations.append(_unknown_policy(fallback_id, "evaluation_error"))
                continue
            try:
                raw = _opa_value(completed.stdout)
                evaluation = _normalize_decision(raw, known_refs)
            except (ValueError, TypeError, json.JSONDecodeError):
                evaluations.append(_unknown_policy(fallback_id, "invalid_output"))
                continue
            evaluations.append(evaluation)

    policy_ids = [str(item["policy_id"]) for item in evaluations]
    if len(policy_ids) != len(set(policy_ids)):
        raise ValueError("Policy directory contains duplicate policy IDs")
    return _document(info, evaluations)


def policy_results_json(document: dict[str, object]) -> str:
    encoded = json.dumps(document, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    if len(encoded.encode("utf-8")) > MAX_POLICY_RESULT_BYTES:
        raise ValueError("Normalized policy results exceed the configured byte limit")
    return encoded


def _findings_for_rule(result: ScanResult, rule_id: str) -> list[Finding]:
    return sorted(
        (finding for finding in result.findings if finding.rule_id == rule_id),
        key=lambda item: item.fingerprint,
    )


def _rule_absence_supported(result: ScanResult, rule_id: str) -> bool:
    rule_status = next(
        (item.status for item in result.analyzers if item.name == f"native-rule:{rule_id}"),
        "skipped",
    )
    native_status = next(
        (item.status for item in result.analyzers if item.name == "fuse-native"),
        "skipped",
    )
    return (
        rule_id in result.rules_enabled
        and rule_status in {"completed", "skipped"}
        and native_status == "completed"
        and result.files_scanned > 0
        and result.discovery_complete
        and not result.files_skipped
        and not result.limits_reached
    )


def _vex_not_affected(finding: Finding) -> bool:
    return finding.vex_review is not None and finding.vex_review.state == "not_affected"


def _finding_signal(findings: list[Finding], status: str) -> dict[str, object]:
    refs = sorted({finding.fingerprint for finding in findings})
    return {
        "status": status,
        "evidence_refs": refs[:MAX_EVIDENCE_REFS],
        "evidence_count": len(refs),
        "omitted_ref_count": max(0, len(refs) - MAX_EVIDENCE_REFS),
    }


def _digest_ref(digest: str | None, kind: str) -> list[str]:
    return [f"{kind}:{digest}"] if digest else []


def _fallback_policy_id(path: Path) -> str:
    stem = re.sub(r"[^a-z0-9._-]+", "-", path.stem.casefold())[:80].strip(".-_")
    return f"unresolved.{stem or 'policy'}"


def _unknown_policy(policy_id: str, reason: str) -> dict[str, object]:
    messages = {
        "opa_unavailable": "OPA/Rego is unavailable; this policy was not evaluated.",
        "input_limit": "Normalized policy input exceeded the configured size limit.",
        "capabilities_unavailable": "OPA capabilities could not be restricted; this policy was not evaluated.",
        "evaluation_timeout": "Policy evaluation exceeded its time limit.",
        "output_limit": "OPA output exceeded the configured size limit.",
        "evaluation_error": "OPA could not evaluate this Rego module.",
        "invalid_output": "OPA output did not match the versioned policy result contract.",
        "conflicting_result": "Policy status conflicts with its violations or unknown evidence.",
    }
    return {
        "policy_id": policy_id,
        "status": "unknown",
        "violations": [],
        "unknowns": [
            {
                "rule": "policy_evaluation",
                "evidence_refs": [],
                "message": messages[reason],
            }
        ],
        "mappings": [],
        "reason": reason,
    }


def _document(info: OpaInfo, evaluations: list[dict[str, object]]) -> dict[str, object]:
    statuses = {str(item["status"]) for item in evaluations}
    status = "fail" if "fail" in statuses else "unknown" if "unknown" in statuses else "pass"
    return {
        "schema_version": POLICY_RESULT_SCHEMA_VERSION,
        "input_schema_version": POLICY_INPUT_SCHEMA_VERSION,
        "engine": {
            "name": "OPA/Rego",
            "available": info.available,
            "version": info.version,
        },
        "status": status,
        "evaluations": evaluations,
    }


def _restricted_capabilities(executable: str) -> dict[str, Any]:
    command = [executable, "capabilities", "--current"]
    completed = _run_opa(command, timeout=OPA_TIMEOUT_SECONDS)
    if completed.returncode != 0:
        raise ValueError("OPA capabilities are unavailable")
    capabilities = json.loads(completed.stdout)
    if not isinstance(capabilities, dict) or not isinstance(capabilities.get("builtins"), list):
        raise ValueError("OPA capabilities output is malformed")
    builtins = capabilities["builtins"]
    if any(
        not isinstance(item, dict) or not isinstance(item.get("name"), str) for item in builtins
    ):
        raise ValueError("OPA capabilities output is malformed")
    capabilities["builtins"] = [
        item for item in builtins if item["name"] not in _DISABLED_CAPABILITIES
    ]
    capabilities["allow_net"] = []
    return capabilities


def _opa_value(output: str) -> object:
    document = json.loads(output)
    if not isinstance(document, dict):
        raise ValueError("OPA result envelope must be an object")
    result = document.get("result")
    if not isinstance(result, list) or len(result) != 1:
        raise ValueError("OPA result envelope must contain one expression")
    expressions = result[0].get("expressions") if isinstance(result[0], dict) else None
    if not isinstance(expressions, list) or len(expressions) != 1:
        raise ValueError("OPA result envelope must contain one expression")
    return expressions[0].get("value") if isinstance(expressions[0], dict) else None


def _normalize_decision(raw: object, known_refs: set[str]) -> dict[str, object]:
    if not isinstance(raw, dict) or set(raw) != {
        "policy_id",
        "status",
        "violations",
        "unknowns",
        "mappings",
    }:
        raise ValueError("Policy decision does not match the result contract")
    policy_id = raw["policy_id"]
    if not isinstance(policy_id, str) or not _POLICY_ID.fullmatch(policy_id):
        raise ValueError("Policy ID is invalid")
    violations = _normalize_records(raw["violations"], "rule", known_refs)
    unknowns = _normalize_records(raw["unknowns"], "rule", known_refs)
    mappings = _normalize_mappings(raw["mappings"], known_refs)
    expected_status = "fail" if violations else "unknown" if unknowns else "pass"
    if raw["status"] != expected_status:
        return _unknown_policy(policy_id, "conflicting_result")
    return {
        "policy_id": policy_id,
        "status": expected_status,
        "violations": violations,
        "unknowns": unknowns,
        "mappings": mappings,
    }


def _policy_directory_files(directory: Path) -> list[Path]:
    candidates: list[Path] = []
    root = directory.resolve()
    directories = [directory]
    visited_directories = 0
    visited_entries = 0
    while directories:
        current = directories.pop()
        visited_directories += 1
        if visited_directories > MAX_POLICY_DIRECTORIES:
            raise ValueError("Policy directory exceeds the traversal limit")
        try:
            with os.scandir(current) as entries:
                for entry in entries:
                    visited_entries += 1
                    if visited_entries > MAX_POLICY_DIRECTORY_ENTRIES:
                        raise ValueError("Policy directory exceeds the traversal limit")
                    if entry.is_symlink():
                        if entry.name.casefold().endswith(".rego"):
                            raise ValueError("Policy modules must be regular, non-symbolic files")
                    elif entry.is_dir(follow_symlinks=False):
                        child = Path(entry.path)
                        if not child.resolve().is_relative_to(root):
                            raise ValueError(
                                "Policy directory traversal cannot leave the selected root"
                            )
                        directories.append(Path(entry.path))
                    elif entry.is_file(follow_symlinks=False) and entry.name.casefold().endswith(
                        ".rego"
                    ):
                        candidate = Path(entry.path)
                        if not candidate.resolve().is_relative_to(root):
                            raise ValueError("Policy modules must stay within the selected root")
                        candidates.append(candidate)
        except (OSError, RuntimeError) as error:
            raise ValueError("Could not safely read the policy directory") from error
    return sorted(candidates, key=lambda item: item.as_posix().casefold())


def _normalize_records(value: object, name: str, known_refs: set[str]) -> list[dict[str, object]]:
    if not isinstance(value, list) or len(value) > MAX_POLICY_ITEMS:
        raise ValueError("Policy decision list is invalid or too large")
    records: list[dict[str, object]] = []
    for item in value:
        if not isinstance(item, dict) or set(item) != {name, "evidence_refs", "message"}:
            raise ValueError("Policy decision record is malformed")
        rule = item[name]
        message = item["message"]
        if not isinstance(rule, str) or not rule or len(rule) > 128:
            raise ValueError("Policy rule name is invalid")
        if not isinstance(message, str) or not message or len(message) > 512:
            raise ValueError("Policy message is invalid")
        records.append(
            {
                name: rule,
                "evidence_refs": _normalize_refs(item["evidence_refs"], known_refs),
                "message": message,
            }
        )
    return sorted(records, key=lambda item: (str(item[name]), str(item["message"])))


def _normalize_mappings(value: object, known_refs: set[str]) -> list[dict[str, object]]:
    if not isinstance(value, list) or len(value) > MAX_POLICY_ITEMS:
        raise ValueError("Policy mapping list is invalid or too large")
    mappings: list[dict[str, object]] = []
    for item in value:
        if not isinstance(item, dict) or set(item) != {"requirement", "status", "evidence_refs"}:
            raise ValueError("Policy mapping record is malformed")
        requirement = item["requirement"]
        status = item["status"]
        if not isinstance(requirement, str) or not requirement or len(requirement) > 256:
            raise ValueError("Policy requirement is invalid")
        if status not in {"mapped", "unknown"}:
            raise ValueError("Policy mapping status is invalid")
        mappings.append(
            {
                "requirement": requirement,
                "status": status,
                "evidence_refs": _normalize_refs(item["evidence_refs"], known_refs),
            }
        )
    return sorted(mappings, key=lambda item: str(item["requirement"]))


def _normalize_refs(value: object, known_refs: set[str]) -> list[str]:
    if not isinstance(value, list) or len(value) > MAX_EVIDENCE_REFS:
        raise ValueError("Policy evidence references are invalid or too large")
    refs: set[str] = set()
    for ref in value:
        if not isinstance(ref, str) or len(ref) > 128 or ref not in known_refs:
            raise ValueError("Policy evidence reference does not identify normalized FUSE evidence")
        refs.add(ref)
    return sorted(refs)


def _evidence_refs(document: dict[str, object]) -> set[str]:
    refs: set[str] = set()
    findings = document.get("findings", [])
    if isinstance(findings, list):
        refs.update(
            str(item["ref"])
            for item in findings
            if isinstance(item, dict) and isinstance(item.get("ref"), str)
        )
    evidence = document.get("evidence", {})
    if isinstance(evidence, dict):
        for item in evidence.values():
            if isinstance(item, dict) and isinstance(item.get("evidence_refs"), list):
                refs.update(str(ref) for ref in item["evidence_refs"] if isinstance(ref, str))
    return refs


def _run_opa(
    command: list[str], *, timeout: int, cwd: Path | None = None
) -> subprocess.CompletedProcess[str]:
    environment = {
        name: value
        for name, value in _analyzer_environment(command).items()
        if not name.upper().startswith("OPA_")
    }
    return _run_with_environment(
        command,
        environment=environment,
        timeout=timeout,
        cwd=cwd,
        output_limit_bytes=MAX_POLICY_OUTPUT_BYTES,
    )
