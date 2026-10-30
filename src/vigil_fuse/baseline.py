from __future__ import annotations

import hashlib
import json
import os
import re
import tempfile
from collections import Counter, defaultdict
from datetime import date, datetime, timezone
from pathlib import Path, PureWindowsPath
from typing import Any

from . import __version__
from .target_labels import validate_target_label

BASELINE_FORMAT_VERSION = "1.1"
SUPPORTED_BASELINE_FORMAT_VERSIONS = frozenset({"1.0", BASELINE_FORMAT_VERSION})
SUPPRESSION_FORMAT_VERSION = "1.0"
MAX_REVIEW_INPUT_BYTES = 50 * 1024 * 1024
_SHA256 = re.compile(r"^[a-f0-9]{64}$")
_SEVERITY_ORDER = {"unknown": -1, "info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
_SEVERITIES = frozenset(_SEVERITY_ORDER)
_CONFIDENCES = frozenset({"high", "medium", "low"})
_INTENTIONAL_SKIPS = (
    "The input is already an SBOM; FUSE uses it directly rather than regenerating it.",
    "No selected input was passed to this rule.",
    "No selected input matched this rule's supported input scope.",
)


def _now() -> datetime:
    return datetime.now(timezone.utc).replace(microsecond=0)


def _timestamp(value: datetime | None = None) -> str:
    return (value or _now()).isoformat().replace("+00:00", "Z")


def _load_json(path: Path) -> dict[str, Any]:
    if path.is_symlink():
        raise ValueError(f"Refusing to read a symbolic-link review file: {path}")
    if not path.is_file():
        raise ValueError(f"Review input is not a regular file: {path}")
    if path.stat().st_size > MAX_REVIEW_INPUT_BYTES:
        raise ValueError(f"Review input exceeds the {MAX_REVIEW_INPUT_BYTES // (1024 * 1024)} MiB limit: {path}")
    with path.open("rb") as source:
        data = source.read(MAX_REVIEW_INPUT_BYTES + 1)
    if len(data) > MAX_REVIEW_INPUT_BYTES:
        raise ValueError(f"Review input exceeds the {MAX_REVIEW_INPUT_BYTES // (1024 * 1024)} MiB limit: {path}")
    try:
        value = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError(f"Review input is not valid UTF-8 JSON: {path}") from error
    if not isinstance(value, dict):
        raise ValueError(f"Review input must contain a JSON object: {path}")
    return value


def _write_json(path: Path, value: dict[str, Any]) -> None:
    if path.is_symlink():
        raise ValueError(f"Refusing to write through a symbolic link: {path}")
    if path.exists() and not path.is_file():
        raise ValueError(f"Review output must be a regular file: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    serialized = json.dumps(value, indent=2, ensure_ascii=False) + "\n"
    temporary_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            newline="\n",
            prefix=f".{path.name}.",
            suffix=".tmp",
            dir=path.parent,
            delete=False,
        ) as temporary:
            temporary.write(serialized)
            temporary_path = Path(temporary.name)
        os.replace(temporary_path, path)
    finally:
        if temporary_path is not None and temporary_path.exists():
            temporary_path.unlink()


def _normalized_path(value: str) -> str:
    return value.replace("\\", "/").strip("/") or "."


def _finding_identity(finding: dict[str, Any]) -> str:
    location = finding.get("location")
    if not isinstance(location, dict):
        raise ValueError("Finding is missing a location object")
    file_path = location.get("file")
    rule_id = finding.get("rule_id")
    title = finding.get("title")
    evidence = finding.get("evidence")
    category = finding.get("category", "")
    analyzer = finding.get("analyzer", "")
    finding_id = finding.get("id")
    if not all(isinstance(item, str) for item in (file_path, rule_id, title, evidence, category, analyzer)):
        raise ValueError("Finding is missing required identity fields")
    if analyzer == "osv-scanner" and isinstance(finding_id, str) and finding_id:
        # Advisory identity already includes the advisory, package/version, and
        # source inventory location, so text changes in upstream summaries do
        # not reset a baseline.
        identity_data = "\0".join((analyzer, finding_id))
        return hashlib.sha256(identity_data.encode("utf-8")).hexdigest()
    # Evidence is already redacted by FUSE. It is used to distinguish multiple
    # same-rule matches in a file, but is not copied into baseline files.
    normalized_evidence = " ".join(evidence.split())
    identity_data = "\0".join(
        (analyzer, rule_id, _normalized_path(file_path), category, title, normalized_evidence)
    )
    return hashlib.sha256(identity_data.encode("utf-8")).hexdigest()


def _finding_move_identity(finding: dict[str, Any]) -> str | None:
    """Return a conservative path-independent identity for native findings."""
    analyzer = finding.get("analyzer", "")
    finding_id = finding.get("id")
    if analyzer == "osv-scanner" and isinstance(finding_id, str) and finding_id:
        # OSV identity includes the source inventory location. A component
        # appearing at another path is a distinct piece of inventory evidence.
        return None

    rule_id = finding.get("rule_id")
    title = finding.get("title")
    evidence = finding.get("evidence")
    category = finding.get("category", "")
    if not all(isinstance(item, str) for item in (analyzer, rule_id, title, evidence, category)):
        raise ValueError("Finding is missing required identity fields")
    normalized_evidence = " ".join(evidence.split())
    identity_data = "\0".join((analyzer, rule_id, category, title, normalized_evidence))
    return hashlib.sha256(identity_data.encode("utf-8")).hexdigest()


def _project(report: dict[str, Any]) -> dict[str, str]:
    scan = report.get("scan")
    if not isinstance(scan, dict):
        raise ValueError("FUSE report is missing scan metadata")
    target = report.get("target")
    target_kind = scan.get("target_kind")
    profile = scan.get("profile")
    if not all(isinstance(item, str) and item for item in (target, target_kind, profile)):
        raise ValueError("FUSE report is missing target, target kind, or profile")
    normalized_target = target.replace("\\", "/")
    # Current FUSE reports store a shareable label. Keep multi-part labels intact
    # so repositories with the same basename do not share baseline identity.
    # Sanitize older reports that may contain a local absolute path.
    if normalized_target.startswith("/") or PureWindowsPath(target).drive:
        normalized_target = normalized_target.rstrip("/").split("/")[-1] or "."
    elif normalized_target != ".":
        normalized_target = validate_target_label(normalized_target)
    return {"target": normalized_target, "target_kind": target_kind, "profile": profile}


def _findings(report: dict[str, Any]) -> list[dict[str, Any]]:
    findings = report.get("findings")
    if not isinstance(findings, list):
        raise ValueError("FUSE report is missing its findings array")
    result: list[dict[str, Any]] = []
    for finding in findings:
        if not isinstance(finding, dict):
            raise ValueError("FUSE report contains a malformed finding")
        fingerprint = finding.get("fingerprint")
        rule_id = finding.get("rule_id")
        title = finding.get("title")
        severity = finding.get("severity")
        confidence = finding.get("confidence")
        category = finding.get("category")
        location = finding.get("location")
        if (
            not isinstance(fingerprint, str)
            or not _SHA256.fullmatch(fingerprint)
            or not all(isinstance(item, str) and item for item in (rule_id, title, severity, confidence, category))
            or severity not in _SEVERITIES
            or confidence not in _CONFIDENCES
            or not isinstance(location, dict)
            or not isinstance(location.get("file"), str)
        ):
            raise ValueError("FUSE report contains a finding with invalid identity metadata")
        item = {
            "identity": _finding_identity(finding),
            "fingerprint": fingerprint,
            "id": finding.get("id") if isinstance(finding.get("id"), str) else fingerprint,
            "rule_id": rule_id,
            "title": title,
            "severity": severity,
            "confidence": confidence,
            "category": category,
            "file": _normalized_path(location["file"]),
            "start_line": location.get("start_line") if isinstance(location.get("start_line"), int) else None,
        }
        move_identity = _finding_move_identity(finding)
        if move_identity is not None:
            item["move_identity"] = move_identity
        result.append(item)

    occurrences: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for item in result:
        occurrences[item["identity"]].append(item)
    for identity, matches in occurrences.items():
        ordered = sorted(
            matches,
            key=lambda item: (item["file"], item["start_line"] or 0, item["fingerprint"]),
        )
        for occurrence, item in enumerate(ordered, start=1):
            material = f"{identity}\0occurrence:{occurrence}"
            item["suppression_identity"] = hashlib.sha256(material.encode("utf-8")).hexdigest()
    return result


def _completion(report: dict[str, Any]) -> tuple[bool, list[str]]:
    summary = report.get("summary")
    coverage = report.get("coverage")
    hardware = report.get("hardware_inventory")
    if not isinstance(summary, dict) or not isinstance(coverage, dict):
        raise ValueError("FUSE report is missing summary or coverage metadata")
    reasons: list[str] = []
    if summary.get("analysis_performed") is not True:
        reasons.append("No supported analyzer completed work on this target.")
    if coverage.get("discovery_complete") is not True:
        reasons.append("Source discovery did not complete.")
    if coverage.get("limits_reached"):
        reasons.append("One or more scan resource limits were reached.")
    inventory = coverage.get("input_inventory")
    if isinstance(inventory, dict) and inventory.get("complete") is not True:
        reasons.append("The input inventory is incomplete.")
    if isinstance(hardware, dict) and hardware.get("complete") is not True:
        reasons.append("The hardware artifact inventory is incomplete.")
    analyzers = coverage.get("analyzers", [])
    if not isinstance(analyzers, list):
        raise ValueError("FUSE report coverage analyzers must be an array")
    for analyzer in analyzers:
        if not isinstance(analyzer, dict):
            reasons.append("An analyzer coverage entry is malformed.")
            continue
        status = analyzer.get("status")
        name = analyzer.get("name", "unknown analyzer")
        detail = analyzer.get("detail")
        if not isinstance(status, str) or status not in {"completed", "partial", "unavailable", "failed", "skipped"}:
            reasons.append(f"{name} has an unknown completion status.")
            continue
        if status in {"partial", "unavailable", "failed"}:
            reasons.append(f"{name} status is {status}.")
        elif status == "skipped" and not (
            isinstance(detail, str) and any(detail.startswith(prefix) for prefix in _INTENTIONAL_SKIPS)
        ):
            reasons.append(f"{name} was skipped.")
    return not reasons, list(dict.fromkeys(reasons))


def _validate_report(report: dict[str, Any]) -> None:
    if report.get("schema_version") not in {"1.1", "1.2", "1.3", "1.4", "1.5", "1.6", "1.7", "1.8", "1.9", "1.10"}:
        raise ValueError("Unsupported FUSE report schema version")
    _project(report)
    _findings(report)
    _completion(report)


def _baseline_document(report: dict[str, Any], report_path: Path) -> dict[str, Any]:
    complete, reasons = _completion(report)
    if not complete:
        raise ValueError("Cannot create a baseline from an incomplete scan: " + " ".join(reasons))
    scan = report["scan"]
    findings = _findings(report)
    return {
        "format_version": BASELINE_FORMAT_VERSION,
        "tool": {"name": "FUSE", "version": __version__},
        "created_at": _timestamp(),
        "project": _project(report),
        "source_report": {
            "file_name": report_path.name,
            "completed_at": scan.get("completed_at"),
            "input_manifest_sha256": scan.get("input_manifest_sha256"),
        },
        "finding_count": len(findings),
        "findings": findings,
    }


def _load_baseline(path: Path) -> dict[str, Any]:
    baseline = _load_json(path)
    version = baseline.get("format_version")
    if not isinstance(version, str) or version not in SUPPORTED_BASELINE_FORMAT_VERSIONS:
        raise ValueError("Unsupported FUSE baseline format version")
    if not isinstance(baseline.get("findings"), list) or not isinstance(baseline.get("project"), dict):
        raise ValueError("Baseline file is missing findings or project metadata")
    if not all(
        isinstance(baseline["project"].get(field), str) and baseline["project"][field]
        for field in ("target", "target_kind", "profile")
    ):
        raise ValueError("Baseline project metadata is malformed")
    for finding in baseline["findings"]:
        suppression_identity = finding.get("suppression_identity", finding.get("identity")) if isinstance(finding, dict) else None
        move_identity = finding.get("move_identity") if isinstance(finding, dict) else None
        if (
            not isinstance(finding, dict)
            or not isinstance(finding.get("identity"), str)
            or not _SHA256.fullmatch(finding["identity"])
            or not isinstance(finding.get("fingerprint"), str)
            or not _SHA256.fullmatch(finding["fingerprint"])
            or not isinstance(suppression_identity, str)
            or not _SHA256.fullmatch(suppression_identity)
            or (
                move_identity is not None
                and (not isinstance(move_identity, str) or not _SHA256.fullmatch(move_identity))
            )
            or not all(
                isinstance(finding.get(field), str) and finding[field]
                for field in ("rule_id", "title", "severity", "confidence", "category", "file")
            )
            or (finding.get("start_line") is not None and not isinstance(finding.get("start_line"), int))
        ):
            raise ValueError("Baseline contains invalid finding identity metadata")
    return baseline


def _load_suppressions(
    path: Path | None, expected_project: dict[str, str] | None = None
) -> dict[str, dict[str, Any]]:
    if path is None:
        return {}
    if path.is_symlink():
        raise ValueError(f"Refusing to read a symbolic-link suppression file: {path}")
    if not path.exists():
        return {}
    document = _load_json(path)
    if document.get("format_version") != SUPPRESSION_FORMAT_VERSION:
        raise ValueError("Unsupported FUSE suppression format version")
    if not isinstance(document.get("project"), dict):
        raise ValueError("Suppression file is missing project metadata")
    if expected_project is not None and document["project"] != expected_project:
        raise ValueError("Suppression file belongs to a different target, target kind, or profile")
    entries = document.get("suppressions")
    if not isinstance(entries, list):
        raise ValueError("Suppression file is missing its suppressions array")
    result: dict[str, dict[str, Any]] = {}
    for entry in entries:
        if (
            not isinstance(entry, dict)
            or not isinstance(entry.get("identity"), str)
            or not _SHA256.fullmatch(entry["identity"])
            or not isinstance(entry.get("reason"), str)
            or not entry["reason"].strip()
            or not isinstance(entry.get("created_at"), str)
            or (entry.get("owner") is not None and not isinstance(entry.get("owner"), str))
            or (entry.get("expires_at") is not None and not isinstance(entry.get("expires_at"), str))
        ):
            raise ValueError("Suppression file contains an invalid entry")
        expires = entry.get("expires_at")
        if expires is not None:
            try:
                date.fromisoformat(expires)
            except (TypeError, ValueError) as error:
                raise ValueError("Suppression expiry must use YYYY-MM-DD") from error
        result[entry["identity"]] = entry
    return result


def _is_active(suppression: dict[str, Any], today: date) -> bool:
    expires = suppression.get("expires_at")
    return expires is None or date.fromisoformat(expires) >= today


def _diff_document(
    report: dict[str, Any], baseline: dict[str, Any], suppressions: dict[str, dict[str, Any]]
) -> dict[str, Any]:
    _validate_report(report)
    current_project = _project(report)
    if current_project != baseline["project"]:
        raise ValueError("Current report target, target kind, or profile does not match this baseline")
    complete, reasons = _completion(report)
    current_findings = _findings(report)

    current_by_identity: dict[str, list[dict[str, Any]]] = defaultdict(list)
    baseline_by_identity: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for item in current_findings:
        current_by_identity[item["identity"]].append(item)
    for item in baseline["findings"]:
        baseline_by_identity[item["identity"]].append(item)

    def sort_finding(item: dict[str, Any]) -> tuple[str, int, str]:
        return item["file"], item["start_line"] or 0, item["fingerprint"]

    persistent_current: set[int] = set()
    matched_baseline: set[int] = set()
    moved_from: dict[int, str] = {}
    for identity in sorted(set(current_by_identity) | set(baseline_by_identity)):
        current_items = sorted(current_by_identity.get(identity, []), key=sort_finding)
        baseline_items = sorted(baseline_by_identity.get(identity, []), key=sort_finding)
        shared = min(len(current_items), len(baseline_items))
        for index in range(shared):
            persistent_current.add(id(current_items[index]))
            matched_baseline.add(id(baseline_items[index]))

    current_by_move_identity: dict[str, list[dict[str, Any]]] = defaultdict(list)
    baseline_by_move_identity: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for item in current_findings:
        move_identity = item.get("move_identity")
        if id(item) not in persistent_current and isinstance(move_identity, str):
            current_by_move_identity[move_identity].append(item)
    for item in baseline["findings"]:
        move_identity = item.get("move_identity")
        if id(item) not in matched_baseline and isinstance(move_identity, str):
            baseline_by_move_identity[move_identity].append(item)

    for move_identity in sorted(set(current_by_move_identity) & set(baseline_by_move_identity)):
        current_items = current_by_move_identity[move_identity]
        baseline_items = baseline_by_move_identity[move_identity]
        if len(current_items) == 1 and len(baseline_items) == 1:
            current_item = current_items[0]
            baseline_item = baseline_items[0]
            moved_from[id(current_item)] = baseline_item["file"]
            matched_baseline.add(id(baseline_item))

    changes: list[dict[str, Any]] = []
    resolved: list[dict[str, Any]] = []
    today = _now().date()
    for identity in sorted(set(current_by_identity) | set(baseline_by_identity)):
        current_items = sorted(current_by_identity.get(identity, []), key=sort_finding)
        baseline_items = sorted(baseline_by_identity.get(identity, []), key=sort_finding)
        for item in current_items:
            if id(item) in persistent_current:
                state = "persistent"
            elif id(item) in moved_from:
                state = "moved"
            else:
                state = "new"
            suppression = suppressions.get(item["suppression_identity"])
            if suppression is None:
                # Older suppression files keyed entries by the shared comparison
                # identity. Keep their previous broad behavior when they are read.
                suppression = suppressions.get(identity)
            active = bool(suppression and _is_active(suppression, today))
            change = {
                **item,
                "change": state,
                "suppressed": active,
                "suppression": (
                    {
                        "reason": suppression["reason"],
                        "owner": suppression.get("owner"),
                        "expires_at": suppression.get("expires_at"),
                    }
                    if active and suppression
                    else None
                ),
            }
            if state == "moved":
                change["moved_from"] = moved_from[id(item)]
            changes.append(change)
        if complete:
            for item in baseline_items:
                if id(item) not in matched_baseline:
                    resolved.append({**item, "change": "resolved"})

    counts = Counter(item["change"] for item in changes)
    summary = {
        "new": counts.get("new", 0),
        "persistent": counts.get("persistent", 0),
        "moved": counts.get("moved", 0),
        "resolved": len(resolved) if complete else None,
        "suppressed": sum(1 for item in changes if item["suppressed"]),
        "expired_suppressions": sum(
            1 for identity, suppression in suppressions.items()
            if identity in current_by_identity and not _is_active(suppression, today)
        ),
        "resolved_evaluated": complete,
        "current_finding_count": len(current_findings),
        "baseline_finding_count": len(baseline["findings"]),
    }
    scan = report["scan"]
    return {
        "format_version": BASELINE_FORMAT_VERSION,
        "project": current_project,
        "analysis_status": "complete" if complete else "incomplete",
        "incomplete_reasons": reasons,
        "baseline_created_at": baseline.get("created_at"),
        "current_scan_completed_at": scan.get("completed_at"),
        "summary": summary,
        "findings": sorted(
            changes,
            key=lambda item: (
                item["change"],
                -_SEVERITY_ORDER.get(item["severity"], -1),
                item["file"],
                item["start_line"] or 0,
            ),
        ),
        "resolved_findings": sorted(
            resolved, key=lambda item: (item["file"], item["start_line"] or 0, item["rule_id"])
        ),
    }


def create_baseline(report_path: Path, output_path: Path) -> int:
    if report_path.resolve() == output_path.resolve():
        raise ValueError("Baseline output cannot overwrite the source findings report")
    report = _load_json(report_path)
    _validate_report(report)
    baseline = _baseline_document(report, report_path)
    _write_json(output_path, baseline)
    print(f"Created FUSE baseline with {baseline['finding_count']} findings: {output_path}")
    return 0


def suppress_finding(
    report_path: Path,
    fingerprint: str,
    reason: str,
    owner: str | None,
    expires_at: str | None,
    output_path: Path,
) -> int:
    if report_path.resolve() == output_path.resolve():
        raise ValueError("Suppression output cannot overwrite the source findings report")
    if not reason.strip():
        raise ValueError("Suppression reason cannot be empty")
    if not _SHA256.fullmatch(fingerprint):
        raise ValueError("--finding must be a 64-character lowercase SHA-256 fingerprint")
    if expires_at is not None:
        try:
            expiry = date.fromisoformat(expires_at)
        except ValueError as error:
            raise ValueError("--expires must use YYYY-MM-DD") from error
        if expiry < _now().date():
            raise ValueError("--expires cannot be in the past")

    report = _load_json(report_path)
    _validate_report(report)
    matching = [item for item in _findings(report) if item["fingerprint"] == fingerprint]
    if not matching:
        raise ValueError("The requested finding fingerprint is not present in this report")
    identities = {item["suppression_identity"] for item in matching}
    project = _project(report)
    existing: dict[str, dict[str, Any]] = {}
    if output_path.exists():
        existing = _load_suppressions(output_path, expected_project=project)
    for identity in identities:
        existing[identity] = {
            "identity": identity,
            "reason": reason.strip(),
            "owner": owner.strip() if owner and owner.strip() else None,
            "created_at": _timestamp(),
            "expires_at": expires_at,
        }
    document = {
        "format_version": SUPPRESSION_FORMAT_VERSION,
        "tool": {"name": "FUSE", "version": __version__},
        "project": project,
        "suppressions": sorted(existing.values(), key=lambda item: item["identity"]),
    }
    _write_json(output_path, document)
    print(f"Recorded {len(identities)} suppression entry/entries: {output_path}")
    return 0


def unsuppress_finding(report_path: Path, fingerprint: str, output_path: Path) -> int:
    if report_path.resolve() == output_path.resolve():
        raise ValueError("Suppression output cannot overwrite the source findings report")
    if not _SHA256.fullmatch(fingerprint):
        raise ValueError("--finding must be a 64-character lowercase SHA-256 fingerprint")
    report = _load_json(report_path)
    _validate_report(report)
    matching = [item for item in _findings(report) if item["fingerprint"] == fingerprint]
    if not matching:
        raise ValueError("The requested finding fingerprint is not present in this report")
    project = _project(report)
    existing = _load_suppressions(output_path, expected_project=project)
    identities = {
        identity
        for item in matching
        for identity in (item["suppression_identity"], item["identity"])
    }
    removed = sum(existing.pop(identity, None) is not None for identity in identities)
    if not removed:
        raise ValueError("No suppression exists for the selected finding identity")
    document = {
        "format_version": SUPPRESSION_FORMAT_VERSION,
        "tool": {"name": "FUSE", "version": __version__},
        "project": project,
        "suppressions": sorted(existing.values(), key=lambda item: item["identity"]),
    }
    _write_json(output_path, document)
    print(f"Removed {removed} suppression(s): {output_path}")
    return 0


def diff_baseline(
    report_path: Path,
    baseline_path: Path,
    suppressions_path: Path | None,
    output_format: str,
    fail_on_new: str,
) -> int:
    report = _load_json(report_path)
    baseline = _load_baseline(baseline_path)
    suppressions = _load_suppressions(suppressions_path, expected_project=_project(report))
    result = _diff_document(report, baseline, suppressions)
    if output_format == "json":
        print(json.dumps(result, indent=2, ensure_ascii=False))
    else:
        summary = result["summary"]
        resolved = summary["resolved"] if summary["resolved_evaluated"] else "not evaluated"
        print(f"FUSE baseline diff: {result['analysis_status']}")
        print(
            f"New: {summary['new']} | Persistent: {summary['persistent']} | "
            f"Moved: {summary['moved']} | Resolved: {resolved} | Suppressed: {summary['suppressed']}"
        )
        if summary["expired_suppressions"]:
            print(f"Expired suppressions with current matches: {summary['expired_suppressions']}")
        for reason in result["incomplete_reasons"]:
            print(f"Incomplete: {reason}")
        for item in result["findings"]:
            marker = "suppressed" if item["suppressed"] else item["change"]
            location = f"{item['file']}:{item['start_line']}" if item["start_line"] else item["file"]
            print(f"  [{item['severity'].upper()}] {marker}: {item['rule_id']} {location} - {item['title']}")
            if item["change"] == "moved":
                print(f"    Moved from: {item['moved_from']}")
            if item["suppression"]:
                print(f"    Reason: {item['suppression']['reason']}")
                if item["suppression"].get("owner"):
                    print(f"    Owner: {item['suppression']['owner']}")
        for item in result["resolved_findings"]:
            location = f"{item['file']}:{item['start_line']}" if item["start_line"] else item["file"]
            print(f"  [RESOLVED] {item['rule_id']} {location} - {item['title']}")

    if result["analysis_status"] != "complete":
        return 2
    if fail_on_new != "none":
        threshold = _SEVERITY_ORDER[fail_on_new]
        if any(
            not item["suppressed"]
            and item["change"] == "new"
            and _SEVERITY_ORDER.get(item["severity"], -1) >= threshold
            for item in result["findings"]
        ):
            return 1
    return 0
