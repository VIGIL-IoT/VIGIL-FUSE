from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
HOLDOUT_ROOT = ROOT / "reports" / "repository-scans" / "holdout"
DEFAULT_MANIFEST = HOLDOUT_ROOT / "manifest.json"
DEFAULT_REPORT_ROOT = HOLDOUT_ROOT / "reports"

sys.path.insert(0, str(ROOT))
from scripts.build_repository_scan_dashboard import RULE_IDS, SEVERITIES, svg_chart, write_json


def _read_report(report_root: Path, scan_id: str) -> dict[str, Any]:
    scan_path = Path(scan_id)
    if (
        not scan_id
        or scan_path.is_absolute()
        or ".." in scan_path.parts
        or scan_path.name != scan_id
    ):
        raise ValueError(f"Invalid holdout scan ID: {scan_id!r}")
    path = (report_root / scan_id / "findings.json").resolve()
    if not path.is_relative_to(report_root.resolve()):
        raise ValueError(f"Holdout report path escapes report root: {scan_id!r}")
    report = json.loads(path.read_text(encoding="utf-8"))
    if str(report.get("schema_version", "")) not in {"1.1", "1.2", "1.3", "1.4", "1.5", "1.6", "1.7"}:
        raise ValueError(f"Unsupported or missing FUSE report schema in {path}")
    if not isinstance(report.get("summary"), dict) or not isinstance(report.get("coverage"), dict):
        raise ValueError(f"FUSE report is missing summary or coverage: {path}")
    return report


def build_summary(manifest_path: Path, report_root: Path, output_root: Path) -> dict[str, Any]:
    manifest_path = manifest_path.resolve()
    report_root = report_root.resolve()
    output_root = output_root.resolve()
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    cohort = manifest.get("cohort")
    if cohort not in {"independent-holdout", "regression-validation"}:
        raise ValueError("Refusing to summarize a manifest that is not a separate holdout or regression-validation cohort")
    if not report_root.is_relative_to(output_root):
        raise ValueError("Holdout reports must be inside the output root")

    reports_relative = report_root.relative_to(output_root).as_posix()
    repositories: list[dict[str, Any]] = []
    rule_counts: Counter[str] = Counter()
    severity_counts: Counter[str] = Counter()
    skipped_by_reason: Counter[str] = Counter()
    totals = Counter()
    hardware_categories: Counter[str] = Counter()

    for repository in manifest.get("repositories", []):
        scopes: list[dict[str, Any]] = []
        repo_rule_counts: Counter[str] = Counter()
        repo_severity_counts: Counter[str] = Counter()
        repo_skips: Counter[str] = Counter()
        repo_totals = Counter()
        repo_hardware_categories: Counter[str] = Counter()

        for scan in repository.get("scans", []):
            report = _read_report(report_root, scan.get("id", ""))
            summary = report["summary"]
            coverage = report["coverage"]
            hardware = report.get("hardware_inventory", {})
            findings = report.get("findings", [])
            if not isinstance(findings, list):
                raise ValueError(f"FUSE findings must be a list for {scan.get('id')}")

            scope_rule_counts = Counter(str(item.get("rule_id", "unknown")) for item in findings)
            scope_severity_counts = Counter(str(item.get("severity", "unknown")) for item in findings)
            scope_skips = Counter(coverage.get("files_skipped_by_reason", {}))
            scope_hardware = Counter(hardware.get("category_counts", {}))
            scope = {
                "id": scan["id"],
                "scope": scan["scope"],
                "profile": repository["profile"],
                "files_discovered": int(summary.get("files_discovered", 0)),
                "files_selected": int(summary.get("files_selected", 0)),
                "files_scanned": int(summary.get("files_scanned", 0)),
                "files_skipped": int(summary.get("files_skipped", 0)),
                "files_skipped_by_reason": dict(sorted(scope_skips.items())),
                "finding_count": len(findings),
                "rule_counts": {rule: scope_rule_counts.get(rule, 0) for rule in RULE_IDS},
                "severity_counts": {severity: scope_severity_counts.get(severity, 0) for severity in SEVERITIES},
                "scan_status": coverage.get("support", {}).get("status", "unknown"),
                "support_label": coverage.get("support", {}).get("label", "unknown"),
                "limits_reached": coverage.get("limits_reached", []),
                "hardware_inventory": {
                    "present": bool(hardware.get("present", False)),
                    "file_count": int(hardware.get("file_count", 0)),
                    "category_counts": dict(sorted(scope_hardware.items())),
                    "complete": bool(hardware.get("complete", False)),
                },
                "report_files": {
                    format_name: f"{reports_relative}/{scan['id']}/findings.{extension}"
                    for format_name, extension in (("json", "json"), ("text", "txt"), ("sarif", "sarif"))
                },
            }
            scopes.append(scope)
            repo_rule_counts.update(scope_rule_counts)
            repo_severity_counts.update(scope_severity_counts)
            repo_skips.update(scope_skips)
            repo_totals.update({
                key: int(summary.get(key, 0))
                for key in ("files_discovered", "files_selected", "files_scanned", "files_skipped")
            })
            repo_hardware_categories.update(scope_hardware)
            rule_counts.update(scope_rule_counts)
            severity_counts.update(scope_severity_counts)
            skipped_by_reason.update(scope_skips)
            hardware_categories.update(scope_hardware)
            totals.update({
                key: int(summary.get(key, 0))
                for key in ("files_discovered", "files_selected", "files_scanned", "files_skipped")
            })

        repositories.append({
            "id": repository["id"],
            "name": repository["name"],
            "url": repository["url"],
            "commit": repository["commit"],
            "profile": repository["profile"],
            "scan_count": len(scopes),
            "files_discovered": repo_totals["files_discovered"],
            "files_selected": repo_totals["files_selected"],
            "files_scanned": repo_totals["files_scanned"],
            "files_skipped": repo_totals["files_skipped"],
            "finding_count": sum(repo_rule_counts.values()),
            "rule_counts": {rule: repo_rule_counts.get(rule, 0) for rule in RULE_IDS},
            "severity_counts": {severity: repo_severity_counts.get(severity, 0) for severity in SEVERITIES},
            "files_skipped_by_reason": dict(sorted(repo_skips.items())),
            "hardware_file_count": sum(repo_hardware_categories.values()),
            "hardware_category_counts": dict(sorted(repo_hardware_categories.items())),
            "scopes": scopes,
        })

    totals_summary = dict(totals)
    totals_summary.update({
        "repository_count": len(repositories),
        "scan_scope_count": sum(repository["scan_count"] for repository in repositories),
        "finding_count": sum(rule_counts.values()),
        "rule_counts": {rule: rule_counts.get(rule, 0) for rule in RULE_IDS},
        "severity_counts": {severity: severity_counts.get(severity, 0) for severity in SEVERITIES},
        "files_skipped_by_reason": dict(sorted(skipped_by_reason.items())),
        "hardware_file_count": sum(hardware_categories.values()),
        "hardware_category_counts": dict(sorted(hardware_categories.items())),
        "hardware_inventory_complete": all(
            scope["hardware_inventory"]["complete"]
            for repository in repositories
            for scope in repository["scopes"]
        ),
    })
    if cohort == "regression-validation":
        interpretation = (
            "Regression validation against patterns observed in the initial holdout snapshot. "
            "The corpus informed these refinements and is not an untouched blind holdout; findings remain static signals, not confirmed vulnerabilities."
        )
    else:
        interpretation = (
            "Qualitative static signals from the selected pinned repository scopes. "
            "This small purposive holdout is not a representative accuracy benchmark; findings are not confirmed vulnerabilities."
        )
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"),
        "scan_date": manifest["scan_date"],
        "cohort": manifest["cohort"],
        "training_manifest": manifest.get("training_manifest"),
        "selection_protocol": manifest.get("selection_protocol", {}),
        "fuse": manifest.get("fuse", {}),
        "interpretation": interpretation,
        "totals": totals_summary,
        "repositories": repositories,
    }


def build_charts(summary: dict[str, Any], output_root: Path) -> None:
    repository_rows = sorted(
        ((item["name"], int(item["finding_count"])) for item in summary["repositories"]),
        key=lambda item: (-item[1], item[0].casefold()),
    )
    rule_rows = [(rule, int(summary["totals"]["rule_counts"].get(rule, 0))) for rule in RULE_IDS]
    plots = output_root / "plots"
    svg_chart("Raw FUSE signals by holdout repository", repository_rows, plots / "findings-by-repository.svg")
    svg_chart("Raw FUSE signals by rule in the holdout", rule_rows, plots / "findings-by-rule.svg")


def main() -> None:
    parser = argparse.ArgumentParser(description="Summarize a separate FUSE holdout report corpus.")
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--report-root", type=Path, default=DEFAULT_REPORT_ROOT)
    parser.add_argument("--output-root", type=Path, default=HOLDOUT_ROOT)
    args = parser.parse_args()
    summary = build_summary(args.manifest, args.report_root, args.output_root)
    output_root = args.output_root.resolve()
    write_json(output_root / "summary.json", summary)
    build_charts(summary, output_root)
    print(
        "Built separate holdout summary: "
        f"{summary['totals']['repository_count']} repositories, "
        f"{summary['totals']['scan_scope_count']} scopes, "
        f"{summary['totals']['files_scanned']} files scanned, "
        f"{summary['totals']['finding_count']} raw signals."
    )


if __name__ == "__main__":
    main()
