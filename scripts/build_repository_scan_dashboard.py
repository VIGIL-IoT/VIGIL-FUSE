from __future__ import annotations

import json
import math
from collections import Counter
from datetime import datetime, timezone
from html import escape
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
REPORT_ROOT = ROOT / "reports" / "repository-scans"
MANIFEST_PATH = REPORT_ROOT / "scan-manifest.json"
SITE_DATA_PATH = ROOT / "site" / "data" / "repository-scan-results.json"
SUPPORT_MATRIX_SOURCE_PATH = ROOT / "src" / "vigil_fuse" / "support-matrix.json"
SITE_SUPPORT_MATRIX_PATH = ROOT / "site" / "data" / "support-matrix.json"
SEVERITIES = ("critical", "high", "medium", "low", "info", "unknown")
RULE_IDS = tuple(f"FUSE{number:03d}" for number in range(1, 8))
SUPPORTED_REPORT_SCHEMAS = frozenset(
    {"1.1", "1.2", "1.3", "1.4", "1.5", "1.6", "1.7", "1.8", "1.9", "1.10"}
)
GITHUB_REPORTS = "https://github.com/VIGIL-IoT/VIGIL-FUSE/blob/main/reports/repository-scans"


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def normalize_report(scan: dict[str, str]) -> dict[str, Any]:
    scan_id = scan["id"]
    directory = REPORT_ROOT / scan_id
    json_path = directory / "findings.json"
    if not json_path.is_file():
        raise FileNotFoundError(f"Missing FUSE JSON report for scan '{scan_id}': {json_path}")

    report = json.loads(json_path.read_text(encoding="utf-8"))
    schema_version = str(report.get("schema_version", ""))
    if schema_version not in SUPPORTED_REPORT_SCHEMAS:
        supported = ", ".join(sorted(SUPPORTED_REPORT_SCHEMAS))
        raise ValueError(
            f"Unsupported FUSE report schema {schema_version!r} in {json_path}; "
            f"expected one of: {supported}"
        )
    # Normalize only the in-memory copy used for the public aggregate. Keep
    # scanner-produced JSON, text, and SARIF files byte-for-byte auditable.
    report["target"] = scan["target_label"]

    return report


def group_findings(scans: list[dict[str, Any]]) -> list[dict[str, Any]]:
    grouped: dict[tuple[str, str, str, str], dict[str, Any]] = {}
    for scan in scans:
        for finding in scan["report"].get("findings", []):
            key = (
                str(finding.get("rule_id", "unknown")),
                str(finding.get("title", "Untitled signal")),
                str(finding.get("severity", "unknown")),
                str(finding.get("category", "unknown")),
            )
            group = grouped.setdefault(
                key,
                {
                    "rule_id": key[0],
                    "title": key[1],
                    "severity": key[2],
                    "category": key[3],
                    "count": 0,
                    "confidence_counts": Counter(),
                    "examples": [],
                },
            )
            group["count"] += 1
            group["confidence_counts"][str(finding.get("confidence", "unknown"))] += 1
            location = finding.get("location", {})
            if len(group["examples"]) < 3:
                group["examples"].append(
                    {
                        "scan_id": scan["id"],
                        "file": str(location.get("file", "")),
                        "line": location.get("start_line"),
                    }
                )

    output = []
    for group in grouped.values():
        group["confidence_counts"] = dict(sorted(group["confidence_counts"].items()))
        output.append(group)
    return sorted(output, key=lambda item: (-item["count"], item["rule_id"], item["title"]))


def summarize_scan(scan: dict[str, str], report: dict[str, Any]) -> dict[str, Any]:
    summary = report.get("summary", {})
    scan_meta = report.get("scan", {})
    coverage = report.get("coverage", {})
    support = coverage.get("support", {})
    hardware = report.get("hardware_inventory", {})
    return {
        "id": scan["id"],
        "profile": scan_meta.get("profile", "unknown"),
        "scope": scan["scope"],
        "target": scan["target_label"],
        "started_at": scan_meta.get("started_at"),
        "completed_at": scan_meta.get("completed_at"),
        "input_manifest_sha256": scan_meta.get("input_manifest_sha256"),
        "files_discovered": int(summary.get("files_discovered", 0)),
        "files_selected": int(summary.get("files_selected", 0)),
        "files_scanned": int(summary.get("files_scanned", 0)),
        "files_skipped": int(summary.get("files_skipped", 0)),
        "files_skipped_by_reason": coverage.get("files_skipped_by_reason", {}),
        "scan_status": support.get("status", "unknown"),
        "support_label": support.get("label", "unknown"),
        "limits_reached": coverage.get("limits_reached", []),
        "hardware_inventory": {
            "present": bool(hardware.get("present", False)),
            "file_count": int(hardware.get("file_count", 0)),
            "category_counts": hardware.get("category_counts", {}),
            "complete": bool(hardware.get("complete", False)),
        },
        "hardware_file_count": int(hardware.get("file_count", 0)),
        "hardware_category_counts": hardware.get("category_counts", {}),
        "hardware_inventory_complete": bool(hardware.get("complete", False)),
        "finding_count": int(summary.get("finding_count", 0)),
        "analysis_performed": bool(summary.get("analysis_performed", False)),
        "report_files": {
            "json": f"reports/repository-scans/{scan['id']}/findings.json",
            "text": f"reports/repository-scans/{scan['id']}/findings.txt",
            "sarif": f"reports/repository-scans/{scan['id']}/findings.sarif",
            "github_json": f"{GITHUB_REPORTS}/{scan['id']}/findings.json",
            "github_text": f"{GITHUB_REPORTS}/{scan['id']}/findings.txt",
            "github_sarif": f"{GITHUB_REPORTS}/{scan['id']}/findings.sarif",
        },
        "report": report,
    }


def sum_field(scans: list[dict[str, Any]], field: str) -> int:
    return sum(int(scan.get(field, 0)) for scan in scans)


def build_summary() -> dict[str, Any]:
    manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    repositories = []
    all_scans = []
    total_rule_counts: Counter[str] = Counter()
    total_severity_counts: Counter[str] = Counter()
    total_skips: Counter[str] = Counter()
    total_hardware_categories: Counter[str] = Counter()

    for repository in manifest["repositories"]:
        scans = []
        for scan_config in repository["scans"]:
            report = normalize_report(scan_config)
            scan = summarize_scan(scan_config, report)
            scans.append(scan)
            all_scans.append(scan)
            total_rule_counts.update(
                finding.get("rule_id", "unknown") for finding in report.get("findings", [])
            )
            total_severity_counts.update(
                finding.get("severity", "unknown") for finding in report.get("findings", [])
            )
            total_skips.update(report.get("coverage", {}).get("files_skipped_by_reason", {}))
            total_hardware_categories.update(scan["hardware_category_counts"])

        rule_counts = Counter()
        severity_counts = Counter()
        for scan in scans:
            for finding in scan["report"].get("findings", []):
                rule_counts[str(finding.get("rule_id", "unknown"))] += 1
                severity_counts[str(finding.get("severity", "unknown"))] += 1

        grouped = group_findings(scans)
        repositories.append(
            {
                "id": repository["id"],
                "name": repository["name"],
                "url": repository["url"],
                "commit": repository["commit"],
                "profile": repository["profile"],
                "scopes": [
                    {
                        key: scan[key]
                        for key in (
                            "id",
                            "profile",
                            "scope",
                            "files_discovered",
                            "files_selected",
                            "files_scanned",
                            "files_skipped",
                            "files_skipped_by_reason",
                            "finding_count",
                            "analysis_performed",
                            "scan_status",
                            "support_label",
                            "limits_reached",
                            "hardware_file_count",
                            "hardware_category_counts",
                            "hardware_inventory",
                            "hardware_inventory_complete",
                            "input_manifest_sha256",
                            "report_files",
                        )
                    }
                    for scan in scans
                ],
                "files_discovered": sum_field(scans, "files_discovered"),
                "files_selected": sum_field(scans, "files_selected"),
                "files_scanned": sum_field(scans, "files_scanned"),
                "files_skipped": sum_field(scans, "files_skipped"),
                "hardware_file_count": sum_field(scans, "hardware_file_count"),
                "hardware_category_counts": dict(
                    sorted(
                        sum(
                            (Counter(scan["hardware_category_counts"]) for scan in scans), Counter()
                        ).items()
                    )
                ),
                "hardware_inventory_complete": all(
                    scan["hardware_inventory_complete"] for scan in scans
                ),
                "finding_count": sum_field(scans, "finding_count"),
                "severity_counts": {key: severity_counts.get(key, 0) for key in SEVERITIES},
                "rule_counts": {key: rule_counts.get(key, 0) for key in RULE_IDS},
                "finding_groups": grouped,
            }
        )

    totals = {
        "repository_count": len(repositories),
        "scan_scope_count": len(all_scans),
        "files_discovered": sum_field(all_scans, "files_discovered"),
        "files_selected": sum_field(all_scans, "files_selected"),
        "files_scanned": sum_field(all_scans, "files_scanned"),
        "files_skipped": sum_field(all_scans, "files_skipped"),
        "hardware_file_count": sum_field(all_scans, "hardware_file_count"),
        "hardware_category_counts": dict(sorted(total_hardware_categories.items())),
        "hardware_inventory_complete": all(
            scan["hardware_inventory_complete"] for scan in all_scans
        ),
        "finding_count": sum_field(all_scans, "finding_count"),
        "severity_counts": {key: total_severity_counts.get(key, 0) for key in SEVERITIES},
        "rule_counts": {key: total_rule_counts.get(key, 0) for key in RULE_IDS},
        "files_skipped_by_reason": dict(sorted(total_skips.items())),
    }
    end_times = [scan["completed_at"] for scan in all_scans if scan.get("completed_at")]
    return {
        "generated_at": datetime.now(timezone.utc)
        .isoformat(timespec="seconds")
        .replace("+00:00", "Z"),
        "scan_date": manifest["scan_date"],
        "fuse": manifest["fuse"],
        "latest_scan_completed_at": max(end_times) if end_times else None,
        "interpretation": "Raw static indicators from the listed source/configuration scopes. Findings are not confirmed vulnerabilities.",
        "totals": totals,
        "repositories": repositories,
    }


def build_support_matrix() -> dict[str, Any]:
    matrix = json.loads(SUPPORT_MATRIX_SOURCE_PATH.read_text(encoding="utf-8"))
    if matrix.get("schema_version") != "1.0" or not isinstance(matrix.get("capabilities"), list):
        raise ValueError(f"Invalid FUSE support matrix: {SUPPORT_MATRIX_SOURCE_PATH}")
    return matrix


def svg_chart(
    title: str,
    rows: list[tuple[str, int]],
    output: Path,
    description: str = "Horizontal bars show raw FUSE signal counts.",
) -> None:
    width = 1120
    left = 340
    plot_width = 620
    row_height = 42
    top = 62
    height = top + max(1, len(rows)) * row_height + 44
    maximum = max((value for _, value in rows), default=0)
    scale_max = max(1.0, math.log10(maximum + 1))
    axis_ticks = [0, 1, 10, 100, 1000, 10000]
    axis_ticks = [tick for tick in axis_ticks if tick <= maximum or tick == 0]
    if maximum and maximum not in axis_ticks:
        axis_ticks.append(maximum)
    axis_ticks = sorted(set(axis_ticks))

    parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {width} {height}" role="img" aria-labelledby="title desc">',
        f'<title id="title">{escape(title)}</title>',
        f'<desc id="desc">{escape(description)} Bar lengths use a logarithmic scale; exact values appear at the right.</desc>',
        "<style>text{font-family:Arial,sans-serif;fill:#161616}.axis{fill:#595959;font-size:12px}.label{font-size:14px}.value{font-size:14px;font-weight:700}.grid{stroke:#dedede;stroke-width:1}.track{fill:#eeeeee}.bar{fill:#d92b21}</style>",
        f'<text x="0" y="24" font-size="18" font-weight="700">{escape(title)}</text>',
        '<text x="0" y="45" class="axis">Log scale for bar length, exact count shown</text>',
    ]
    grid_top = top - 12
    grid_bottom = top + len(rows) * row_height - 8
    for tick in axis_ticks:
        transformed = math.log10(tick + 1) / scale_max if maximum else 0
        x = left + transformed * plot_width
        parts.append(
            f'<line x1="{x:.1f}" y1="{grid_top}" x2="{x:.1f}" y2="{grid_bottom}" class="grid"/>'
        )
        parts.append(
            f'<text x="{x:.1f}" y="{height - 12}" text-anchor="middle" class="axis">{tick}</text>'
        )

    for index, (label, value) in enumerate(rows):
        y = top + index * row_height
        parts.append(f'<text x="0" y="{y + 17}" class="label">{escape(label)}</text>')
        parts.append(f'<rect x="{left}" y="{y}" width="{plot_width}" height="22" class="track"/>')
        transformed = math.log10(value + 1) / scale_max if value else 0
        bar_width = max(0, transformed * plot_width)
        if value and bar_width < 2:
            bar_width = 2
        parts.append(f'<rect x="{left}" y="{y}" width="{bar_width:.1f}" height="22" class="bar"/>')
        parts.append(
            f'<text x="{left + plot_width + 14}" y="{y + 17}" class="value">{value}</text>'
        )
    parts.append("</svg>")
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text("\n".join(parts) + "\n", encoding="utf-8")


def build_charts(summary: dict[str, Any]) -> None:
    repository_rows = sorted(
        ((item["name"], int(item["finding_count"])) for item in summary["repositories"]),
        key=lambda item: (-item[1], item[0].casefold()),
    )
    rule_rows = [(rule, int(summary["totals"]["rule_counts"].get(rule, 0))) for rule in RULE_IDS]
    charts = [
        (
            "Raw FUSE signals by repository",
            repository_rows,
            "findings-by-repository.svg",
            "scan-findings-by-repository.svg",
        ),
        (
            "Raw FUSE signals by rule",
            rule_rows,
            "findings-by-rule.svg",
            "scan-findings-by-rule.svg",
        ),
    ]
    for title, rows, report_name, site_name in charts:
        svg_chart(title, rows, REPORT_ROOT / "plots" / report_name)
        svg_chart(title, rows, ROOT / "site" / "assets" / site_name)


def main() -> None:
    summary = build_summary()
    support_matrix = build_support_matrix()
    write_json(REPORT_ROOT / "summary.json", summary)
    write_json(SITE_DATA_PATH, summary)
    write_json(SITE_SUPPORT_MATRIX_PATH, support_matrix)
    build_charts(summary)
    print(
        "Built repository scan summary: "
        f"{summary['totals']['repository_count']} repositories, "
        f"{summary['totals']['scan_scope_count']} scan scopes, "
        f"{summary['totals']['files_scanned']} files scanned, "
        f"{summary['totals']['finding_count']} raw signals."
    )


if __name__ == "__main__":
    main()
