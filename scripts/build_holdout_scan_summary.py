from __future__ import annotations

import argparse
import json
import re
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
from scripts.build_repository_scan_dashboard import (  # noqa: E402
    RULE_IDS,
    SEVERITIES,
    svg_chart,
    write_json,
)


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
    if str(report.get("schema_version", "")) not in {
        "1.1",
        "1.2",
        "1.3",
        "1.4",
        "1.5",
        "1.6",
        "1.7",
        "1.8",
        "1.9",
        "1.10",
    }:
        raise ValueError(f"Unsupported or missing FUSE report schema in {path}")
    if not isinstance(report.get("summary"), dict) or not isinstance(report.get("coverage"), dict):
        raise ValueError(f"FUSE report is missing summary or coverage: {path}")
    return report


def _rule_sort_key(rule_id: str) -> tuple[int, int | str]:
    match = re.fullmatch(r"FUSE(\d{3})", rule_id)
    if match:
        return (0, int(match.group(1)))
    return (1, rule_id)


def _module_coverage(report: dict[str, Any]) -> dict[str, Any]:
    coverage = report.get("coverage", {})
    if not isinstance(coverage, dict):
        coverage = {}
    build_context = report.get("build_context", {})
    platformio = build_context.get("platformio", {}) if isinstance(build_context, dict) else {}
    firmware = report.get("firmware_candidates", {})
    actions = report.get("github_actions", {})
    netlist = report.get("hardware_netlist", {})
    environments = (
        platformio.get("selected_environments", []) if isinstance(platformio, dict) else []
    )
    configurations = platformio.get("configurations", []) if isinstance(platformio, dict) else []
    extension_counts = firmware.get("extension_counts", {}) if isinstance(firmware, dict) else {}
    debug_candidates = netlist.get("debug_net_candidates", []) if isinstance(netlist, dict) else []
    encoding_fallback = coverage.get("encoding_fallback", {})
    if not isinstance(encoding_fallback, dict):
        encoding_fallback = {}
    fallback_files = encoding_fallback.get("files", [])
    return {
        "source_decoding": {
            "fallback_encoding": encoding_fallback.get("encoding", "iso-8859-1"),
            "fallback_file_count": int(encoding_fallback.get("count", 0)),
            "fallback_files": [path for path in fallback_files if isinstance(path, str)]
            if isinstance(fallback_files, list)
            else [],
            "omitted_count": int(encoding_fallback.get("omitted_count", 0)),
        },
        "platformio": {
            "status": platformio.get("status", "not-reported")
            if isinstance(platformio, dict)
            else "not-reported",
            "environment_count": len(environments) if isinstance(environments, list) else 0,
            "configuration_count": len(configurations) if isinstance(configurations, list) else 0,
        },
        "firmware_candidates": {
            "status": firmware.get("status", "not-reported")
            if isinstance(firmware, dict)
            else "not-reported",
            "candidate_count": int(firmware.get("candidate_count", 0))
            if isinstance(firmware, dict)
            else 0,
            "extension_counts": dict(sorted(extension_counts.items()))
            if isinstance(extension_counts, dict)
            else {},
        },
        "github_actions": {
            "status": actions.get("status", "not-reported")
            if isinstance(actions, dict)
            else "not-reported",
            "workflow_count": int(actions.get("workflow_count", 0))
            if isinstance(actions, dict)
            else 0,
            "non_sha_action_reference_count": int(actions.get("non_sha_action_reference_count", 0))
            if isinstance(actions, dict)
            else 0,
            "floating_branch_reference_count": int(
                actions.get("floating_branch_reference_count", 0)
            )
            if isinstance(actions, dict)
            else 0,
            "finding_count": int(actions.get("finding_count", 0))
            if isinstance(actions, dict)
            else 0,
        },
        "hardware_netlist": {
            "status": netlist.get("status", "not-reported")
            if isinstance(netlist, dict)
            else "not-reported",
            "component_count": int(netlist.get("component_count", 0))
            if isinstance(netlist, dict)
            else 0,
            "net_count": int(netlist.get("net_count", 0)) if isinstance(netlist, dict) else 0,
            "debug_net_candidate_count": len(debug_candidates)
            if isinstance(debug_candidates, list)
            else 0,
        },
    }


def _has_partial_analysis(report: dict[str, Any]) -> bool:
    coverage = report.get("coverage", {})
    support = coverage.get("support", {}) if isinstance(coverage, dict) else {}
    if isinstance(support, dict) and support.get("status") in {"partial", "invalid"}:
        return True

    summary = report.get("summary", {})
    if isinstance(summary, dict) and int(summary.get("files_skipped", 0)) > 0:
        return True

    analyzers = coverage.get("analyzers", []) if isinstance(coverage, dict) else []
    if isinstance(analyzers, list):
        for analyzer in analyzers:
            if not isinstance(analyzer, dict):
                return True
            if analyzer.get("status") in {"partial", "unavailable", "failed"}:
                return True

    module_statuses = (
        (report.get("build_context", {}), "platformio", {"partial", "invalid"}),
        (report.get("build_context", {}), "compilation_database", {"partial", "invalid"}),
        (report, "firmware_candidates", {"partial"}),
        (report, "github_actions", {"partial"}),
        (report, "hardware_netlist", {"partial", "invalid"}),
        (report, "hardware_bom", {"partial", "invalid"}),
        (report.get("product_context", {}), "vex_import", {"partial", "invalid"}),
    )
    for parent, key, incomplete_statuses in module_statuses:
        value = parent.get(key) if isinstance(parent, dict) else None
        if isinstance(value, dict) and value.get("status") in incomplete_statuses:
            return True

    provenance = report.get("provenance")
    return isinstance(provenance, dict) and provenance.get("status") not in {
        "not-requested",
        "subject-match",
    }


def _sum_module_coverage(scopes: list[dict[str, Any]]) -> dict[str, Any]:
    platformio_environments = 0
    platformio_configurations = 0
    platformio_partial_scopes = 0
    firmware_candidates = 0
    firmware_extensions: Counter[str] = Counter()
    workflows = 0
    non_sha_references = 0
    floating_branch_references = 0
    workflow_findings = 0
    netlist_components = 0
    netlist_nets = 0
    debug_net_candidates = 0
    netlist_scopes = 0
    fallback_file_count = 0
    fallback_files: list[str] = []
    fallback_encoding = "iso-8859-1"
    fallback_omitted_count = 0
    for scope in scopes:
        modules = scope["module_coverage"]
        source_decoding = modules["source_decoding"]
        pio = modules["platformio"]
        firmware = modules["firmware_candidates"]
        actions = modules["github_actions"]
        netlist = modules["hardware_netlist"]
        platformio_environments += pio["environment_count"]
        platformio_configurations += pio["configuration_count"]
        platformio_partial_scopes += int(pio["status"] == "partial")
        firmware_candidates += firmware["candidate_count"]
        firmware_extensions.update(firmware["extension_counts"])
        workflows += actions["workflow_count"]
        non_sha_references += actions["non_sha_action_reference_count"]
        floating_branch_references += actions["floating_branch_reference_count"]
        workflow_findings += actions["finding_count"]
        netlist_components += netlist["component_count"]
        netlist_nets += netlist["net_count"]
        debug_net_candidates += netlist["debug_net_candidate_count"]
        netlist_scopes += int(netlist["status"] in {"completed", "partial"})
        fallback_file_count += source_decoding["fallback_file_count"]
        fallback_files.extend(source_decoding["fallback_files"])
        fallback_omitted_count += source_decoding["omitted_count"]
        fallback_encoding = source_decoding["fallback_encoding"]
    return {
        "source_decoding": {
            "fallback_encoding": fallback_encoding,
            "fallback_file_count": fallback_file_count,
            "fallback_files": sorted(set(fallback_files)),
            "omitted_count": fallback_omitted_count,
        },
        "platformio": {
            "environment_count": platformio_environments,
            "configuration_count": platformio_configurations,
            "partial_scope_count": platformio_partial_scopes,
        },
        "firmware_candidates": {
            "candidate_count": firmware_candidates,
            "extension_counts": dict(sorted(firmware_extensions.items())),
        },
        "github_actions": {
            "workflow_count": workflows,
            "non_sha_action_reference_count": non_sha_references,
            "floating_branch_reference_count": floating_branch_references,
            "finding_count": workflow_findings,
        },
        "hardware_netlist": {
            "scope_count": netlist_scopes,
            "component_count": netlist_components,
            "net_count": netlist_nets,
            "debug_net_candidate_count": debug_net_candidates,
        },
    }


def build_summary(manifest_path: Path, report_root: Path, output_root: Path) -> dict[str, Any]:
    manifest_path = manifest_path.resolve()
    report_root = report_root.resolve()
    output_root = output_root.resolve()
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    cohort = manifest.get("cohort")
    if cohort not in {"independent-holdout", "regression-validation"}:
        raise ValueError(
            "Refusing to summarize a manifest that is not a separate holdout or regression-validation cohort"
        )
    if not report_root.is_relative_to(output_root):
        raise ValueError("Holdout reports must be inside the output root")

    reports_by_scan_id: dict[str, dict[str, Any]] = {}
    all_rule_ids = set(RULE_IDS)
    for repository in manifest.get("repositories", []):
        for scan in repository.get("scans", []):
            scan_id = scan.get("id", "")
            if scan_id in reports_by_scan_id:
                raise ValueError(f"Duplicate scan ID in manifest: {scan_id!r}")
            report = _read_report(report_root, scan_id)
            reports_by_scan_id[scan_id] = report
            all_rule_ids.update(
                str(item.get("rule_id", "unknown"))
                for item in report.get("findings", [])
                if isinstance(item, dict)
            )
    rule_ids = tuple(sorted(all_rule_ids, key=_rule_sort_key))

    reports_relative = report_root.relative_to(output_root).as_posix()
    repositories: list[dict[str, Any]] = []
    rule_counts: Counter[str] = Counter()
    severity_counts: Counter[str] = Counter()
    skipped_by_reason: Counter[str] = Counter()
    totals = Counter()
    hardware_categories: Counter[str] = Counter()
    all_scopes: list[dict[str, Any]] = []

    for repository in manifest.get("repositories", []):
        scopes: list[dict[str, Any]] = []
        repo_rule_counts: Counter[str] = Counter()
        repo_severity_counts: Counter[str] = Counter()
        repo_skips: Counter[str] = Counter()
        repo_totals = Counter()
        repo_hardware_categories: Counter[str] = Counter()
        repo_scopes: list[dict[str, Any]] = []

        for scan in repository.get("scans", []):
            report = reports_by_scan_id[scan.get("id", "")]
            summary = report["summary"]
            coverage = report["coverage"]
            hardware = report.get("hardware_inventory", {})
            findings = report.get("findings", [])
            if not isinstance(findings, list):
                raise ValueError(f"FUSE findings must be a list for {scan.get('id')}")

            scope_rule_counts = Counter(str(item.get("rule_id", "unknown")) for item in findings)
            scope_severity_counts = Counter(
                str(item.get("severity", "unknown")) for item in findings
            )
            scope_skips = Counter(coverage.get("files_skipped_by_reason", {}))
            scope_hardware = Counter(hardware.get("category_counts", {}))
            module_coverage = _module_coverage(report)
            support_status = coverage.get("support", {}).get("status", "unknown")
            files_skipped = int(summary.get("files_skipped", 0))
            scan_status = (
                "partial" if _has_partial_analysis(report) or files_skipped else support_status
            )
            scope = {
                "id": scan["id"],
                "scope": scan["scope"],
                "profile": repository["profile"],
                "files_discovered": int(summary.get("files_discovered", 0)),
                "files_selected": int(summary.get("files_selected", 0)),
                "files_scanned": int(summary.get("files_scanned", 0)),
                "files_skipped": files_skipped,
                "files_skipped_by_reason": dict(sorted(scope_skips.items())),
                "finding_count": len(findings),
                "rule_counts": {rule: scope_rule_counts.get(rule, 0) for rule in rule_ids},
                "severity_counts": {
                    severity: scope_severity_counts.get(severity, 0) for severity in SEVERITIES
                },
                "scan_status": scan_status,
                "support_label": coverage.get("support", {}).get("label", "unknown"),
                "limits_reached": coverage.get("limits_reached", []),
                "hardware_inventory": {
                    "present": bool(hardware.get("present", False)),
                    "file_count": int(hardware.get("file_count", 0)),
                    "category_counts": dict(sorted(scope_hardware.items())),
                    "complete": bool(hardware.get("complete", False)),
                },
                "module_coverage": module_coverage,
                "report_files": {
                    format_name: f"{reports_relative}/{scan['id']}/findings.{extension}"
                    for format_name, extension in (
                        ("json", "json"),
                        ("text", "txt"),
                        ("sarif", "sarif"),
                    )
                },
            }
            scopes.append(scope)
            repo_scopes.append(scope)
            all_scopes.append(scope)
            repo_rule_counts.update(scope_rule_counts)
            repo_severity_counts.update(scope_severity_counts)
            repo_skips.update(scope_skips)
            repo_totals.update(
                {
                    key: int(summary.get(key, 0))
                    for key in (
                        "files_discovered",
                        "files_selected",
                        "files_scanned",
                        "files_skipped",
                    )
                }
            )
            repo_hardware_categories.update(scope_hardware)
            rule_counts.update(scope_rule_counts)
            severity_counts.update(scope_severity_counts)
            skipped_by_reason.update(scope_skips)
            hardware_categories.update(scope_hardware)
            totals.update(
                {
                    key: int(summary.get(key, 0))
                    for key in (
                        "files_discovered",
                        "files_selected",
                        "files_scanned",
                        "files_skipped",
                    )
                }
            )

        repositories.append(
            {
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
                "rule_counts": {rule: repo_rule_counts.get(rule, 0) for rule in rule_ids},
                "severity_counts": {
                    severity: repo_severity_counts.get(severity, 0) for severity in SEVERITIES
                },
                "module_coverage": _sum_module_coverage(repo_scopes),
                "files_skipped_by_reason": dict(sorted(repo_skips.items())),
                "hardware_file_count": sum(repo_hardware_categories.values()),
                "hardware_category_counts": dict(sorted(repo_hardware_categories.items())),
                "scopes": scopes,
            }
        )

    totals_summary = dict(totals)
    totals_summary.update(
        {
            "repository_count": len(repositories),
            "scan_scope_count": sum(repository["scan_count"] for repository in repositories),
            "finding_count": sum(rule_counts.values()),
            "rule_counts": {rule: rule_counts.get(rule, 0) for rule in rule_ids},
            "severity_counts": {
                severity: severity_counts.get(severity, 0) for severity in SEVERITIES
            },
            "files_skipped_by_reason": dict(sorted(skipped_by_reason.items())),
            "hardware_file_count": sum(hardware_categories.values()),
            "hardware_category_counts": dict(sorted(hardware_categories.items())),
            "hardware_inventory_complete": all(
                scope["hardware_inventory"]["complete"]
                for repository in repositories
                for scope in repository["scopes"]
            ),
            "module_coverage": _sum_module_coverage(all_scopes),
        }
    )
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
        "generated_at": datetime.now(timezone.utc)
        .isoformat(timespec="seconds")
        .replace("+00:00", "Z"),
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
    rule_rows = [(rule, int(count)) for rule, count in summary["totals"]["rule_counts"].items()]
    plots = output_root / "plots"
    svg_chart(
        "Raw FUSE signals by repository", repository_rows, plots / "findings-by-repository.svg"
    )
    svg_chart("Raw FUSE signals by rule", rule_rows, plots / "findings-by-rule.svg")
    for module_key, metric_key, filename, title in (
        (
            "firmware_candidates",
            "candidate_count",
            "firmware-candidates-by-repository.svg",
            "Firmware file candidates by repository",
        ),
        (
            "github_actions",
            "floating_branch_reference_count",
            "floating-action-branches-by-repository.svg",
            "Floating GitHub Action branches by repository",
        ),
        (
            "platformio",
            "environment_count",
            "platformio-environments-by-repository.svg",
            "PlatformIO environments recovered by repository",
        ),
        (
            "hardware_netlist",
            "debug_net_candidate_count",
            "netlist-debug-candidates-by-repository.svg",
            "KiCad debug-net candidates by repository",
        ),
    ):
        rows = sorted(
            (
                (item["name"], int(item["module_coverage"][module_key][metric_key]))
                for item in summary["repositories"]
            ),
            key=lambda item: (-item[1], item[0].casefold()),
        )
        svg_chart(title, rows, plots / filename)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Summarize a separate FUSE holdout or regression-validation corpus."
    )
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--report-root", type=Path, default=DEFAULT_REPORT_ROOT)
    parser.add_argument("--output-root", type=Path, default=HOLDOUT_ROOT)
    args = parser.parse_args()
    summary = build_summary(args.manifest, args.report_root, args.output_root)
    output_root = args.output_root.resolve()
    write_json(output_root / "summary.json", summary)
    build_charts(summary, output_root)
    print(
        f"Built {summary['cohort']} summary: "
        f"{summary['totals']['repository_count']} repositories, "
        f"{summary['totals']['scan_scope_count']} scopes, "
        f"{summary['totals']['files_scanned']} files scanned, "
        f"{summary['totals']['finding_count']} raw signals."
    )


if __name__ == "__main__":
    main()
