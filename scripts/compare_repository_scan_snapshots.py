from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path
from typing import Any


def _read_object(path: Path) -> dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"Expected a JSON object in {path}")
    return data


def _scan_specs(manifest: dict[str, Any]) -> list[tuple[str, str]]:
    repositories = manifest.get("repositories")
    if not isinstance(repositories, list):
        raise ValueError("Manifest must contain a repositories list")

    specs: list[tuple[str, str]] = []
    seen_scan_ids: set[str] = set()
    for repository in repositories:
        if not isinstance(repository, dict):
            raise ValueError("Each repository manifest entry must be an object")
        repository_id = repository.get("id")
        scans = repository.get("scans")
        if not isinstance(repository_id, str) or not repository_id:
            raise ValueError("Each repository must have a non-empty ID")
        if not isinstance(scans, list):
            raise ValueError(f"Repository {repository_id!r} must contain a scans list")
        for scan in scans:
            if not isinstance(scan, dict):
                raise ValueError(f"Repository {repository_id!r} has an invalid scan entry")
            scan_id = scan.get("id")
            if (
                not isinstance(scan_id, str)
                or not scan_id
                or Path(scan_id).is_absolute()
                or ".." in Path(scan_id).parts
            ):
                raise ValueError(f"Repository {repository_id!r} has an invalid scan ID")
            if scan_id in seen_scan_ids:
                raise ValueError(f"Duplicate scan ID in manifest: {scan_id!r}")
            seen_scan_ids.add(scan_id)
            specs.append((repository_id, scan_id))
    return specs


def _read_findings(report_root: Path, scan_id: str) -> tuple[str, dict[str, dict[str, Any]]]:
    root = report_root.resolve()
    report_path = (root / scan_id / "findings.json").resolve()
    if not report_path.is_relative_to(root):
        raise ValueError(f"Scan report path escapes its report root: {scan_id!r}")
    report = _read_object(report_path)
    schema_version = report.get("schema_version")
    if not isinstance(schema_version, str) or not schema_version:
        raise ValueError(f"Report is missing a schema version: {report_path}")
    findings = report.get("findings")
    if not isinstance(findings, list):
        raise ValueError(f"Report must contain a findings list: {report_path}")

    indexed: dict[str, dict[str, Any]] = {}
    for finding in findings:
        if not isinstance(finding, dict):
            raise ValueError(f"Report has a non-object finding: {report_path}")
        finding_id = finding.get("id")
        if not isinstance(finding_id, str) or not finding_id:
            raise ValueError(f"Report has a finding without a stable ID: {report_path}")
        if finding_id in indexed:
            raise ValueError(f"Report has duplicate finding ID {finding_id!r}: {report_path}")
        indexed[finding_id] = finding
    return schema_version, indexed


def _rule_id(finding: dict[str, Any]) -> str:
    value = finding.get("rule_id")
    return value if isinstance(value, str) and value else "unknown"


def _changed_fields(baseline: dict[str, Any], candidate: dict[str, Any]) -> list[str]:
    missing = object()
    return sorted(
        key
        for key in baseline.keys() | candidate.keys()
        if key != "id" and baseline.get(key, missing) != candidate.get(key, missing)
    )


def _provenance(manifest: dict[str, Any]) -> dict[str, Any]:
    fuse = manifest.get("fuse")
    if not isinstance(fuse, dict):
        return {
            "version": None,
            "commit": None,
            "source_tree_sha256": None,
            "source_tree_dirty": None,
        }
    return {
        "version": fuse.get("version"),
        "commit": fuse.get("commit"),
        "source_tree_sha256": fuse.get("source_tree_sha256"),
        "source_tree_dirty": fuse.get("source_tree_dirty"),
    }


def compare_snapshots(
    baseline_manifest_path: Path,
    baseline_report_root: Path,
    candidate_manifest_path: Path,
    candidate_report_root: Path,
) -> dict[str, Any]:
    baseline_manifest = _read_object(baseline_manifest_path)
    candidate_manifest = _read_object(candidate_manifest_path)
    baseline_repositories = baseline_manifest.get("repositories")
    candidate_repositories = candidate_manifest.get("repositories")
    if baseline_repositories != candidate_repositories:
        raise ValueError("Repository targets or scan scopes differ between manifests")

    baseline_specs = _scan_specs(baseline_manifest)
    candidate_specs = _scan_specs(candidate_manifest)
    if baseline_specs != candidate_specs:
        raise ValueError("Repository scan IDs differ between manifests")

    total_baseline = 0
    total_candidate = 0
    total_retained = 0
    total_added = 0
    total_removed = 0
    total_changed = 0
    total_changed_fields: Counter[str] = Counter()
    scans: list[dict[str, Any]] = []

    for repository_id, scan_id in baseline_specs:
        baseline_schema, baseline = _read_findings(baseline_report_root, scan_id)
        candidate_schema, candidate = _read_findings(candidate_report_root, scan_id)
        if baseline_schema != candidate_schema:
            raise ValueError(
                f"Report schemas differ for scan {scan_id!r}: "
                f"{baseline_schema!r} versus {candidate_schema!r}"
            )
        baseline_ids = baseline.keys()
        candidate_ids = candidate.keys()
        added_ids = candidate_ids - baseline_ids
        removed_ids = baseline_ids - candidate_ids
        common_ids = baseline_ids & candidate_ids

        rule_stats: dict[str, dict[str, Any]] = {}

        def rule_bucket(rule: str) -> dict[str, Any]:
            if rule not in rule_stats:
                rule_stats[rule] = {
                    "baseline_findings": 0,
                    "candidate_findings": 0,
                    "retained": 0,
                    "added": 0,
                    "removed": 0,
                    "changed": 0,
                    "changed_fields": Counter(),
                }
            return rule_stats[rule]

        for finding in baseline.values():
            rule_bucket(_rule_id(finding))["baseline_findings"] += 1
        for finding in candidate.values():
            rule_bucket(_rule_id(finding))["candidate_findings"] += 1
        for finding_id in added_ids:
            rule_bucket(_rule_id(candidate[finding_id]))["added"] += 1
        for finding_id in removed_ids:
            rule_bucket(_rule_id(baseline[finding_id]))["removed"] += 1

        scan_changed_fields: Counter[str] = Counter()
        scan_changed = 0
        for finding_id in common_ids:
            old = baseline[finding_id]
            new = candidate[finding_id]
            rule = _rule_id(old)
            bucket = rule_bucket(rule)
            bucket["retained"] += 1
            changes = _changed_fields(old, new)
            if changes:
                scan_changed += 1
                bucket["changed"] += 1
                for field in changes:
                    scan_changed_fields[field] += 1
                    bucket["changed_fields"][field] += 1

        baseline_count = len(baseline)
        candidate_count = len(candidate)
        retained_count = len(common_ids)
        total_baseline += baseline_count
        total_candidate += candidate_count
        total_retained += retained_count
        total_added += len(added_ids)
        total_removed += len(removed_ids)
        total_changed += scan_changed
        total_changed_fields.update(scan_changed_fields)

        scans.append(
            {
                "repository_id": repository_id,
                "scan_id": scan_id,
                "schema_version": baseline_schema,
                "baseline_findings": baseline_count,
                "candidate_findings": candidate_count,
                "retained": retained_count,
                "added": len(added_ids),
                "removed": len(removed_ids),
                "changed": scan_changed,
                "changed_fields": dict(sorted(scan_changed_fields.items())),
                "rules": {
                    rule: {
                        **{key: value for key, value in stats.items() if key != "changed_fields"},
                        "changed_fields": dict(sorted(stats["changed_fields"].items())),
                    }
                    for rule, stats in sorted(rule_stats.items())
                },
            }
        )

    return {
        "schema_version": "1",
        "comparison_type": "stored-report-artifact-diff",
        "baseline_cohort": baseline_manifest.get("cohort"),
        "candidate_cohort": candidate_manifest.get("cohort"),
        "same_repository_targets_and_scopes": True,
        "baseline_fuse": _provenance(baseline_manifest),
        "candidate_fuse": _provenance(candidate_manifest),
        "totals": {
            "baseline_findings": total_baseline,
            "candidate_findings": total_candidate,
            "retained": total_retained,
            "added": total_added,
            "removed": total_removed,
            "changed": total_changed,
            "changed_fields": dict(sorted(total_changed_fields.items())),
        },
        "scans": scans,
        "interpretation": (
            "Compares saved finding objects by stable finding ID. It does not rerun FUSE, "
            "adjudicate findings, or measure detection accuracy. Field names and counts are "
            "reported without copying finding evidence or field values."
        ),
    }


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Compare stored FUSE scan reports for identical pinned repository scopes."
    )
    parser.add_argument("--baseline-manifest", type=Path, required=True)
    parser.add_argument("--baseline-report-root", type=Path, required=True)
    parser.add_argument("--candidate-manifest", type=Path, required=True)
    parser.add_argument("--candidate-report-root", type=Path, required=True)
    parser.add_argument("--output", type=Path, help="write JSON to this path instead of stdout")
    args = parser.parse_args()

    try:
        comparison = compare_snapshots(
            args.baseline_manifest,
            args.baseline_report_root,
            args.candidate_manifest,
            args.candidate_report_root,
        )
    except (OSError, json.JSONDecodeError, ValueError) as error:
        parser.error(str(error))

    serialized = json.dumps(comparison, indent=2, ensure_ascii=False) + "\n"
    if args.output:
        args.output.write_text(serialized, encoding="utf-8")
    else:
        print(serialized, end="")


if __name__ == "__main__":
    main()
