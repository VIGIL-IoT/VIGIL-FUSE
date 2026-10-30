#!/usr/bin/env python3
"""Build a redacted report bundle and static site data for a FUSE regression run."""

from __future__ import annotations

import argparse
import csv
import json
from collections import Counter
from pathlib import Path
from urllib.parse import quote


ROOT = Path(__file__).resolve().parents[1]


def read_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def source_url(repository_url: str, commit: str, file_path: str, line: int) -> str:
    encoded_path = quote(file_path, safe="/")
    return f"{repository_url.rstrip('/')}/blob/{commit}/{encoded_path}#L{line}"


def read_triage_counts(path: Path | None) -> dict[str, int]:
    if path is None or not path.is_file():
        return {}
    counts: Counter[str] = Counter()
    with path.open(newline="", encoding="utf-8") as stream:
        for row in csv.DictReader(stream):
            disposition = row.get("disposition")
            if disposition:
                counts[disposition] += 1
    return dict(sorted(counts.items()))


def build_data(summary_path: Path, baseline_triage_path: Path | None = None) -> dict:
    summary = read_json(summary_path)
    summary_root = summary_path.parent
    findings: list[dict] = []
    repositories: list[dict] = []

    for repository in summary["repositories"]:
        scopes = []
        for scope in repository.get("scopes", []):
            scopes.append(
                {
                    "id": scope["id"],
                    "profile": scope.get("profile", "unknown"),
                    "status": scope.get("scan_status", "unknown"),
                    "support": scope.get("support_label", "unknown"),
                    "filesDiscovered": scope.get("files_discovered", 0),
                    "filesSelected": scope.get("files_selected", 0),
                    "filesScanned": scope.get("files_scanned", 0),
                    "filesSkipped": scope.get("files_skipped", 0),
                    "filesSkippedByReason": scope.get("files_skipped_by_reason", {}),
                    "limitsReached": scope.get("limits_reached", []),
                    "reportFiles": scope.get("report_files", {}),
                }
            )
            report_ref = scope.get("report_files", {}).get("json")
            if not report_ref:
                continue
            report = read_json(summary_root / report_ref)
            for item in report.get("findings", []):
                location = item.get("location") or {}
                file_path = location.get("file")
                line = location.get("start_line")
                if not file_path or not isinstance(line, int):
                    continue
                findings.append(
                    {
                        "id": item.get("id", ""),
                        "ruleId": item.get("rule_id", "unknown"),
                        "title": item.get("title", "Untitled finding"),
                        "severity": item.get("severity", "unknown"),
                        "confidence": item.get("confidence", "unknown"),
                        "category": item.get("category", "unknown"),
                        "repositoryId": repository["id"],
                        "repository": repository["name"],
                        "scopeId": scope["id"],
                        "file": file_path,
                        "line": line,
                        "sourceUrl": source_url(
                            repository["url"], repository["commit"], file_path, line
                        ),
                    }
                )

        scope_statuses = [scope["status"] for scope in scopes]
        status = "partial" if "partial" in scope_statuses else "completed"
        module = repository.get("module_coverage", {})
        repositories.append(
            {
                "id": repository["id"],
                "name": repository["name"],
                "url": repository["url"],
                "commit": repository["commit"],
                "profile": repository.get("profile", "unknown"),
                "scanStatus": status,
                "scanCount": repository.get("scan_count", len(scopes)),
                "filesDiscovered": repository.get("files_discovered", 0),
                "filesSelected": repository.get("files_selected", 0),
                "filesScanned": repository.get("files_scanned", 0),
                "filesSkipped": repository.get("files_skipped", 0),
                "filesSkippedByReason": repository.get("files_skipped_by_reason", {}),
                "findingCount": repository.get("finding_count", 0),
                "severityCounts": repository.get("severity_counts", {}),
                "ruleCounts": repository.get("rule_counts", {}),
                "moduleCoverage": module,
                "scopes": scopes,
            }
        )

    totals = summary["totals"]
    if len(findings) != totals.get("finding_count"):
        raise ValueError(
            f"Loaded {len(findings)} finding records, expected "
            f"{totals.get('finding_count')} from summary totals"
        )

    rule_counts = totals.get("rule_counts", {})
    severity_counts = totals.get("severity_counts", {})
    confidence_counts = dict(Counter(item["confidence"] for item in findings))
    current_triage = read_triage_counts(summary_root / "manual-triage.csv")
    baseline_triage = read_triage_counts(baseline_triage_path)
    return {
        "meta": {
            "title": "FUSE repository validation",
            "scanDate": summary.get("scan_date"),
            "cohort": summary.get("cohort"),
            "generatedAt": summary.get("generated_at"),
            "interpretation": summary.get("interpretation", ""),
            "selectionProtocol": summary.get("selection_protocol", {}),
            "fuse": summary.get("fuse", {}),
        },
        "totals": totals,
        "ruleCounts": rule_counts,
        "severityCounts": severity_counts,
        "confidenceCounts": confidence_counts,
        "triageSummary": {
            "signalCount": sum(current_triage.values()),
            "dispositions": current_triage,
        },
        "noiseReduction": {
            "baselineSignalCount": sum(baseline_triage.values()),
            "filteredPlaceholderCount": baseline_triage.get("filtered-placeholder", 0),
        },
        "repositories": repositories,
        "findings": findings,
    }


def write_csv(path: Path, findings: list[dict]) -> None:
    fields = [
        "repository",
        "scope_id",
        "rule_id",
        "severity",
        "confidence",
        "title",
        "file",
        "line",
        "source_url",
    ]
    with path.open("w", encoding="utf-8-sig", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields)
        writer.writeheader()
        for item in findings:
            writer.writerow(
                {
                    "repository": item["repository"],
                    "scope_id": item["scopeId"],
                    "rule_id": item["ruleId"],
                    "severity": item["severity"],
                    "confidence": item["confidence"],
                    "title": item["title"],
                    "file": item["file"],
                    "line": item["line"],
                    "source_url": item["sourceUrl"],
                }
            )


def format_number(value: int) -> str:
    return f"{value:,}"


def format_count(value: int, noun: str) -> str:
    return f"{format_number(value)} {noun}{'' if value == 1 else 's'}"


def render_readme(data: dict, site_path: str = "site/regression") -> str:
    totals = data["totals"]
    modules = totals.get("module_coverage", {})
    severity = data["severityCounts"]
    rules = data["ruleCounts"]
    fuse = data["meta"].get("fuse", {})
    protocol = data["meta"].get("selectionProtocol", {})
    firmware_extensions = modules.get("firmware_candidates", {}).get("extension_counts", {})
    source_decoding = modules.get("source_decoding", {})
    actions = modules.get("github_actions", {})
    platformio = modules.get("platformio", {})
    partial_scopes = sum(
        scope.get("status") == "partial"
        for repository in data["repositories"]
        for scope in repository.get("scopes", [])
    )
    noise_reduction = data.get("noiseReduction", {})
    triage = data.get("triageSummary", {})
    extension_text = (
        ", ".join(f"{key} {value}" for key, value in firmware_extensions.items()) or "none"
    )
    fallback_files = source_decoding.get("fallback_files", [])
    fallback_text = ", ".join(f"`{path}`" for path in fallback_files) or "none"
    if source_decoding.get("omitted_count", 0):
        fallback_text += f" and {source_decoding['omitted_count']} omitted"
    cohort_description = (
        "This reruns the same pinned repository corpus after local FUSE changes. The corpus informed rule refinements, so this is regression validation. It is not an independent or blind holdout, representative sample, or accuracy benchmark."
        if data["meta"].get("cohort") == "regression-validation"
        else "This uses a separately selected pinned repository corpus. It is a qualitative holdout, not a representative sample or accuracy benchmark."
    )
    report_title = (
        "FUSE regression validation"
        if data["meta"].get("cohort") == "regression-validation"
        else "FUSE independent validation"
    )
    is_regression = data["meta"].get("cohort") == "regression-validation"
    retained_credential_signals = format_count(rules.get("FUSE001", 0), "FUSE001 signal")
    total_scopes = totals.get("scan_scope_count", 0)
    partial_scope_text = (
        f"{format_number(partial_scopes)} of {format_number(total_scopes)} "
        f"{'scope' if total_scopes == 1 else 'scopes'} "
        f"{'is' if partial_scopes == 1 else 'are'} marked partial."
    )
    if noise_reduction.get("baselineSignalCount", 0):
        credential_triage_note = f"FUSE001 retained {format_count(rules.get('FUSE001', 0), 'credential-like signal')} after excluding known tutorial placeholder patterns from the earlier regression corpus. Remaining matches are not automatically valid or deployed credentials. The published view omits matched evidence values."
        noise_note = f"The earlier regression ledger contains {format_count(noise_reduction.get('filteredPlaceholderCount', 0), 'credential-like match')} now excluded as narrow tutorial placeholders. The current run retains {retained_credential_signals} for review. Placeholder filtering is fixture-backed and does not suppress ordinary hard-coded values."
    else:
        credential_triage_note = f"FUSE001 retained {format_count(rules.get('FUSE001', 0), 'credential-like signal')}. This independent cohort has no placeholder-baseline comparison. Remaining matches are not automatically valid or deployed credentials. The published view omits matched evidence values."
        noise_note = f"No placeholder-baseline comparison is attached to this cohort. The current run retains {retained_credential_signals} for review. Placeholder filtering remains limited to fixture-backed patterns and does not suppress ordinary hard-coded values."
    if platformio.get("partial_scope_count", 0):
        platformio_note = f"PlatformIO found {format_number(platformio.get('environment_count', 0))} environments across {format_number(platformio.get('configuration_count', 0))} configuration files. {format_count(platformio.get('partial_scope_count', 0), 'scope')} has partial context because optional include files are absent from the pinned checkout."
    else:
        platformio_note = f"PlatformIO found {format_number(platformio.get('environment_count', 0))} environments across {format_number(platformio.get('configuration_count', 0))} configuration files. No partial PlatformIO context was reported."
    overlap_note = (
        "Counts are raw per scanned scope. The IoTGoat scope includes OpenWrt source also present in the OpenWrt snapshot, so some source lines overlap across repositories."
        if is_regression
        else "Counts are raw per repository snapshot and are not deduplicated across repositories."
    )
    lines = [
        f"# {report_title}",
        "",
        f"Scan date: {data['meta'].get('scanDate', 'unknown')}",
        "",
        "## Purpose and limits",
        "",
        str(protocol.get("purpose", "")),
        "",
        f"{cohort_description} Every row is a static signal for review, not a confirmed vulnerability.",
        "",
        f"FUSE version `{fuse.get('version', 'unknown')}` at commit `{str(fuse.get('commit', 'unknown'))[:12]}`. The working source tree was {'dirty' if fuse.get('source_tree_dirty') else 'clean'}. Its recorded source hash is `{fuse.get('source_tree_sha256', 'unavailable')}`.",
        "",
        "## Run totals",
        "",
        "| Measure | Result |",
        "| --- | ---: |",
        f"| Repositories | {format_number(totals.get('repository_count', 0))} |",
        f"| Scan scopes | {format_number(totals.get('scan_scope_count', 0))} |",
        f"| Files discovered | {format_number(totals.get('files_discovered', 0))} |",
        f"| Files selected | {format_number(totals.get('files_selected', 0))} |",
        f"| Files scanned | {format_number(totals.get('files_scanned', 0))} |",
        f"| Files skipped | {format_number(totals.get('files_skipped', 0))} |",
        f"| Raw finding signals | {format_number(totals.get('finding_count', 0))} |",
        "",
        "Severity and confidence are separate fields. Severity counts describe the possible impact suggested by a rule. Confidence describes the strength of the static match. Neither proves that the code is reachable or deployed.",
        "",
        f"Severity: {format_number(severity.get('high', 0))} high, {format_number(severity.get('medium', 0))} medium, {format_number(severity.get('info', 0))} informational. Critical: {format_number(severity.get('critical', 0))}; low: {format_number(severity.get('low', 0))}.",
        "",
        "### Signals by rule",
        "",
        "| Rule | Count |",
        "| --- | ---: |",
    ]
    for rule, count in rules.items():
        lines.append(f"| `{rule}` | {format_number(count)} |")
    lines.extend(
        [
            "",
            "## Repository snapshots",
            "",
            overlap_note,
            "",
            "| Repository | Commit | Files scanned | Signals | High | Medium | Info | Status |",
            "| --- | --- | ---: | ---: | ---: | ---: | ---: | --- |",
        ]
    )
    for repo in data["repositories"]:
        sev = repo.get("severityCounts", {})
        lines.append(
            f"| [{repo['name']}]({repo['url']}/tree/{repo['commit']}) | `{repo['commit'][:12]}` | "
            f"{format_number(repo['filesScanned'])} | {format_number(repo['findingCount'])} | "
            f"{format_number(sev.get('high', 0))} | {format_number(sev.get('medium', 0))} | "
            f"{format_number(sev.get('info', 0))} | {repo['scanStatus']} |"
        )

    lines.extend(
        [
            "",
            "## Report design notes",
            "",
            "Screen question: what did FUSE surface in the pinned corpus, and how much of the selected input was actually covered? The main finding is the concentration of signals in credential-like example settings and explicit TLS bypass indicators.",
            "",
            "The view uses the framed-sheet app style, seed `2054999557`, while keeping FUSE's red data accent and Schibsted type. Its signature element is a pinned-source ledger: each repository is tied to the exact commit, and each finding links to its file and line in that snapshot. The report-style time chart was replaced with repository and rule distributions because this run has no time-series data.",
            "",
            "## Plots",
            "",
            "![Raw findings by repository](plots/findings-by-repository.svg)",
            "",
            "![Raw findings by rule](plots/findings-by-rule.svg)",
            "",
            "![Firmware filename candidates by repository](plots/firmware-candidates-by-repository.svg)",
            "",
            "![Floating GitHub Actions branch references by repository](plots/floating-action-branches-by-repository.svg)",
            "",
            "![PlatformIO environments by repository](plots/platformio-environments-by-repository.svg)",
            "",
            "![Netlist debug-name candidates by repository](plots/netlist-debug-candidates-by-repository.svg)",
            "",
            "## Additional inventory",
            "",
            f"- Firmware filename candidates: {format_number(modules.get('firmware_candidates', {}).get('candidate_count', 0))}. Extensions: {extension_text}. The scanner inventoried names and sizes only; it did not inspect firmware bytes.",
            f"- Hardware filename matches: {format_number(totals.get('hardware_file_count', 0))}. This is file inventory only. No schematic or PCB security analysis was performed, and no netlist components or nets were parsed.",
            f"- GitHub Actions: {format_number(actions.get('workflow_count', 0))} workflow files and {format_number(actions.get('non_sha_action_reference_count', 0))} non-SHA references inventoried, including {format_number(actions.get('floating_branch_reference_count', 0))} floating branch references. Non-SHA references include version tags and are not all unsafe.",
            f"- {platformio_note}",
            "",
            "## Triage notes",
            "",
            credential_triage_note,
            "",
            f"FUSE002 produced {format_count(rules.get('FUSE002', 0), 'private-key marker signal')}. A marker match does not establish that key material is active, shipped, or trusted. Review intended use and packaging before changing rule behavior.",
            "",
            f"The current run includes {format_count(rules.get('FUSE003', 0), 'TLS verification-bypass signal')}. Review whether each matched call is reachable in a shipped configuration before interpreting severity as deployment risk.",
            "",
            "## Noise reduction and triage",
            "",
            noise_note,
            "",
            f"Manual source-context triage covers {format_number(triage.get('signalCount', 0))} current signals. See [`manual-triage.md`](manual-triage.md) and [`manual-triage.csv`](manual-triage.csv). The ledger excludes matched evidence values.",
            "",
            "## Coverage caveats",
            "",
            f"- {partial_scope_text} {format_count(totals.get('files_skipped', 0), 'selected file')} were skipped.",
            f"- {format_number(source_decoding.get('fallback_file_count', 0))} legacy text files used `{source_decoding.get('fallback_encoding', 'iso-8859-1')}` fallback decoding: {fallback_text}. This is disclosed coverage metadata.",
            f"- {platformio_note}",
            f"- GitHub Actions inventory found {format_number(actions.get('workflow_count', 0))} workflow files and {format_number(actions.get('non_sha_action_reference_count', 0))} non-SHA references. Non-SHA references include version tags and are not all unsafe.",
            "- No build resolution, runtime or device validation, dependency advisory analysis, firmware byte inspection, or hardware design security review was performed.",
            "- A clean scan means no enabled rule matched selected inputs. It does not prove that a project is secure or fully covered.",
            "",
            "## Local artifacts",
            "",
            "- `summary.json`: aggregate counts, coverage and provenance.",
            "- `reports/<scope>/findings.json`: full versioned per-scope report with evidence.",
            "- `reports/<scope>/findings.txt`: readable per-scope report.",
            "- `reports/<scope>/findings.sarif`: SARIF per-scope report.",
            "- `triage.csv`: source-linked finding index with evidence values excluded.",
            "- `manifest.json`: pinned repository inputs and selection protocol.",
            "",
            f"The static site view is in `{site_path}/`. The main site links to this report. No package release, deployment, or push is part of this local proof of concept.",
            "",
        ]
    )
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--summary", type=Path, required=True)
    parser.add_argument("--site-output", type=Path, default=Path("site/regression"))
    parser.add_argument("--baseline-triage", type=Path)
    args = parser.parse_args()

    summary_path = args.summary.resolve()
    site_output = args.site_output.resolve()
    report_output = summary_path.parent
    baseline_triage = args.baseline_triage
    cohort = read_json(summary_path).get("cohort")
    if baseline_triage is None and cohort == "regression-validation":
        candidate = summary_path.parent.parent / "regression-2026-10-28" / "manual-triage.csv"
        baseline_triage = candidate if candidate.is_file() else None
    data = build_data(summary_path, baseline_triage)
    site_output.mkdir(parents=True, exist_ok=True)
    (site_output / "data.json").write_text(
        json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    write_csv(report_output / "triage.csv", data["findings"])
    write_csv(site_output / "triage.csv", data["findings"])
    for filename in ("manual-triage.csv", "manual-triage.md"):
        source = report_output / filename
        if source.is_file():
            (site_output / filename).write_bytes(source.read_bytes())
    try:
        site_label = site_output.relative_to(ROOT).as_posix()
    except ValueError:
        site_label = site_output.as_posix()
    (report_output / "README.md").write_text(render_readme(data, site_label), encoding="utf-8")
    print(
        f"Built local validation bundle: {len(data['repositories'])} repositories, "
        f"{len(data['findings'])} signals, {site_output}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
