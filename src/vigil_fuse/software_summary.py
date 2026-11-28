from __future__ import annotations

from collections import Counter
from dataclasses import asdict

from .model import ScanResult


def software_summary(result: ScanResult) -> dict[str, object]:
    statuses = {item.name: item.status for item in result.analyzers}

    def combined(*names: str) -> str:
        values = [statuses.get(name, "skipped") for name in names]
        if any(value in {"partial", "failed", "timeout", "incompatible"} for value in values):
            return "partial"
        return "completed" if "completed" in values else "skipped"

    lanes = {
        "native_python": combined(
            "native-rule:FUSE-SW001",
            "native-rule:FUSE-SW003",
            "native-rule:FUSE-SW004",
        ),
        "container_config": combined("native-rule:FUSE-SW002"),
        "native_secrets_all_domains": combined("native-rule:FUSE001", "native-rule:FUSE002"),
        "github_actions": statuses.get("github-actions-static", "skipped"),
        "dependency_inventory": result.package_inventory_status
        if result.package_inventory_status != "not-requested"
        else statuses.get("syft", "skipped"),
        "advisory_matching": statuses.get("osv-scanner", "skipped"),
        "git_history_secrets": statuses.get("gitleaks-history", "skipped"),
        "trivy_secrets": statuses.get("trivy-secrets", "skipped"),
        "semgrep": statuses.get("semgrep", "skipped"),
        "codeql": statuses.get("codeql", "skipped"),
        "iac": statuses.get("trivy-config", "skipped"),
        "container_image": statuses.get("trivy-image", "skipped"),
    }
    software_findings = [
        finding
        for finding in result.findings
        if finding.rule_id.startswith("FUSE-SW")
        or finding.analyzer in {"semgrep", "codeql", "trivy"}
    ]
    counts = Counter(finding.severity for finding in software_findings)
    return {
        "lanes": lanes,
        "finding_count": len(software_findings),
        "severity_counts": {
            level: counts.get(level, 0)
            for level in ("critical", "high", "medium", "low", "info", "unknown")
        },
        "scope": "Software-specific native and optional analyzer observations; shared secret and workflow findings are reported separately.",
        "dependency_inventory": {
            "status": result.package_inventory_status,
            "component_count": len(result.software_components),
            "components": [asdict(item) for item in result.software_components],
            "advisory_match_count": sum(
                finding.category == "dependency-vulnerability" for finding in result.findings
            ),
            "component_presence_means": "recorded in the selected CycloneDX, SPDX 2.x JSON, or Trivy image inventory",
            "advisory_match_means": "package and version matched an advisory; exploitability is not established",
            "reachability": "unknown",
        },
        "reachability": "unknown",
    }
