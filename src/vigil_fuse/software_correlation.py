from __future__ import annotations

import hashlib
from collections import defaultdict
from dataclasses import replace

from .model import Finding


def _secret_kind(finding: Finding) -> str | None:
    if finding.rule_id == "FUSE001":
        return "credential"
    if finding.rule_id == "FUSE002":
        return "private-key"
    if finding.analyzer == "trivy-secrets" and finding.rule_id.startswith("TRIVY-SECRET:"):
        rule = finding.rule_id.removeprefix("TRIVY-SECRET:").casefold()
        if "private" in rule and "key" in rule:
            return "private-key"
        if any(token in rule for token in ("password", "secret", "token", "api-key", "access-key")):
            return "credential"
        return None
    if finding.analyzer != "gitleaks-history" or not finding.rule_id.startswith("GITLEAKS:"):
        return None
    rule = finding.rule_id.removeprefix("GITLEAKS:").casefold()
    if "private" in rule and "key" in rule:
        return "private-key"
    if any(token in rule for token in ("password", "secret", "token", "api-key", "access-key")):
        return "credential"
    return None


def correlate_findings(findings: tuple[Finding, ...]) -> tuple[Finding, ...]:
    """Add review-only groups for tightly matching cross-engine observations."""
    groups: dict[tuple[str, ...], list[int]] = defaultdict(list)
    for index, finding in enumerate(findings):
        key: tuple[str, ...]
        if finding.category == "software-source" and len(finding.cwe) == 1:
            if finding.start_line is None:
                continue
            key = (
                "source",
                finding.file.replace("\\", "/"),
                str(finding.start_line),
                str(finding.end_line or finding.start_line),
                finding.cwe[0],
            )
            groups[key].append(index)
        elif (
            finding.category in {"secrets", "historical-secret-exposure"}
            and finding.analyzer in {"fuse-native", "gitleaks-history", "trivy-secrets"}
            and finding.start_line is not None
        ):
            secret_kind = _secret_kind(finding)
            if secret_kind is not None:
                key = (
                    "secret-location",
                    secret_kind,
                    finding.file.replace("\\", "/"),
                    str(finding.start_line),
                    str(finding.end_line or finding.start_line),
                )
                groups[key].append(index)
        elif finding.category == "dependency-vulnerability" and finding.component is not None:
            advisory = finding.engine_rule_id or finding.rule_id
            advisory = advisory.removeprefix("OSV-").removeprefix("TRIVY-").casefold()
            key = (
                "dependency-advisory",
                finding.component.ecosystem.casefold(),
                finding.component.name.casefold(),
                finding.component.version.casefold(),
                advisory,
            )
            groups[key].append(index)
    replacements: dict[int, str] = {}
    for key, indices in groups.items():
        if len({findings[index].analyzer for index in indices}) < 2:
            continue
        group = hashlib.sha256("\0".join(key).encode("utf-8")).hexdigest()
        replacements.update({index: group for index in indices})
    return tuple(
        replace(finding, correlation_group=replacements.get(index))
        if finding.correlation_group != replacements.get(index)
        else finding
        for index, finding in enumerate(findings)
    )
