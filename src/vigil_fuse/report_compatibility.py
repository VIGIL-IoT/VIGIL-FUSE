"""Distinguish canonical reports from independently versioned branch formats."""

from __future__ import annotations

from typing import Any


def require_canonical_114(report: dict[str, Any]) -> None:
    """Reject the independently developed, incompatible software 1.14 format."""
    if report.get("schema_version") != "1.14":
        return
    identity = report.get("project_identity")
    generated = report.get("generated_by")
    if (
        not isinstance(identity, dict)
        or not isinstance(identity.get("domains"), dict)
        or not isinstance(identity.get("primary_type"), str)
        or not isinstance(generated, dict)
        or generated.get("name") != "FUSE"
        or "software_security" in report
    ):
        raise ValueError("Unsupported or ambiguous FUSE 1.14 report lineage")
