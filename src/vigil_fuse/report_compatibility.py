"""Distinguish canonical reports from independently versioned branch formats."""

from __future__ import annotations

from typing import Any


def require_canonical_report(report: dict[str, Any]) -> None:
    """Reject incompatible report lineages with colliding version identifiers."""
    version = report.get("schema_version")
    if version not in {"1.14", "1.15"}:
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
        raise ValueError(f"Unsupported or ambiguous FUSE {version} report lineage")
    if version == "1.15" and (
        not isinstance(identity.get("classifications"), list)
        or not isinstance(report.get("project_inventory"), dict)
    ):
        raise ValueError("Invalid FUSE 1.15 identity or inventory")
