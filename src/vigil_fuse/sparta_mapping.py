from __future__ import annotations

import json

from .model import Finding
from .hardware_advisories import load_advisory_catalog


def sparta_mapping_document(findings: tuple[Finding, ...]) -> str | None:
    """Serialize only advisory mappings backed by the checked-in source record."""
    catalog = load_advisory_catalog()
    by_cve = {cve: advisory for advisory in catalog for cve in advisory.cve_ids}
    mappings: list[dict[str, object]] = []
    for finding in findings:
        if finding.rule_id != "FUSE-HW-ADV-001":
            continue
        advisory = next((by_cve[cve] for cve in finding.references if cve in by_cve), None)
        if advisory is None:
            advisory = next(
                (
                    item
                    for item in catalog
                    if any(source in finding.references for source in item.sources)
                ),
                None,
            )
        if advisory is None:
            continue
        for mapping in advisory.sparta_mappings:
            mappings.append(
                {
                    "finding_id": finding.id,
                    "finding_rule": finding.rule_id,
                    "finding_title": finding.title,
                    "sparta_id": mapping["id"],
                    "sparta_title": mapping["title"],
                    "mapping_type": "analyst-assessed threat technique association",
                    "assessment": "mapped for engineering review; not a compliance assessment",
                    "mapping_basis": mapping["mapping_basis"],
                    "evidence": finding.evidence,
                    "unknowns": [
                        "Exact chip revision and configuration applicability",
                        "Physical attack opportunity on the deployed product",
                        "Exploitability and mission-specific consequence",
                    ],
                    "sources": [*advisory.sources, mapping["source"]],
                }
            )
    if not mappings:
        return None
    document = {
        "schema_version": "1",
        "report_type": "SPARTA security mapping and assessment",
        "compliance_certification": False,
        "mappings": sorted(
            mappings, key=lambda item: (str(item["sparta_id"]), str(item["finding_id"]))
        ),
    }
    return json.dumps(document, indent=2, ensure_ascii=False) + "\n"
