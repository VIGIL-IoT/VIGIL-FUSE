from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import re
from importlib.resources import files
from typing import Literal

from .model import Finding, HardwareBOMComponent, HardwareBOMInventory
from .text_safety import safe_report_text

MAX_ADVISORY_CATALOG_BYTES = 1024 * 1024
AdvisoryState = Literal[
    "MATCH_CONFIRMED",
    "FAMILY_CANDIDATE",
    "REVISION_UNKNOWN",
    "CONDITION_UNKNOWN",
    "NOT_AFFECTED_WITH_EVIDENCE",
    "UNSUPPORTED",
]


@dataclass(frozen=True)
class HardwareAdvisory:
    advisory_id: str
    title: str
    manufacturer: str
    manufacturer_aliases: tuple[str, ...]
    affected_products: tuple[str, ...]
    part_number_aliases: tuple[str, ...]
    affected_revisions: tuple[str, ...]
    unaffected_revisions: tuple[str, ...]
    component_type: str
    cve_ids: tuple[str, ...]
    cwe_ids: tuple[str, ...]
    sparta_mappings: tuple[dict[str, str], ...]
    severity: str
    confidence: str
    description: str
    conditions: tuple[str, ...]
    mitigations: tuple[str, ...]
    sources: tuple[str, ...]
    last_verified: str


@dataclass(frozen=True)
class AdvisoryMatch:
    advisory: HardwareAdvisory
    component: HardwareBOMComponent
    status: AdvisoryState
    product_identification: str


_PART_NORMALIZE = re.compile(r"[^a-z0-9]+")
_REVISION = re.compile(r"^(?:chip\s*)?(?:rev(?:ision)?\s*)?v?(\d+(?:\.\d+)+)$", re.IGNORECASE)
_CVE = re.compile(r"^CVE-\d{4}-\d{4,}$")


def _normalize(value: str) -> str:
    return _PART_NORMALIZE.sub("", value.casefold())


def _revision(value: str | None) -> str | None:
    if not value:
        return None
    match = _REVISION.fullmatch(value.strip())
    return f"v{match.group(1)}" if match else None


def parse_advisory_catalog(data: bytes) -> tuple[HardwareAdvisory, ...]:
    if len(data) > MAX_ADVISORY_CATALOG_BYTES:
        raise ValueError("Hardware advisory catalog exceeds the 1 MiB limit")
    try:
        document = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("Hardware advisory catalog is not valid UTF-8 JSON") from error
    if not isinstance(document, dict) or document.get("version") != 1:
        raise ValueError("Hardware advisory catalog has an unsupported version")
    records = document.get("advisories")
    if not isinstance(records, list) or len(records) > 1000:
        raise ValueError("Hardware advisory catalog needs an advisories array of at most 1000 entries")
    advisories: list[HardwareAdvisory] = []
    seen: set[str] = set()
    required_strings = (
        "advisory_id",
        "title",
        "manufacturer",
        "component_type",
        "severity",
        "confidence",
        "description",
        "last_verified",
    )
    required_lists = (
        "manufacturer_aliases",
        "affected_products",
        "part_number_aliases",
        "affected_revisions",
        "unaffected_revisions",
        "cve_ids",
        "cwe_ids",
        "sparta_mappings",
        "conditions",
        "mitigations",
        "sources",
    )
    for record in records:
        if not isinstance(record, dict):
            raise ValueError("Each hardware advisory must be an object")
        if any(not isinstance(record.get(key), str) or not record[key] for key in required_strings):
            raise ValueError("Hardware advisories require non-empty identifying text fields")
        if any(not isinstance(record.get(key), list) for key in required_lists):
            raise ValueError("Hardware advisory list fields must be arrays")
        if record["severity"] not in {"critical", "high", "medium", "low", "info", "unknown"}:
            raise ValueError("Hardware advisory severity is invalid")
        if record["confidence"] not in {"high", "medium", "low"}:
            raise ValueError("Hardware advisory confidence is invalid")
        if any(not isinstance(item, str) or not item for key in required_lists[:-1] for item in record[key]
               if key != "sparta_mappings"):
            raise ValueError("Hardware advisory list entries must be non-empty strings")
        if any(not _CVE.fullmatch(item) for item in record["cve_ids"]):
            raise ValueError("Hardware advisory CVE identifiers are invalid")
        advisory_id = record["advisory_id"]
        if advisory_id in seen:
            raise ValueError("Hardware advisory identifiers must be unique")
        seen.add(advisory_id)
        mappings: list[dict[str, str]] = []
        for mapping in record["sparta_mappings"]:
            if not isinstance(mapping, dict) or not all(
                isinstance(mapping.get(key), str) and mapping[key]
                for key in ("id", "title", "source", "mapping_basis")
            ):
                raise ValueError("SPARTA mappings require id, title, source, and mapping_basis text")
            mappings.append({key: mapping[key] for key in ("id", "title", "source", "mapping_basis")})
        if any(not isinstance(item, str) or not item for item in record["sources"]):
            raise ValueError("Hardware advisory sources must be non-empty strings")
        advisories.append(
            HardwareAdvisory(
                advisory_id=advisory_id,
                title=record["title"],
                manufacturer=record["manufacturer"],
                manufacturer_aliases=tuple(record["manufacturer_aliases"]),
                affected_products=tuple(record["affected_products"]),
                part_number_aliases=tuple(record["part_number_aliases"]),
                affected_revisions=tuple(record["affected_revisions"]),
                unaffected_revisions=tuple(record["unaffected_revisions"]),
                component_type=record["component_type"],
                cve_ids=tuple(record["cve_ids"]),
                cwe_ids=tuple(record["cwe_ids"]),
                sparta_mappings=tuple(mappings),
                severity=record["severity"],
                confidence=record["confidence"],
                description=record["description"],
                conditions=tuple(record["conditions"]),
                mitigations=tuple(record["mitigations"]),
                sources=tuple(record["sources"]),
                last_verified=record["last_verified"],
            )
        )
    return tuple(sorted(advisories, key=lambda item: item.advisory_id))


def load_advisory_catalog() -> tuple[HardwareAdvisory, ...]:
    data = files("vigil_fuse").joinpath("hardware_advisories.json").read_bytes()
    return parse_advisory_catalog(data)


def _product_match(
    component: HardwareBOMComponent, advisory: HardwareAdvisory
) -> tuple[bool, str]:
    manufacturer = _normalize(component.manufacturer or "")
    allowed_manufacturers = {
        _normalize(advisory.manufacturer),
        *(_normalize(item) for item in advisory.manufacturer_aliases),
    }
    if manufacturer and manufacturer not in allowed_manufacturers:
        return False, "manufacturer mismatch"
    identifiers = (component.part_number or "", component.name, component.description or "")
    normalized = tuple(_normalize(item) for item in identifiers if item)
    if any(value in {_normalize(alias) for alias in advisory.part_number_aliases} for value in normalized):
        return True, "exact part-number or product-name alias"
    excluded_series = ("esp32c", "esp32s", "esp32h", "esp32p")
    if any(value.startswith(excluded_series) for value in normalized):
        return False, "different Espressif product series"
    for alias in advisory.part_number_aliases:
        normalized_alias = _normalize(alias)
        if len(normalized_alias) < 8:
            continue
        if any(value.startswith(normalized_alias) for value in normalized):
            return True, "family-level part-number match"
    return False, "product not identified"


def match_hardware_bom(
    inventory: HardwareBOMInventory,
    *,
    catalog: tuple[HardwareAdvisory, ...] | None = None,
    condition_evidence: dict[tuple[str, str], bool] | None = None,
) -> tuple[AdvisoryMatch, ...]:
    if inventory.status not in {"imported", "partial"}:
        return ()
    records = load_advisory_catalog() if catalog is None else catalog
    evidence = condition_evidence or {}
    matches: list[AdvisoryMatch] = []
    seen: set[tuple[str, str, str, str]] = set()
    for component in inventory.components:
        for advisory in records:
            identified, identification = _product_match(component, advisory)
            if not identified:
                continue
            revision = _revision(component.revision)
            if revision and revision in advisory.unaffected_revisions:
                status: AdvisoryState = "NOT_AFFECTED_WITH_EVIDENCE"
            elif revision in advisory.affected_revisions:
                if all(evidence.get((component.reference, condition)) is True for condition in advisory.conditions):
                    status = "MATCH_CONFIRMED"
                else:
                    status = "CONDITION_UNKNOWN"
            elif revision:
                status = "UNSUPPORTED"
            elif identification.startswith("family-level"):
                status = "FAMILY_CANDIDATE"
            else:
                status = "REVISION_UNKNOWN"
            identity = (
                advisory.advisory_id,
                component.reference.casefold(),
                _normalize(component.part_number or component.name),
                revision or "unknown",
            )
            if identity in seen:
                continue
            seen.add(identity)
            matches.append(AdvisoryMatch(advisory, component, status, identification))
    return tuple(
        sorted(matches, key=lambda item: (item.advisory.advisory_id, item.component.reference.casefold()))
    )


def findings_from_matches(matches: tuple[AdvisoryMatch, ...], *, source_path: str) -> tuple[Finding, ...]:
    findings: list[Finding] = []
    for match in matches:
        advisory = match.advisory
        component = match.component
        revision = _revision(component.revision) or "unknown"
        evidence = safe_report_text(
            f"{component.reference}: {component.manufacturer or 'manufacturer unknown'} "
            f"{component.part_number or component.name}; revision {revision}; "
            f"advisory state {match.status}; identification {match.product_identification}.",
            limit=1000,
        ) or "Hardware advisory matched a BOM component."
        identity = "\0".join((advisory.advisory_id, component.reference, evidence))
        fingerprint = hashlib.sha256(identity.encode("utf-8")).hexdigest()
        sparta_summary = "; ".join(
            f"{mapping['id']} {mapping['title']} (analyst-assessed mapping)"
            for mapping in advisory.sparta_mappings
        )
        references = tuple(
            dict.fromkeys(
                (
                    *advisory.sources,
                    *(mapping["source"] for mapping in advisory.sparta_mappings),
                )
            )
        )
        applicability = (
            "not_applicable"
            if match.status == "NOT_AFFECTED_WITH_EVIDENCE"
            else "applicable"
            if match.status == "MATCH_CONFIRMED"
            else "candidate"
        )
        findings.append(
            Finding(
                id=f"{advisory.advisory_id}:{component.reference}:{fingerprint[:12]}",
                fingerprint=fingerprint,
                rule_id="FUSE-HW-ADV-001",
                rule_version="1.0.0",
                analyzer="hardware-advisory-catalog",
                title=advisory.title,
                severity=advisory.severity,  # Advisory severity remains independent of exposure evidence.
                confidence="high" if match.status in {"MATCH_CONFIRMED", "NOT_AFFECTED_WITH_EVIDENCE"} else "medium",
                category="hardware-silicon",
                file=source_path,
                start_line=None,
                end_line=None,
                evidence=evidence,
                explanation=(
                    f"{advisory.description} Applicability state: {match.status}. "
                    "This advisory match does not establish exploitability on a deployed product."
                    + (f" SPARTA mapping: {sparta_summary}." if sparta_summary else "")
                ),
                potential_impact="The documented hardware behavior may affect the stated security control if the product and conditions match.",
                remediation="Review the manufacturer advisory, confirm the exact silicon revision and configuration, and record product-specific validation.",
                references=references,
                applicability=applicability,
                validation_method="advisory-match",
                validation_status="not-validated",
            )
        )
    return tuple(findings)
