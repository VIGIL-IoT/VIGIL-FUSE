from __future__ import annotations

import hashlib
import re

from .model import Finding, HardwareBOMComponent, HardwareBOMInventory
from .text_safety import safe_report_text

_MEMORY_PART_PREFIXES = (
    "w25",
    "mx25",
    "n25q",
    "mt25",
    "s25fl",
    "gd25",
    "is25",
    "at24",
    "at25",
    "24lc",
    "m24",
    "m95",
    "mb85",
    "fm24",
    "fm25",
)
_MEMORY_TERMS = re.compile(
    r"\b(?:serial\s+flash|spi\s+flash|qspi\s+flash|nor\s+flash|nand\s+flash|"
    r"(?:i2c\s+)?eeprom|fram|nvram|external\s+memory)\b",
    re.IGNORECASE,
)


def is_external_nonvolatile_memory(component: HardwareBOMComponent) -> bool:
    part_number = re.sub(r"[^a-z0-9]", "", (component.part_number or "").casefold())
    if part_number.startswith(_MEMORY_PART_PREFIXES):
        return True
    description = " ".join((component.name, component.description or ""))
    return bool(_MEMORY_TERMS.search(description))


def external_memory_findings(inventory: HardwareBOMInventory) -> tuple[Finding, ...]:
    if inventory.status not in {"imported", "partial"}:
        return ()
    findings: list[Finding] = []
    seen: set[tuple[str, str]] = set()
    for component in sorted(inventory.components, key=lambda item: item.reference.casefold()):
        if not is_external_nonvolatile_memory(component):
            continue
        identity = (
            component.reference.casefold(),
            (component.part_number or component.name).casefold(),
        )
        if identity in seen:
            continue
        seen.add(identity)
        evidence = (
            safe_report_text(
                f"BOM component {component.reference}: {component.manufacturer or 'manufacturer unknown'} "
                f"{component.part_number or component.name}; silicon revision "
                f"{component.revision or 'unknown'}.",
                limit=1000,
            )
            or "A nonvolatile-memory component is listed in the selected BOM."
        )
        fingerprint = hashlib.sha256(f"FUSE-HW-MEM-001\0{evidence}".encode("utf-8")).hexdigest()
        findings.append(
            Finding(
                id=f"FUSE-HW-MEM-001:{component.reference}:{fingerprint[:12]}",
                fingerprint=fingerprint,
                rule_id="FUSE-HW-MEM-001",
                rule_version="1.0.0",
                analyzer="external-memory-static",
                title="External nonvolatile memory identified; protection is unknown",
                severity="unknown",
                confidence="medium",
                category="hardware-bus-exposure",
                file=inventory.source_path or "hardware-bom",
                start_line=None,
                end_line=None,
                evidence=evidence,
                explanation=(
                    "The selected BOM identifies a likely external nonvolatile-memory component. "
                    "This does not establish plaintext storage, readable contents, or physical access."
                ),
                potential_impact="If firmware or sensitive data are stored there without effective protection and the bus is accessible, confidentiality or integrity may be affected.",
                remediation="Review the exact memory part, firmware encryption and write-protection configuration, and the selected board netlist before making a security conclusion.",
                applicability="candidate",
                validation_method="static",
                validation_status="not-validated",
            )
        )
    return tuple(findings)
