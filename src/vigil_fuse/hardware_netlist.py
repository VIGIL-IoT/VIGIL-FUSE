from __future__ import annotations

import hashlib
import re
import xml.etree.ElementTree as ET
from xml.parsers import expat
from pathlib import Path
from typing import TypedDict

from .build_context import _read_bounded, _select_project_file
from .model import Finding, NetlistInventory
from .text_safety import safe_report_text

MAX_KICAD_NETLIST_BYTES = 10 * 1024 * 1024
MAX_KICAD_XML_ELEMENTS = 100_000
MAX_KICAD_XML_DEPTH = 128
_DEBUG_NET = re.compile(
    r"(?:jtag|swdio|swclk|swdclk|\bswd\b|\btms\b|\btdi\b|\btdo\b|\btck\b|debug|uart)",
    re.IGNORECASE,
)
_CONNECTOR_REFERENCE = re.compile(r"^(?:J|P|CN|CONN?|TP)[A-Z]*\d+[A-Z]*$", re.IGNORECASE)
_CONNECTOR_WORDS = re.compile(
    r"connector|pin.?header|debug|jtag|swd|uart|test.?point", re.IGNORECASE
)


class _UnsafeNetlistXml(ValueError):
    """Raised when the selected XML exceeds safe parser limits."""


class _NetlistBase(TypedDict):
    path: str
    sha256: str
    byte_size: int


def _preflight_xml(data: bytes) -> None:
    """Reject unsafe encodings, DTDs, and oversized XML structure before tree parsing."""
    try:
        data.decode("utf-8-sig")
    except UnicodeDecodeError as error:
        raise _UnsafeNetlistXml("KiCad XML netlists must use UTF-8 encoding.") from error

    parser = expat.ParserCreate()
    depth = 0
    element_count = 0

    def on_start(_name: str, _attributes: dict[str, str]) -> None:
        nonlocal depth, element_count
        depth += 1
        element_count += 1
        if depth > MAX_KICAD_XML_DEPTH:
            raise _UnsafeNetlistXml(
                f"KiCad XML nesting exceeds the limit of {MAX_KICAD_XML_DEPTH} elements."
            )
        if element_count > MAX_KICAD_XML_ELEMENTS:
            raise _UnsafeNetlistXml(
                f"KiCad XML exceeds the limit of {MAX_KICAD_XML_ELEMENTS} elements."
            )

    def on_end(_name: str) -> None:
        nonlocal depth
        depth -= 1

    def reject_doctype(*_args: object) -> None:
        raise _UnsafeNetlistXml("DTD and entity declarations are not accepted in KiCad netlists.")

    parser.StartElementHandler = on_start
    parser.EndElementHandler = on_end
    parser.StartDoctypeDeclHandler = reject_doctype
    parser.EntityDeclHandler = reject_doctype
    parser.ExternalEntityRefHandler = lambda *_args: 0
    parser.SetParamEntityParsing(expat.XML_PARAM_ENTITY_PARSING_NEVER)
    parser.Parse(data, True)


def inspect_kicad_netlist(
    root: Path, supplied: str | Path, *, strict_format: bool = True
) -> tuple[NetlistInventory, tuple[Finding, ...]]:
    """Read a bounded KiCad XML netlist and report debug-interface candidates only."""
    try:
        path, display = _select_project_file(root, supplied, "--hardware-netlist")
        data = _read_bounded(path, MAX_KICAD_NETLIST_BYTES, "KiCad netlist")
    except ValueError as error:
        return NetlistInventory(status="invalid", limitations=(str(error),)), ()
    digest = hashlib.sha256(data).hexdigest()
    base: _NetlistBase = {
        "path": display,
        "sha256": digest,
        "byte_size": len(data),
    }
    try:
        _preflight_xml(data)
    except _UnsafeNetlistXml as error:
        return NetlistInventory(
            status="invalid",
            **base,
            limitations=(str(error),),
        ), ()
    except expat.ExpatError:
        return NetlistInventory(
            status="invalid" if strict_format else "not-detected",
            **base,
            limitations=(
                "Selected file is not well-formed KiCad XML and was not analyzed as a KiCad netlist.",
            ),
        ), ()
    try:
        document = ET.fromstring(data)
    except (ET.ParseError, RecursionError):
        return NetlistInventory(
            status="invalid" if strict_format else "not-detected",
            **base,
            limitations=(
                "Selected file is not well-formed KiCad XML and was not analyzed as a KiCad netlist.",
            ),
        ), ()
    if document.tag != "export":
        return NetlistInventory(
            status="invalid" if strict_format else "not-detected",
            **base,
            limitations=("Selected XML root is not the KiCad netlist export element.",),
        ), ()

    components_section = document.find("components")
    nets_section = document.find("nets")
    if components_section is None or nets_section is None:
        return NetlistInventory(
            status="partial",
            **base,
            limitations=("KiCad netlist is missing a components or nets section.",),
        ), ()

    components: dict[str, str] = {}
    for component in components_section.findall("comp"):
        reference = component.attrib.get("ref", "").strip()
        if not reference:
            continue
        description = " ".join(
            item.text or ""
            for item in (component.find("value"), component.find("footprint"))
            if item is not None
        )
        components[reference] = description

    candidates: list[str] = []
    findings: list[Finding] = []
    nets = nets_section.findall("net")
    for net in nets:
        name = safe_report_text(net.attrib.get("name"), limit=240)
        if not name or not _DEBUG_NET.search(name):
            continue
        connected = [node for node in net.findall("node") if node.attrib.get("ref") in components]
        connector_nodes = [
            node
            for node in connected
            if _CONNECTOR_REFERENCE.fullmatch(node.attrib.get("ref", ""))
            or _CONNECTOR_WORDS.search(components.get(node.attrib.get("ref", ""), ""))
        ]
        if not connector_nodes:
            continue
        endpoints = ", ".join(
            f"{node.attrib.get('ref', '?')}.{node.attrib.get('pin', '?')}"
            for node in connector_nodes[:20]
        )
        description = safe_report_text(f"{name} connects to {endpoints}", limit=240) or name
        candidates.append(description)
        evidence = (
            safe_report_text(
                f"KiCad net {name!r} has connector-designator node(s): {endpoints}", limit=240
            )
            or "Debug-labeled net connects to a connector-designator node."
        )
        fingerprint = hashlib.sha256(
            f"FUSE-HW-001\0{display}\0{net.attrib.get('code', '')}\0{evidence}".encode("utf-8")
        ).hexdigest()
        findings.append(
            Finding(
                id=f"FUSE-HW-001:{display}:{net.attrib.get('code', 'unknown')}",
                fingerprint=fingerprint,
                rule_id="FUSE-HW-001",
                rule_version="1.0.0",
                analyzer="kicad-netlist-static",
                title="Debug-labeled net reaches a connector candidate",
                severity="info",
                confidence="high",
                category="hardware-debug-interface",
                file=display,
                start_line=None,
                end_line=None,
                evidence=evidence,
                explanation=(
                    "The selected KiCad netlist names a signal with a debug-interface keyword and connects it to a connector-designator or connector-like component. "
                    "This does not establish PCB routing, physical accessibility, target configuration, or an enabled debug port."
                ),
                potential_impact=(
                    "If the corresponding interface is routed, accessible, and enabled on the deployed device, it may expose debugging or programming access."
                ),
                remediation=(
                    "Review the schematic and PCB routing, verify debug-port lifecycle settings and production fuses, and restrict physical access where required."
                ),
                references=("https://docs.kicad.org/9.0/en/eeschema/eeschema.pdf",),
                applicability="candidate",
                validation_method="static",
                validation_status="not-validated",
            )
        )

    inventory = NetlistInventory(
        status="parsed",
        **base,
        component_count=len(components),
        net_count=len(nets),
        debug_net_candidates=tuple(candidates),
        limitations=(
            "Netlist connectivity is design evidence only; verify PCB routing, physical access, and device configuration before drawing an exposure conclusion.",
        ),
    )
    return inventory, tuple(findings)
