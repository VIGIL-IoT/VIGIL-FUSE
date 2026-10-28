from __future__ import annotations

import csv
import hashlib
import io
import json
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path

from .build_context import _read_bounded, _select_project_file
from .model import HardwareBOMComponent, HardwareBOMInventory
from .text_safety import safe_report_text

MAX_HARDWARE_BOM_BYTES = 10 * 1024 * 1024
MAX_HARDWARE_BOM_ROWS = 50_000
MAX_BOM_CELL_CHARS = 500
MAX_COMPONENT_QUANTITY = 1_000_000

_HEADER_ALIASES = {
    "reference": {"ref", "refs", "reference", "references", "designator", "designators", "refdes"},
    "name": {"value", "name", "component", "comment", "description", "part"},
    "footprint": {"footprint", "package", "landpattern"},
    "manufacturer": {"manufacturer", "mfr", "vendor", "supplier"},
    "part_number": {
        "mpn", "partnumber", "manufacturerpartnumber", "manufacturerpn", "supplierpartnumber",
    },
    "quantity": {"qty", "quantity", "count"},
}


def _header_key(value: str) -> str:
    compact = re.sub(r"[^a-z0-9]", "", (safe_report_text(value, limit=500) or "").casefold())
    for canonical, aliases in _HEADER_ALIASES.items():
        if compact in aliases:
            return canonical
    return compact


def _quantity(raw: str, reference: str) -> int | None:
    value = raw.strip()
    if value:
        if not value.isdecimal():
            return None
        quantity = int(value)
        return quantity if 1 <= quantity <= MAX_COMPONENT_QUANTITY else None
    references = [item for item in re.split(r"[,;\s]+", reference.strip()) if item]
    return min(len(references), MAX_COMPONENT_QUANTITY) if references else 1


def inspect_hardware_bom(root: Path, supplied: str | Path) -> HardwareBOMInventory:
    path, display = _select_project_file(root, supplied, "--hardware-bom")
    if path.suffix.casefold() not in {".csv", ".tsv"}:
        raise ValueError("--hardware-bom currently accepts CSV or TSV files")
    data = _read_bounded(path, MAX_HARDWARE_BOM_BYTES, "Hardware BOM")
    digest = hashlib.sha256(data).hexdigest()
    try:
        text = data.decode("utf-8-sig")
    except UnicodeDecodeError:
        return HardwareBOMInventory(
            status="invalid",
            source_path=display,
            sha256=digest,
            byte_size=len(data),
            format=path.suffix.lstrip(".").casefold(),
            limitations=("BOM is not UTF-8 text; convert it to UTF-8 CSV or TSV.",),
        )

    delimiter = "\t" if path.suffix.casefold() == ".tsv" else ","
    try:
        rows = csv.reader(io.StringIO(text, newline=""), delimiter=delimiter, strict=True)
        header = next(rows, None)
        if not header:
            raise ValueError("Hardware BOM has no header row")
        indexes: dict[str, int] = {}
        for index, column in enumerate(header):
            key = _header_key(column.strip())
            if key in _HEADER_ALIASES and key not in indexes:
                indexes[key] = index
        if "reference" not in indexes and "part_number" not in indexes:
            raise ValueError("Hardware BOM needs a reference/designator or part-number column")
        if not any(field in indexes for field in ("name", "part_number")):
            raise ValueError("Hardware BOM needs a value/name or part-number column")

        components: list[HardwareBOMComponent] = []
        malformed_rows = 0
        row_count = 0
        for row in rows:
            if not row or all(not item.strip() for item in row):
                continue
            row_count += 1
            if row_count > MAX_HARDWARE_BOM_ROWS:
                break

            def cell(key: str) -> str:
                index = indexes.get(key)
                if index is None or index >= len(row):
                    return ""
                return safe_report_text(row[index], limit=MAX_BOM_CELL_CHARS) or ""

            reference = cell("reference")
            part_number = cell("part_number") or None
            name = cell("name") or part_number or reference
            quantity = _quantity(cell("quantity"), reference)
            if not name or quantity is None:
                malformed_rows += 1
                continue
            components.append(
                HardwareBOMComponent(
                    reference=reference or f"line-{row_count + 1}",
                    name=name,
                    quantity=quantity,
                    footprint=cell("footprint") or None,
                    manufacturer=cell("manufacturer") or None,
                    part_number=part_number,
                    description=cell("name") if part_number and cell("name") != part_number else None,
                )
            )
    except (csv.Error, StopIteration, ValueError) as error:
        return HardwareBOMInventory(
            status="invalid",
            source_path=display,
            sha256=digest,
            byte_size=len(data),
            format=path.suffix.lstrip(".").casefold(),
            limitations=(str(error)[:240],),
        )

    limitations: list[str] = []
    if row_count > MAX_HARDWARE_BOM_ROWS:
        limitations.append(f"BOM rows exceeded the {MAX_HARDWARE_BOM_ROWS}-row limit.")
    if malformed_rows:
        limitations.append(f"{malformed_rows} row(s) did not contain a usable name and quantity.")
    if not components:
        limitations.append("No hardware components were imported.")
    return HardwareBOMInventory(
        status="partial" if limitations else "imported",
        source_path=display,
        sha256=digest,
        byte_size=len(data),
        format=path.suffix.lstrip(".").casefold(),
        component_count=len(components),
        quantity_total=sum(item.quantity for item in components),
        components=tuple(components),
        limitations=tuple(limitations),
    )


def hardware_bom_document(
    inventory: HardwareBOMInventory,
    *,
    product_name: str,
) -> str:
    if inventory.status not in {"imported", "partial"}:
        raise ValueError("No importable hardware BOM is available")
    components = []
    for item in inventory.components:
        identity = "\0".join((item.reference, item.name, item.part_number or "", item.manufacturer or ""))
        bom_ref = "urn:fuse:hardware:" + hashlib.sha256(identity.encode("utf-8")).hexdigest()
        properties = [
            {"name": "fuse:reference", "value": item.reference},
            {"name": "fuse:quantity", "value": str(item.quantity)},
        ]
        if item.footprint:
            properties.append({"name": "fuse:footprint", "value": item.footprint})
        if item.part_number:
            properties.append({"name": "fuse:part-number", "value": item.part_number})
        if item.description:
            properties.append({"name": "fuse:description", "value": item.description})
        component = {
            "type": "device",
            "bom-ref": bom_ref,
            "name": item.name,
            "properties": properties,
        }
        if item.manufacturer:
            component["supplier"] = {"name": item.manufacturer}
        components.append(component)
    document = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "component": {
                "type": "device",
                "bom-ref": "urn:fuse:hardware:product",
                "name": safe_report_text(product_name, limit=500) or "FUSE hardware inventory",
            },
            "properties": [
                {"name": "fuse:source-path", "value": inventory.source_path or "unknown"},
                {"name": "fuse:source-sha256", "value": inventory.sha256 or ""},
            ],
        },
        "components": components,
    }
    return json.dumps(document, indent=2, ensure_ascii=False) + "\n"
