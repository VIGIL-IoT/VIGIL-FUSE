"""Generate deliberately limited synthetic Renode Python-peripheral descriptions."""

from __future__ import annotations

from dataclasses import dataclass
import json
from typing import Mapping

from .digital_twin import DigitalTwinDescription, MAX_TWIN_JSON_BYTES

MAX_REGION_BYTES = 1024 * 1024
MAX_ADDRESS = (1 << 64) - 1


@dataclass(frozen=True)
class RenodeExport:
    status: str
    platform: str
    limitations: tuple[str, ...]


def export_renode(
    twin: DigitalTwinDescription,
    region_sizes: Mapping[str, int],
    synthetic_set_bits: Mapping[tuple[str, str], int] | None = None,
) -> RenodeExport:
    """Export stateless, 32-bit reset reads; mappings and overrides are explicit."""
    overrides = synthetic_set_bits or {}
    if not twin.peripherals:
        raise ValueError("At least one peripheral is required")
    if set(region_sizes) != {peripheral.name for peripheral in twin.peripherals}:
        raise ValueError("An explicit region size is required for each selected peripheral")
    if len(overrides) > 10_000:
        raise ValueError("Synthetic override limit exceeded")
    used_overrides: set[tuple[str, str]] = set()
    regions: list[tuple[int, int]] = []
    lines = ["# Synthetic FUSE mock: not measured hardware behavior."]
    total_size = len(lines[0]) + 1
    for index, peripheral in enumerate(twin.peripherals):
        region_size = region_sizes[peripheral.name]
        base = peripheral.base_address
        if (
            type(region_size) is not int
            or type(base) is not int
            or not 4 <= region_size <= MAX_REGION_BYTES
            or region_size % 4
            or not 0 <= base <= MAX_ADDRESS
            or base % 4
            or base + region_size - 1 > MAX_ADDRESS
        ):
            raise ValueError("Invalid or unaligned Renode memory region")
        if any(base < end and start < base + region_size for start, end in regions):
            raise ValueError("Renode peripheral regions overlap")
        regions.append((base, base + region_size))
        values: dict[int, int] = {}
        if not peripheral.registers:
            raise ValueError("At least one described register is required per peripheral")
        for register in peripheral.registers:
            if (
                type(register.offset) is not int
                or type(register.reset_value) is not int
                or register.size_bits != 32
                or register.reset_mask != 0xFFFFFFFF
                or register.offset % 4
                or not 0 <= register.offset
                or register.offset + 4 > region_size
                or register.offset in values
                or not 0 <= register.reset_value <= 0xFFFFFFFF
            ):
                raise ValueError(
                    "Renode export requires unique 32-bit registers with fully known resets"
                )
            key = (peripheral.name, register.name)
            bits = overrides.get(key, 0)
            if type(bits) is not int or not 0 <= bits <= 0xFFFFFFFF:
                raise ValueError("Synthetic ready-bit masks must be 32-bit integers")
            if key in overrides:
                used_overrides.add(key)
            values[register.offset] = register.reset_value | bits
        mapping = (
            "{" + ", ".join(f"{offset}: {value}" for offset, value in sorted(values.items())) + "}"
        )
        script = (
            f"request.Value = {mapping}.get(request.Offset, 0) if request.IsRead else request.Value"
        )
        block = (
            f"fuse_mock_{index}: Python.PythonPeripheral @ sysbus 0x{base:x}\n"
            f"    size: 0x{region_size:x}\n    initable: false\n"
            f"    script: {json.dumps(script)}\n"
        )
        total_size += len(block)
        if total_size > MAX_TWIN_JSON_BYTES:
            raise ValueError("Renode output size limit exceeded")
        lines.append(block)
    if set(overrides) != used_overrides:
        raise ValueError("A synthetic override did not match a selected register")
    return RenodeExport(
        "experimental",
        "\n".join(lines),
        (
            "Synthetic stateless reads return listed reset values and zero for all other offsets.",
            "Writes are ignored; access permissions, read widths, side effects and interrupts are not modeled.",
            "Explicit ready-bit masks are synthetic and applied on every read, not measured hardware behavior.",
            "Region sizes are caller-supplied and require independent verification.",
            "Generated platform descriptions have not been validated by a Renode execution.",
        ),
    )
