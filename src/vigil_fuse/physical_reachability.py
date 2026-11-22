"""Conservative correlation of explicitly supplied pin mappings and design evidence."""

from __future__ import annotations

from dataclasses import dataclass
import json
import re
from typing import Literal

from .device_tree import DeviceTreeNode, DeviceTreeResult
from .hardware_netlist import NetlistTopology

MAX_RESOURCE_PINS = 256
MAX_PHYSICAL_CONNECTIONS = 10_000
MAX_REG_CELLS = 128
PhysicalStatus = Literal[
    "PHYSICALLY_EXPOSED",
    "PHYSICALLY_INTERNAL",
    "PHYSICALLY_UNROUTED",
    "DEVICE_DISABLED",
    "UNKNOWN",
    "PARTIAL",
    "UNSUPPORTED",
]


@dataclass(frozen=True)
class ResourceCandidates:
    status: str
    node_paths: tuple[str, ...]
    limitations: tuple[str, ...]


def _unique_property(node: DeviceTreeNode, name: str) -> str | None:
    values = [value for key, value in node.properties if key == name]
    return values[0] if len(values) == 1 else None


def _cells(value: str | None) -> tuple[int, ...] | None:
    if value is None or len(value) > 4096 or not re.fullmatch(r"[<>,\s0-9a-fA-FxX]+", value):
        return None
    groups = value.split(",")
    if any(
        not group.strip().startswith("<")
        or not group.strip().endswith(">")
        or "<" in group.strip()[1:]
        or ">" in group.strip()[:-1]
        for group in groups
    ):
        return None
    words = " ".join(group.strip()[1:-1] for group in groups).split()
    if not words or len(words) > MAX_REG_CELLS:
        return None
    cells: list[int] = []
    for word in words:
        if re.fullmatch(r"0[xX][0-9a-fA-F]+", word):
            cell = int(word, 16)
        elif word.isascii() and word.isdecimal():
            cell = int(word, 10)
        else:
            return None
        if cell > 0xFFFFFFFF:
            return None
        cells.append(cell)
    return tuple(cells)


def find_resource_candidates(
    tree: DeviceTreeResult, *, compatible: str | None = None, mmio: int | None = None
) -> ResourceCandidates:
    """Match literal identifiers without resolving preprocessing or bus translation."""
    if (
        (compatible is None and mmio is None)
        or (compatible is not None and not compatible)
        or (compatible is not None and len(compatible) > 1024)
    ):
        raise ValueError("A compatible identifier or register address is required")
    if mmio is not None and (type(mmio) is not int or not 0 <= mmio < 1 << 64):
        raise ValueError("Register address must be an unsigned 64-bit integer")
    paths: dict[str, list[DeviceTreeNode]] = {}
    for node in tree.nodes:
        paths.setdefault(node.path, []).append(node)
    matches: list[str] = []
    for node in tree.nodes:
        if len(paths[node.path]) != 1:
            continue
        if compatible is not None:
            raw = _unique_property(node, "compatible")
            if raw is None or len(raw) > 4096:
                continue
            try:
                values = json.loads("[" + raw + "]")
            except (json.JSONDecodeError, RecursionError):
                continue
            if (
                not isinstance(values, list)
                or not all(isinstance(value, str) for value in values)
                or compatible not in values
            ):
                continue
        if mmio is not None:
            parent_path = node.path.rpartition("/")[0] or "/"
            parents = paths.get(parent_path, [])
            if len(parents) != 1 or parent_path == node.path:
                continue
            address_cells = _cells(_unique_property(parents[0], "#address-cells"))
            size_cells = _cells(_unique_property(parents[0], "#size-cells"))
            cells = _cells(_unique_property(node, "reg"))
            if (
                address_cells not in {(1,), (2,)}
                or size_cells not in {(0,), (1,), (2,)}
                or cells is None
            ):
                continue
            address_count, size_count = address_cells[0], size_cells[0]
            stride = address_count + size_count
            if len(cells) % stride:
                continue
            addresses = []
            for index in range(0, len(cells), stride):
                address = (
                    cells[index] if address_count == 1 else (cells[index] << 32) | cells[index + 1]
                )
                addresses.append(address)
            if mmio not in addresses:
                continue
        matches.append(node.path)
    return ResourceCandidates(
        "PARTIAL" if len(matches) == 1 and tree.status != "invalid" else "UNKNOWN",
        tuple(sorted(matches)),
        (
            "Literal matches are candidates; includes, macros and overlays are unresolved.",
            "Register addresses are bus cells and are not translated through ranges.",
        ),
    )


@dataclass(frozen=True)
class ResourceBinding:
    finding_id: str
    resource_id: str
    device_tree_node: str
    component: str
    pins: tuple[str, ...]
    mapping_evidence: str


@dataclass(frozen=True)
class PhysicalConnection:
    mcu_pin: str
    net: str
    endpoint: str
    endpoint_pin: str


@dataclass(frozen=True)
class PhysicalReachability:
    finding_id: str
    resource_id: str
    device_tree_node: str
    physical_status: PhysicalStatus
    confidence: str
    observed_device_status: str | None
    connections: tuple[PhysicalConnection, ...]
    mapping_evidence: str
    limitations: tuple[str, ...]


def correlate_physical_evidence(
    binding: ResourceBinding, tree: DeviceTreeResult, topology: NetlistTopology
) -> PhysicalReachability:
    """Correlate an operator-supplied mapping; do not infer pins or exploitability."""
    labels = (
        binding.finding_id,
        binding.resource_id,
        binding.device_tree_node,
        binding.component,
        binding.mapping_evidence,
    )
    if (
        not binding.finding_id
        or not binding.resource_id
        or not binding.device_tree_node
        or not binding.component
        or not binding.mapping_evidence
        or not binding.pins
        or len(binding.pins) > MAX_RESOURCE_PINS
        or any(not pin for pin in binding.pins)
        or any(len(value) > 1024 or "\0" in value for value in labels)
        or any(len(pin) > 128 or "\0" in pin for pin in binding.pins)
        or len(set(binding.pins)) != len(binding.pins)
    ):
        raise ValueError("A bounded, evidenced resource-to-pin mapping is required")
    nodes = [node for node in tree.nodes if node.path == binding.device_tree_node]
    limitations = [
        "The resource-to-pin mapping is supplied by the caller and has not been verified.",
        "Netlist connector candidates do not prove physical access or exploitability.",
    ]
    connections: list[PhysicalConnection] = []
    mapped_pins_on_nets: set[str] = set()
    if topology.status in {"parsed", "partial"}:
        pins = set(binding.pins)
        for net in topology.nets:
            source_pins = {
                endpoint.pin
                for endpoint in net.endpoints
                if endpoint.reference == binding.component and endpoint.pin in pins
            }
            mapped_pins_on_nets.update(source_pins)
            for source_pin in sorted(source_pins):
                for endpoint in net.endpoints:
                    if endpoint.connector_candidate and endpoint.reference != binding.component:
                        if len(connections) >= MAX_PHYSICAL_CONNECTIONS:
                            break
                        connections.append(
                            PhysicalConnection(
                                source_pin, net.name, endpoint.reference, endpoint.pin
                            )
                        )
                if len(connections) >= MAX_PHYSICAL_CONNECTIONS:
                    break
            if len(connections) >= MAX_PHYSICAL_CONNECTIONS:
                limitations.append(
                    "Connection output reached its limit; further paths were omitted."
                )
                break
    if tree.status != "parsed":
        limitations.append("Device-tree preprocessing and configuration are incomplete.")
    if topology.status != "parsed":
        limitations.append("Netlist topology is unavailable or incomplete.")
    if len(nodes) != 1:
        limitations.append("The selected device-tree node is missing or ambiguous.")
    elif nodes[0].property("status") is None:
        limitations.append("No literal device status was observed.")
    node_status = nodes[0].property("status") if len(nodes) == 1 else None
    literal_status = node_status.strip().strip('"') if node_status else None
    if topology.status == "unsupported":
        status: PhysicalStatus = "UNSUPPORTED"
    elif (
        tree.status == "invalid" or len(nodes) != 1 or binding.component not in topology.components
    ):
        status = "UNKNOWN"
        if binding.component not in topology.components:
            limitations.append("The mapped component is not present in the supplied netlist.")
    elif literal_status == "disabled" and tree.status == "parsed":
        status = "DEVICE_DISABLED"
    elif connections:
        status = "PHYSICALLY_EXPOSED"
    elif tree.status != "parsed" or topology.status != "parsed":
        status = "PARTIAL"
    elif mapped_pins_on_nets:
        status = "PHYSICALLY_INTERNAL"
    else:
        status = "PHYSICALLY_UNROUTED"
    if status in {"PHYSICALLY_EXPOSED", "PHYSICALLY_INTERNAL", "PHYSICALLY_UNROUTED"}:
        if literal_status != "okay":
            limitations.append("The peripheral is not explicitly enabled by a literal okay status.")
    if status == "PHYSICALLY_EXPOSED":
        limitations.append("PCB copper routing and physical connector access are unverified.")
    return PhysicalReachability(
        binding.finding_id,
        binding.resource_id,
        binding.device_tree_node,
        status,
        "low",
        node_status,
        tuple(sorted(connections, key=lambda c: (c.mcu_pin, c.net, c.endpoint, c.endpoint_pin))),
        binding.mapping_evidence,
        tuple(limitations),
    )
