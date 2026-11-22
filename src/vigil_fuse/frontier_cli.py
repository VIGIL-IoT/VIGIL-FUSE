"""Noninteractive entry points for experimental cyber-physical evidence."""

from __future__ import annotations

import argparse
import hashlib
from pathlib import Path
import sys
from typing import TypedDict

from .build_context import _read_bounded, _select_project_file
from .digital_twin import MAX_TWIN_JSON_BYTES, synthesize_digital_twin
from .device_tree import MAX_DTS_BYTES, parse_device_tree
from .flight_bus import (
    MAX_BUS_FILE_BYTES,
    MAX_BUS_FILES,
    MAX_BUS_TOTAL_BYTES,
    build_bus_graph,
    extract_bus_calls,
)
from .flight_policy import MAX_POLICY_BYTES, apply_bus_policy, parse_bus_policy
from .hardware_bom import inspect_hardware_bom
from .hardware_netlist import read_netlist_topology
from .json_limits import bounded_json
from .physical_reachability import (
    MAX_RESOURCE_PINS,
    ResourceBinding,
    correlate_physical_evidence,
    find_resource_candidates,
)
from .renode_export import export_renode
from .seu_analysis import MAX_SEU_BYTES, inspect_critical_state
from .svd import MAX_SVD_BYTES, parse_svd
from .text_safety import safe_terminal_text


class FrontierHint(TypedDict):
    name: str
    evidence: list[str]


def frontier_hints(
    samples: list[str],
    unsupported: dict[str, int],
    hardware: dict[str, int],
    *,
    has_bom: bool,
    has_netlist: bool,
) -> list[FrontierHint]:
    """Use bounded discovery metadata only; absence is not a negative conclusion."""
    suffixes = {Path(path).suffix.casefold() for path in samples}
    names = {Path(path).name.casefold() for path in samples}
    dts = bool(suffixes & {".dts", ".dtsi"}) or bool(
        unsupported.get(".dts", 0) or unsupported.get(".dtsi", 0)
    )
    svd = ".svd" in suffixes or bool(unsupported.get(".svd", 0))
    netlist = has_netlist or bool(hardware.get("netlist", 0))
    bom = has_bom or bool(hardware.get("bill-of-materials", 0))
    hints: list[FrontierHint] = []
    if dts and netlist and suffixes & {".c", ".cc", ".cpp"}:
        hints.append(
            {
                "name": "physical-reachability",
                "evidence": [
                    "DTS, netlist and C-family source filenames observed; an explicit pin mapping is required"
                ],
            }
        )
    if names & {"cfe_sb.h", "cfe_sb_api.h"}:
        hints.append(
            {
                "name": "flight-bus",
                "evidence": [
                    "cFE software-bus header filename observed; application assignments are required"
                ],
            }
        )
    if svd and (netlist or bom):
        hints.append(
            {
                "name": "digital-twin",
                "evidence": [
                    "SVD and hardware input filenames observed; select the intended local SVD"
                ],
            }
        )
    return hints


def register_commands(commands: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    twin = commands.add_parser("digital-twin", help="describe selected local SVD peripherals")
    twin.add_argument("target", type=Path, help="root containing the selected inputs")
    twin.add_argument("--svd", required=True, help="local CMSIS-SVD file inside target")
    twin.add_argument(
        "--peripheral", action="append", default=[], help="select a peripheral by name"
    )
    twin.add_argument("--hardware-bom", help="optional CSV or TSV BOM inside target")
    twin.add_argument("--format", choices=("json", "renode"), default="json")
    twin.add_argument(
        "--region",
        action="append",
        default=[],
        metavar="PERIPHERAL=BYTES",
        help="explicit Renode region size; repeat per selected peripheral",
    )
    twin.add_argument(
        "--ready-bit",
        action="append",
        default=[],
        metavar="PERIPHERAL.REGISTER=MASK",
        help="explicit synthetic bits set on each Renode read",
    )
    bus = commands.add_parser("flight-bus", help="extract partial cFE bus evidence")
    bus.add_argument("target", type=Path, help="root containing selected C source files")
    bus.add_argument(
        "--source",
        action="append",
        required=True,
        metavar="APP=PATH",
        help="assign a local C file to an application; repeat as needed",
    )
    bus.add_argument("--policy", help="optional local TOML flight policy inside target")
    seu = commands.add_parser("seu", help="observe selected resilience indicators")
    seu.add_argument("target", type=Path, help="root containing the selected C file")
    seu.add_argument("--source", required=True, help="local C source file inside target")
    physical = commands.add_parser("physical-reachability", help="correlate explicit pin evidence")
    physical.add_argument("target", type=Path, help="root containing device tree and netlist")
    physical.add_argument("--dts", required=True, help="local DTS file inside target")
    physical.add_argument("--netlist", required=True, help="local KiCad XML netlist inside target")
    physical.add_argument("--finding", required=True, help="finding identifier")
    physical.add_argument("--resource", required=True, help="resource identifier")
    physical.add_argument("--node", help="literal device-tree node path")
    physical.add_argument("--compatible", help="exact literal device-tree compatible string")
    physical.add_argument("--mmio", help="literal untranslated device-tree bus address")
    physical.add_argument("--component", required=True, help="MCU component reference")
    physical.add_argument(
        "--pin", action="append", required=True, help="mapped MCU pin; repeatable"
    )
    physical.add_argument(
        "--mapping-evidence", required=True, help="source of the supplied pin mapping"
    )


def run_command(args: argparse.Namespace) -> int:
    try:
        if args.command == "physical-reachability":
            if len(args.pin) > MAX_RESOURCE_PINS:
                raise ValueError("Pin mapping limit exceeded")
            path, display = _select_project_file(args.target, args.dts, "--dts")
            data = _read_bounded(path, MAX_DTS_BYTES, "DTS")
            tree = parse_device_tree(data)
            topology = read_netlist_topology(args.target, args.netlist)
            if args.node and (args.compatible is not None or args.mmio is not None):
                raise ValueError("Use --node or resource identifiers, not both")
            candidates = None
            node_path = args.node
            if node_path is None:
                address = int(args.mmio, 0) if args.mmio is not None else None
                candidates = find_resource_candidates(
                    tree, compatible=args.compatible, mmio=address
                )
                if candidates.status == "PARTIAL" and len(candidates.node_paths) == 1:
                    node_path = candidates.node_paths[0]
            evidence = None
            if node_path is not None:
                binding = ResourceBinding(
                    args.finding,
                    args.resource,
                    node_path,
                    args.component,
                    tuple(args.pin),
                    args.mapping_evidence,
                )
                evidence = correlate_physical_evidence(binding, tree, topology)
            payload = {
                "status": evidence.physical_status if evidence is not None else "UNKNOWN",
                "device_tree": {
                    "path": display,
                    "sha256": hashlib.sha256(data).hexdigest(),
                    "status": tree.status,
                    "limitations": tree.limitations,
                },
                "netlist": {
                    "path": topology.path,
                    "sha256": topology.sha256,
                    "status": topology.status,
                    "limitations": topology.limitations,
                },
                "requested_resource": {
                    "finding_id": args.finding,
                    "resource_id": args.resource,
                    "compatible": args.compatible,
                    "mmio": args.mmio,
                },
                "resource_candidates": candidates,
                "evidence": evidence,
            }
            sys.stdout.write(bounded_json(payload, 4 * 1024 * 1024, indent=2))
            return 1
        if args.command == "flight-bus":
            if len(args.source) > MAX_BUS_FILES:
                raise ValueError("Software-bus file limit exceeded")
            files: dict[str, bytes] = {}
            applications: dict[str, str] = {}
            total = 0
            for assignment in args.source:
                app, separator, supplied = assignment.partition("=")
                if not separator or not app or not supplied:
                    raise ValueError("Each --source must be APP=PATH")
                path, display = _select_project_file(args.target, supplied, "--source")
                if display in files:
                    raise ValueError("A source file cannot be assigned more than once")
                data = _read_bounded(path, MAX_BUS_FILE_BYTES, "C source")
                total += len(data)
                if total > MAX_BUS_TOTAL_BYTES:
                    raise ValueError("Software-bus total byte limit exceeded")
                files[display] = data
                applications[display] = app
            graph = build_bus_graph(extract_bus_calls(files), applications)
            if args.policy:
                policy_path, policy_display = _select_project_file(
                    args.target, args.policy, "--policy"
                )
                policy_data = _read_bounded(policy_path, MAX_POLICY_BYTES, "Flight policy")
                graph = apply_bus_policy(graph, parse_bus_policy(policy_data, policy_display))
            sys.stdout.write(graph.to_json())
            return 1
        if args.command == "seu":
            path, display = _select_project_file(args.target, args.source, "--source")
            seu_result = inspect_critical_state(_read_bounded(path, MAX_SEU_BYTES, "C source"))
            seu_payload: dict[str, object] = {
                "source": display,
                "status": seu_result.status,
                "states": seu_result.states,
                "limitations": seu_result.limitations,
            }
            sys.stdout.write(bounded_json(seu_payload, 4 * 1024 * 1024, indent=2))
            return 1
        path, display = _select_project_file(args.target, args.svd, "--svd")
        data = _read_bounded(path, MAX_SVD_BYTES, "SVD")
        result = parse_svd(data, display)
        if result.device is None:
            raise ValueError("; ".join(result.limitations))
        bom = inspect_hardware_bom(args.target, args.hardware_bom) if args.hardware_bom else None
        twin = synthesize_digital_twin(result, tuple(args.peripheral), bom)
        if args.format == "renode":
            if len(args.region) > 2048 or len(args.ready_bit) > 10_000:
                raise ValueError("Renode configuration limit exceeded")
            regions: dict[str, int] = {}
            for assignment in args.region:
                name, separator, raw_size = assignment.partition("=")
                if not separator or not name or name in regions:
                    raise ValueError("Each --region must uniquely specify PERIPHERAL=BYTES")
                regions[name] = int(raw_size, 0)
            ready: dict[tuple[str, str], int] = {}
            for assignment in args.ready_bit:
                name, separator, raw_bits = assignment.partition("=")
                peripheral, dot, register = name.rpartition(".")
                key = (peripheral, register)
                if not separator or not dot or not peripheral or not register or key in ready:
                    raise ValueError(
                        "Each --ready-bit must uniquely specify PERIPHERAL.REGISTER=MASK"
                    )
                ready[key] = int(raw_bits, 0)
            exported = export_renode(twin, regions, ready)
            platform = "".join(f"# {item}\n" for item in exported.limitations) + exported.platform
            if len(platform.encode("utf-8")) > MAX_TWIN_JSON_BYTES:
                raise ValueError("Renode output size limit exceeded")
            sys.stdout.write(platform)
        else:
            if args.region or args.ready_bit:
                raise ValueError("--region and --ready-bit require --format renode")
            sys.stdout.write(twin.to_json())
        return 1
    except (OSError, ValueError) as error:
        print(safe_terminal_text(f"vigil-fuse: {error}"), file=sys.stderr)
        return 2
