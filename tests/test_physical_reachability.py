from pathlib import Path

import pytest

from vigil_fuse.device_tree import parse_device_tree
from vigil_fuse.hardware_netlist import read_netlist_topology
from vigil_fuse.physical_reachability import (
    ResourceBinding,
    correlate_physical_evidence,
    find_resource_candidates,
)


def test_explicit_binding_records_connector_without_claiming_exploitability(tmp_path: Path) -> None:
    board = tmp_path / "board.net"
    board.write_text(
        """<export><components>
      <comp ref="U1"><value>MCU</value></comp><comp ref="J3"><value>Header</value></comp>
      </components><nets><net name="UART2_TX"><node ref="U1" pin="42"/>
      <node ref="J3" pin="2"/></net></nets></export>""",
        encoding="utf-8",
    )
    tree = parse_device_tree(b'/ { soc { serial@40004400 { status = "okay"; }; }; };')
    binding = ResourceBinding(
        "FUSE-1", "UART2", "/soc/serial@40004400", "U1", ("42",), "Operator-supplied board pin map"
    )
    result = correlate_physical_evidence(binding, tree, read_netlist_topology(tmp_path, board))
    assert result.physical_status == "PHYSICALLY_EXPOSED"
    assert result.observed_device_status == '"okay"'
    assert [(c.mcu_pin, c.net, c.endpoint, c.endpoint_pin) for c in result.connections] == [
        ("42", "UART2_TX", "J3", "2")
    ]
    assert result.confidence == "low"
    assert any("unverified" in item for item in result.limitations)


def test_missing_node_is_unknown_and_empty_mapping_is_rejected(tmp_path: Path) -> None:
    tree = parse_device_tree(b"/ { };")
    topology = read_netlist_topology(tmp_path, "missing.net")
    binding = ResourceBinding("FUSE-1", "UART2", "/missing", "U1", ("42",), "board map")
    assert correlate_physical_evidence(binding, tree, topology).physical_status == "UNKNOWN"
    with pytest.raises(ValueError):
        correlate_physical_evidence(
            ResourceBinding("FUSE-1", "UART2", "/missing", "U1", (), "board map"),
            tree,
            topology,
        )


def test_exact_compatible_and_reg_cells_produce_partial_candidate() -> None:
    tree = parse_device_tree(b"""/ { soc { #address-cells = <1>; #size-cells = <1>;
      uart2: serial@40004400 { compatible = "vendor,uart", "vendor,serial";
        reg = <0x40004400 0x400>; };
      serial@5000 { compatible = "vendor,uart"; reg = <0x5000 0x100>; };
    }; };""")
    result = find_resource_candidates(tree, compatible="vendor,uart", mmio=0x40004400)
    assert result.status == "PARTIAL"
    assert result.node_paths == ("/soc/serial@40004400",)
    assert find_resource_candidates(tree, compatible="vendor,uart").status == "UNKNOWN"
    assert find_resource_candidates(tree, compatible="vendor,uart", mmio=0x9999).status == "UNKNOWN"


def test_missing_address_cells_do_not_guess_reg_interpretation() -> None:
    tree = parse_device_tree(b"/ { soc { serial@4000 { reg = <0x4000 0x100>; }; }; };")
    assert not find_resource_candidates(tree, mmio=0x4000).node_paths


def test_internal_unrouted_and_disabled_states_require_complete_literals(tmp_path: Path) -> None:
    path = tmp_path / "board.net"
    path.write_text(
        """<export><components><comp ref="U1"/><comp ref="R1"/>
      </components><nets><net name="INTERNAL"><node ref="U1" pin="42"/>
      <node ref="R1" pin="1"/></net></nets></export>""",
        encoding="utf-8",
    )
    topology = read_netlist_topology(tmp_path, path)
    binding = ResourceBinding("F1", "UART", "/soc/uart", "U1", ("42",), "mapping")
    okay = parse_device_tree(b'/ { soc { uart { status = "okay"; }; }; };')
    assert okay.status == "parsed"
    assert (
        correlate_physical_evidence(binding, okay, topology).physical_status
        == "PHYSICALLY_INTERNAL"
    )
    unconnected = tmp_path / "empty.net"
    unconnected.write_text('<export><components><comp ref="U1"/></components><nets/></export>')
    assert (
        correlate_physical_evidence(
            binding, okay, read_netlist_topology(tmp_path, unconnected)
        ).physical_status
        == "PHYSICALLY_UNROUTED"
    )
    disabled = parse_device_tree(b'/ { soc { uart { status = "disabled"; }; }; };')
    assert (
        correlate_physical_evidence(binding, disabled, topology).physical_status
        == "DEVICE_DISABLED"
    )


def test_non_kicad_xml_is_unsupported(tmp_path: Path) -> None:
    path = tmp_path / "other.xml"
    path.write_text("<other/>")
    assert read_netlist_topology(tmp_path, path).status == "unsupported"
