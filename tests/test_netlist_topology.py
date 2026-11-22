from pathlib import Path

from vigil_fuse.hardware_netlist import read_netlist_topology


def test_netlist_topology_exposes_deterministic_connectivity(tmp_path: Path) -> None:
    path = tmp_path / "board.xml"
    path.write_text(
        """<export><components>
      <comp ref="U1"><value>MCU</value></comp>
      <comp ref="J3"><value>Header</value></comp>
      <comp ref="TP1"><value>Test point</value></comp>
      </components><nets><net name="UART2_TX">
      <node ref="U1" pin="42"/><node ref="TP1" pin="1"/>
      <node ref="J3" pin="2"/></net></nets></export>""",
        encoding="utf-8",
    )
    result = read_netlist_topology(tmp_path, path)
    assert result.status == "parsed"
    assert result.sha256 is not None and len(result.sha256) == 64
    assert [(p.reference, p.pin, p.connector_candidate) for p in result.nets[0].endpoints] == [
        ("J3", "2", True),
        ("TP1", "1", True),
        ("U1", "42", False),
    ]
    assert result == read_netlist_topology(tmp_path, path)


def test_unsafe_or_incomplete_netlist_is_not_complete(tmp_path: Path) -> None:
    path = tmp_path / "board.xml"
    path.write_text('<!DOCTYPE export [<!ENTITY x SYSTEM "file:///secret">]><export/>')
    assert read_netlist_topology(tmp_path, path).status == "invalid"
    path.write_text(
        '<export><components/><nets><net name="x"><node ref="U1" pin="1"/></net></nets></export>'
    )
    result = read_netlist_topology(tmp_path, path)
    assert result.status == "partial"
    assert result.nets[0].endpoints == ()


def test_repeated_physical_pin_marks_topology_partial(tmp_path: Path) -> None:
    path = tmp_path / "board.xml"
    path.write_text(
        """<export><components><comp ref="U1"/></components><nets>
      <net name="A"><node ref="U1" pin="1"/></net>
      <net name="B"><node ref="U1" pin="1"/></net>
      </nets></export>""",
        encoding="utf-8",
    )
    assert read_netlist_topology(tmp_path, path).status == "partial"
