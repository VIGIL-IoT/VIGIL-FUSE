from __future__ import annotations

from pathlib import Path
import tempfile
import unittest

from vigil_fuse.bus_exposure import external_memory_findings, is_external_nonvolatile_memory
from vigil_fuse.hardware_netlist import inspect_kicad_netlist
from vigil_fuse.model import HardwareBOMComponent, HardwareBOMInventory


class BusExposureTests(unittest.TestCase):
    def setUp(self) -> None:
        self.flash = HardwareBOMComponent(
            reference="U2",
            name="W25Q64JV serial NOR flash",
            quantity=1,
            manufacturer="Winbond",
            part_number="W25Q64JV",
        )

    def _inventory(self, *components: HardwareBOMComponent) -> HardwareBOMInventory:
        return HardwareBOMInventory(
            status="imported",
            source_path="bom.csv",
            component_count=len(components),
            components=components,
        )

    def _netlist(self, root: Path, connector: bool) -> None:
        connector_component = (
            '<comp ref="J1"><value>External Bus Header</value>'
            "<footprint>Connector_PinHeader_2.54mm</footprint></comp>"
            if connector
            else '<comp ref="U1"><value>MCU</value><footprint>Package_QFP</footprint></comp>'
        )
        other_ref = "J1" if connector else "U1"
        text = (
            '<?xml version="1.0" encoding="UTF-8"?>'
            '<export version="E"><components>'
            '<comp ref="U2"><value>W25Q64JV</value><footprint>Package_SO</footprint></comp>'
            f"{connector_component}"
            '</components><nets><net code="1" name="/SPI_CLK">'
            f'<node ref="U2" pin="6"/><node ref="{other_ref}" pin="1"/>'
            "</net></nets></export>"
        )
        (root / "board.net").write_text(text, encoding="utf-8")

    def test_bom_component_is_reported_without_claiming_plaintext_exposure(self) -> None:
        findings = external_memory_findings(self._inventory(self.flash))

        self.assertEqual(1, len(findings))
        self.assertEqual("unknown", findings[0].severity)
        self.assertEqual("candidate", findings[0].applicability)
        self.assertIn("does not establish plaintext storage", findings[0].explanation)

    def test_memory_recognition_uses_part_prefixes_and_explicit_descriptions(self) -> None:
        self.assertTrue(is_external_nonvolatile_memory(self.flash))
        self.assertTrue(
            is_external_nonvolatile_memory(
                HardwareBOMComponent("U3", "I2C EEPROM", 1, part_number="24LC64")
            )
        )
        self.assertFalse(
            is_external_nonvolatile_memory(
                HardwareBOMComponent("U1", "Microcontroller", 1, part_number="STM32F407")
            )
        )

    def test_memory_bus_connected_to_header_is_only_a_candidate(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self._netlist(root, connector=True)
            inventory, findings = inspect_kicad_netlist(
                root, "board.net", hardware_bom=self._inventory(self.flash)
            )

        bus = next(item for item in findings if item.rule_id == "FUSE-HW-BUS-001")
        self.assertEqual("parsed", inventory.status)
        self.assertEqual("unknown", bus.severity)
        self.assertEqual("candidate", bus.applicability)
        self.assertIn("U2.6", bus.evidence)
        self.assertIn("J1.1", bus.evidence)
        self.assertIn("does not prove PCB routing", bus.explanation)

    def test_internal_memory_bus_does_not_create_connector_finding(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self._netlist(root, connector=False)
            _inventory, findings = inspect_kicad_netlist(
                root, "board.net", hardware_bom=self._inventory(self.flash)
            )

        self.assertFalse(any(item.rule_id == "FUSE-HW-BUS-001" for item in findings))


if __name__ == "__main__":
    unittest.main()
