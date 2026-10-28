from __future__ import annotations

import unittest
from pathlib import Path

from vigil_fuse.hardware import classify_hardware_file


class HardwareInventoryTests(unittest.TestCase):
    def test_kconfig_net_is_not_classified_as_an_electronic_netlist(self) -> None:
        artifact = classify_hardware_file(Path("Kconfig.net"), "drivers/Kconfig.net")
        self.assertIsNone(artifact)

    def test_design_net_file_remains_a_hardware_netlist(self) -> None:
        artifact = classify_hardware_file(Path("board.net"), "hardware/board.net")
        self.assertIsNotNone(artifact)
        assert artifact is not None
        self.assertEqual("netlist", artifact.category)


if __name__ == "__main__":
    unittest.main()
