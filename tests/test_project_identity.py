from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from vigil_fuse.project_identity import inspect_project_identity


class ProjectIdentityTests(unittest.TestCase):
    def test_inventory_reports_bounded_path_observations_and_partial_state(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self._write(root, "pyproject.toml", "[project]\nname='sample'\n")
            self._write(root, "app.py", "pass\n")
            identity = inspect_project_identity(root)
            self.assertEqual({"Python": 1}, identity.inventory["languages"])
            self.assertEqual({"pyproject.toml": 1}, identity.inventory["dependency_manifests"])
            self.assertTrue(identity.inventory["complete"])
            partial = inspect_project_identity(root, max_paths=1)
            self.assertFalse(partial.inventory["complete"])
            self.assertLessEqual(partial.inventory["files_observed"], 1)
            self.assertTrue(partial.inventory["limitations"])

    @staticmethod
    def _write(root: Path, relative: str, content: str = "") -> None:
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")

    def test_classifies_software_and_web_subtypes_from_independent_markers(self) -> None:
        cases = (
            (
                "software",
                {
                    "pyproject.toml": "[project]\nname='sample'\n",
                    "src/app.py": "print('hello')\n",
                    "src/util.py": "pass\n",
                    "src/config.py": "pass\n",
                },
                None,
            ),
            (
                "web-frontend",
                {
                    "package.json": json.dumps({"dependencies": {"react": "1"}}),
                    "vite.config.ts": "export default {}\n",
                    "src/App.tsx": "export default function App() {}\n",
                },
                "web-frontend",
            ),
            (
                "web-backend",
                {
                    "package.json": json.dumps({"dependencies": {"express": "1"}}),
                    "server.js": "module.exports = {}\n",
                    "src/routes.js": "module.exports = {}\n",
                },
                "web-backend",
            ),
        )
        for name, files, subtype in cases:
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                for relative, content in files.items():
                    self._write(root, relative, content)
                identity = inspect_project_identity(root)
                self.assertEqual("software", identity.primary_type)
                self.assertEqual(subtype, identity.subtype)
                self.assertIn(identity.confidence, {"low", "medium", "high"})
                self.assertGreater(identity.domains["software"], 0.5)

    def test_classifies_embedded_firmware_hardware_rtl_and_hybrid_projects(self) -> None:
        fixtures = (
            (
                "embedded",
                {
                    "sdkconfig": "CONFIG_BOOTLOADER_APP_ROLLBACK_ENABLE=y\n",
                    "idf_component.yml": "dependencies: {}\n",
                    "CMakeLists.txt": "idf_component_register()\n",
                    "main/main.c": "void app_main(void) {}\n",
                },
                "esp-idf",
            ),
            (
                "embedded",
                {
                    "prj.conf": "CONFIG_MAIN_STACK_SIZE=2048\n",
                    "west.yml": "manifest: {}\n",
                    "boards/demo/src/main.c": "int main(void) { return 0; }\n",
                },
                "zephyr",
            ),
            (
                "embedded",
                {
                    "platformio.ini": "[env:demo]\nplatform=espressif32\n",
                    "src/main.cpp": "void setup() {}\n",
                },
                "platformio",
            ),
            (
                "firmware",
                {
                    "edksetup.bat": "@echo off\n",
                    "MdePkg/MdePkg.dsc": "[Defines]\n",
                    "MdePkg/MdePkg.fdf": "[FV.FVMAIN]\n",
                    "MdePkg/Base.inf": "[Defines]\n",
                    "Platform/Board/Board.inf": "[Defines]\n",
                },
                "uefi-platform-firmware",
            ),
            (
                "hardware",
                {
                    "board.kicad_pcb": "(kicad_pcb)\n",
                    "board.kicad_sch": "(kicad_sch)\n",
                },
                "kicad-hardware",
            ),
            (
                "rtl",
                {
                    "rtl/cpu.sv": "module cpu; endmodule\n",
                    "rtl/bus.v": "module bus; endmodule\n",
                    "constraints/top.xdc": "set_property PACKAGE_PIN A1\n",
                },
                "fpga",
            ),
            (
                "hybrid",
                {
                    "pyproject.toml": "[project]\nname='board-tools'\n",
                    "src/app.py": "pass\n",
                    "src/util.py": "pass\n",
                    "src/config.py": "pass\n",
                    "board.kicad_pcb": "(kicad_pcb)\n",
                    "board.kicad_sch": "(kicad_sch)\n",
                },
                "hardware-software",
            ),
        )
        for expected, files, subtype in fixtures:
            with (
                self.subTest(expected=expected, subtype=subtype),
                tempfile.TemporaryDirectory() as temporary,
            ):
                root = Path(temporary)
                for relative, content in files.items():
                    self._write(root, relative, content)
                identity = inspect_project_identity(root)
                self.assertEqual(expected, identity.primary_type)
                self.assertEqual(subtype, identity.subtype)
                self.assertTrue(identity.complete)
                self.assertGreater(identity.evidence_score, 0.5)

    def test_empty_ambiguous_and_malformed_projects_stay_unknown(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            empty = Path(temporary) / "empty"
            empty.mkdir()
            identity = inspect_project_identity(empty)
            self.assertEqual("unknown", identity.primary_type)
            self.assertTrue(identity.complete)
            self.assertTrue(identity.limitations)

            ambiguous = Path(temporary) / "ambiguous"
            ambiguous.mkdir()
            self._write(ambiguous, "main.py", "print(1)\n")
            weak = inspect_project_identity(ambiguous)
            self.assertEqual("unknown", weak.primary_type)
            self.assertGreater(weak.domains["software"], 0)

            malformed = Path(temporary) / "malformed"
            malformed.mkdir()
            self._write(malformed, "package.json", "{ malformed json")
            self._write(malformed, "src/main.js", "console.log(1)\n")
            partial = inspect_project_identity(malformed)
            self.assertEqual("unknown", partial.primary_type)
            self.assertFalse(partial.complete)
            self.assertTrue(partial.limitations)

    def test_path_budget_and_depth_limits_mark_identity_incomplete(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self._write(root, "a.py", "pass\n")
            self._write(root, "b.py", "pass\n")
            self._write(root, "nested/deeper/c.py", "pass\n")
            path_limited = inspect_project_identity(root, max_paths=1)
            self.assertFalse(path_limited.complete)
            self.assertEqual("unknown", path_limited.primary_type)
            self.assertTrue(any("path limit" in item for item in path_limited.limitations))

            depth_limited = inspect_project_identity(root, max_depth=1)
            self.assertFalse(depth_limited.complete)
            self.assertTrue(any("depth limit" in item for item in depth_limited.limitations))

    def test_identity_time_budget_is_finite_and_checked_per_directory(self) -> None:
        for budget in (0, -1, float("inf"), float("nan"), float("-inf"), True):
            with self.subTest(budget=budget), self.assertRaises(ValueError):
                inspect_project_identity(".", budget_seconds=budget)

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "empty"
            root.mkdir()
            (root / "nested").mkdir()
            with patch(
                "vigil_fuse.project_identity.time.monotonic",
                side_effect=(0.0, 0.25, 0.75),
            ):
                identity = inspect_project_identity(root, budget_seconds=0.5)
            self.assertFalse(identity.complete)
            self.assertIn("Project identity time limit reached.", identity.limitations)

    def test_symbolic_links_are_excluded_and_make_identity_incomplete(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "project"
            outside = Path(temporary) / "outside"
            root.mkdir()
            outside.mkdir()
            self._write(outside, "sdkconfig", "CONFIG_IDF_TARGET=esp32\n")
            try:
                os.symlink(outside / "sdkconfig", root / "sdkconfig")
            except (OSError, NotImplementedError) as error:
                self.skipTest(f"Symbolic links unavailable: {error}")

            identity = inspect_project_identity(root)
            self.assertFalse(identity.complete)
            self.assertEqual("unknown", identity.primary_type)
            self.assertFalse(any("ESP-IDF" in signal for signal in identity.supporting_signals))


if __name__ == "__main__":
    unittest.main()
