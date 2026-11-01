from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
from pathlib import Path

from jsonschema import Draft202012Validator

from vigil_fuse.cli import main

FIXTURES = Path(__file__).parent / "fixtures"


def _write_project(root: Path, *, secure: bool) -> None:
    (root / "src").mkdir(parents=True)
    (root / "build" / "config").mkdir(parents=True)
    (root / "hardware").mkdir(parents=True)
    (root / "CMakeLists.txt").write_text(
        "include($ENV{IDF_PATH}/tools/cmake/project.cmake)\n"
        "project(fixture)\n"
        'file(WRITE "${CMAKE_CURRENT_LIST_DIR}/build-command-ran.txt" "unexpected")\n',
        encoding="utf-8",
    )
    endpoint = "https://device.local/api" if secure else "http://device.local/api"
    (root / "src" / "main.c").write_text(
        f'const char *endpoint = "{endpoint}";\n', encoding="utf-8"
    )
    config_value = "0" if secure else "1"
    (root / "build" / "config" / "sdkconfig.h").write_text(
        '#define CONFIG_IDF_TARGET "esp32"\n'
        f"#define CONFIG_BOOTLOADER_SKIP_VALIDATE_ALWAYS {config_value}\n"
        f"#define CONFIG_BOOTLOADER_SKIP_VALIDATE_IN_DEEP_SLEEP {config_value}\n",
        encoding="utf-8",
    )
    (root / "build" / "project_description.json").write_text(
        json.dumps({"target": "esp32", "git_revision": "v5.2.1"}), encoding="utf-8"
    )
    netlist_name = "secure.net" if secure else "debug-interface.net"
    (root / "hardware" / "board.net").write_text(
        (FIXTURES / "hardware" / netlist_name).read_text(encoding="utf-8"),
        encoding="utf-8",
    )
    (root / "hardware" / "board.kicad_pcb").write_text(
        "Filename inventory only\n", encoding="utf-8"
    )
    (root / "hardware" / "board-bom.csv").write_text(
        "Reference,Value,Footprint\nU1,MCU,QFN-32\n", encoding="utf-8"
    )


class EmbeddedProjectCliIntegrationTests(unittest.TestCase):
    def _scan_project(self, root: Path, output: Path) -> tuple[int, dict[str, object]]:
        stdout = StringIO()
        stderr = StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            exit_code = main(
                [
                    "scan",
                    str(root),
                    "--profile",
                    "esp-idf",
                    "--build-dir",
                    "build",
                    "--hardware-netlist",
                    "hardware/board.net",
                    "--hardware-bom",
                    "hardware/board-bom.csv",
                    "--no-network",
                    "--format",
                    "json",
                    "--output-dir",
                    str(output),
                ]
            )
        report_path = output / "findings.json"
        self.assertTrue(report_path.is_file())
        self.assertTrue((output / "findings.txt").is_file())
        self.assertTrue((output / "findings.sarif").is_file())
        report = json.loads(report_path.read_text(encoding="utf-8"))
        return exit_code, report

    def test_cli_wires_source_build_context_hardware_and_report_artifact(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary)
            root = workspace / "embedded-project"
            output = workspace / "reports"
            root.mkdir()
            _write_project(root, secure=False)

            exit_code, report = self._scan_project(root, output)

            schema_path = (
                Path(__file__).parents[1]
                / "src"
                / "vigil_fuse"
                / "schemas"
                / "fuse-report-1.10.schema.json"
            )
            schema = json.loads(schema_path.read_text(encoding="utf-8"))
            Draft202012Validator(schema).validate(report)
            bom_path = output / "hardware-bom.cdx.json"
            self.assertTrue(bom_path.is_file())
            bom_digest = hashlib.sha256(bom_path.read_bytes()).hexdigest()
            self.assertFalse((root / "build-command-ran.txt").exists())

        self.assertEqual(0, exit_code)
        self.assertTrue(report["summary"]["analysis_performed"])
        self.assertTrue(report["coverage"]["discovery_complete"])
        self.assertEqual("esp-idf", report["project_context"]["framework"])
        self.assertEqual("esp32", report["project_context"]["target"])
        self.assertEqual("parsed", report["hardware_netlist"]["status"])
        self.assertEqual("imported", report["hardware_bom"]["status"])
        self.assertEqual(1, report["hardware_bom"]["component_count"])
        self.assertTrue(report["hardware_inventory"]["present"])
        self.assertIn("pcb-layout", report["hardware_inventory"]["category_counts"])
        self.assertEqual(bom_digest, report["artifacts"][0]["sha256"])

        findings = {item["rule_id"]: item for item in report["findings"]}
        self.assertTrue({"FUSE004", "FUSE006", "FUSE007", "FUSE-HW-001"} <= set(findings))
        for rule_id in ("FUSE006", "FUSE007"):
            self.assertEqual("candidate", findings[rule_id]["applicability"])
            self.assertEqual("generated-config", findings[rule_id]["validation_method"])
        for finding in findings.values():
            self.assertIn(
                finding["severity"], {"critical", "high", "medium", "low", "info", "unknown"}
            )
            self.assertIn(finding["confidence"], {"high", "medium", "low"})
            self.assertIn("location", finding)
            self.assertIn("explanation", finding)
            self.assertIn("potential_impact", finding)
            self.assertIn("remediation", finding)
        self.assertNotIn(str(workspace), json.dumps(report))

    def test_secure_control_fixture_has_no_paired_weakness_findings(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary)
            root = workspace / "embedded-project"
            output = workspace / "reports"
            root.mkdir()
            _write_project(root, secure=True)

            exit_code, report = self._scan_project(root, output)

        self.assertEqual(0, exit_code)
        rule_ids = {item["rule_id"] for item in report["findings"]}
        self.assertTrue(report["summary"]["analysis_performed"])
        self.assertFalse({"FUSE004", "FUSE006", "FUSE007", "FUSE-HW-001"} & rule_ids)


if __name__ == "__main__":
    unittest.main()
