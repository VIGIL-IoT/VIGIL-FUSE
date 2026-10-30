from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from vigil_fuse.reporting import to_json
from vigil_fuse.scanner import scan
from vigil_fuse.zephyr_hardening import (
    inspect_hardening_report,
    resolve_hardening_report_path,
)

FIXTURES = Path(__file__).parent / "fixtures" / "zephyr"


def _project(root: Path) -> Path:
    (root / "CMakeLists.txt").write_text(
        "find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})\n",
        encoding="utf-8",
    )
    (root / "prj.conf").write_text("CONFIG_MAIN_STACK_SIZE=2048\n", encoding="utf-8")
    generated = root / "build" / "zephyr"
    generated.mkdir(parents=True)
    (generated / ".config").write_text(
        'CONFIG_BOARD="native_sim"\nCONFIG_KERNELVERSION="4.5.0"\n',
        encoding="utf-8",
    )
    return root / "build"


class ZephyrHardeningTests(unittest.TestCase):
    def test_imported_failure_preserves_source_and_separates_severity_from_confidence(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            build_dir = _project(root)
            report_path = build_dir / "hardenconfig.json"
            report_path.write_bytes((FIXTURES / "hardenconfig-failing.json").read_bytes())

            result = scan(
                root,
                profile="zephyr",
                build_dir="build",
                zephyr_hardening_report="build/hardenconfig.json",
            )
            report = json.loads(to_json(result))

        finding = next(
            item for item in report["findings"] if item["rule_id"] == "ZEPHYR-HARDENCONFIG"
        )
        self.assertEqual("unknown", finding["severity"])
        self.assertEqual("high", finding["confidence"])
        self.assertEqual("candidate", finding["applicability"])
        self.assertEqual("external-tool", finding["validation_method"])
        self.assertEqual("build/hardenconfig.json", finding["location"]["file"])
        self.assertEqual(
            "https://cwe.mitre.org/data/definitions/200.html",
            finding["references"][1],
        )
        analyzer = next(
            item
            for item in report["coverage"]["analyzers"]
            if item["name"] == "zephyr-hardenconfig"
        )
        self.assertEqual("completed", analyzer["status"])
        self.assertEqual(1, analyzer["findings"])
        self.assertIn("1 FAIL, 1 PASS, 1 not applicable", analyzer["detail"])
        self.assertNotIn("/private/build", json.dumps(report))
        self.assertEqual(
            "build/zephyr/.config", report["project_context"]["configuration_files"][0]["path"]
        )
        self.assertEqual(
            "build/hardenconfig.json", report["project_context"]["configuration_files"][1]["path"]
        )

    def test_passing_report_completes_without_emitting_findings(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            build_dir = _project(root)
            report_path = build_dir / "hardenconfig.json"
            report_path.write_bytes((FIXTURES / "hardenconfig-passing.json").read_bytes())

            artifact, findings, status = inspect_hardening_report(root, build_dir, report_path)

        self.assertEqual("build/hardenconfig.json", artifact.path)
        self.assertEqual(64, len(artifact.sha256 or ""))
        self.assertEqual((), findings)
        self.assertEqual("completed", status.status)
        self.assertEqual(0, status.findings)
        self.assertIn("0 FAIL, 1 PASS", status.detail or "")

    def test_invalid_failure_count_is_reported_as_failed_coverage(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            build_dir = _project(root)
            report_path = build_dir / "hardenconfig.json"
            report_path.write_text(
                json.dumps(
                    {
                        "profile": "strict",
                        "fail_count": 0,
                        "options": [
                            {
                                "name": "SHELL",
                                "recommended": "n",
                                "rationale": "Disables an interactive shell.",
                                "result": "FAIL",
                                "current": "y",
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )

            artifact, findings, status = inspect_hardening_report(root, build_dir, report_path)

        self.assertIsNotNone(artifact.sha256)
        self.assertEqual((), findings)
        self.assertEqual("failed", status.status)
        self.assertIn("fail_count does not match", status.detail or "")

    def test_report_must_be_inside_the_selected_build_directory(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            build_dir = _project(root)
            outside = root / "hardenconfig.json"
            outside.write_bytes((FIXTURES / "hardenconfig-passing.json").read_bytes())

            with self.assertRaisesRegex(ValueError, "inside the selected --build-dir"):
                resolve_hardening_report_path(root, build_dir, outside)

    def test_cli_plan_shows_import_as_optional_and_non_executing(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            build_dir = _project(root)
            report_path = build_dir / "hardenconfig.json"
            report_path.write_bytes((FIXTURES / "hardenconfig-passing.json").read_bytes())

            from io import StringIO
            from contextlib import redirect_stdout
            from vigil_fuse.cli import main

            output = StringIO()
            with redirect_stdout(output):
                exit_code = main(
                    [
                        "scan",
                        str(root),
                        "--profile",
                        "zephyr",
                        "--build-dir",
                        "build",
                        "--zephyr-hardening-report",
                        "build/hardenconfig.json",
                        "--plan",
                        "--format",
                        "json",
                    ]
                )
            plan = json.loads(output.getvalue())

        self.assertEqual(0, exit_code)
        stage = next(item for item in plan["stages"] if item["name"] == "zephyr-hardenconfig")
        self.assertTrue(stage["requested"])
        self.assertEqual("planned", stage["status"])
        self.assertFalse(plan["executed"])
        self.assertEqual("build/hardenconfig.json", plan["selected_zephyr_hardening_report"])


if __name__ == "__main__":
    unittest.main()
