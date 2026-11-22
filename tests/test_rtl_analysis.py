from __future__ import annotations

import json
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path
import unittest
from unittest.mock import patch

from jsonschema import Draft202012Validator

from vigil_fuse.cli import main
from vigil_fuse.model import HardwareArtifact, SourceFile
from vigil_fuse.profiles import get_profile
from vigil_fuse.reporting import to_json
from vigil_fuse.rtl_analysis import analyze_rtl
from vigil_fuse.scanner import scan

FIXTURES = Path(__file__).parent / "fixtures" / "rtl"
SCHEMA = (
    Path(__file__).parents[1] / "src" / "vigil_fuse" / "schemas" / "fuse-report-1.12.schema.json"
)
RTL_RULES = {"FUSE-RTL-001", "FUSE-RTL-002", "FUSE-RTL-003", "FUSE-RTL-004"}


def _scan_fixture(name: str) -> tuple[object, dict[str, object]]:
    with patch("vigil_fuse.rtl_analysis.shutil.which", return_value=None):
        result = scan(FIXTURES / name, profile="rtl")
    report = json.loads(to_json(result))
    return result, report


class RTLAnalysisTests(unittest.TestCase):
    def test_profile_selects_hdl_but_does_not_expand_generic_input_types(self) -> None:
        generic = get_profile("generic")
        rtl = get_profile("rtl")
        self.assertTrue(generic.supports(Path("unit.v")))
        self.assertTrue(generic.supports(Path("header.vh")))
        self.assertTrue(generic.supports(Path("unit.sv")))
        self.assertTrue(generic.supports(Path("header.svh")))
        self.assertTrue(rtl.supports(Path("pins.xdc")))
        self.assertFalse(rtl.supports(Path("driver.cpp")))

    def test_secure_configurable_unlock_and_disabled_debug_are_observations(self) -> None:
        result, report = _scan_fixture("secure")
        analysis = report["hardware_inventory"]["rtl_analysis"]
        self.assertEqual("partial", analysis["status"])
        self.assertIn("secure_access", analysis["top_module_candidates"])
        self.assertEqual(1, analysis["package_count"])
        self.assertIn("security_defaults.svh", json.dumps(analysis["files"]))
        self.assertIn("rtl-reset-security-state", {item["kind"] for item in analysis["evidence"]})
        self.assertIn(
            "rtl-security-control-constant", {item["kind"] for item in analysis["evidence"]}
        )
        self.assertEqual(
            set(), RTL_RULES.intersection({finding.rule_id for finding in result.findings})
        )
        Draft202012Validator(json.loads(SCHEMA.read_text(encoding="utf-8"))).validate(report)

    def test_insecure_debug_unlock_bypass_and_reset_candidates_are_reported_redacted(self) -> None:
        result, report = _scan_fixture("insecure")
        rule_ids = {finding.rule_id for finding in result.findings}
        self.assertTrue(
            {"FUSE-RTL-001", "FUSE-RTL-002", "FUSE-RTL-003", "FUSE-RTL-004"} <= rule_ids
        )
        self.assertNotIn("C0DECAFE", json.dumps(report))
        self.assertEqual("unknown", report["findings"][0]["applicability"])
        self.assertIn(
            "PRESENT",
            {
                item["build_status"]
                for item in report["hardware_inventory"]["rtl_analysis"]["files"]
            },
        )

    def test_macro_conditional_debug_path_is_ambiguous_not_a_finding(self) -> None:
        result, report = _scan_fixture("boundary")
        analysis = report["hardware_inventory"]["rtl_analysis"]
        self.assertIn("FUSE_ENABLE_DEBUG", json.dumps(analysis["files"]))
        self.assertEqual(1, analysis["testbench_count"])
        self.assertEqual(
            set(), RTL_RULES.intersection({finding.rule_id for finding in result.findings})
        )
        self.assertIn("top.xdc", json.dumps(analysis["related_files"]))

    def test_yosys_literal_inclusion_and_module_hierarchy_stay_distinct(self) -> None:
        _, report = _scan_fixture("multi_module")
        analysis = report["hardware_inventory"]["rtl_analysis"]
        self.assertIn("fpga_top", analysis["top_module_candidates"])
        self.assertIn("unused_module", analysis["top_module_candidates"])
        self.assertEqual(["fpga_top"], analysis["declared_top_modules"])
        file_statuses = {item["path"]: item["build_status"] for item in analysis["files"]}
        self.assertEqual("BUILD_INCLUDED", file_statuses["rtl/top.sv"])
        self.assertEqual("BUILD_INCLUDED", file_statuses["rtl/secure_child.sv"])
        self.assertEqual("PRESENT", file_statuses["rtl/unused_module.sv"])
        top = next(item for item in analysis["files"] if item["path"] == "rtl/top.sv")
        self.assertEqual("secure_child", top["units"][0]["instances"][0]["type"])

    def test_unit_cap_is_reported(self) -> None:
        with (
            patch("vigil_fuse.rtl_analysis.shutil.which", return_value=None),
            patch("vigil_fuse.rtl_analysis._RTL_MAX_UNITS", 1),
        ):
            _, report = _scan_fixture("multi_module")
        analysis = report["hardware_inventory"]["rtl_analysis"]
        self.assertEqual(1, analysis["module_count"])
        self.assertGreaterEqual(analysis["omitted_units"], 2)
        self.assertEqual("partial", analysis["status"])

    def test_expired_deadline_marks_unparsed_rtl(self) -> None:
        path = "unit.sv"
        source = SourceFile(path=path, text="module unit; endmodule", byte_size=22)
        artifact = HardwareArtifact(path=path, category="HDL", format="SystemVerilog")
        with (
            patch("vigil_fuse.rtl_analysis.shutil.which", return_value=None),
            patch("vigil_fuse.rtl_analysis.time.monotonic", return_value=10.0),
        ):
            analysis, _, status = analyze_rtl([source], [artifact], FIXTURES, deadline=9.0)
        self.assertEqual("partial", analysis.status)
        self.assertEqual("time-limit", analysis.files[0]["parse_status"])
        self.assertEqual("partial", status.status if status else None)

    def test_doctor_reports_builtin_backend_when_verible_is_missing(self) -> None:
        with (
            patch(
                "vigil_fuse.cli.inspect_rtl_backend",
                return_value=(
                    "AVAILABLE",
                    "FUSE structural parser (Verible unavailable)",
                    "builtin-1",
                    "UNAVAILABLE",
                ),
            ),
            patch(
                "vigil_fuse.cli.doctor_status",
                return_value={"available": False, "installed": False},
            ),
            redirect_stdout(StringIO()) as output,
        ):
            exit_code = main(["doctor"])
        self.assertEqual(0, exit_code)
        self.assertIn("RTL analyzer: AVAILABLE", output.getvalue())
        self.assertIn("backend: FUSE structural parser", output.getvalue())
        self.assertIn("version: builtin-1", output.getvalue())


if __name__ == "__main__":
    unittest.main()
