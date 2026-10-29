from pathlib import Path
from contextlib import redirect_stderr, redirect_stdout
from dataclasses import replace
from io import StringIO
import json
import os
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from vigil_fuse.analyzers import AdapterResult
from vigil_fuse.cli import main
from vigil_fuse.config import load_config
from vigil_fuse.model import AnalysisArtifact, AnalyzerStatus, Finding
from vigil_fuse.reporting import to_json, to_text
from vigil_fuse.sarif import to_sarif
from vigil_fuse.scanner import scan


class ScannerAndReporterTests(unittest.TestCase):
    @staticmethod
    def credential_assignment(value: str) -> str:
        key = "pass" + "word"
        return f'{key} = "{value}"\n'

    @staticmethod
    def esp_idf_secret_config() -> str:
        key = "CONFIG_WIFI_" + "PASS" + "WORD"
        value = "device" + "-secret" + "-123456"
        return f'{key}="{value}"\n'

    def test_generic_profile_scans_berry_source_and_detects_http_ota_endpoint(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "partition_wizard.be"
            source.write_text(
                'static OTA_URL = "http://ota.device.local/releases/latest.bin"\n',
                encoding="utf-8",
            )

            result = scan(root, profile="generic")

        self.assertEqual(1, result.files_scanned)
        self.assertEqual(["FUSE004"], [finding.rule_id for finding in result.findings])

    def test_kconfig_only_rules_skip_unrelated_source_files(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "main.c").write_text("int main(void) { return 0; }\n", encoding="utf-8")
            result = scan(root)

        statuses = {item.name: item.status for item in result.analyzers}
        self.assertEqual("skipped", statuses["native-rule:FUSE006"])
        self.assertEqual("skipped", statuses["native-rule:FUSE007"])

    def test_scan_and_json_report_have_schema_and_relative_location(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source_dir = root / "src"
            source_dir.mkdir()
            source_content = self.credential_assignment("embedded-value-123456")
            (source_dir / "network.py").write_text(source_content, encoding="utf-8")
            (source_dir / "notes.md").write_text(
                self.credential_assignment("not-scanned-from-markdown"), encoding="utf-8"
            )
            (root / "node_modules").mkdir()
            (root / "node_modules" / "module.py").write_text(
                self.credential_assignment("not-scanned-here"), encoding="utf-8"
            )

            result = scan(root)
            payload = json.loads(to_json(result))

        self.assertEqual("1.10", payload["schema_version"])
        self.assertEqual(root.name, payload["target"])
        self.assertNotIn(str(root), to_json(result))
        self.assertEqual(1, payload["summary"]["files_discovered"])
        self.assertEqual(1, payload["summary"]["files_selected"])
        self.assertEqual(1, payload["summary"]["files_scanned"])
        self.assertTrue(payload["summary"]["analysis_performed"])
        self.assertEqual(
            "not-inspected",
            payload["project_context"]["configuration_origin"]["status"],
        )
        finding = payload["findings"][0]
        self.assertEqual("src/network.py", finding["location"]["file"])
        self.assertEqual(1, finding["location"]["start_line"])
        self.assertNotIn("embedded-value-123456", finding["evidence"])
        self.assertEqual("medium", finding["severity"])
        self.assertEqual("high", finding["confidence"])
        self.assertEqual("fuse-native", finding["analyzer"])
        self.assertEqual(64, len(finding["fingerprint"]))
        self.assertEqual([], payload["artifacts"])

    def test_scan_records_latin1_fallback_for_legacy_text_files(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "legacy.c"
            source.write_bytes(
                b'const char *password = "embedded-secret-value"; // caf\xe9\x1b\n'
            )
            result = scan(root)
            report = json.loads(to_json(result))

        self.assertEqual(1, result.files_scanned)
        self.assertEqual({}, result.files_skipped_by_reason)
        self.assertEqual(1, result.encoding_fallback_count)
        self.assertEqual(("legacy.c",), result.encoding_fallback_files)
        self.assertEqual(
            {
                "encoding": "iso-8859-1",
                "count": 1,
                "files": ["legacy.c"],
                "omitted_count": 0,
            },
            report["coverage"]["encoding_fallback"],
        )
        self.assertEqual("FUSE001", report["findings"][0]["rule_id"])
        self.assertNotIn("embedded-secret-value", report["findings"][0]["evidence"])

    def test_sarif_export_keeps_finding_identity_and_severity(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "network.cpp").write_text(
                'const char* endpoint = "' + "http" + "://" + 'device.local";\n',
                encoding="utf-8",
            )
            report = json.loads(to_sarif(scan(root)))
        self.assertEqual("2.1.0", report["version"])
        self.assertEqual("FUSE004", report["runs"][0]["results"][0]["ruleId"])
        self.assertEqual("warning", report["runs"][0]["results"][0]["level"])
        self.assertEqual(
            report["runs"][0]["results"][0]["properties"]["fuseId"],
            "FUSE004:network.cpp:1",
        )
        partial_fingerprints = report["runs"][0]["results"][0]["partialFingerprints"]
        self.assertRegex(partial_fingerprints["primaryLocationLineHash"], r"^[a-f0-9]{64}:1$")
        physical_location = report["runs"][0]["results"][0]["locations"][0]["physicalLocation"]
        self.assertEqual("%SRCROOT%", physical_location["artifactLocation"]["uriBaseId"])
        self.assertIn("%SRCROOT%", report["runs"][0]["originalUriBaseIds"])

    def test_sarif_primary_fingerprint_survives_line_insertion(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "network.cpp"
            endpoint = 'const char* endpoint = "http://device.local";\n'
            source.write_text(endpoint, encoding="utf-8")
            first = json.loads(to_sarif(scan(root)))["runs"][0]["results"][0]
            source.write_text("// unrelated comment\n" + endpoint, encoding="utf-8")
            shifted = json.loads(to_sarif(scan(root)))["runs"][0]["results"][0]

        self.assertEqual(
            first["partialFingerprints"]["primaryLocationLineHash"],
            shifted["partialFingerprints"]["primaryLocationLineHash"],
        )
        self.assertNotEqual(
            first["partialFingerprints"]["vigilIoTFingerprint/v1"],
            shifted["partialFingerprints"]["vigilIoTFingerprint/v1"],
        )
        self.assertEqual(1, first["locations"][0]["physicalLocation"]["region"]["startLine"])
        self.assertEqual(2, shifted["locations"][0]["physicalLocation"]["region"]["startLine"])

    def test_sarif_identity_is_stable_across_working_directories(self) -> None:
        original_cwd = Path.cwd()
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary)
            reports = []
            for parent_name in ("checkout-a", "checkout-b"):
                working_directory = parent / parent_name
                project = working_directory / "device-project"
                project.mkdir(parents=True)
                (project / "network.cpp").write_text(
                    'const char* endpoint = "http://device.local";\n', encoding="utf-8"
                )
                try:
                    os.chdir(working_directory)
                    reports.append(json.loads(to_sarif(scan(Path("device-project")))))
                finally:
                    os.chdir(original_cwd)

        first = reports[0]["runs"][0]["results"][0]
        second = reports[1]["runs"][0]["results"][0]
        self.assertEqual(
            first["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
            second["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
        )
        self.assertEqual(
            first["partialFingerprints"]["primaryLocationLineHash"],
            second["partialFingerprints"]["primaryLocationLineHash"],
        )

    def test_sarif_primary_fingerprint_disambiguates_repeated_matches(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "network.cpp"
            endpoint = 'const char* endpoint = "http://device.local";\n'
            source.write_text(endpoint + endpoint, encoding="utf-8")
            first = json.loads(to_sarif(scan(root)))["runs"][0]["results"]
            source.write_text("// unrelated comment\n" + endpoint + endpoint, encoding="utf-8")
            shifted = json.loads(to_sarif(scan(root)))["runs"][0]["results"]

        first_hashes = [item["partialFingerprints"]["primaryLocationLineHash"] for item in first]
        shifted_hashes = [item["partialFingerprints"]["primaryLocationLineHash"] for item in shifted]
        self.assertEqual(2, len(first_hashes))
        self.assertEqual(2, len(set(first_hashes)))
        self.assertEqual(first_hashes, shifted_hashes)

    def test_sarif_result_limit_records_omitted_results(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "network.cpp").write_text(
                'const char* endpoint = "http://8.8.8.8/update";\n', encoding="utf-8"
            )
            base = scan(root)
            self.assertTrue(base.findings)
            finding = base.findings[0]
            many_findings = tuple(
                replace(
                    finding,
                    id=f"{finding.rule_id}:network.cpp:{index}",
                    fingerprint=f"{index:064x}",
                    evidence=("evidence " + str(index) + " ") * 20,
                )
                for index in range(40)
            )
            result = replace(base, findings=many_findings)
            with patch("vigil_fuse.sarif.MAX_SARIF_BYTES", 8000):
                serialized = to_sarif(result)

        report = json.loads(serialized)
        export = report["runs"][0]["properties"]["sarifExport"]
        self.assertEqual(40, export["resultsAvailable"])
        self.assertGreater(export["resultsOmitted"], 0)
        self.assertEqual(export["resultsIncluded"], len(report["runs"][0]["results"]))
        self.assertLessEqual(len(serialized.encode("utf-8")), 8000)

    def test_sarif_exports_line_less_advisory_and_sbom_hash(self) -> None:
        dependency = Finding(
            id="OSV:GHSA-example:device-lib@1.0:components.cdx.json",
            fingerprint="a" * 64,
            rule_id="OSV-GHSA-example",
            rule_version="osv-scanner 2.3.0",
            analyzer="osv-scanner",
            title="Known vulnerable dependency: device-lib@1.0",
            severity="unknown",
            confidence="high",
            category="dependency-vulnerability",
            file="components.cdx.json",
            start_line=None,
            end_line=None,
            evidence="npm device-lib@1.0 matched advisory GHSA-example",
            explanation="An inventory matched an advisory.",
            potential_impact="Conditional on deployment and reachability.",
            remediation="Review the advisory and update the component.",
            references=("https://osv.dev/vulnerability/GHSA-example",),
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "app.py").write_text("value = 1\n", encoding="utf-8")
            base = scan(root)
        result = replace(
            base,
            findings=(dependency,),
            artifacts=(AnalysisArtifact("components.cdx.json", "application/vnd.cyclonedx+json", "b" * 64),),
        )
        report = json.loads(to_sarif(result))
        result_item = report["runs"][0]["results"][0]
        self.assertNotIn("region", result_item["locations"][0]["physicalLocation"])
        self.assertEqual("note", result_item["level"])
        self.assertEqual("b" * 64, report["runs"][0]["artifacts"][0]["hashes"]["sha-256"])

    def test_text_report_explains_clean_scan(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "app.py").write_text("transport = 'https://device.example'\n", encoding="utf-8")
            report = to_text(scan(root))
        self.assertIn("No findings from the enabled rules.", report)

    def test_unsupported_only_target_is_not_reported_as_clean_scan(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "firmware.bin").write_bytes(b"\x00\xff")
            result = scan(root)
            report = to_text(result)
            payload = json.loads(to_json(result))
        self.assertIn("No supported source/configuration files were analyzed for profile 'generic'.", report)
        self.assertFalse(payload["summary"]["analysis_performed"])

    def test_unsupported_only_target_returns_incomplete_cli_status(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "firmware.bin").write_bytes(b"\x00\xff")
            output = root / "reports"
            stdout = StringIO()
            stderr = StringIO()
            with redirect_stdout(stdout), redirect_stderr(stderr):
                exit_code = main(["scan", str(root), "--output-dir", str(output)])
            report = json.loads((output / "findings.json").read_text(encoding="utf-8"))

        self.assertEqual(2, exit_code)
        self.assertFalse(report["summary"]["analysis_performed"])
        self.assertEqual("detected", report["coverage"]["support"]["status"])

    def test_oversized_source_is_read_only_to_the_configured_limit_and_reported(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "app.py"
            source.write_bytes(b"x" * 1024)

            result = scan(root, max_file_bytes=16)
            report = json.loads(to_json(result))

        self.assertEqual(1, result.files_skipped_by_reason["too_large"])
        self.assertEqual(0, result.files_scanned)
        self.assertFalse(report["summary"]["analysis_performed"])

    def test_esp_idf_profile_discovers_sdkconfig(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "sdkconfig").write_text(
                self.esp_idf_secret_config(), encoding="utf-8"
            )
            generic = scan(root)
            esp_idf = scan(root, profile="esp-idf")
        self.assertEqual(0, generic.files_discovered)
        self.assertEqual(1, esp_idf.files_discovered)
        self.assertEqual("esp-idf", esp_idf.profile)
        self.assertEqual("FUSE001", esp_idf.findings[0].rule_id)

    def test_esp_idf_profile_reports_boot_validation_settings(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            option_a = "CONFIG_BOOTLOADER_" + "SKIP_VALIDATE_ALWAYS"
            option_b = "CONFIG_BOOTLOADER_SKIP_VALIDATE_" + "IN_DEEP_SLEEP"
            (root / "sdkconfig").write_text(
                f"{option_a}=y\n{option_b}=y\n", encoding="utf-8"
            )

            generic = scan(root, profile="generic")
            esp_idf = scan(root, profile="esp-idf")

        self.assertEqual(0, generic.files_scanned)
        self.assertEqual(1, esp_idf.files_scanned)
        self.assertEqual({"FUSE006", "FUSE007"}, {finding.rule_id for finding in esp_idf.findings})
        self.assertTrue(all(finding.file == "sdkconfig" for finding in esp_idf.findings))

    def test_path_filters_are_reported_in_coverage(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "src").mkdir()
            (root / "vendor").mkdir()
            (root / "src" / "app.py").write_text("value = 1\n", encoding="utf-8")
            (root / "vendor" / "app.py").write_text("value = 2\n", encoding="utf-8")
            result = scan(root, exclude=("vendor/**",))
        self.assertEqual(2, result.files_discovered)
        self.assertEqual(1, result.files_selected)
        self.assertEqual(1, result.files_filtered)
        self.assertEqual(1, result.files_scanned)

    def test_output_dir_writes_both_formats_and_is_excluded_from_scan(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "app.py").write_text("value = 1\n", encoding="utf-8")
            output_dir = root / "results"
            output_dir.mkdir()
            (output_dir / "stale.json").write_text(
                '{"password": "old-secret-value"}\n', encoding="utf-8"
            )
            stdout = StringIO()
            stderr = StringIO()
            with redirect_stdout(stdout), redirect_stderr(stderr):
                exit_code = main(["scan", str(root), "--output-dir", str(output_dir)])
            report = json.loads((output_dir / "findings.json").read_text(encoding="utf-8"))
            text_report = (output_dir / "findings.txt").read_text(encoding="utf-8")
            sarif_exists = (output_dir / "findings.sarif").is_file()
        self.assertEqual(0, exit_code)
        self.assertEqual(1, report["summary"]["files_scanned"])
        self.assertEqual(1, report["summary"]["files_filtered"])
        self.assertIn("Files scanned: 1", text_report)
        self.assertTrue(sarif_exists)

    def test_default_scan_writes_report_set_to_fuse_results_folder(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "app.py").write_text("value = 1\n", encoding="utf-8")
            stdout = StringIO()
            stderr = StringIO()
            with redirect_stdout(stdout), redirect_stderr(stderr):
                exit_code = main(["scan", str(root)])
            output_dir = root / ".fuse-results"
            report = json.loads((output_dir / "findings.json").read_text(encoding="utf-8"))
            text_exists = (output_dir / "findings.txt").is_file()
            sarif_exists = (output_dir / "findings.sarif").is_file()

        self.assertEqual(0, exit_code)
        self.assertTrue(text_exists)
        self.assertTrue(sarif_exists)
        self.assertEqual(1, report["summary"]["files_scanned"])

    def test_scan_plan_reports_stages_without_running_scanner(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "app.py").write_text("value = 1\n", encoding="utf-8")
            (root / "board.kicad_pcb").write_text("placeholder\n", encoding="utf-8")
            stdout = StringIO()
            stderr = StringIO()
            with patch("vigil_fuse.cli.scan", side_effect=AssertionError("scanner ran")) as scan_call, \
                 redirect_stdout(stdout), redirect_stderr(stderr):
                exit_code = main(["scan", str(root), "--plan", "--format", "json"])
            plan = json.loads(stdout.getvalue())

        self.assertEqual(0, exit_code)
        self.assertFalse(plan["executed"])
        self.assertEqual(1, plan["discovery_preview"]["files_selected"])
        self.assertEqual(1, plan["discovery_preview"]["hardware_artifact_count"])
        self.assertEqual("planned", plan["stages"][0]["status"])
        scan_call.assert_not_called()

    def test_scan_plan_reports_configured_resource_budgets(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "app.py").write_text("value = 1\n", encoding="utf-8")
            stdout = StringIO()
            with redirect_stdout(stdout):
                exit_code = main([
                    "scan", str(root), "--plan", "--format", "json",
                    "--max-discovered-paths", "5",
                    "--max-discovered-directories", "4",
                    "--max-source-bytes", "100",
                    "--max-scan-seconds", "12",
                ])
            plan = json.loads(stdout.getvalue())

        self.assertEqual(0, exit_code)
        self.assertEqual(
            {
                "discovered_paths": 5,
                "discovered_directories": 4,
                "source_bytes": 100,
                "firmware_image_bytes": 536870912,
                "elapsed_seconds": 12,
                "native_rule_seconds_per_input": 2.0,
                "plan_preview_seconds": 12,
            },
            plan["resource_limits"],
        )

    def test_incomplete_plan_preview_does_not_claim_no_native_inputs_exist(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "a.txt").write_text("not selected by the generic profile\n", encoding="utf-8")
            (root / "b.py").write_text("value = 1\n", encoding="utf-8")
            stdout = StringIO()
            with redirect_stdout(stdout):
                exit_code = main([
                    "scan", str(root), "--plan", "--format", "json",
                    "--max-discovered-paths", "1",
                ])
            plan = json.loads(stdout.getvalue())

        self.assertEqual(0, exit_code)
        self.assertFalse(plan["discovery_preview"]["discovery_complete"])
        self.assertEqual(0, plan["discovery_preview"]["files_selected"])
        self.assertEqual("planned", plan["stages"][0]["status"])
        self.assertIn("incomplete", plan["stages"][0]["reason"])

    def test_aggregate_source_budget_marks_remaining_files_incomplete(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "a.py").write_text("x=1", encoding="utf-8")
            (root / "b.py").write_text("y=2", encoding="utf-8")
            result = scan(root, max_source_bytes=3)
            report = json.loads(to_json(result))

        self.assertEqual(1, result.files_scanned)
        self.assertEqual(3, report["summary"]["source_bytes_read"])
        self.assertEqual(1, report["coverage"]["files_skipped_by_reason"]["total_source_bytes_limit"])
        self.assertIn("total-source-bytes", report["coverage"]["limits_reached"])
        native = next(
            item for item in report["coverage"]["analyzers"] if item["name"] == "fuse-native"
        )
        self.assertEqual("partial", native["status"])

    def test_scan_plan_shows_requested_git_history_stage(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "main.c").write_text("int main(void) { return 0; }\n", encoding="utf-8")
            stdout = StringIO()
            with patch("vigil_fuse.cli.shutil.which", return_value="tool.exe"), \
                 patch(
                     "vigil_fuse.cli.subprocess.run",
                     return_value=SimpleNamespace(returncode=0, stdout=str(root)),
                 ), \
                 patch("vigil_fuse.cli.scan", side_effect=AssertionError("scanner ran")) as scan_call, \
                 redirect_stdout(stdout):
                exit_code = main(["scan", str(root), "--git-history", "--plan", "--format", "json"])
            plan = json.loads(stdout.getvalue())

        history = next(stage for stage in plan["stages"] if stage["name"] == "gitleaks-history")
        self.assertEqual(0, exit_code)
        self.assertEqual("planned", history["status"])
        self.assertTrue(history["requested"])
        self.assertIn("redacted", history["reason"])
        scan_call.assert_not_called()

    def test_doctor_reports_optional_tools_without_blocking(self) -> None:
        tools = (
            ("Syft", None, None),
            ("OSV-Scanner", "C:/tools/osv-scanner.exe", "OSV-Scanner 2.3.0"),
            ("Binwalk", None, None),
        )
        stdout = StringIO()
        with patch("vigil_fuse.cli.inspect_tools", return_value=tools), \
             patch("vigil_fuse.cli.lock_parser_available", return_value=False), \
             redirect_stdout(stdout):
            exit_code = main(["doctor"])

        self.assertEqual(0, exit_code)
        self.assertIn("Syft: not installed", stdout.getvalue())
        self.assertIn("OSV-Scanner: OSV-Scanner 2.3.0", stdout.getvalue())
        self.assertIn("Platform:", stdout.getvalue())
        self.assertIn("Core scanner: available", stdout.getvalue())

    def test_hardware_inventory_reports_known_design_bom_and_hdl_files(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "app.py").write_text("value = 1\n", encoding="utf-8")
            hardware_files = {
                "controller.kicad_sch": "schematic",
                "controller.kicad_pcb": "pcb-layout",
                "controller_BOM.csv": "bill-of-materials",
                "top.gbr": "fabrication",
                "enclosure.step": "mechanical-cad",
                "fpga_top.sv": "hdl",
            }
            for name in hardware_files:
                (root / name).write_text("placeholder\n", encoding="utf-8")

            result = scan(root)
            report = json.loads(to_json(result))

        inventory = report["hardware_inventory"]
        self.assertTrue(inventory["present"])
        self.assertTrue(inventory["complete"])
        self.assertEqual(len(hardware_files), inventory["file_count"])
        self.assertEqual(
            {"bill-of-materials": 1, "fabrication": 1, "hdl": 1, "mechanical-cad": 1,
             "pcb-layout": 1, "schematic": 1},
            inventory["category_counts"],
        )
        self.assertEqual(set(hardware_files), {item["path"] for item in inventory["artifacts"]})

    def test_hardware_inventory_is_marked_incomplete_when_discovery_budget_is_hit(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "a.py").write_text("value = 1\n", encoding="utf-8")
            (root / "b.kicad_pcb").write_text("placeholder\n", encoding="utf-8")
            result = scan(root, max_discovered_paths=1)
            report = json.loads(to_json(result))

        self.assertFalse(report["coverage"]["input_inventory"]["complete"])
        self.assertFalse(report["hardware_inventory"]["complete"])
        self.assertIn("discovery-budget", report["coverage"]["limits_reached"])

    def test_toml_config_applies_profile_and_output_dir(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "sdkconfig").write_text(
                self.esp_idf_secret_config(), encoding="utf-8"
            )
            (root / "app.py").write_text("value = 1\n", encoding="utf-8")
            config = root / "fuse.toml"
            config.write_text(
                '[scan]\nprofile = "esp-idf"\ninclude = ["sdkconfig"]\n'
                'max_discovered_paths = 42\n'
                'max_discovered_directories = 12\n'
                'max_source_bytes = 4096\n'
                'max_scan_seconds = 30\n'
                'max_firmware_bytes = 1073741824\n'
                '[rules]\ndisabled = []\n'
                '[report]\noutput_dir = "scan-results"\n',
                encoding="utf-8",
            )
            stdout = StringIO()
            stderr = StringIO()
            with redirect_stdout(stdout), redirect_stderr(stderr):
                exit_code = main(["scan", str(root), "--config", str(config)])
            report = json.loads(
                (root / "scan-results" / "findings.json").read_text(encoding="utf-8")
            )
            configured_firmware_limit = load_config(config).max_firmware_bytes
            configured_source_limits = load_config(config)
        self.assertEqual(0, exit_code)
        self.assertEqual("esp-idf", report["scan"]["profile"])
        self.assertEqual(1073741824, configured_firmware_limit)
        self.assertEqual(42, configured_source_limits.max_discovered_paths)
        self.assertEqual(12, configured_source_limits.max_discovered_directories)
        self.assertEqual(4096, configured_source_limits.max_source_bytes)
        self.assertEqual(30, configured_source_limits.max_scan_seconds)
        self.assertEqual(1, report["summary"]["files_scanned"])
        self.assertEqual(2, report["summary"]["files_filtered"])

    def test_config_accepts_optional_analysis_switches_and_validates_offline(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            config = Path(temporary) / "fuse.toml"
            config.write_text(
                "[analysis]\nsbom = true\nvulnerabilities = true\n"
                "firmware = false\noffline_vulnerabilities = true\ngit_history = true\n",
                encoding="utf-8",
            )
            loaded = load_config(config)
            config.write_text(
                "[analysis]\noffline_vulnerabilities = true\n",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ValueError, "requires analysis.vulnerabilities"):
                load_config(config)
        self.assertTrue(loaded.sbom)
        self.assertTrue(loaded.vulnerabilities)
        self.assertTrue(loaded.offline_vulnerabilities)
        self.assertTrue(loaded.git_history)

    def test_single_report_output_overrides_configured_output_directory(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "app.py").write_text("value = 1\n", encoding="utf-8")
            config = root / "fuse.toml"
            config.write_text('[report]\noutput_dir = "scan-results"\n', encoding="utf-8")
            report_path = root / "scan.json"
            stdout = StringIO()
            stderr = StringIO()
            with redirect_stdout(stdout), redirect_stderr(stderr):
                exit_code = main([
                    "scan", str(root), "--config", str(config),
                    "--output", str(report_path), "--format", "json",
                ])
            report = json.loads(report_path.read_text(encoding="utf-8"))
            output_dir_created = (root / "scan-results").exists()
        self.assertEqual(0, exit_code)
        self.assertEqual("1.10", report["schema_version"])
        self.assertFalse(output_dir_created)

    def test_firmware_target_is_hashed_without_claiming_native_content_scan(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            firmware = Path(temporary) / "device.bin"
            firmware.write_bytes(b"firmware-image\x00payload")
            result = scan(firmware, firmware_image=True)
            payload = json.loads(to_json(result))
        self.assertEqual("firmware-image", result.target_kind)
        self.assertEqual(64, len(result.input_manifest_sha256))
        self.assertEqual(0, result.files_scanned)
        self.assertEqual("firmware-image", payload["scan"]["target_kind"])

    def test_firmware_image_over_configured_limit_is_rejected_before_hashing(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            firmware = Path(temporary) / "device.bin"
            firmware.write_bytes(b"firmware")
            with patch("vigil_fuse.scanner._sha256_file") as hash_file:
                result = scan(firmware, firmware_image=True, max_firmware_bytes=4)
            report = json.loads(to_json(result))
        status = next(item for item in result.analyzers if item.name == "firmware-input")
        self.assertEqual("failed", status.status)
        self.assertFalse(result.analysis_performed)
        self.assertIn("firmware-image-bytes", result.limits_reached)
        self.assertEqual("unsupported", report["coverage"]["support"]["status"])
        hash_file.assert_not_called()

    def test_oversized_firmware_writes_unsupported_report_and_skips_binwalk(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            firmware = root / "device.bin"
            firmware.write_bytes(b"firmware")
            output = root / "reports"
            stdout = StringIO()
            stderr = StringIO()
            with patch("vigil_fuse.cli.identify_firmware") as binwalk, \
                 redirect_stdout(stdout), redirect_stderr(stderr):
                exit_code = main([
                    "scan", str(firmware), "--firmware", "--max-firmware-bytes", "4",
                    "--output-dir", str(output),
                ])
            report = json.loads((output / "findings.json").read_text(encoding="utf-8"))

        self.assertEqual(2, exit_code)
        self.assertFalse(report["summary"]["analysis_performed"])
        self.assertEqual("unsupported", report["coverage"]["support"]["status"])
        statuses = {item["name"]: item["status"] for item in report["coverage"]["analyzers"]}
        self.assertEqual("failed", statuses["firmware-input"])
        self.assertEqual("skipped", statuses["binwalk"])
        binwalk.assert_not_called()

    def test_successful_binwalk_signature_scan_is_complete_for_its_contract(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            firmware = Path(temporary) / "device.bin"
            firmware.write_bytes(b"firmware-image\x00payload")
            stdout = StringIO()
            stderr = StringIO()
            signature_scan = AdapterResult(
                AnalyzerStatus(
                    "binwalk",
                    "completed",
                    version="Binwalk v3",
                    detail="Signature identification only; no extraction or firmware execution was attempted.",
                )
            )
            with patch("vigil_fuse.cli.identify_firmware", return_value=signature_scan), \
                 redirect_stdout(stdout), redirect_stderr(stderr):
                exit_code = main(["scan", str(firmware), "--firmware"])
            report = json.loads(
                (Path(temporary) / ".fuse-results" / "findings.json").read_text(encoding="utf-8")
            )

        self.assertEqual(0, exit_code)
        binwalk_status = next(
            analyzer for analyzer in report["coverage"]["analyzers"]
            if analyzer["name"] == "binwalk"
        )
        self.assertEqual("completed", binwalk_status["status"])

    def test_truncated_binwalk_report_returns_incomplete_cli_status(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            firmware = root / "device.bin"
            firmware.write_bytes(b"firmware-image\x00payload")
            output = root / "reports"
            stdout = StringIO()
            stderr = StringIO()
            partial_result = AdapterResult(
                AnalyzerStatus(
                    "binwalk",
                    "partial",
                    version="Binwalk v3",
                    detail="The saved signature report was truncated.",
                )
            )
            with patch("vigil_fuse.cli.identify_firmware", return_value=partial_result), \
                 redirect_stdout(stdout), redirect_stderr(stderr):
                exit_code = main([
                    "scan", str(firmware), "--firmware", "--output-dir", str(output)
                ])
            report = json.loads((output / "findings.json").read_text(encoding="utf-8"))

        self.assertEqual(2, exit_code)
        binwalk_status = next(
            analyzer for analyzer in report["coverage"]["analyzers"]
            if analyzer["name"] == "binwalk"
        )
        self.assertEqual("partial", binwalk_status["status"])

    def test_sbom_target_is_routed_away_from_native_source_rules(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            sbom = Path(temporary) / "components.cdx.json"
            sbom.write_text(
                json.dumps({"bomFormat": "CycloneDX", "specVersion": "1.7", "components": []}),
                encoding="utf-8",
            )
            result = scan(sbom, sbom_input=True)
            report = to_text(result)
        self.assertEqual("sbom", result.target_kind)
        self.assertEqual(0, result.files_scanned)
        self.assertEqual(64, len(result.input_manifest_sha256))
        self.assertIn("use --vulnerabilities", report)

    def test_existing_sbom_is_sent_to_osv_without_syft_regeneration(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            sbom = root / "device.cdx.json"
            sbom.write_text('{"bomFormat":"CycloneDX","components":[]}', encoding="utf-8")
            output = root / "reports"
            stdout = StringIO()
            stderr = StringIO()
            result = AdapterResult(AnalyzerStatus("osv-scanner", "completed", findings=0))
            with patch("vigil_fuse.cli.generate_sbom") as generate, \
                 patch("vigil_fuse.cli.scan_vulnerabilities", return_value=result) as osv, \
                 redirect_stdout(stdout), redirect_stderr(stderr):
                exit_code = main([
                    "scan", str(sbom), "--vulnerabilities", "--output-dir", str(output)
                ])
            report = json.loads((output / "findings.json").read_text(encoding="utf-8"))
            osv_kwargs = osv.call_args.kwargs

        self.assertEqual(0, exit_code)
        self.assertEqual("sbom", report["scan"]["target_kind"])
        self.assertEqual(sbom, osv_kwargs["sbom_path"])
        generate.assert_not_called()

    def test_strict_no_network_mode_is_passed_to_osv_and_recorded(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            sbom = root / "device.cdx.json"
            sbom.write_text('{"bomFormat":"CycloneDX","components":[]}', encoding="utf-8")
            output = root / "reports"
            stdout = StringIO()
            stderr = StringIO()
            result = AdapterResult(AnalyzerStatus("osv-scanner", "completed", version="OSV-Scanner 2.3.0"))
            with patch("vigil_fuse.cli.scan_vulnerabilities", return_value=result) as osv, \
                 redirect_stdout(stdout), redirect_stderr(stderr):
                exit_code = main([
                    "scan", str(sbom), "--vulnerabilities", "--no-network",
                    "--output-dir", str(output),
                ])
            report = json.loads((output / "findings.json").read_text(encoding="utf-8"))

        self.assertEqual(0, exit_code)
        self.assertTrue(osv.call_args.kwargs["no_network"])
        self.assertEqual("no-network", report["scan"]["network_policy"])

    def test_oversized_sbom_is_reported_as_unsupported_without_osv_invocation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            sbom = root / "bom.json"
            sbom.write_text('{"bomFormat":"CycloneDX","components":[]}', encoding="utf-8")
            output = root / "reports"
            stdout = StringIO()
            stderr = StringIO()
            with patch("vigil_fuse.cli.MAX_SBOM_DETECTION_BYTES", 8), \
                 patch("vigil_fuse.scanner.MAX_SBOM_DETECTION_BYTES", 8), \
                 patch("vigil_fuse.cli.scan_vulnerabilities") as osv, \
                 redirect_stdout(stdout), redirect_stderr(stderr):
                exit_code = main([
                    "scan", str(sbom), "--vulnerabilities", "--output-dir", str(output)
                ])
            report = json.loads((output / "findings.json").read_text(encoding="utf-8"))

        self.assertEqual(2, exit_code)
        self.assertEqual("unsupported", report["coverage"]["support"]["label"])
        self.assertEqual(1, report["summary"]["files_skipped"])
        self.assertFalse(report["summary"]["analysis_performed"])
        osv.assert_not_called()

    def test_missing_target_is_reported_as_error(self) -> None:
        with self.assertRaises(FileNotFoundError):
            scan(Path("missing-fuse-target"))

    def test_explicit_symbolic_link_target_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            actual = root / "app.py"
            actual.write_text("value = 1\n", encoding="utf-8")
            link = root / "linked-app.py"
            try:
                link.symlink_to(actual)
            except (OSError, NotImplementedError) as error:
                self.skipTest(f"symbolic links are unavailable: {error}")

            with self.assertRaisesRegex(ValueError, "Symbolic-link targets are not followed"):
                scan(link)

    def test_env_files_are_scanned_and_fail_threshold_is_applied(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            env_key = "pass" + "word"
            env_content = f"{env_key}=embedded-env-value-123\n"
            (root / ".env").write_text(
                env_content, encoding="utf-8"
            )
            result = scan(root)
            self.assertEqual(1, result.files_scanned)
            self.assertEqual("FUSE001", result.findings[0].rule_id)
            stdout = StringIO()
            stderr = StringIO()
            with redirect_stdout(stdout), redirect_stderr(stderr):
                exit_code = main(["scan", str(root), "--fail-on", "medium"])
        self.assertEqual(1, exit_code)
        self.assertIn("FUSE001", stdout.getvalue())


if __name__ == "__main__":
    unittest.main()
