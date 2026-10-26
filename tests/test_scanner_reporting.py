from pathlib import Path
from contextlib import redirect_stderr, redirect_stdout
from dataclasses import replace
from io import StringIO
import json
import tempfile
import unittest
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
                'static OTA_URL = "http://ota.device.example/releases/latest.bin"\n',
                encoding="utf-8",
            )

            result = scan(root, profile="generic")

        self.assertEqual(1, result.files_scanned)
        self.assertEqual(["FUSE004"], [finding.rule_id for finding in result.findings])

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

        self.assertEqual("1.2", payload["schema_version"])
        self.assertEqual(1, payload["summary"]["files_discovered"])
        self.assertEqual(1, payload["summary"]["files_selected"])
        self.assertEqual(1, payload["summary"]["files_scanned"])
        self.assertTrue(payload["summary"]["analysis_performed"])
        finding = payload["findings"][0]
        self.assertEqual("src/network.py", finding["location"]["file"])
        self.assertEqual(1, finding["location"]["start_line"])
        self.assertNotIn("embedded-value-123456", finding["evidence"])
        self.assertEqual("medium", finding["severity"])
        self.assertEqual("high", finding["confidence"])
        self.assertEqual("fuse-native", finding["analyzer"])
        self.assertEqual(64, len(finding["fingerprint"]))
        self.assertEqual([], payload["artifacts"])

    def test_sarif_export_keeps_finding_identity_and_severity(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "network.cpp").write_text(
                'const char* endpoint = "' + "http" + "://" + 'device.example";\n',
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
        self.assertEqual(0, exit_code)
        self.assertEqual("esp-idf", report["scan"]["profile"])
        self.assertEqual(1, report["summary"]["files_scanned"])
        self.assertEqual(2, report["summary"]["files_filtered"])

    def test_config_accepts_optional_analysis_switches_and_validates_offline(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            config = Path(temporary) / "fuse.toml"
            config.write_text(
                "[analysis]\nsbom = true\nvulnerabilities = true\n"
                "firmware = false\noffline_vulnerabilities = true\n",
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
        self.assertEqual("1.2", report["schema_version"])
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

    def test_missing_target_is_reported_as_error(self) -> None:
        with self.assertRaises(FileNotFoundError):
            scan(Path("missing-fuse-target"))

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
