from __future__ import annotations

import csv
import hashlib
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path

from vigil_fuse.build_context import inspect_compilation_database, inspect_platformio
from vigil_fuse.cli import main
from vigil_fuse.hardware_bom import hardware_bom_document, inspect_hardware_bom
from vigil_fuse.model import DependencyComponent, Finding
from vigil_fuse.product_context import (
    import_vex,
    inspect_provenance,
    package_purl,
    validate_package_purl,
)
from vigil_fuse.reporting import to_json
from vigil_fuse.scanner import scan


def _dependency_finding() -> Finding:
    return Finding(
        id="OSV:CVE-2026-1000:sample@1.0.0:package-lock.json",
        fingerprint="a" * 64,
        rule_id="OSV-CVE-2026-1000",
        rule_version="osv-scanner 2.5.0",
        analyzer="osv-scanner",
        title="Known vulnerable dependency: sample@1.0.0 (CVE-2026-1000)",
        severity="high",
        confidence="high",
        category="dependency-vulnerability",
        file="package-lock.json",
        start_line=None,
        end_line=None,
        evidence="npm package sample@1.0.0; advisory CVE-2026-1000; source package-lock.json",
        explanation="An inventory matched an advisory.",
        potential_impact="The impact depends on deployed use and reachability.",
        remediation="Review the advisory and update the package.",
        component=DependencyComponent(
            name="sample",
            version="1.0.0",
            ecosystem="npm",
            purl="pkg:npm/sample@1.0.0",
        ),
    )


class PlatformIOInventoryTests(unittest.TestCase):
    def test_platformio_environment_matrix_resolves_shared_and_extended_settings(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "platformio.ini").write_text(
                "[platformio]\n"
                "default_envs = release\n"
                "[env]\n"
                "platform = espressif32\n"
                "framework = arduino\n"
                "upload_protocol = esptool\n"
                "upload_password = should-not-be-reported\n"
                "[env:base]\n"
                "board = esp32dev\n"
                "[env:release]\n"
                "extends = base\n"
                "build_type = release\n"
                "framework = espidf\n",
                encoding="utf-8",
            )
            inventory = inspect_platformio(root)
            report = json.loads(to_json(scan(root)))

        self.assertEqual("parsed", inventory.status)
        self.assertEqual(("release",), inventory.selected_environments)
        release = next(item for item in inventory.environments if item.name == "release")
        self.assertEqual("espressif32", release.platform)
        self.assertEqual("esp32dev", release.board)
        self.assertEqual(("espidf",), release.frameworks)
        self.assertEqual("release", release.build_type)
        self.assertNotIn("should-not-be-reported", json.dumps(report))
        self.assertEqual("release", report["build_context"]["platformio"]["selected_environments"][0])

    def test_platformio_selection_rejects_unknown_environment(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "platformio.ini").write_text("[env:board]\nboard = esp32dev\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "Unknown PlatformIO"):
                inspect_platformio(root, selected_environments=("missing",))

    def test_platformio_metadata_removes_terminal_controls(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "platformio.ini").write_text(
                "[env:release\x1b[31m]\nplatform = espressif\x1b[31m32\nboard = esp32dev\n",
                encoding="utf-8",
            )
            inventory = inspect_platformio(root)

        environment = inventory.environments[0]
        self.assertNotIn("\x1b", environment.name)
        self.assertNotIn("\x1b", environment.platform)

    def test_cli_plan_shows_platformio_and_compile_database_without_execution(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "platformio.ini").write_text(
                "[env:esp32dev]\nplatform = espressif32\nboard = esp32dev\nframework = arduino\n",
                encoding="utf-8",
            )
            (root / "compile_commands.json").write_text(
                json.dumps([
                    {
                        "directory": str(root),
                        "file": "main.c",
                        "arguments": ["xtensa-esp32-elf-gcc", "-c", "main.c"],
                    }
                ]),
                encoding="utf-8",
            )
            stdout = StringIO()
            with redirect_stdout(stdout):
                exit_code = main(["scan", str(root), "--plan", "--format", "json", "--platformio-env", "esp32dev"])
            plan = json.loads(stdout.getvalue())

        stages = {item["name"]: item for item in plan["stages"]}
        self.assertEqual(0, exit_code)
        self.assertFalse(plan["executed"])
        self.assertEqual(["esp32dev"], plan["build_context"]["platformio"]["selected_environments"])
        self.assertEqual(1, plan["build_context"]["compilation_database"]["unique_translation_units"])
        self.assertIn("never executed", stages["compilation-database-index"]["reason"])


class CompilationDatabaseTests(unittest.TestCase):
    def test_compilation_database_is_indexed_as_data_without_running_commands(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "src").mkdir()
            (root / "build").mkdir()
            marker = root / "command-was-run.txt"
            outside_source = root.parent / "outside-project" / "lib.c"
            database = [
                {
                    "directory": str(root / "build"),
                    "file": "../src/main.c",
                    "arguments": ["xtensa-esp32-elf-gcc", "-c", "../src/main.c"],
                },
                {
                    "directory": str(root / "build"),
                    "file": str(outside_source),
                    "command": f'python -c "from pathlib import Path; Path(r\'{marker}\').write_text(\'ran\')"',
                },
                {"file": "missing-directory.c"},
            ]
            (root / "compile_commands.json").write_text(json.dumps(database), encoding="utf-8")
            result = scan(root)
            report = json.loads(to_json(result))

        inventory = report["build_context"]["compilation_database"]
        self.assertEqual("partial", inventory["status"])
        self.assertEqual(3, inventory["entry_count"])
        self.assertEqual(2, inventory["unique_translation_units"])
        self.assertEqual(1, inventory["in_target_source_count"])
        self.assertEqual(1, inventory["external_source_count"])
        self.assertEqual(1, inventory["malformed_entries"])
        self.assertEqual(1, inventory["compiler_families"]["gcc-compatible"])
        self.assertFalse(marker.exists())
        self.assertNotIn(str(root / "build"), json.dumps(report))

    def test_explicit_compilation_database_cannot_escape_target(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "project"
            root.mkdir()
            outside = Path(temporary) / "compile_commands.json"
            outside.write_text("[]", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "inside the scan target"):
                inspect_compilation_database(root, database_path=outside)


class HardwareBOMTests(unittest.TestCase):
    def test_csv_bom_normalizes_components_and_emits_cyclonedx_hbom(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "board-bom.csv"
            source.write_text(
                "Reference,Value,Footprint,Manufacturer,MPN\n"
                "R1,R 10k,0603,Acme,RES-10K\n"
                'C1; C2,100nF,0402,Parts Inc,CAP-100N\n',
                encoding="utf-8",
            )
            inventory = inspect_hardware_bom(root, source.name)
            document = json.loads(hardware_bom_document(inventory, product_name="lab/controller"))
            result = scan(root, hardware_bom=source.name)
            report = json.loads(to_json(result))

        self.assertEqual("imported", inventory.status)
        self.assertEqual(2, inventory.component_count)
        self.assertEqual(3, inventory.quantity_total)
        self.assertEqual("CycloneDX", document["bomFormat"])
        self.assertEqual("1.6", document["specVersion"])
        self.assertEqual("device", document["metadata"]["component"]["type"])
        self.assertEqual(["R1", "C1; C2"], [item["properties"][0]["value"] for item in document["components"]])
        self.assertEqual(2, report["hardware_bom"]["component_count"])

    def test_invalid_hardware_bom_is_reported_without_inventing_components(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "bom.csv"
            source.write_text("Part,Color\nconnector,blue\n", encoding="utf-8")
            inventory = inspect_hardware_bom(root, source.name)

        self.assertEqual("invalid", inventory.status)
        self.assertEqual(0, inventory.component_count)
        self.assertIn("reference/designator", inventory.limitations[0])

    def test_cli_writes_hbom_artifact_and_links_its_digest_in_report(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "main.c").write_text("int main(void) { return 0; }\n", encoding="utf-8")
            (root / "bom.csv").write_text(
                "Reference,Value,Footprint\nR1,10k,0603\n", encoding="utf-8"
            )
            stdout = StringIO()
            with redirect_stdout(stdout):
                exit_code = main(["scan", str(root), "--hardware-bom", "bom.csv", "--format", "json"])
            report = json.loads((root / ".fuse-results" / "findings.json").read_text(encoding="utf-8"))
            hbom_path = root / ".fuse-results" / "hardware-bom.cdx.json"
            digest = hashlib.sha256(hbom_path.read_bytes()).hexdigest()

        self.assertEqual(0, exit_code)
        self.assertEqual("1.10", report["schema_version"])
        self.assertEqual(digest, report["artifacts"][0]["sha256"])
        self.assertEqual("hardware-bom.cdx.json", report["artifacts"][0]["path"])


class ProductContextTests(unittest.TestCase):
    def test_common_osv_ecosystems_get_package_urls(self) -> None:
        self.assertEqual("pkg:pypi/requests@2.32.0", package_purl("PyPI", "Requests", "2.32.0"))
        self.assertEqual("pkg:npm/%40scope/package@1.2.3", package_purl("npm", "@scope/package", "1.2.3"))
        self.assertEqual(
            "pkg:maven/org.example/demo@1.0",
            package_purl("Maven", "org.example:demo", "1.0"),
        )
        self.assertIsNone(package_purl("custom", "package", "1"))

    def test_product_package_url_requires_a_type_and_name(self) -> None:
        self.assertEqual("pkg:generic/device@1.0", validate_package_purl("pkg:generic/device@1.0"))
        for invalid in ("pkg:", "pkg:generic", "pkg:generic/", "pkg:generic/device%GG"):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                validate_package_purl(invalid)

    def test_vex_review_matches_product_purl_package_purl_and_advisory_exactly(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "review.vex.json").write_text(
                json.dumps(
                    {
                        "bomFormat": "CycloneDX",
                        "specVersion": "1.6",
                        "metadata": {"component": {"type": "application", "name": "device", "purl": "pkg:generic/device@1.0"}},
                        "vulnerabilities": [
                            {
                                "id": "CVE-2026-1000",
                                "analysis": {
                                    "state": "not_affected",
                                    "justification": "code_not_present",
                                    "detail": "The affected feature is not included in this build.\x1b[2J",
                                },
                                "affects": [{"ref": "pkg:npm/sample@1.0.0"}],
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            finding = _dependency_finding()
            findings, vex_import = import_vex(
                root,
                "review.vex.json",
                product_purl="pkg:generic/device@1.0",
                findings=(finding,),
            )

        self.assertEqual("imported", vex_import.status)
        self.assertEqual(1, vex_import.matched_findings)
        self.assertEqual("not_affected", findings[0].vex_review.state)
        self.assertEqual("high", findings[0].severity)
        self.assertNotIn("\x1b", findings[0].vex_review.detail)

    def test_vex_product_mismatch_does_not_apply_review(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "review.vex.json").write_text(
                json.dumps({
                    "bomFormat": "CycloneDX",
                    "specVersion": "1.5",
                    "metadata": {"component": {"purl": "pkg:generic/other@1"}},
                    "vulnerabilities": [],
                }),
                encoding="utf-8",
            )
            findings, vex_import = import_vex(
                root,
                "review.vex.json",
                product_purl="pkg:generic/device@1",
                findings=(_dependency_finding(),),
            )

        self.assertEqual("invalid", vex_import.status)
        self.assertIsNone(findings[0].vex_review)

    def test_provenance_only_reports_subject_digest_match_not_authentication(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            firmware = root / "firmware.bin"
            firmware.write_bytes(b"signed firmware placeholder")
            digest = hashlib.sha256(firmware.read_bytes()).hexdigest()
            (root / "firmware.intoto.json").write_text(
                json.dumps(
                    {
                        "_type": "https://in-toto.io/Statement/v1",
                        "predicateType": "https://slsa.dev/provenance/v1",
                        "subject": [{"name": "dist/firmware.bin", "digest": {"sha256": digest}}],
                        "predicate": {
                            "buildDefinition": {"buildType": "https://example.invalid/build"},
                            "runDetails": {"builder": {"id": "https://example.invalid/builder"}},
                        },
                    }
                ),
                encoding="utf-8",
            )
            record = inspect_provenance(
                root,
                "firmware.intoto.json",
                firmware_path=firmware,
                max_firmware_bytes=1024,
            )

        self.assertEqual("subject-match", record.status)
        self.assertEqual("firmware.bin", record.subject_name)
        self.assertFalse(record.signature_verified)
        self.assertIn("does not authenticate", record.limitations[0])

    def test_provenance_malformed_types_return_invalid_instead_of_crashing(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            firmware = root / "firmware.bin"
            firmware.write_bytes(b"firmware")
            (root / "bad.intoto.json").write_text(
                json.dumps({"_type": [], "predicateType": {}, "subject": [], "predicate": []}),
                encoding="utf-8",
            )
            record = inspect_provenance(
                root,
                "bad.intoto.json",
                firmware_path=firmware,
                max_firmware_bytes=1024,
            )

        self.assertEqual("invalid", record.status)
