from __future__ import annotations

import json
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from jsonschema import Draft202012Validator

from vigil_fuse.reporting import to_json
from vigil_fuse.scanner import scan
from vigil_fuse.model import (
    DependencyComponent,
    Finding,
    ProvenanceRecord,
    VexImport,
    VexReview,
)


class ReportSchemaTests(unittest.TestCase):
    def test_current_report_validates_against_packaged_schema(self) -> None:
        schema_path = (
            Path(__file__).parents[1]
            / "src"
            / "vigil_fuse"
            / "schemas"
            / "fuse-report-1.10.schema.json"
        )
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
        Draft202012Validator.check_schema(schema)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "main.c").write_text("int main(void) { return 0; }\n", encoding="utf-8")
            report = json.loads(to_json(scan(root)))

        Draft202012Validator(schema).validate(report)

    def test_report_schema_rejects_unrecognized_fields(self) -> None:
        schema_path = (
            Path(__file__).parents[1]
            / "src"
            / "vigil_fuse"
            / "schemas"
            / "fuse-report-1.10.schema.json"
        )
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
        report = {
            "schema_version": "1.10",
            "tool": {"name": "FUSE", "version": "test"},
            "target": ".",
            "unexpected": True,
        }
        validator = Draft202012Validator(schema)
        self.assertTrue(list(validator.iter_errors(report)))

    def test_reviewed_advisory_report_validates_with_component_and_vex_context(self) -> None:
        schema_path = (
            Path(__file__).parents[1]
            / "src"
            / "vigil_fuse"
            / "schemas"
            / "fuse-report-1.10.schema.json"
        )
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
        finding = Finding(
            id="OSV:CVE-2026-1000:sample@1.0.0:package-lock.json",
            fingerprint="a" * 64,
            rule_id="OSV-CVE-2026-1000",
            rule_version="test",
            analyzer="osv-scanner",
            title="Known vulnerable dependency",
            severity="high",
            confidence="high",
            category="dependency-vulnerability",
            file="package-lock.json",
            start_line=None,
            end_line=None,
            evidence="package sample@1.0.0; advisory CVE-2026-1000",
            explanation="Inventory evidence matched an advisory.",
            potential_impact="Impact depends on inclusion and reachability.",
            remediation="Review and update the dependency.",
            component=DependencyComponent("sample", "1.0.0", "npm", "pkg:npm/sample@1.0.0"),
            vex_review=VexReview(
                "not_affected", "code_not_present", "Reviewed against the selected product."
            ),
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "main.c").write_text("int main(void) { return 0; }\n", encoding="utf-8")
            result = replace(
                scan(root),
                findings=(finding,),
                product_purl="pkg:generic/device@1.0",
                vex_import=VexImport(
                    status="imported",
                    source_path="device.vex.json",
                    sha256="b" * 64,
                    byte_size=100,
                    product_purl="pkg:generic/device@1.0",
                    record_count=1,
                    matched_findings=1,
                ),
                provenance=ProvenanceRecord(
                    status="subject-match",
                    source_path="firmware.intoto.json",
                    sha256="c" * 64,
                    byte_size=200,
                    predicate_type="https://slsa.dev/provenance/v1",
                    builder_id="https://example.invalid/builder",
                    build_type="https://example.invalid/build",
                    subject_name="firmware.bin",
                    subject_sha256="d" * 64,
                    signature_verified=False,
                    limitations=("Subject digest compared; signature not checked.",),
                ),
            )
            report = json.loads(to_json(result))

        Draft202012Validator(schema).validate(report)

    def test_build_context_and_hardware_bom_report_validate(self) -> None:
        schema_path = (
            Path(__file__).parents[1]
            / "src"
            / "vigil_fuse"
            / "schemas"
            / "fuse-report-1.10.schema.json"
        )
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "main.c").write_text("int main(void) { return 0; }\n", encoding="utf-8")
            (root / "platformio.ini").write_text(
                "[platformio]\ndefault_envs = release\n"
                "[env:release]\nplatform = espressif32\nboard = esp32dev\nframework = arduino\n",
                encoding="utf-8",
            )
            (root / "compile_commands.json").write_text(
                json.dumps(
                    [
                        {
                            "directory": str(root),
                            "file": "main.c",
                            "arguments": ["clang", "-c", "main.c"],
                        }
                    ]
                ),
                encoding="utf-8",
            )
            (root / "bom.csv").write_text(
                "Reference,Value,Footprint,Manufacturer,MPN\nR1,10k,0603,Acme,RES-10K\n",
                encoding="utf-8",
            )
            result = scan(root, hardware_bom="bom.csv")
            report = json.loads(to_json(result))

        Draft202012Validator(schema).validate(report)
