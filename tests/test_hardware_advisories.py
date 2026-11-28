from __future__ import annotations

from dataclasses import replace
import json
from pathlib import Path
import tempfile
import unittest

from vigil_fuse.hardware_advisories import (
    MAX_ADVISORY_CATALOG_BYTES,
    findings_from_matches,
    load_advisory_catalog,
    match_hardware_bom,
    parse_advisory_catalog,
)
from vigil_fuse.model import HardwareBOMComponent, HardwareBOMInventory
from vigil_fuse.reporting import to_json
from vigil_fuse.sarif import to_sarif
from vigil_fuse.sparta_mapping import sparta_mapping_document
from vigil_fuse.scanner import scan
from vigil_fuse.cli import main
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO


def inventory(*components: HardwareBOMComponent) -> HardwareBOMInventory:
    return HardwareBOMInventory(
        status="imported",
        source_path="bom.csv",
        component_count=len(components),
        components=components,
    )


class HardwareAdvisoryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.catalog = load_advisory_catalog()
        self.advisory = self.catalog[0]

    def test_exact_part_match_keeps_unknown_revision_unknown(self) -> None:
        component = HardwareBOMComponent(
            reference="U1",
            name="ESP32",
            quantity=1,
            manufacturer="ESPRESSIF SYSTEMS",
            part_number="ESP32-WROOM-32",
        )

        matches = match_hardware_bom(inventory(component), catalog=self.catalog)

        self.assertEqual(1, len(matches))
        self.assertEqual("REVISION_UNKNOWN", matches[0].status)

    def test_family_match_does_not_infer_silicon_revision(self) -> None:
        component = HardwareBOMComponent(
            reference="U1",
            name="ESP32-WROOM-32E module",
            quantity=1,
            manufacturer="Espressif",
            part_number="ESP32-WROOM-32E",
        )

        matches = match_hardware_bom(inventory(component), catalog=self.catalog)

        self.assertEqual("FAMILY_CANDIDATE", matches[0].status)

    def test_affected_revision_requires_all_explicit_conditions(self) -> None:
        component = HardwareBOMComponent(
            reference="U1",
            name="ESP32",
            quantity=1,
            manufacturer="Espressif",
            part_number="ESP32",
            revision="Rev v3.0",
        )
        evidence = {("U1", condition): True for condition in self.advisory.conditions}

        without_conditions = match_hardware_bom(inventory(component), catalog=self.catalog)
        confirmed = match_hardware_bom(
            inventory(component), catalog=self.catalog, condition_evidence=evidence
        )

        self.assertEqual("CONDITION_UNKNOWN", without_conditions[0].status)
        self.assertEqual("MATCH_CONFIRMED", confirmed[0].status)

    def test_only_explicit_unaffected_revision_is_not_affected(self) -> None:
        component = HardwareBOMComponent(
            reference="U1",
            name="ESP32",
            quantity=1,
            manufacturer="Espressif",
            part_number="ESP32",
            revision="2.0",
        )
        catalog = (replace(self.advisory, unaffected_revisions=("v2.0",)),)

        matches = match_hardware_bom(inventory(component), catalog=catalog)

        self.assertEqual("NOT_AFFECTED_WITH_EVIDENCE", matches[0].status)

    def test_unknown_revision_is_not_suppressed_by_unlisted_revision(self) -> None:
        component = HardwareBOMComponent(
            reference="U1",
            name="ESP32",
            quantity=1,
            manufacturer="Espressif",
            part_number="ESP32",
            revision="2.0",
        )

        matches = match_hardware_bom(inventory(component), catalog=self.catalog)

        self.assertEqual("UNSUPPORTED", matches[0].status)

    def test_other_esp32_series_do_not_match_classic_esp32_advisory(self) -> None:
        component = HardwareBOMComponent(
            reference="U1",
            name="ESP32-C3",
            quantity=1,
            manufacturer="Espressif",
            part_number="ESP32-C3",
        )

        self.assertEqual((), match_hardware_bom(inventory(component), catalog=self.catalog))

    def test_duplicate_bom_rows_are_deduplicated_by_component_identity(self) -> None:
        component = HardwareBOMComponent(
            reference="U1",
            name="ESP32",
            quantity=1,
            manufacturer="Espressif",
            part_number="ESP32",
        )

        matches = match_hardware_bom(inventory(component, component), catalog=self.catalog)

        self.assertEqual(1, len(matches))

    def test_findings_keep_intrinsic_severity_unknown(self) -> None:
        component = HardwareBOMComponent(
            reference="U1",
            name="ESP32",
            quantity=1,
            manufacturer="Espressif",
            part_number="ESP32",
        )
        matches = match_hardware_bom(inventory(component), catalog=self.catalog)
        findings = findings_from_matches(matches, source_path="bom.csv")

        self.assertEqual("unknown", findings[0].severity)
        self.assertEqual("candidate", findings[0].applicability)
        self.assertEqual("not-validated", findings[0].validation_status)

    def test_sparta_mapping_is_review_only_and_source_backed(self) -> None:
        component = HardwareBOMComponent(
            reference="U1",
            name="ESP32",
            quantity=1,
            manufacturer="Espressif",
            part_number="ESP32",
        )
        findings = findings_from_matches(
            match_hardware_bom(inventory(component), catalog=self.catalog),
            source_path="bom.csv",
        )

        document = json.loads(sparta_mapping_document(findings) or "{}")

        self.assertFalse(document["compliance_certification"])
        self.assertEqual("EX-0006", document["mappings"][0]["sparta_id"])
        self.assertIn(
            "https://sparta.aerospace.org/related-work/questionnaire",
            document["mappings"][0]["sources"],
        )

    def test_catalog_rejects_malformed_or_oversized_data(self) -> None:
        for payload in (b"{", b'{"version": 2, "advisories": []}'):
            with self.subTest(payload=payload):
                with self.assertRaises(ValueError):
                    parse_advisory_catalog(payload)
        with self.assertRaisesRegex(ValueError, "1 MiB"):
            parse_advisory_catalog(b" " * (MAX_ADVISORY_CATALOG_BYTES + 1))

        malformed = json.loads(
            (Path(__file__).parents[1] / "src/vigil_fuse/hardware_advisories.json").read_text(
                encoding="utf-8"
            )
        )
        malformed["advisories"][0]["cve_ids"] = ["CVE-NOT-VALID"]
        with self.assertRaisesRegex(ValueError, "CVE"):
            parse_advisory_catalog(json.dumps(malformed).encode("utf-8"))

    def test_scanner_exports_advisory_through_json_and_sarif(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "main.c").write_text("int main(void) { return 0; }\n", encoding="utf-8")
            (root / "bom.csv").write_text(
                "Reference,Name,Manufacturer,MPN,Revision\n"
                "U1,ESP32,Espressif,ESP32-WROOM-32,Rev v3.0\n",
                encoding="utf-8",
            )
            result = scan(root, hardware_bom="bom.csv")

        finding = next(item for item in result.findings if item.rule_id == "FUSE-HW-ADV-001")
        self.assertEqual(
            "CONDITION_UNKNOWN", finding.evidence.split("advisory state ")[1].split(";")[0]
        )
        self.assertEqual("Rev v3.0", result.hardware_bom.components[0].revision)
        self.assertIn("CVE-2023-35818", to_json(result))
        self.assertIn("FUSE-HW-ADV-001", to_sarif(result))

    def test_cli_writes_sparta_review_artifact_with_bom_report(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "project"
            output = Path(temporary) / "reports"
            root.mkdir()
            (root / "main.c").write_text("int main(void) { return 0; }\n", encoding="utf-8")
            (root / "bom.csv").write_text(
                "Reference,Name,Manufacturer,MPN,Revision\nU1,ESP32,Espressif,ESP32,3.0\n",
                encoding="utf-8",
            )
            with redirect_stdout(StringIO()), redirect_stderr(StringIO()):
                exit_code = main(
                    ["scan", str(root), "--hardware-bom", "bom.csv", "--output-dir", str(output)]
                )
            report = json.loads((output / "findings.json").read_text(encoding="utf-8"))
            mapping_path = output / "hardware-sparta-mapping.json"
            mapping = json.loads(mapping_path.read_text(encoding="utf-8"))

        self.assertEqual(0, exit_code)
        self.assertFalse(mapping["compliance_certification"])
        self.assertTrue(any(item["path"] == mapping_path.name for item in report["artifacts"]))


if __name__ == "__main__":
    unittest.main()
