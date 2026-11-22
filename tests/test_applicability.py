from __future__ import annotations

import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from jsonschema import Draft202012Validator

from vigil_fuse.applicability import analyze_report
from vigil_fuse.cli import main


def _source_report() -> dict:
    return {
        "schema_version": "1.11",
        "tool": {"name": "FUSE", "version": "0.4.0"},
        "coverage": {
            "discovery_complete": True,
            "analyzers": [{"name": "osv-scanner", "version": "2.7.0", "status": "completed"}],
        },
        "project_context": {
            "framework": "esp-idf",
            "target": "esp32",
            "board": None,
            "component_lock": {
                "status": "target-matches",
                "selected_target_match": True,
                "sha256": "b" * 64,
                "components": [{"name": "idf-example", "version": "1.2.3"}],
            },
        },
        "product_context": {
            "product_purl": None,
            "vex_import": {"status": "not-requested"},
        },
        "findings": [
            {
                "id": "OSV:CVE-2026-1234:idf-example@1.2.3:dependencies.lock",
                "fingerprint": "a" * 64,
                "rule_id": "OSV-CVE-2026-1234",
                "analyzer": "osv-scanner",
                "category": "dependency-vulnerability",
                "validation_method": "advisory-match",
                "confidence": "high",
                "component": {
                    "name": "idf-example",
                    "version": "1.2.3",
                    "ecosystem": "ESP-IDF Component Manager",
                    "purl": "pkg:generic/idf-example@1.2.3",
                },
                "vex_review": None,
            }
        ],
    }


class ApplicabilityTests(unittest.TestCase):
    def write_report(self, root: Path, report: dict | None = None) -> Path:
        path = root / "findings.json"
        path.write_text(json.dumps(report or _source_report()), encoding="utf-8")
        return path

    def test_osv_and_target_lock_evidence_do_not_imply_build_inclusion(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            report_path = self.write_report(Path(temporary))
            result = analyze_report(report_path)

        item = result["assessments"][0]
        self.assertEqual("UNDER_INVESTIGATION", item["assessment"])
        self.assertEqual("TRUE", item["states"]["DEPENDENCY_PRESENT"]["value"])
        self.assertEqual("TRUE", item["states"]["VERSION_AFFECTED"]["value"])
        self.assertEqual(
            "TRUE", item["states"]["COMPONENT_RESOLVED_FOR_CONFIGURED_TARGET"]["value"]
        )
        self.assertEqual("UNKNOWN", item["states"]["BUILD_INCLUDED"]["value"])
        self.assertTrue(
            all(
                item["states"][state]["value"] == "UNKNOWN"
                for state in (
                    "FEATURE_ENABLED",
                    "DEVICE_ENABLED",
                    "BINARY_PRESENT",
                    "RUNTIME_REACHABLE",
                    "PHYSICALLY_EXPOSED",
                )
            )
        )
        self.assertEqual("CVE-2026-1234", item["vulnerability_id"])
        self.assertEqual("completed", result["coverage"]["dependency_analyzer_status"])
        self.assertTrue(result["coverage"]["source_discovery_complete"])
        resolution_claim = next(
            claim
            for claim in result["claims"]
            if claim["predicate"] == "COMPONENT_RESOLVED_FOR_CONFIGURED_TARGET"
        )
        self.assertEqual("TRUE", resolution_claim["value"])
        self.assertEqual("b" * 64, resolution_claim["artifact_digest"])

    def test_lock_version_conflict_remains_visible_and_not_affected_is_not_inferred(self) -> None:
        report = _source_report()
        report["project_context"]["component_lock"]["components"][0]["version"] = "2.0.0"
        with tempfile.TemporaryDirectory() as temporary:
            result = analyze_report(self.write_report(Path(temporary), report))

        item = result["assessments"][0]
        self.assertEqual(
            "CONTRADICTORY",
            item["states"]["COMPONENT_RESOLVED_FOR_CONFIGURED_TARGET"]["value"],
        )
        self.assertEqual("UNDER_INVESTIGATION", item["assessment"])
        self.assertNotEqual("NOT_AFFECTED", item["assessment"])

    def test_lock_match_without_artifact_digest_remains_unknown(self) -> None:
        report = _source_report()
        report["project_context"]["component_lock"]["sha256"] = None
        with tempfile.TemporaryDirectory() as temporary:
            result = analyze_report(self.write_report(Path(temporary), report))

        item = result["assessments"][0]
        self.assertEqual(
            "UNKNOWN",
            item["states"]["COMPONENT_RESOLVED_FOR_CONFIGURED_TARGET"]["value"],
        )
        self.assertFalse(
            any(
                claim["predicate"] == "COMPONENT_RESOLVED_FOR_CONFIGURED_TARGET"
                for claim in result["claims"]
            )
        )

    def test_exact_reviewed_vex_can_record_not_affected_with_justification(self) -> None:
        report = _source_report()
        report["product_context"] = {
            "product_purl": "pkg:generic/product@1.0.0",
            "vex_import": {
                "status": "imported",
                "product_purl": "pkg:generic/product@1.0.0",
                "sha256": "c" * 64,
            },
        }
        report["findings"][0]["vex_review"] = {
            "state": "not_affected",
            "justification": "code_not_present",
            "detail": "Reviewed product configuration.",
        }
        with tempfile.TemporaryDirectory() as temporary:
            result = analyze_report(self.write_report(Path(temporary), report))

        self.assertEqual("NOT_AFFECTED", result["assessments"][0]["assessment"])
        review_claim = next(
            claim for claim in result["claims"] if claim["predicate"] == "REVIEWED_VEX_ASSESSMENT"
        )
        self.assertEqual("code_not_present", review_claim["justification"])
        self.assertEqual("c" * 64, review_claim["artifact_digest"])

    def test_exact_reviewed_vex_can_record_affected(self) -> None:
        report = _source_report()
        report["product_context"] = {
            "product_purl": "pkg:generic/product@1.0.0",
            "vex_import": {
                "status": "imported",
                "product_purl": "pkg:generic/product@1.0.0",
                "sha256": "c" * 64,
            },
        }
        report["findings"][0]["vex_review"] = {
            "state": "exploitable",
            "justification": None,
            "detail": "Reviewed behavior.",
        }
        with tempfile.TemporaryDirectory() as temporary:
            result = analyze_report(self.write_report(Path(temporary), report))

        self.assertEqual("AFFECTED", result["assessments"][0]["assessment"])
        self.assertEqual("reviewed-vex", result["assessments"][0]["assessment_source"])

    def test_unjustified_vex_does_not_produce_not_affected(self) -> None:
        report = _source_report()
        report["product_context"] = {
            "product_purl": "pkg:generic/product@1.0.0",
            "vex_import": {
                "status": "imported",
                "product_purl": "pkg:generic/product@1.0.0",
                "sha256": "c" * 64,
            },
        }
        report["findings"][0]["vex_review"] = {
            "state": "not_affected",
            "justification": None,
            "detail": None,
        }
        with tempfile.TemporaryDirectory() as temporary:
            result = analyze_report(self.write_report(Path(temporary), report))

        self.assertEqual("UNDER_INVESTIGATION", result["assessments"][0]["assessment"])
        self.assertFalse(
            any(claim["predicate"] == "REVIEWED_VEX_ASSESSMENT" for claim in result["claims"])
        )

    def test_output_is_deterministic_and_cli_preserves_the_source_report(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            input_path = self.write_report(root)
            first = analyze_report(input_path)
            self.assertEqual(first, analyze_report(input_path))
            output_path = root / "applicability.json"
            stdout = io.StringIO()
            stderr = io.StringIO()
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                code = main(
                    [
                        "applicability",
                        "analyze",
                        "--report",
                        str(input_path),
                        "--output",
                        str(output_path),
                    ],
                    _show_banner=False,
                )
            self.assertEqual(0, code)
            self.assertEqual(first, json.loads(output_path.read_text(encoding="utf-8")))
            source_before = input_path.read_bytes()
            with contextlib.redirect_stderr(stderr):
                code = main(
                    [
                        "applicability",
                        "analyze",
                        "--report",
                        str(input_path),
                        "--output",
                        str(input_path),
                    ],
                    _show_banner=False,
                )
            self.assertEqual(2, code)
            self.assertEqual(source_before, input_path.read_bytes())

    def test_malformed_and_oversized_reports_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "findings.json"
            path.write_text("{broken", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "valid UTF-8 JSON"):
                analyze_report(path)

            path.write_text("{}", encoding="utf-8")
            with patch("vigil_fuse.applicability.MAX_APPLICABILITY_INPUT_BYTES", 1):
                with self.assertRaisesRegex(ValueError, "exceeds the 0 MiB limit"):
                    analyze_report(path)

    def test_output_matches_the_versioned_schema(self) -> None:
        schema_path = (
            Path(__file__).parents[1]
            / "src"
            / "vigil_fuse"
            / "schemas"
            / "applicability-1.0.schema.json"
        )
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
        with tempfile.TemporaryDirectory() as temporary:
            result = analyze_report(self.write_report(Path(temporary)))

        Draft202012Validator(schema).validate(result)


if __name__ == "__main__":
    unittest.main()
