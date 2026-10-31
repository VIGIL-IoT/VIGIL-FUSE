from __future__ import annotations

import sys
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from scripts.run_repository_scan_pilot import (
    build_scan_command,
    report_has_incomplete_coverage,
    update_scanner_provenance,
)


class RepositoryScanRunnerTests(unittest.TestCase):
    def test_runner_can_record_provenance_in_a_separate_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            manifest_path = Path(temporary) / "holdout-manifest.json"
            manifest_path.write_text(
                json.dumps({"cohort": "holdout", "repositories": []}), encoding="utf-8"
            )

            provenance = update_scanner_provenance(manifest_path)
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))

        self.assertEqual("holdout", manifest["cohort"])
        self.assertEqual(provenance, manifest["fuse"])

    def test_runner_refuses_dirty_scanner_before_updating_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            manifest_path = Path(temporary) / "holdout-manifest.json"
            original = {"cohort": "holdout", "repositories": []}
            manifest_path.write_text(json.dumps(original), encoding="utf-8")

            with mock.patch(
                "scripts.run_repository_scan_pilot.git_status",
                return_value=" M src/vigil_fuse/rules.py",
            ):
                with self.assertRaisesRegex(RuntimeError, "dirty FUSE source tree"):
                    update_scanner_provenance(manifest_path, require_clean=True)

            self.assertEqual(original, json.loads(manifest_path.read_text(encoding="utf-8")))

    def test_runner_passes_manifest_target_label_to_fuse(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            checkout = root / "firmware"
            output = root / "reports"
            command = build_scan_command(
                checkout,
                "generic",
                {
                    "target_label": "org/repository, mqtt examples",
                    "includes": ["examples/**", "src/**"],
                    "rule_timeout_seconds": 10,
                    "max_file_bytes": 5 * 1024 * 1024,
                },
                output,
            )

        self.assertEqual(sys.executable, command[0])
        self.assertIn("--no-sbom", command)
        self.assertIn("--no-vulnerabilities", command)
        self.assertIn("--no-firmware", command)
        self.assertIn("--no-git-history", command)
        self.assertIn("--no-network", command)
        self.assertIn("--target-label", command)
        label_index = command.index("--target-label")
        self.assertEqual("org/repository, mqtt examples", command[label_index + 1])
        self.assertIn("--rule-timeout", command)
        self.assertEqual("10", command[command.index("--rule-timeout") + 1])
        self.assertIn("--max-file-bytes", command)
        self.assertEqual(5 * 1024 * 1024, int(command[command.index("--max-file-bytes") + 1]))
        self.assertEqual(2, command.count("--include"))
        self.assertEqual(str(output), command[-1])

    def test_runner_keeps_folder_default_when_manifest_has_no_target_label(self) -> None:
        command = build_scan_command(Path("repo"), "generic", {}, Path("reports"))
        self.assertNotIn("--target-label", command)

    def test_runner_rejects_out_of_range_rule_timeout(self) -> None:
        with self.assertRaisesRegex(ValueError, "rule_timeout_seconds"):
            build_scan_command(
                Path("repo"), "generic", {"rule_timeout_seconds": 31}, Path("reports")
            )

    def test_runner_rejects_invalid_max_file_bytes(self) -> None:
        for max_file_bytes in (True, 0, 100 * 1024 * 1024 + 1, "large"):
            with self.subTest(max_file_bytes=max_file_bytes):
                with self.assertRaisesRegex(ValueError, "max_file_bytes"):
                    build_scan_command(
                        Path("repo"), "generic", {"max_file_bytes": max_file_bytes}, Path("reports")
                    )

    def test_runner_rejects_invalid_manifest_target_label(self) -> None:
        for target_label in ("", 42):
            with self.subTest(target_label=target_label):
                with self.assertRaisesRegex(ValueError, "target_label"):
                    build_scan_command(
                        Path("repo"), "generic", {"target_label": target_label}, Path("reports")
                    )

    def test_runner_treats_native_rules_without_matching_inputs_as_intentional_skips(self) -> None:
        report = {
            "summary": {"analysis_performed": True},
            "coverage": {
                "analyzers": [
                    {
                        "name": "native-rule:FUSE006",
                        "status": "skipped",
                        "detail": "No selected input matched this rule's supported input scope.",
                    }
                ]
            },
        }
        self.assertFalse(report_has_incomplete_coverage(report))

    def test_runner_keeps_other_skipped_analyzers_incomplete(self) -> None:
        report = {
            "summary": {"analysis_performed": True},
            "coverage": {"analyzers": [{"name": "osv-scanner", "status": "skipped"}]},
        }
        self.assertTrue(report_has_incomplete_coverage(report))

    def test_runner_counts_partial_platformio_context_as_incomplete(self) -> None:
        report = {
            "summary": {"analysis_performed": True},
            "coverage": {"analyzers": []},
            "build_context": {
                "platformio": {"status": "partial"},
                "compilation_database": {"status": "not-detected"},
            },
        }
        self.assertTrue(report_has_incomplete_coverage(report))


if __name__ == "__main__":
    unittest.main()
