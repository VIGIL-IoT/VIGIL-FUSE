from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from scripts.build_holdout_scan_summary import build_charts, build_summary


class HoldoutScanSummaryTests(unittest.TestCase):
    def test_summary_keeps_an_independent_cohort_and_aggregates_coverage(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            reports = root / "reports"
            (reports / "example").mkdir(parents=True)
            manifest_path = root / "manifest.json"
            manifest_path.write_text(
                json.dumps(
                    {
                        "cohort": "independent-holdout",
                        "scan_date": "2026-10-28",
                        "training_manifest": "../scan-manifest.json",
                        "selection_protocol": {"rule_tuning_during_holdout": False},
                        "fuse": {"version": "0.2.0"},
                        "repositories": [
                            {
                                "id": "example",
                                "name": "example/project",
                                "url": "https://github.com/example/project",
                                "commit": "a" * 40,
                                "profile": "generic",
                                "scans": [{"id": "example", "scope": "selected source"}],
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            (reports / "example" / "findings.json").write_text(
                json.dumps(
                    {
                        "schema_version": "1.10",
                        "summary": {
                            "files_discovered": 4,
                            "files_selected": 3,
                            "files_scanned": 2,
                            "files_skipped": 1,
                        },
                        "coverage": {
                            "files_skipped_by_reason": {"not_utf8": 1},
                            "encoding_fallback": {
                                "encoding": "iso-8859-1",
                                "count": 1,
                                "files": ["legacy.c"],
                                "omitted_count": 0,
                            },
                            "limits_reached": [],
                            "support": {"status": "completed", "label": "basic"},
                        },
                        "build_context": {
                            "platformio": {
                                "status": "partial",
                                "environments": [
                                    {"name": "env-a"},
                                    {"name": "env-b"},
                                    {"name": "env-c"},
                                ],
                                "selected_environments": ["env-a", "env-b"],
                                "configurations": [{"path": "platformio.ini"}],
                            },
                        },
                        "firmware_candidates": {
                            "status": "complete",
                            "candidate_count": 3,
                            "extension_counts": {".bin": 2, ".hex": 1},
                        },
                        "github_actions": {
                            "status": "completed",
                            "workflow_count": 2,
                            "non_sha_action_reference_count": 3,
                            "floating_branch_reference_count": 1,
                            "finding_count": 1,
                        },
                        "hardware_netlist": {
                            "status": "completed",
                            "component_count": 4,
                            "net_count": 5,
                            "debug_net_candidates": [{"net": "SWDIO"}],
                        },
                        "hardware_inventory": {
                            "present": False,
                            "file_count": 0,
                            "category_counts": {},
                            "complete": True,
                        },
                        "findings": [
                            {"rule_id": "FUSE001", "severity": "medium"},
                            {"rule_id": "FUSE-GHA-002", "severity": "info"},
                        ],
                    }
                ),
                encoding="utf-8",
            )

            summary = build_summary(manifest_path, reports, root)
            build_charts(summary, root)
            platformio_chart = (
                root / "plots" / "platformio-environments-by-repository.svg"
            ).read_text(encoding="utf-8")

        self.assertEqual("independent-holdout", summary["cohort"])
        self.assertEqual(2, summary["totals"]["files_scanned"])
        self.assertEqual(2, summary["totals"]["finding_count"])
        self.assertEqual(1, summary["totals"]["rule_counts"]["FUSE-GHA-002"])
        self.assertEqual(3, summary["totals"]["module_coverage"]["platformio"]["environment_count"])
        self.assertEqual(
            2,
            summary["totals"]["module_coverage"]["platformio"]["selected_environment_count"],
        )
        self.assertIn("PlatformIO environments detected", platformio_chart)
        self.assertIn("No builds were run", platformio_chart)
        self.assertNotIn("raw FUSE signal counts", platformio_chart)
        self.assertEqual(
            3, summary["totals"]["module_coverage"]["firmware_candidates"]["candidate_count"]
        )
        self.assertEqual(
            1,
            summary["totals"]["module_coverage"]["github_actions"][
                "floating_branch_reference_count"
            ],
        )
        self.assertEqual(
            1, summary["totals"]["module_coverage"]["hardware_netlist"]["debug_net_candidate_count"]
        )
        self.assertEqual(
            1, summary["totals"]["module_coverage"]["source_decoding"]["fallback_file_count"]
        )
        self.assertEqual(
            ["legacy.c"], summary["totals"]["module_coverage"]["source_decoding"]["fallback_files"]
        )
        self.assertEqual("partial", summary["repositories"][0]["scopes"][0]["scan_status"])
        self.assertEqual(1, summary["totals"]["files_skipped_by_reason"]["not_utf8"])
        self.assertFalse(summary["selection_protocol"]["rule_tuning_during_holdout"])

    def test_summary_refuses_the_training_corpus_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            manifest_path = root / "manifest.json"
            manifest_path.write_text(
                json.dumps({"cohort": "training", "repositories": []}), encoding="utf-8"
            )

            with self.assertRaisesRegex(ValueError, "separate holdout"):
                build_summary(manifest_path, root / "reports", root)


if __name__ == "__main__":
    unittest.main()
