from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from scripts.build_holdout_scan_summary import build_summary


class HoldoutScanSummaryTests(unittest.TestCase):
    def test_summary_keeps_an_independent_cohort_and_aggregates_coverage(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            reports = root / "reports"
            (reports / "example").mkdir(parents=True)
            manifest_path = root / "manifest.json"
            manifest_path.write_text(
                json.dumps({
                    "cohort": "independent-holdout",
                    "scan_date": "2026-10-28",
                    "training_manifest": "../scan-manifest.json",
                    "selection_protocol": {"rule_tuning_during_holdout": False},
                    "fuse": {"version": "0.2.0"},
                    "repositories": [{
                        "id": "example",
                        "name": "example/project",
                        "url": "https://github.com/example/project",
                        "commit": "a" * 40,
                        "profile": "generic",
                        "scans": [{"id": "example", "scope": "selected source"}],
                    }],
                }),
                encoding="utf-8",
            )
            (reports / "example" / "findings.json").write_text(
                json.dumps({
                    "schema_version": "1.6",
                    "summary": {
                        "files_discovered": 4,
                        "files_selected": 3,
                        "files_scanned": 2,
                        "files_skipped": 1,
                    },
                    "coverage": {
                        "files_skipped_by_reason": {"not_utf8": 1},
                        "limits_reached": [],
                        "support": {"status": "partial", "label": "basic"},
                    },
                    "hardware_inventory": {
                        "present": False,
                        "file_count": 0,
                        "category_counts": {},
                        "complete": True,
                    },
                    "findings": [{"rule_id": "FUSE001", "severity": "medium"}],
                }),
                encoding="utf-8",
            )

            summary = build_summary(manifest_path, reports, root)

        self.assertEqual("independent-holdout", summary["cohort"])
        self.assertEqual(2, summary["totals"]["files_scanned"])
        self.assertEqual(1, summary["totals"]["finding_count"])
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
