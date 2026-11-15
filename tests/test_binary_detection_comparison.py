from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest

from scripts.build_binary_detection_comparison import TARGETS, build


class BinaryDetectionComparisonTests(unittest.TestCase):
    def test_builds_separate_report_with_inventory_and_detection_statuses(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            source.mkdir()
            for target in TARGETS:
                previous = json.loads(
                    (
                        Path(__file__).parents[1]
                        / "reports/evaluation/2026-11-14/evidence"
                        / target
                        / "compatibility.json"
                    ).read_text(encoding="utf-8")
                )
                old_record = next(
                    record for record in previous["records"] if "provenance" in record
                )
                real_id = f"{target}-idf-hello-world"
                record = {
                    "id": real_id,
                    "provenance": old_record["provenance"],
                    "input_sha256": (
                        "0" * 64 if target == TARGETS[0] else old_record["input_sha256"]
                    ),
                    "input_bytes": old_record["input_bytes"],
                    "inventory_status": "partial",
                    "security_evaluation_status": "complete",
                    "security_rule_statuses": {
                        "FUSE-BIN-001": "complete",
                        "FUSE-BIN-002": "complete",
                    },
                    "rule_ids": [],
                    "truncation": {"strings": True},
                    "elapsed_seconds": 12.5,
                    "peak_process_tree_rss_bytes": 1024,
                    "artifact_bytes": 2048,
                    "tool": {"version": "12.2"},
                    "security_counts": {"data_items_scanned": 1501},
                }
                target_root = source / target
                output = target_root / "outputs" / real_id
                output.mkdir(parents=True)
                (target_root / "compatibility.json").write_text(
                    json.dumps(
                        {
                            "target": target,
                            "fuse_commit": "a" * 40,
                            "harness_commit": "b" * 40,
                            "records": [record],
                        }
                    ),
                    encoding="utf-8",
                )
                (output / "findings.json").write_text("{}\n", encoding="utf-8")

            destination = root / "report"
            build(source, destination)
            comparison = json.loads((destination / "comparison.json").read_text(encoding="utf-8"))
            report = (destination / "README.md").read_text(encoding="utf-8")
            self.assertEqual("1.1", comparison["schema_version"])
            for target in TARGETS:
                self.assertEqual(
                    "unsupported",
                    comparison["targets"][target]["previous"]["security_evaluation_status"],
                )
                self.assertEqual(
                    "partial", comparison["targets"][target]["revised"]["inventory_status"]
                )
                self.assertEqual(
                    "complete",
                    comparison["targets"][target]["revised"]["security_evaluation_status"],
                )
                self.assertEqual(
                    target != TARGETS[0],
                    comparison["targets"][target]["input_comparison"]["sha256_matches"],
                )
                self.assertEqual(
                    comparison["targets"][target]["previous"]["provenance"],
                    comparison["targets"][target]["revised"]["provenance"],
                )
            self.assertIn("Old rule evaluation | New rule evaluation", report)
            self.assertIn("original November 14 ELF files were not archived", report)
            self.assertNotIn(chr(0x2014), report)
            with self.assertRaises(FileExistsError):
                build(source, destination)

            current_path = source / TARGETS[1] / "compatibility.json"
            current = json.loads(current_path.read_text(encoding="utf-8"))
            current["records"][0]["provenance"]["commit"] = "changed"
            current_path.write_text(json.dumps(current), encoding="utf-8")
            invalid_destination = root / "invalid-report"
            with self.assertRaisesRegex(ValueError, "Pinned build provenance changed"):
                build(source, invalid_destination)
            self.assertFalse(invalid_destination.exists())


if __name__ == "__main__":
    unittest.main()
