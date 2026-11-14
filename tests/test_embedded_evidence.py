import hashlib
import json
from pathlib import Path
import unittest

from scripts.evaluate_detection_accuracy import evaluate

ROOT = Path(__file__).resolve().parents[1]
EVIDENCE = ROOT / "reports/evaluation/2026-11-14"


class PublishedEvidenceTests(unittest.TestCase):
    def test_published_artifact_hashes_and_metrics_are_reproducible(self):
        hashes = json.loads((EVIDENCE / "evidence-hashes.json").read_text())
        for name, expected in hashes.items():
            self.assertEqual(
                expected, hashlib.sha256((EVIDENCE / name).read_bytes()).hexdigest(), name
            )
        targets = list((EVIDENCE / "evidence").glob("*/compatibility.json"))
        self.assertEqual(5, len(targets))
        records = []
        for path in targets:
            records.extend(json.loads(path.read_text())["records"])
            dataset = json.loads((path.parent / "dataset.json").read_text())
            metrics = json.loads((path.parent / "metrics/metrics.json").read_text())
            self.assertEqual(evaluate(dataset)["rules"], metrics["rules"])
        self.assertEqual(60, len(records))
        for record in records:
            self.assertTrue(record["schemas_valid"])
            self.assertTrue(record["temporary_cleanup"])
            self.assertTrue(record["redaction_passed"])
            if not record["experimental"]:
                self.assertTrue(record["expected_rules_match"])
                self.assertEqual("completed", record["status"])
        self.assertEqual(3, sum(r["status"] == "partial" for r in records))
