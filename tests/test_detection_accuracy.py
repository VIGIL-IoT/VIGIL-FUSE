import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from jsonschema import Draft202012Validator

from scripts.evaluate_detection_accuracy import evaluate, wilson, write_results
from scripts.freeze_evaluation import freeze, verify

ROOT = Path(__file__).resolve().parents[1]


def dataset():
    cases = []
    for index, (expected, observed) in enumerate(
        [("positive", True), ("negative", True), ("negative", False), ("positive", False)]
    ):
        cases.append(
            {
                "id": str(index),
                "rule_id": "FUSE-BIN-001",
                "input_sha256": hashlib.sha256(str(index).encode()).hexdigest(),
                "expected": expected,
                "observed": observed,
                "status": "completed",
                "coverage": {
                    "complete": True,
                    "files_discovered": 1,
                    "files_scanned": 1,
                    "files_skipped": 0,
                    "bytes_scanned": 100,
                },
            }
        )
    return {
        "schema_version": "1.0",
        "dataset_id": "test",
        "split": "controlled-binary",
        "scope": "code-referenced HTTP",
        "ground_truth": "known construction",
        "fuse_commit": "a" * 40,
        "rules": ["FUSE-BIN-001", "FUSE-BIN-002"],
        "cases": cases,
    }


class AccuracyTests(unittest.TestCase):
    def test_confusion_and_zero_support(self):
        result = evaluate(dataset())
        row = result["rules"]["FUSE-BIN-001"]
        self.assertEqual([1, 1, 1, 1], [row[k] for k in ("tp", "fp", "tn", "fn")])
        self.assertEqual([0.5] * 3, [row[k] for k in ("precision", "recall", "f1")])
        empty = result["rules"]["FUSE-BIN-002"]
        self.assertIsNone(empty["precision"])
        self.assertIsNone(empty["recall"])
        self.assertIsNone(empty["f1"])
        self.assertEqual(["FUSE-BIN-001"], result["macro"]["recall"]["rules"])

    def test_undefined_and_all_wrong(self):
        data = dataset()
        data["cases"] = [data["cases"][1], data["cases"][3]]
        row = evaluate(data)["micro"]
        self.assertEqual(0, row["f1"])
        data["cases"] = [dataset()["cases"][2]]
        row = evaluate(data)["micro"]
        self.assertIsNone(row["recall"])
        self.assertIsNone(row["precision"])

    def test_wilson_edges(self):
        self.assertIsNone(wilson(0, 0))
        self.assertAlmostEqual(0, wilson(0, 1)[0])
        self.assertAlmostEqual(1, wilson(1, 1)[1])
        self.assertAlmostEqual(0.206549314377, wilson(1, 1)[0])

    def test_uncertainty_and_partial_never_become_negatives(self):
        data = dataset()
        for label, case in zip(("unknown", "uncertain", "not_applicable"), data["cases"]):
            case["expected"] = label
        data["cases"][3]["status"] = "partial"
        data["cases"][3]["coverage"]["complete"] = False
        row = evaluate(data)["rules"]["FUSE-BIN-001"]
        self.assertEqual(0, row["support"])
        self.assertEqual(
            {"unknown": 1, "uncertain": 1, "not_applicable": 1, "incomplete_analysis": 1},
            row["excluded"],
        )

    def test_duplicate_leakage_and_missing_data(self):
        for mutation in ("duplicate", "hash", "missing", "coverage", "observed", "rule"):
            with self.subTest(mutation=mutation):
                data = dataset()
                case = data["cases"][0]
                if mutation == "duplicate":
                    duplicate = copy.deepcopy(case)
                    duplicate["id"] = "new-id"
                    data["cases"].append(duplicate)
                elif mutation == "hash":
                    case["input_sha256"] = "bad"
                elif mutation == "missing":
                    del case["coverage"]
                elif mutation == "coverage":
                    case["coverage"]["files_scanned"] = 0
                elif mutation == "observed":
                    case["observed"] = 1
                else:
                    case["rule_id"] = "undeclared"
                with self.assertRaises(ValueError):
                    evaluate(data)
        data = dataset()
        data["split"] = "independent-holdout"
        with self.assertRaisesRegex(ValueError, "leakage"):
            evaluate(data, [dataset()])

    def test_deterministic_and_schema(self):
        data = dataset()
        schema = json.loads((ROOT / "scripts/schemas/evaluation-dataset.schema.json").read_text())
        Draft202012Validator.check_schema(schema)
        Draft202012Validator(schema).validate(data)
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary)
            write_results(data, path)
            first = (path / "metrics.json").read_bytes()
            data["rules"].reverse()
            self.assertEqual(evaluate(dataset()), evaluate(data))
            write_results(dataset(), path)
            self.assertEqual(first, (path / "metrics.json").read_bytes())

    def test_freeze_is_repeatable_and_detects_changes(self):
        first = freeze()
        self.assertEqual(first, freeze())
        verify(first)
        first["detector_files"]["src/vigil_fuse/terminal.py"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "mismatch"):
            verify(first)
