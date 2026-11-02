from __future__ import annotations

import json
from pathlib import Path
import unittest

from jsonschema import Draft202012Validator


class GhidraBenchmarkSchemaTests(unittest.TestCase):
    def test_archived_ghidra_benchmark_validates_and_has_no_machine_paths(self) -> None:
        repository = Path(__file__).parents[1]
        schema = json.loads(
            (repository / "src/vigil_fuse/schemas/ghidra-benchmark.schema.json").read_text(
                encoding="utf-8"
            )
        )
        report = json.loads(
            (repository / "reports/benchmark/ghidra-adapter-windows-2026-11-03.json").read_text(
                encoding="utf-8"
            )
        )
        Draft202012Validator.check_schema(schema)
        Draft202012Validator(schema, format_checker=Draft202012Validator.FORMAT_CHECKER).validate(
            report
        )
        self.assertNotIn("path", report["input"])
        self.assertNotIn("executable", report["environment"])


if __name__ == "__main__":
    unittest.main()
