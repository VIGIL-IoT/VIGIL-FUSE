import json
import unittest
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker

from scripts.benchmark_repository_cohort import (
    RepositoryBenchmarkError,
    _median_absolute_deviation,
    _scan_command,
    summarize_samples,
)


class RepositoryBenchmarkTests(unittest.TestCase):
    def test_performance_report_schema_accepts_a_complete_sample(self) -> None:
        schema_path = (
            Path(__file__).resolve().parents[1]
            / "reports"
            / "benchmark"
            / "repository-scan-performance.schema.json"
        )
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
        Draft202012Validator.check_schema(schema)
        report = {
            "schema_version": "1.0",
            "benchmark": "fuse-pinned-repository-scan",
            "generated_at_utc": "2026-10-31T00:00:00+00:00",
            "tool": {"name": "FUSE", "version": "0.2.0"},
            "source_revision": {"commit": "a" * 40, "working_tree_dirty": False},
            "environment": {
                "python_version": "3.14.7",
                "operating_system": "Windows",
                "os_release": "11",
                "machine": "AMD64",
                "logical_cpu_count": 8,
            },
            "cohort": {
                "scan_date": "2026-10-28",
                "repository_count": 1,
                "manifest_sha256": "b" * 64,
                "repository_commits": {"example": "c" * 40},
            },
            "configuration": {
                "warmups": 1,
                "repetitions": 2,
                "timeout_seconds": 900,
                "network_enabled": False,
                "optional_analyzers_enabled": False,
                "native_rules_enabled": True,
            },
            "scopes": [
                {
                    "repository_id": "example",
                    "repository": "Example project",
                    "repository_commit": "c" * 40,
                    "scan_id": "all",
                    "scope": "tracked project files",
                    "profile": "generic",
                    "include_patterns": ["src/**"],
                    "files_discovered": 2,
                    "files_selected": 2,
                    "files_scanned": 2,
                    "source_bytes_read": 256,
                    "files_skipped": 0,
                    "finding_count": 0,
                    "discovery_complete": True,
                    "scan_return_code": 0,
                    "warmup_count": 1,
                    "warmup_seconds": [0.2],
                    "repetition_count": 2,
                    "wall_time_seconds": {
                        "samples": [0.18, 0.2],
                        "median": 0.19,
                        "minimum": 0.18,
                        "maximum": 0.2,
                        "median_absolute_deviation": 0.01,
                    },
                    "files_per_second_at_median": 10.526,
                    "mebibytes_per_second_at_median": 0.001284,
                }
            ],
            "scope_limitations": ["One pinned repository scope was measured."],
        }

        errors = list(
            Draft202012Validator(schema, format_checker=FormatChecker()).iter_errors(report)
        )
        self.assertEqual([], errors)

    def test_median_absolute_deviation(self) -> None:
        self.assertEqual(1.0, _median_absolute_deviation([1.0, 2.0, 3.0]))

    def test_summary_reports_reproducible_throughput_and_spread(self) -> None:
        summary = summarize_samples([1.0, 2.0, 3.0], files_scanned=20, source_bytes_read=1048576)

        self.assertEqual([1.0, 2.0, 3.0], summary["wall_time_seconds"]["samples"])
        self.assertEqual(2.0, summary["wall_time_seconds"]["median"])
        self.assertEqual(1.0, summary["wall_time_seconds"]["median_absolute_deviation"])
        self.assertEqual(10.0, summary["files_per_second_at_median"])
        self.assertEqual(0.5, summary["mebibytes_per_second_at_median"])

    def test_summary_rejects_missing_or_nonpositive_durations(self) -> None:
        for values in ([], [0.0], [float("nan")]):
            with self.subTest(values=values), self.assertRaises(ValueError):
                summarize_samples(values, files_scanned=1, source_bytes_read=1)

    def test_scan_command_disables_network_and_optional_external_analyzers(self) -> None:
        command = _scan_command(
            Path("target"),
            "generic",
            {
                "id": "example",
                "target_label": "org/repo",
                "includes": ["src/**"],
            },
            Path("temporary-report"),
        )

        for option in (
            "--no-network",
            "--no-sbom",
            "--no-vulnerabilities",
            "--no-firmware",
            "--no-git-history",
        ):
            with self.subTest(option=option):
                self.assertIn(option, command)
        self.assertIn("--include", command)
        self.assertIn("src/**", command)

    def test_scan_command_rejects_non_string_include_patterns(self) -> None:
        with self.assertRaises(RepositoryBenchmarkError):
            _scan_command(Path("target"), "generic", {"id": "x", "includes": [None]}, Path("out"))
