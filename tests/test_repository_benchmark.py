import json
import tempfile
import unittest
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker

from scripts.prepare_repository_benchmark_cohort import (
    DEFAULT_MANIFEST,
    CohortPreparationError,
    _load_cohort,
)
from scripts.benchmark_repository_cohort import (
    RepositoryBenchmarkError,
    _manifest_sha256,
    _median_absolute_deviation,
    _scan_command,
    _summary_signature,
    summarize_samples,
)


class RepositoryBenchmarkTests(unittest.TestCase):
    def test_manifest_digest_normalizes_line_endings_across_platforms(self) -> None:
        manifest = b'{"repositories": []}\n'

        self.assertEqual(
            _manifest_sha256(manifest),
            _manifest_sha256(manifest.replace(b"\n", b"\r\n")),
        )
        self.assertEqual(
            _manifest_sha256(manifest),
            _manifest_sha256(manifest.replace(b"\n", b"\r")),
        )

    def test_default_cohort_manifest_has_four_pinned_safe_plans(self) -> None:
        plans = _load_cohort(DEFAULT_MANIFEST)

        self.assertEqual(
            {"mynewt-core", "mbedtls", "openthread", "esp-iot-solution"},
            {plan["id"] for plan in plans},
        )
        self.assertTrue(all(len(plan["commit"]) == 40 for plan in plans))
        self.assertTrue(all(plan["url"].startswith("https://github.com/") for plan in plans))
        self.assertTrue(all(plan["includes"] for plan in plans))

    def test_cohort_manifest_rejects_unsafe_repository_paths_and_urls(self) -> None:
        source = json.loads(DEFAULT_MANIFEST.read_text(encoding="utf-8"))
        invalid_cases = (
            ("repository id", lambda manifest: manifest["repositories"][0].update(id="../escape")),
            ("commit", lambda manifest: manifest["repositories"][0].update(commit="not-a-sha")),
            (
                "URL",
                lambda manifest: manifest["repositories"][0].update(
                    url="https://example.com/owner/repo"
                ),
            ),
            (
                "URL port",
                lambda manifest: manifest["repositories"][0].update(
                    url="https://github.com:8443/owner/repo"
                ),
            ),
            (
                "include pattern",
                lambda manifest: manifest["repositories"][0]["scans"][0].update(
                    includes=["../../outside"]
                ),
            ),
            (
                "negative include pattern",
                lambda manifest: manifest["repositories"][0]["scans"][0].update(
                    includes=["!apps/**"]
                ),
            ),
            (
                "drive-qualified include pattern",
                lambda manifest: manifest["repositories"][0]["scans"][0].update(
                    includes=["C:/outside"]
                ),
            ),
        )
        for label, mutate in invalid_cases:
            with self.subTest(label=label), tempfile.TemporaryDirectory() as temporary:
                manifest = json.loads(json.dumps(source))
                mutate(manifest)
                path = Path(temporary) / "manifest.json"
                path.write_text(json.dumps(manifest), encoding="utf-8")
                with self.assertRaises(CohortPreparationError):
                    _load_cohort(path)

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
                    "files_skipped_by_reason": {},
                    "finding_count": 0,
                    "discovery_complete": True,
                    "native_analysis_status": "completed",
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

    def test_repeatability_signature_includes_skip_reasons_and_native_status(self) -> None:
        report = {
            "summary": {
                "files_discovered": 1,
                "files_selected": 1,
                "files_scanned": 1,
                "source_bytes_read": 10,
                "files_skipped": 0,
                "finding_count": 0,
            },
            "coverage": {
                "discovery_complete": True,
                "files_skipped_by_reason": {},
                "analyzers": [{"name": "fuse-native", "status": "completed"}],
            },
        }
        signature = _summary_signature(report)

        report["coverage"]["files_skipped_by_reason"] = {"too_large": 1}
        self.assertNotEqual(signature, _summary_signature(report))
        report["coverage"]["files_skipped_by_reason"] = {}
        report["coverage"]["analyzers"][0]["status"] = "partial"
        self.assertNotEqual(signature, _summary_signature(report))

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
