from __future__ import annotations

import hashlib
import json
from pathlib import Path
import stat
import tempfile
from typing import Any
import unittest
from unittest.mock import MagicMock, patch
from zipfile import ZipInfo, ZipFile

from scripts.evaluate_sard_fuse001_cohort import (
    CASES,
    SardCase,
    _safe_extract_zip,
    download_case,
)
from scripts.evaluate_sard_fuse001_catalogue import (
    DEFAULT_MANIFEST,
    DEFAULT_OUTPUT,
    _safe_manifest_path,
    _verify_source_targets,
    load_manifest,
    summarize_findings,
)


class SardCohortInputTests(unittest.TestCase):
    def _make_archive(self, root: Path, name: str, entries: list[tuple[str, bytes]]) -> Path:
        archive_path = root / name
        with ZipFile(archive_path, "w") as archive:
            for path, content in entries:
                archive.writestr(path, content)
        return archive_path

    def test_cohort_manifest_has_unique_pinned_cases_and_targets(self) -> None:
        self.assertEqual(10, len(CASES))
        self.assertEqual(10, len({case.case_id for case in CASES}))
        self.assertEqual(10, len({case.archive_sha256 for case in CASES}))
        self.assertTrue(all(len(case.archive_sha256) == 64 for case in CASES))
        self.assertTrue(all(case.target_filename in case.expected_fuse_files for case in CASES))
        self.assertEqual(12, sum(len(case.expected_fuse_files) for case in CASES))

    def test_catalogue_manifest_pins_complete_query_result_and_target_hashes(self) -> None:
        manifest, cases = load_manifest(DEFAULT_MANIFEST)

        self.assertEqual(76, manifest["selection"]["api_total"])
        self.assertEqual(76, len(cases))
        self.assertEqual(76, len({case["case_id"] for case in cases}))
        self.assertTrue(
            all(
                set(case["sarif_targets"]).issubset(
                    {target["path"] for target in case["target_files"]}
                )
                for case in cases
            )
        )

    def test_catalogue_manifest_rejects_unsafe_source_paths(self) -> None:
        for path in ("../escape.c", "C:/escape.c", "src\\escape.c"):
            with self.subTest(path=path), self.assertRaises(ValueError):
                _safe_manifest_path(path)

    def test_catalogue_findings_separate_sarif_target_hits_from_other_files(self) -> None:
        case = {"sarif_targets": ["src/testcases/target.c"]}
        findings = [
            {
                "location": {
                    "file": r"C:\temp\case\src\testcases\target.c",
                    "start_line": 12,
                },
                "rule_version": "1.9.0",
            },
            {
                "location": {"file": "support.c", "start_line": 27},
                "rule_version": "1.9.0",
            },
        ]

        result = summarize_findings(case, findings)

        self.assertEqual(2, result["finding_count"])
        self.assertEqual(
            [{"file": "target.c", "detected": True, "finding_count": 1}],
            result["nist_sarif_targets"],
        )
        self.assertEqual(["support.c"], result["additional_fuse001_files"])
        self.assertEqual(
            [{"file": "support.c", "line": 27}],
            result["additional_fuse001_locations"],
        )

    def test_catalogue_compares_macro_literals_without_recording_secret_values(self) -> None:
        secret = "sensitive-fixture-value-123"
        source_lines = {
            "target.c": f'#define DEVICE_PASSWORD "{secret}"\n'.encode("utf-8"),
            "same.c": f'#define DEVICE_PASSWORD "{secret}"\n'.encode("utf-8"),
            "different.c": b'#define DEVICE_PASSWORD "another-fixture-value"\n',
        }
        findings = []
        target_files = []
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for name, content in source_lines.items():
                (root / name).write_bytes(content)
                target_files.append(
                    {
                        "path": name,
                        "length": len(content),
                        "sha256": hashlib.sha256(content).hexdigest(),
                    }
                )
                findings.append({"location": {"file": name, "start_line": 1}})

            result = summarize_findings(
                {
                    "sarif_targets": ["target.c"],
                    "target_files": target_files,
                },
                findings,
                root,
            )

        self.assertEqual(1, result["additional_same_named_macro_literal_matches"])
        self.assertEqual(2, result["additional_macro_literal_comparisons"])
        locations = {item["file"]: item for item in result["additional_fuse001_locations"]}
        self.assertIs(True, locations["same.c"]["same_named_macro_literal_as_sarif_target"])
        self.assertIs(
            False,
            locations["different.c"]["same_named_macro_literal_as_sarif_target"],
        )
        self.assertNotIn(secret, json.dumps(result))

    def test_checked_in_catalogue_result_preserves_complete_secret_safe_comparison(self) -> None:
        report = json.loads(DEFAULT_OUTPUT.read_text(encoding="utf-8"))
        summary = report["summary"]

        self.assertTrue(report["experiment"]["source_working_tree_clean"])
        self.assertEqual(76, summary["nist_sarif_target_files_detected"])
        self.assertEqual(76, summary["nist_sarif_target_files"])
        self.assertEqual(110, summary["fuse001_findings"])
        self.assertEqual(34, summary["additional_fuse001_file_observations"])
        self.assertEqual(34, summary["additional_macro_literal_comparisons"])
        self.assertEqual(34, summary["additional_same_named_macro_literal_matches"])
        self.assertEqual(0, summary["additional_macro_literal_comparisons_unresolved"])
        for case in report["cases"]:
            for location in case["additional_fuse001_locations"]:
                self.assertIs(True, location["same_named_macro_literal_as_sarif_target"])
                self.assertEqual(
                    {"file", "line", "same_named_macro_literal_as_sarif_target"},
                    set(location),
                )

    def test_catalogue_marks_unparsed_or_unverified_macro_comparisons_unresolved(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            sources = {
                "target.c": b'#define DEVICE_PASSWORD "fixture-password-123"\n',
                "support.c": b"const char *password = derive_secret();\n",
            }
            target_files = []
            for name, content in sources.items():
                (root / name).write_bytes(content)
                target_files.append(
                    {
                        "path": name,
                        "length": len(content),
                        "sha256": hashlib.sha256(content).hexdigest(),
                    }
                )
            result = summarize_findings(
                {"sarif_targets": ["target.c"], "target_files": target_files},
                [
                    {"location": {"file": "target.c", "start_line": 1}},
                    {"location": {"file": "support.c", "start_line": 1}},
                ],
                root,
            )

        self.assertEqual(0, result["additional_same_named_macro_literal_matches"])
        self.assertEqual(0, result["additional_macro_literal_comparisons"])
        self.assertEqual(1, result["additional_macro_literal_comparisons_unresolved"])
        self.assertIsNone(
            result["additional_fuse001_locations"][0]["same_named_macro_literal_as_sarif_target"]
        )

    def test_catalogue_target_verification_checks_length_and_digest(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            relative_path = "src/testcases/target.c"
            content = b"int target(void) { return 0; }\n"
            target_path = root / relative_path
            target_path.parent.mkdir(parents=True)
            target_path.write_bytes(content)
            case: dict[str, Any] = {
                "case_id": "sample",
                "target_files": [
                    {
                        "path": relative_path,
                        "length": len(content),
                        "sha256": hashlib.sha256(content).hexdigest(),
                    }
                ],
            }

            _verify_source_targets(case, root)
            case["target_files"][0]["sha256"] = "0" * 64
            with self.assertRaisesRegex(ValueError, "SHA-256 mismatch"):
                _verify_source_targets(case, root)

    def test_sard_download_retries_connection_reset_and_checks_digest(self) -> None:
        content = b"pinned archive bytes"
        response = MagicMock()
        stream = response.__enter__.return_value
        stream.headers.get.return_value = str(len(content))
        stream.read.side_effect = [content, b""]
        case = SardCase("12345", "01", hashlib.sha256(content).hexdigest(), "target.c", ())

        with tempfile.TemporaryDirectory() as temporary:
            destination = Path(temporary) / "case.zip"
            with (
                patch(
                    "scripts.evaluate_sard_fuse001_cohort.urlopen",
                    side_effect=[ConnectionResetError("temporary reset"), response],
                ) as open_url,
                patch("scripts.evaluate_sard_fuse001_cohort.time.sleep"),
            ):
                download_case(case, destination)

            self.assertEqual(2, open_url.call_count)
            self.assertEqual(content, destination.read_bytes())

    def test_safe_extraction_accepts_regular_files(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            archive_path = self._make_archive(
                root,
                "valid.zip",
                [("src/example.c", b"int main(void) { return 0; }\n")],
            )

            extracted_size = _safe_extract_zip(archive_path, root / "out")

            self.assertEqual(len(b"int main(void) { return 0; }\n"), extracted_size)
            self.assertTrue((root / "out" / "src" / "example.c").is_file())

    def test_safe_extraction_rejects_parent_traversal(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            archive_path = self._make_archive(root, "traversal.zip", [("../escape.txt", b"x")])

            with self.assertRaisesRegex(ValueError, "unsafe path"):
                _safe_extract_zip(archive_path, root / "out")

    def test_safe_extraction_rejects_windows_absolute_paths(self) -> None:
        for archive_name in ("C:/escape.txt", "//?/C:/escape.txt"):
            with (
                self.subTest(archive_name=archive_name),
                tempfile.TemporaryDirectory() as temporary,
            ):
                root = Path(temporary)
                archive_path = self._make_archive(
                    root,
                    "unsafe.zip",
                    [(archive_name, b"x")],
                )

                with self.assertRaisesRegex(ValueError, "unsafe path"):
                    _safe_extract_zip(archive_path, root / "out")

    def test_safe_extraction_rejects_symlink_entries(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            archive_path = root / "symlink.zip"
            info = ZipInfo("link")
            info.create_system = 3
            info.external_attr = (stat.S_IFLNK | 0o777) << 16
            with ZipFile(archive_path, "w") as archive:
                archive.writestr(info, "outside")

            with self.assertRaisesRegex(ValueError, "link or special file"):
                _safe_extract_zip(archive_path, root / "out")

    def test_safe_extraction_enforces_entry_and_expansion_limits(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            archive_path = self._make_archive(
                root,
                "bounded.zip",
                [("one.txt", b"1234"), ("two.txt", b"5678")],
            )

            with self.assertRaisesRegex(ValueError, "entry limit"):
                _safe_extract_zip(archive_path, root / "entries", max_entries=1)
            with self.assertRaisesRegex(ValueError, "expanded-size limit"):
                _safe_extract_zip(archive_path, root / "size", max_uncompressed_bytes=7)
