from __future__ import annotations

from pathlib import Path
import stat
import tempfile
import unittest
from zipfile import ZipInfo, ZipFile

from scripts.evaluate_sard_fuse001_cohort import CASES, _safe_extract_zip


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
