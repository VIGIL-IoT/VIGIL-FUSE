from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
from pathlib import Path

from vigil_fuse import __version__
from vigil_fuse.attribution import FUSE_REPOSITORY, generated_by_metadata
from vigil_fuse.cli import _default_output_dir, main
from vigil_fuse.reporting import to_json, to_text
from vigil_fuse.sarif import to_sarif
from vigil_fuse.scanner import scan


class IdentityAttributionTests(unittest.TestCase):
    def test_scan_reports_include_identity_and_canonical_attribution(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "project"
            root.mkdir()
            (root / "pyproject.toml").write_text("[project]\nname='sample'\n", encoding="utf-8")
            (root / "src" / "main.py").parent.mkdir()
            (root / "src" / "main.py").write_text("print('hello')\n", encoding="utf-8")
            result = scan(root, target_label="team/sample")

        report = json.loads(to_json(result))
        self.assertEqual("1.15", report["schema_version"])
        self.assertEqual(generated_by_metadata(), report["generated_by"])
        self.assertEqual("team/sample", report["scan"]["target_label"])
        self.assertEqual("software", report["project_identity"]["primary_type"])
        self.assertTrue(report["project_identity"]["analysis_recommendations"]["advisory_only"])

        text = to_text(result)
        self.assertTrue(
            text.startswith("FUSE - Firmware & Unified Security Engine\nA VIGIL Project\n")
        )
        self.assertIn(FUSE_REPOSITORY, text)
        self.assertIn("Project identity: software", text)
        self.assertIn("Advisory analysis recommendations (no tools auto-enabled):", text)

        sarif = json.loads(to_sarif(result))
        driver = sarif["runs"][0]["tool"]["driver"]
        self.assertEqual(__version__, driver["version"])
        self.assertEqual(FUSE_REPOSITORY, driver["informationUri"])
        self.assertEqual(generated_by_metadata(), sarif["runs"][0]["properties"]["generatedBy"])
        self.assertEqual("team/sample", sarif["runs"][0]["properties"]["targetLabel"])
        self.assertEqual(
            "software", sarif["runs"][0]["properties"]["projectIdentity"]["primary_type"]
        )

    def test_report_bundle_hashes_exact_report_bytes_and_cites_runtime_version(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "project"
            output = Path(temporary) / "reports"
            root.mkdir()
            (root / "main.c").write_text("int main(void) { return 0; }\n", encoding="utf-8")
            before = {path.relative_to(root).as_posix() for path in root.rglob("*")}
            with redirect_stdout(StringIO()), redirect_stderr(StringIO()):
                exit_code = main(
                    [
                        "scan",
                        str(root),
                        "--output-dir",
                        str(output),
                        "--target-label",
                        "org/project",
                    ]
                )

            provenance_path = output / "FUSE_SCAN_PROVENANCE.json"
            provenance = json.loads(provenance_path.read_text(encoding="utf-8"))
            self.assertEqual("org/project", provenance["scan"]["target_label"])
            self.assertEqual("generic", provenance["scan"]["configuration"]["profile"])
            self.assertEqual(64, len(provenance["scan"]["configuration_sha256"]))
            self.assertEqual(
                {"findings.json", "findings.txt", "findings.sarif"},
                set(provenance["artifacts"]),
            )
            for name, details in provenance["artifacts"].items():
                actual = hashlib.sha256((output / name).read_bytes()).hexdigest()
                self.assertEqual(actual, details["sha256"])
            self.assertFalse(provenance_path.is_symlink())
            self.assertNotIn(str(root), provenance_path.read_text(encoding="utf-8"))
            self.assertIn(f'version: "{__version__}"', (output / "CITATION.cff").read_text())
            canonical_citation = Path(__file__).parents[1] / "CITATION.cff"
            self.assertEqual(
                canonical_citation.read_text(encoding="utf-8"),
                (output / "CITATION.cff").read_text(encoding="utf-8"),
            )
            after = {path.relative_to(root).as_posix() for path in root.rglob("*")}

        self.assertEqual(0, exit_code)
        self.assertEqual(before, after)

    def test_default_report_directory_is_a_sibling_of_directory_target(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "project"
            root.mkdir()
            (root / "main.py").write_text("print(1)\n", encoding="utf-8")
            target_entries_before = {path.relative_to(root).as_posix() for path in root.rglob("*")}
            output = _default_output_dir(root)
            expected = root.resolve().parent / ".fuse-results" / root.name
            self.assertEqual(expected, output)
            self.assertFalse(output.is_relative_to(root.resolve()))
            with redirect_stdout(StringIO()), redirect_stderr(StringIO()):
                exit_code = main(["scan", str(root)])
            target_entries_after = {path.relative_to(root).as_posix() for path in root.rglob("*")}
            self.assertTrue((output / "findings.json").is_file())

        self.assertEqual(0, exit_code)
        self.assertEqual(target_entries_before, target_entries_after)

    def test_scan_plan_includes_identity_scores_and_advisory_recommendations(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "project"
            root.mkdir()
            (root / "platformio.ini").write_text(
                "[env:demo]\nplatform=espressif32\n", encoding="utf-8"
            )
            (root / "src").mkdir()
            (root / "src" / "main.cpp").write_text("void setup() {}\n", encoding="utf-8")
            output = StringIO()
            with redirect_stdout(output), redirect_stderr(StringIO()):
                exit_code = main(["scan", str(root), "--plan", "--format", "json"])
            plan = json.loads(output.getvalue())

        identity = plan["project_identity"]
        self.assertEqual(0, exit_code)
        self.assertEqual("embedded", identity["primary_type"])
        self.assertIn("embedded", identity["domains"])
        self.assertTrue(identity["analysis_recommendations"]["advisory_only"])
        self.assertFalse(plan["executed"])


if __name__ == "__main__":
    unittest.main()
