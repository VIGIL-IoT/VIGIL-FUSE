from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from vigil_fuse.report_pdf import _render_report, write_pdf_report
from vigil_fuse.terminal import _ASCII_MARK


class PDFReportTests(unittest.TestCase):
    def _result(self) -> SimpleNamespace:
        finding = SimpleNamespace(
            id="FUSE-FIND-001",
            severity="high",
            confidence="medium",
            title="Credential & key",
            rule_id="FUSE001",
            category="secrets",
            file="src/config_file.c",
            start_line=12,
            evidence=r"password = \input{unsafe} 100%",
            explanation="A matching credential-like literal was found.",
            potential_impact="A deployed credential may be exposed.",
            remediation="Use a secret store and rotate exposed credentials.",
            references=("https://example.invalid/security-guidance",),
        )
        return SimpleNamespace(
            findings=(finding,),
            files_scanned=12,
            files_selected=13,
            files_skipped=1,
            discovery_complete=False,
            limits_reached=("source byte limit",),
            analyzers=(),
            target=r"C:\project\firmware & tests",
            profile="generic",
            target_kind="directory",
            started_at="2026-11-14T10:00:00Z",
            completed_at="2026-11-14T10:00:02Z",
        )

    def test_latex_keeps_severity_and_confidence_separate_and_escapes_input(self) -> None:
        report = _render_report(self._result())

        self.assertIn(r"\textbf{Severity:} high", report)
        self.assertIn(r"\textbf{Confidence:} medium", report)
        self.assertIn("FUSE-FIND-001", report)
        self.assertIn("security-guidance", report)
        self.assertIn(r"\&", report)
        self.assertIn(r"\textbackslash{}input", report)
        self.assertIn(r"\%", report)
        self.assertIn("source byte limit", report)
        self.assertIn(r"\setmainfont{Times New Roman}", report)
        self.assertIn(_ASCII_MARK[0].replace(" ", r"\ "), report)
        self.assertIn("by VIGIL", report)
        self.assertIn("Static evidence. Explicit coverage.", report)
        self.assertIn("LOCAL ANALYSIS / Type /help to begin", report)
        self.assertIn("v0.5.0", report)

    def test_writer_prefers_xelatex_for_times_new_roman_pdf(self) -> None:
        def compile_xelatex(arguments: list[str], **options: object) -> SimpleNamespace:
            self.assertEqual(Path(arguments[0]).name, "xelatex")
            self.assertIn("-disable-installer", arguments)
            build_dir = Path(str(options["cwd"]))
            self.assertIn(
                r"\setmainfont{Times New Roman}", (build_dir / "fuse-report.tex").read_text()
            )
            (build_dir / "fuse-report.pdf").write_bytes(b"%PDF-1.4 test")
            return SimpleNamespace(returncode=0)

        with (
            TemporaryDirectory() as temporary,
            patch(
                "vigil_fuse.report_pdf.shutil.which",
                side_effect=lambda name: f"/opt/miktex/bin/{name}" if name == "xelatex" else None,
            ),
            patch("vigil_fuse.report_pdf.subprocess.run", side_effect=compile_xelatex),
        ):
            pdf_path, note = write_pdf_report(self._result(), Path(temporary))

            self.assertIsNone(note)
            self.assertTrue(pdf_path and pdf_path.is_file())

    def test_pdflatex_template_uses_times_compatible_fallback(self) -> None:
        report = _render_report(self._result(), xelatex=False)

        self.assertIn(r"\usepackage{mathptmx}", report)
        self.assertNotIn(r"\usepackage{fontspec}", report)

    def test_missing_latex_keeps_source_without_claiming_pdf_exists(self) -> None:
        with (
            TemporaryDirectory() as temporary,
            patch("vigil_fuse.report_pdf.shutil.which", return_value=None),
        ):
            output_dir = Path(temporary)
            pdf_path, note = write_pdf_report(self._result(), output_dir)
            self.assertIsNone(pdf_path)
            self.assertIn("xelatex and pdflatex were not found", note or "")
            self.assertTrue((output_dir / "fuse-report.tex").is_file())
            self.assertFalse((output_dir / "fuse-report.pdf").exists())


if __name__ == "__main__":
    unittest.main()
