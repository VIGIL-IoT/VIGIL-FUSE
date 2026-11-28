from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts import build_repository_scan_dashboard as dashboard


class RepositoryScanDashboardTests(unittest.TestCase):
    def test_normalize_report_accepts_current_schema_115(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            run = root / "current"
            run.mkdir()
            (run / "findings.json").write_text(
                '{"schema_version":"1.15","target":"local/path","findings":[]}',
                encoding="utf-8",
            )
            with patch.object(dashboard, "REPORT_ROOT", root):
                report = dashboard.normalize_report(
                    {"id": "current", "target_label": "fixture/project"}
                )

        self.assertEqual("fixture/project", report["target"])

    def test_report_only_does_not_write_generated_site_files(self) -> None:
        summary = {
            "repositories": [],
            "totals": {
                "rule_counts": {},
                "repository_count": 0,
                "scan_scope_count": 0,
                "files_scanned": 0,
                "finding_count": 0,
            },
        }

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            report_root = root / "reports"
            site_data = root / "site" / "data" / "repository-scan-results.json"
            site_support_matrix = root / "site" / "data" / "support-matrix.json"

            with (
                patch.object(dashboard, "ROOT", root),
                patch.object(dashboard, "REPORT_ROOT", report_root),
                patch.object(dashboard, "SITE_DATA_PATH", site_data),
                patch.object(dashboard, "SITE_SUPPORT_MATRIX_PATH", site_support_matrix),
                patch.object(dashboard, "build_summary", return_value=summary),
                patch.object(
                    dashboard,
                    "build_support_matrix",
                    side_effect=AssertionError("report-only mode must skip site data"),
                ),
                patch.object(sys, "argv", ["build_repository_scan_dashboard.py", "--report-only"]),
            ):
                dashboard.main()

            self.assertTrue((report_root / "summary.json").is_file())
            self.assertTrue((report_root / "plots" / "findings-by-repository.svg").is_file())
            self.assertTrue((report_root / "plots" / "findings-by-rule.svg").is_file())
            self.assertFalse(site_data.exists())
            self.assertFalse(site_support_matrix.exists())
            self.assertFalse((root / "site" / "assets").exists())


if __name__ == "__main__":
    unittest.main()
