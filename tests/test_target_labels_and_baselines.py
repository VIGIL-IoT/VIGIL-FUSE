from __future__ import annotations

import json
import os
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
from pathlib import Path

from vigil_fuse.baseline import create_baseline, diff_baseline, suppress_finding, unsuppress_finding
from vigil_fuse.cli import main
from vigil_fuse.config import load_config
from vigil_fuse.reporting import to_json
from vigil_fuse.scanner import scan
from vigil_fuse.target_labels import validate_target_label


class TargetLabelAndBaselineTests(unittest.TestCase):
    @staticmethod
    def write_vulnerable_source(root: Path, *, add_comment: bool = False) -> None:
        source = root / "src" / "config.yaml"
        source.parent.mkdir(parents=True, exist_ok=True)
        prefix = "# generated configuration\n" if add_comment else ""
        source.write_text(
            prefix + 'network:\n  mqtt_password: "S0me-realistic-secret"\n',
            encoding="utf-8",
        )

    @classmethod
    def create_report(
        cls, root: Path, report_path: Path, label: str, *, add_comment: bool = False
    ) -> dict:
        cls.write_vulnerable_source(root, add_comment=add_comment)
        result = scan(root, target_label=label)
        report_path.write_text(to_json(result), encoding="utf-8")
        return json.loads(report_path.read_text(encoding="utf-8"))

    @staticmethod
    def diff_json(
        report_path: Path, baseline_path: Path, suppressions_path: Path | None = None
    ) -> tuple[int, dict]:
        stdout = StringIO()
        with redirect_stdout(stdout):
            code = diff_baseline(report_path, baseline_path, suppressions_path, "json", "none")
        return code, json.loads(stdout.getvalue())

    def test_target_labels_accept_repository_names_and_reject_paths(self) -> None:
        self.assertEqual(
            "my-lab/firmware-project", validate_target_label(" my-lab/firmware-project ")
        )
        for label in (
            "",
            ".",
            "../repo",
            "org//repo",
            "/tmp/repo",
            "C:/repo",
            r"org\repo",
            "bad\nlabel",
        ):
            with self.subTest(label=label):
                with self.assertRaises(ValueError):
                    validate_target_label(label)

    def test_default_dot_target_uses_project_basename_without_disclosing_path(self) -> None:
        original_cwd = Path.cwd()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "firmware-project"
            root.mkdir()
            try:
                os.chdir(root)
                result = scan(Path("."))
            finally:
                os.chdir(original_cwd)

        self.assertEqual("firmware-project", result.target)
        self.assertNotIn(str(root), to_json(result))

    def test_target_label_is_used_in_reports_and_scan_plans(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "same-folder-name"
            root.mkdir()
            (root / "main.py").write_text("value = 1\n", encoding="utf-8")
            report_path = Path(temporary) / "report.json"
            stdout = StringIO()
            stderr = StringIO()
            with redirect_stdout(stdout), redirect_stderr(stderr):
                code = main(
                    [
                        "scan",
                        str(root),
                        "--target-label",
                        "lab/actual-repository",
                        "--output",
                        str(report_path),
                        "--format",
                        "json",
                    ]
                )
            report = json.loads(report_path.read_text(encoding="utf-8"))

            plan_stdout = StringIO()
            with redirect_stdout(plan_stdout), redirect_stderr(StringIO()):
                plan_code = main(
                    [
                        "scan",
                        str(root),
                        "--plan",
                        "--format",
                        "json",
                        "--target-label",
                        "lab/actual-repository",
                    ]
                )
            plan = json.loads(plan_stdout.getvalue())

        self.assertEqual(0, code)
        self.assertEqual(0, plan_code)
        self.assertEqual("lab/actual-repository", report["target"])
        self.assertEqual("lab/actual-repository", plan["target"])
        self.assertNotIn(str(root), json.dumps(report))

    def test_toml_target_label_is_validated_and_cli_value_overrides_it(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "repository"
            root.mkdir()
            (root / "main.py").write_text("value = 1\n", encoding="utf-8")
            config = Path(temporary) / "fuse.toml"
            config.write_text('[scan]\ntarget_label = "config/repository"\n', encoding="utf-8")
            loaded = load_config(config)
            output = Path(temporary) / "configured.json"
            stdout = StringIO()
            with redirect_stdout(stdout), redirect_stderr(StringIO()):
                code = main(
                    [
                        "scan",
                        str(root),
                        "--config",
                        str(config),
                        "--output",
                        str(output),
                        "--format",
                        "json",
                        "--target-label",
                        "cli/repository",
                    ]
                )
            report = json.loads(output.read_text(encoding="utf-8"))
            config.write_text('[scan]\ntarget_label = "../local-path"\n', encoding="utf-8")
            with self.assertRaises(ValueError):
                load_config(config)

        self.assertEqual("config/repository", loaded.target_label)
        self.assertEqual(0, code)
        self.assertEqual("cli/repository", report["target"])

    def test_baseline_keeps_full_target_label_and_line_shifts_are_persistent(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary)
            root = parent / "checkout"
            report_path = parent / "first.json"
            baseline_path = parent / "baseline.json"
            first = self.create_report(root, report_path, "team-a/firmware")
            stdout = StringIO()
            with redirect_stdout(stdout):
                create_code = create_baseline(report_path, baseline_path)
            baseline = json.loads(baseline_path.read_text(encoding="utf-8"))

            current_path = parent / "current.json"
            current = self.create_report(root, current_path, "team-a/firmware", add_comment=True)
            diff_code, diff = self.diff_json(current_path, baseline_path)

        self.assertTrue(first["findings"])
        self.assertTrue(current["findings"])
        self.assertEqual(0, create_code)
        self.assertEqual("team-a/firmware", baseline["project"]["target"])
        self.assertEqual(0, diff_code)
        self.assertEqual(0, diff["summary"]["new"])
        self.assertEqual(1, diff["summary"]["persistent"])
        self.assertEqual(0, diff["summary"]["resolved"])

    def test_unique_native_finding_file_move_is_reported_without_new_or_resolved(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary)
            root = parent / "checkout"
            source = root / "src" / "config.yaml"
            source.parent.mkdir(parents=True)
            source.write_text(
                'network:\n  mqtt_password: "S0me-realistic-secret"\n', encoding="utf-8"
            )
            first_path = parent / "first.json"
            first_path.write_text(
                to_json(scan(root, target_label="team/firmware")), encoding="utf-8"
            )
            baseline_path = parent / "baseline.json"
            with redirect_stdout(StringIO()):
                create_baseline(first_path, baseline_path)

            moved_source = root / "src" / "settings.yaml"
            source.rename(moved_source)
            current_path = parent / "current.json"
            current_path.write_text(
                to_json(scan(root, target_label="team/firmware")), encoding="utf-8"
            )
            code, diff = self.diff_json(current_path, baseline_path)

        self.assertEqual(0, code)
        self.assertEqual(0, diff["summary"]["new"])
        self.assertEqual(0, diff["summary"]["persistent"])
        self.assertEqual(1, diff["summary"]["moved"])
        self.assertEqual(0, diff["summary"]["resolved"])
        self.assertEqual("moved", diff["findings"][0]["change"])
        self.assertEqual("src/config.yaml", diff["findings"][0]["moved_from"])

    def test_ambiguous_identical_moves_remain_new_and_resolved_for_review(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary)
            root = parent / "checkout"
            content = 'network:\n  mqtt_password: "S0me-realistic-secret"\n'
            for filename in ("first.yaml", "second.yaml"):
                source = root / "src" / filename
                source.parent.mkdir(parents=True, exist_ok=True)
                source.write_text(content, encoding="utf-8")
            first_path = parent / "first.json"
            first_path.write_text(
                to_json(scan(root, target_label="team/firmware")), encoding="utf-8"
            )
            baseline_path = parent / "baseline.json"
            with redirect_stdout(StringIO()):
                create_baseline(first_path, baseline_path)

            (root / "src" / "first.yaml").unlink()
            (root / "src" / "second.yaml").unlink()
            (root / "src" / "renamed.yaml").write_text(content, encoding="utf-8")
            current_path = parent / "current.json"
            current_path.write_text(
                to_json(scan(root, target_label="team/firmware")), encoding="utf-8"
            )
            code, diff = self.diff_json(current_path, baseline_path)

        self.assertEqual(0, code)
        self.assertEqual(1, diff["summary"]["new"])
        self.assertEqual(0, diff["summary"]["moved"])
        self.assertEqual(2, diff["summary"]["resolved"])

    def test_moved_finding_does_not_inherit_path_specific_suppression(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary)
            root = parent / "checkout"
            source = root / "src" / "config.yaml"
            source.parent.mkdir(parents=True)
            source.write_text(
                'network:\n  mqtt_password: "S0me-realistic-secret"\n', encoding="utf-8"
            )
            first_path = parent / "first.json"
            first_path.write_text(
                to_json(scan(root, target_label="team/firmware")), encoding="utf-8"
            )
            first_report = json.loads(first_path.read_text(encoding="utf-8"))
            baseline_path = parent / "baseline.json"
            suppressions_path = parent / "suppressions.json"
            with redirect_stdout(StringIO()):
                create_baseline(first_path, baseline_path)
                suppress_finding(
                    first_path,
                    first_report["findings"][0]["fingerprint"],
                    "Reviewed at the original path",
                    "firmware team",
                    None,
                    suppressions_path,
                )

            source.rename(root / "src" / "renamed.yaml")
            current_path = parent / "current.json"
            current_path.write_text(
                to_json(scan(root, target_label="team/firmware")), encoding="utf-8"
            )
            code, diff = self.diff_json(current_path, baseline_path, suppressions_path)

        self.assertEqual(0, code)
        self.assertEqual(1, diff["summary"]["moved"])
        self.assertEqual(0, diff["summary"]["suppressed"])

    def test_osv_findings_do_not_receive_path_independent_move_identity(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary)
            root = parent / "checkout"
            first_path = parent / "first.json"
            first_report = self.create_report(root, first_path, "team/firmware")
            native = first_report["findings"][0]
            native["analyzer"] = "osv-scanner"
            native["id"] = "OSV:OSV-EXAMPLE:component@1.0:src/config.yaml"
            native["rule_id"] = "OSV-EXAMPLE"
            native["category"] = "dependencies"
            first_path.write_text(json.dumps(first_report), encoding="utf-8")
            baseline_path = parent / "baseline.json"
            with redirect_stdout(StringIO()):
                create_baseline(first_path, baseline_path)

            current_report = json.loads(first_path.read_text(encoding="utf-8"))
            current_report["findings"][0]["location"]["file"] = "src/renamed.yaml"
            current_report["findings"][0]["id"] = "OSV:OSV-EXAMPLE:component@1.0:src/renamed.yaml"
            current_path = parent / "current.json"
            current_path.write_text(json.dumps(current_report), encoding="utf-8")
            code, diff = self.diff_json(current_path, baseline_path)

        self.assertEqual(0, code)
        self.assertEqual(1, diff["summary"]["new"])
        self.assertEqual(0, diff["summary"]["moved"])
        self.assertEqual(1, diff["summary"]["resolved"])

    def test_baseline_rejects_same_basename_under_a_different_target_label(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary)
            first_root = parent / "first" / "firmware"
            first_root.mkdir(parents=True)
            first_report = parent / "first.json"
            self.create_report(first_root, first_report, "team-a/firmware")
            baseline_path = parent / "baseline.json"
            with redirect_stdout(StringIO()):
                create_baseline(first_report, baseline_path)

            second_root = parent / "second" / "firmware"
            second_report = parent / "second.json"
            self.create_report(second_root, second_report, "team-b/firmware")
            with self.assertRaisesRegex(ValueError, "does not match this baseline"):
                self.diff_json(second_report, baseline_path)

    def test_incomplete_diff_does_not_mark_baseline_findings_resolved(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary)
            root = parent / "checkout"
            report_path = parent / "complete.json"
            report = self.create_report(root, report_path, "team/firmware")
            baseline_path = parent / "baseline.json"
            with redirect_stdout(StringIO()):
                create_baseline(report_path, baseline_path)

            report["coverage"]["discovery_complete"] = False
            report["hardware_inventory"]["complete"] = False
            incomplete_path = parent / "incomplete.json"
            incomplete_path.write_text(json.dumps(report), encoding="utf-8")
            code, diff = self.diff_json(incomplete_path, baseline_path)

        self.assertEqual(2, code)
        self.assertEqual("incomplete", diff["analysis_status"])
        self.assertIsNone(diff["summary"]["resolved"])
        self.assertFalse(diff["summary"]["resolved_evaluated"])
        self.assertEqual([], diff["resolved_findings"])

    def test_suppressions_require_a_reason_and_can_be_removed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary)
            root = parent / "checkout"
            report_path = parent / "report.json"
            report = self.create_report(root, report_path, "team/firmware")
            self.assertTrue(report["findings"])
            fingerprint = report["findings"][0]["fingerprint"]
            baseline_path = parent / "baseline.json"
            suppressions_path = parent / "suppressions.json"
            with redirect_stdout(StringIO()):
                create_baseline(report_path, baseline_path)
                suppress_code = suppress_finding(
                    report_path,
                    fingerprint,
                    "Reviewed with the hardware owner",
                    "firmware team",
                    None,
                    suppressions_path,
                )
            suppressed_code, suppressed = self.diff_json(
                report_path, baseline_path, suppressions_path
            )

            with redirect_stdout(StringIO()):
                unsuppress_code = unsuppress_finding(report_path, fingerprint, suppressions_path)
            unsuppressed_code, unsuppressed = self.diff_json(
                report_path, baseline_path, suppressions_path
            )
            suppression_data = json.loads(suppressions_path.read_text(encoding="utf-8"))

        self.assertEqual(0, suppress_code)
        self.assertEqual(0, suppressed_code)
        self.assertEqual(1, suppressed["summary"]["suppressed"])
        self.assertEqual(0, unsuppress_code)
        self.assertEqual(0, unsuppressed_code)
        self.assertEqual(0, unsuppressed["summary"]["suppressed"])
        self.assertEqual([], suppression_data["suppressions"])

    def test_duplicate_finding_suppressions_remain_independent_after_line_shift(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary)
            root = parent / "checkout"
            source = root / "src" / "config.yaml"
            source.parent.mkdir(parents=True)
            assignment = '  mqtt_password: "S0me-realistic-secret"\n'
            source.write_text("network:\n" + assignment * 2, encoding="utf-8")
            first_path = parent / "first.json"
            first_path.write_text(
                to_json(scan(root, target_label="team/firmware")), encoding="utf-8"
            )
            first_report = json.loads(first_path.read_text(encoding="utf-8"))
            self.assertEqual(2, len(first_report["findings"]))

            baseline_path = parent / "baseline.json"
            suppressions_path = parent / "suppressions.json"
            with redirect_stdout(StringIO()):
                create_baseline(first_path, baseline_path)
                suppress_finding(
                    first_path,
                    first_report["findings"][0]["fingerprint"],
                    "Reviewed this occurrence",
                    "firmware team",
                    None,
                    suppressions_path,
                )

            source.write_text("# unrelated comment\nnetwork:\n" + assignment * 2, encoding="utf-8")
            current_path = parent / "current.json"
            current_path.write_text(
                to_json(scan(root, target_label="team/firmware")), encoding="utf-8"
            )
            code, diff = self.diff_json(current_path, baseline_path, suppressions_path)
            current_report = json.loads(current_path.read_text(encoding="utf-8"))
            with redirect_stdout(StringIO()):
                unsuppress_code = unsuppress_finding(
                    current_path,
                    current_report["findings"][0]["fingerprint"],
                    suppressions_path,
                )
            unsuppressed_code, unsuppressed = self.diff_json(
                current_path, baseline_path, suppressions_path
            )

        self.assertEqual(0, code)
        self.assertEqual(2, diff["summary"]["persistent"])
        self.assertEqual(1, diff["summary"]["suppressed"])
        self.assertEqual(1, sum(item["suppressed"] for item in diff["findings"]))
        self.assertEqual(0, unsuppress_code)
        self.assertEqual(0, unsuppressed_code)
        self.assertEqual(0, unsuppressed["summary"]["suppressed"])

    def test_legacy_baseline_and_suppression_identity_remain_readable(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary)
            root = parent / "checkout"
            report_path = parent / "report.json"
            self.create_report(root, report_path, "team/firmware")
            baseline_path = parent / "baseline.json"
            with redirect_stdout(StringIO()):
                create_baseline(report_path, baseline_path)

            baseline = json.loads(baseline_path.read_text(encoding="utf-8"))
            for finding in baseline["findings"]:
                finding.pop("suppression_identity", None)
                finding.pop("move_identity", None)
            baseline["format_version"] = "1.0"
            baseline_path.write_text(json.dumps(baseline), encoding="utf-8")
            suppression_path = parent / "legacy-suppressions.json"
            suppression_path.write_text(
                json.dumps(
                    {
                        "format_version": "1.0",
                        "project": baseline["project"],
                        "suppressions": [
                            {
                                "identity": baseline["findings"][0]["identity"],
                                "reason": "Existing reviewed suppression",
                                "owner": None,
                                "created_at": "2026-01-01T00:00:00Z",
                                "expires_at": None,
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )

            code, diff = self.diff_json(report_path, baseline_path, suppression_path)

        self.assertEqual(0, code)
        self.assertEqual(1, diff["summary"]["persistent"])
        self.assertEqual(1, diff["summary"]["suppressed"])


if __name__ == "__main__":
    unittest.main()
