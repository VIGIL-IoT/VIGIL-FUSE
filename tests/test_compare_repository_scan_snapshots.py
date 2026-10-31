from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from scripts.compare_repository_scan_snapshots import compare_snapshots


class CompareRepositoryScanSnapshotsTests(unittest.TestCase):
    def _write_json(self, path: Path, value: object) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(value), encoding="utf-8")

    def test_comparison_reports_counts_without_copying_finding_values(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            baseline_manifest = root / "baseline.json"
            candidate_manifest = root / "candidate.json"
            manifest = {
                "cohort": "baseline",
                "repositories": [
                    {
                        "id": "example",
                        "name": "example/project",
                        "commit": "a" * 40,
                        "profile": "generic",
                        "scans": [{"id": "example", "scope": "source", "includes": ["src/**"]}],
                    }
                ],
            }
            self._write_json(baseline_manifest, manifest)
            self._write_json(candidate_manifest, {**manifest, "cohort": "candidate"})
            self._write_json(
                root / "baseline-reports" / "example" / "findings.json",
                {
                    "schema_version": "1.0",
                    "findings": [
                        {
                            "id": "FUSE001:src/a.c:2",
                            "rule_id": "FUSE001",
                            "rule_version": "1.0.0",
                            "evidence": {"value": "baseline-secret"},
                        },
                        {"id": "FUSE002:src/b.c:5", "rule_id": "FUSE002"},
                    ],
                },
            )
            self._write_json(
                root / "candidate-reports" / "example" / "findings.json",
                {
                    "schema_version": "1.0",
                    "findings": [
                        {
                            "id": "FUSE001:src/a.c:2",
                            "rule_id": "FUSE001",
                            "rule_version": "1.1.0",
                            "evidence": {"value": "candidate-secret"},
                        },
                        {"id": "FUSE007:src/c.c:9", "rule_id": "FUSE007"},
                    ],
                },
            )

            result = compare_snapshots(
                baseline_manifest,
                root / "baseline-reports",
                candidate_manifest,
                root / "candidate-reports",
            )
            serialized = json.dumps(result)

        scan = result["scans"][0]
        self.assertEqual(
            {
                "baseline_findings": 2,
                "candidate_findings": 2,
                "retained": 1,
                "added": 1,
                "removed": 1,
                "changed": 1,
                "changed_fields": {"evidence": 1, "rule_version": 1},
            },
            {
                key: scan[key]
                for key in (
                    "baseline_findings",
                    "candidate_findings",
                    "retained",
                    "added",
                    "removed",
                    "changed",
                    "changed_fields",
                )
            },
        )
        self.assertNotIn("baseline-secret", serialized)
        self.assertNotIn("candidate-secret", serialized)

    def test_comparison_rejects_different_pinned_repository_scopes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            baseline_manifest = root / "baseline.json"
            candidate_manifest = root / "candidate.json"
            base = {"cohort": "baseline", "repositories": []}
            candidate = {
                "cohort": "candidate",
                "repositories": [{"id": "example", "commit": "a" * 40, "scans": []}],
            }
            self._write_json(baseline_manifest, base)
            self._write_json(candidate_manifest, candidate)

            with self.assertRaisesRegex(ValueError, "targets or scan scopes differ"):
                compare_snapshots(baseline_manifest, root, candidate_manifest, root)

    def test_comparison_rejects_report_path_traversal(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            baseline_manifest = root / "baseline.json"
            candidate_manifest = root / "candidate.json"
            manifest = {
                "cohort": "baseline",
                "repositories": [
                    {
                        "id": "example",
                        "commit": "a" * 40,
                        "scans": [{"id": "../escape"}],
                    }
                ],
            }
            self._write_json(baseline_manifest, manifest)
            self._write_json(candidate_manifest, {**manifest, "cohort": "candidate"})

            with self.assertRaisesRegex(ValueError, "invalid scan ID"):
                compare_snapshots(baseline_manifest, root, candidate_manifest, root)

    def test_comparison_rejects_incompatible_report_schemas(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            baseline_manifest = root / "baseline.json"
            candidate_manifest = root / "candidate.json"
            manifest = {
                "cohort": "baseline",
                "repositories": [
                    {
                        "id": "example",
                        "commit": "a" * 40,
                        "scans": [{"id": "example"}],
                    }
                ],
            }
            self._write_json(baseline_manifest, manifest)
            self._write_json(candidate_manifest, {**manifest, "cohort": "candidate"})
            self._write_json(
                root / "baseline-reports" / "example" / "findings.json",
                {"schema_version": "1.0", "findings": []},
            )
            self._write_json(
                root / "candidate-reports" / "example" / "findings.json",
                {"schema_version": "2.0", "findings": []},
            )

            with self.assertRaisesRegex(ValueError, "Report schemas differ"):
                compare_snapshots(
                    baseline_manifest,
                    root / "baseline-reports",
                    candidate_manifest,
                    root / "candidate-reports",
                )


if __name__ == "__main__":
    unittest.main()
