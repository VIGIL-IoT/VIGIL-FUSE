from __future__ import annotations

from contextlib import redirect_stderr
import io
import json
from pathlib import Path
import tempfile
import unittest

from jsonschema import Draft202012Validator

from vigil_fuse.cli import main
from vigil_fuse.reasoning_context import (
    ReasoningContextLimits,
    build_reasoning_context,
    load_scan_report,
)


def _finding(
    finding_id: str = "FUSE-001-1",
    *,
    category: str = "security",
    rule_id: str = "FUSE-001",
    file: str = "src/main.c",
    evidence: str = "password=secret-value",
) -> dict[str, object]:
    return {
        "id": finding_id,
        "rule_id": rule_id,
        "analyzer": "native-rules",
        "title": "Example finding",
        "severity": "high",
        "confidence": "high",
        "category": category,
        "applicability": "unknown",
        "validation_method": "static",
        "validation_status": "not-validated",
        "location": {"file": file, "start_line": 12, "end_line": 12},
        "evidence": evidence,
        "explanation": "A test explanation.",
        "potential_impact": "A test impact.",
        "remediation": "A test remediation.",
        "vex_review": None,
    }


def _report(*findings: dict[str, object]) -> dict[str, object]:
    return {
        "schema_version": "1.11",
        "tool": {"name": "FUSE", "version": "0.4.0"},
        "summary": {"files_skipped": 0},
        "coverage": {
            "discovery_complete": True,
            "limits_reached": [],
            "analyzers": [{"name": "native-rules", "status": "complete"}],
            "support": {"status": "supported"},
        },
        "findings": list(findings),
        "project_context": {"configuration_files": [], "settings": []},
        "firmware_candidates": {"candidates": []},
        "hardware_inventory": {"artifacts": []},
        "hardware_netlist": None,
        "hardware_bom": None,
    }


class ReasoningContextTests(unittest.TestCase):
    def test_builds_schema_valid_context_for_only_selected_finding(self) -> None:
        report = _report(_finding(), _finding("FUSE-002-1", rule_id="FUSE-002"))
        context = build_reasoning_context(report, "FUSE-001-1")
        schema_path = Path(__file__).parents[1] / "src/vigil_fuse/schemas/reasoning-context-v1.schema.json"
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
        errors = list(Draft202012Validator(schema).iter_errors(context))
        self.assertEqual(errors, [])
        self.assertEqual(context["finding"]["id"], "FUSE-001-1")  # type: ignore[index]
        self.assertEqual(context["finding"]["severity"], "high")  # type: ignore[index]
        self.assertEqual(
            context["evidence_state"]["unknown"][0]["kind"], "applicability"  # type: ignore[index]
        )
        self.assertEqual(context["evidence_state"]["supported"][0]["kind"], "scanner_finding")  # type: ignore[index]
        self.assertEqual(context["evidence_state"]["confirmed"], [])  # type: ignore[index]
        self.assertEqual(context["evidence_state"]["contradicted"], [])  # type: ignore[index]
        serialized = json.dumps(context)
        self.assertNotIn("FUSE-002-1", serialized)
        self.assertIn("[REDACTED]", serialized)
        self.assertNotIn("secret-value", serialized)
        output_schema_path = Path(__file__).parents[1] / "src/vigil_fuse/schemas/reasoning-output-v1.schema.json"
        output_schema = json.loads(output_schema_path.read_text(encoding="utf-8"))
        output_validator = Draft202012Validator(output_schema)
        output = {
            "summary": "",
            "reasoning": "",
            "missing_evidence": [],
            "recommended_checks": [],
            "remediation": [],
            "limitations": [],
        }
        self.assertTrue(output_validator.is_valid(output))
        output["severity"] = "critical"
        self.assertFalse(output_validator.is_valid(output))

    def test_is_deterministic_and_redacts_private_paths_and_credentials(self) -> None:
        report = _report(
            _finding(
                file=r"C:\Users\person\project\src\main.c",
                evidence="https://user:password@example.test/x Bearer abcdefghijkl password=hunter2",
            )
        )
        first = build_reasoning_context(report, "FUSE-001-1")
        second = build_reasoning_context(report, "FUSE-001-1")
        self.assertEqual(json.dumps(first, sort_keys=True), json.dumps(second, sort_keys=True))
        rendered = json.dumps(first)
        self.assertNotIn("C:\\Users", rendered)
        self.assertNotIn("hunter2", rendered)
        self.assertNotIn("user:password@", rendered)
        self.assertNotIn("abcdefghijkl", rendered)

    def test_related_report_paths_are_sanitized_in_provenance(self) -> None:
        absolute_path = str((Path.cwd() / "private" / "main.c").resolve())
        report = _report(_finding(file=absolute_path))
        report["project_context"] = {
            "configuration_files": [{"path": absolute_path, "role": "build configuration"}],
            "settings": [{"path": absolute_path, "name": "DEBUG_ENABLED", "value": "true", "line": 12}],
        }
        context = build_reasoning_context(report, "FUSE-001-1")
        rendered = json.dumps(context)
        self.assertNotIn(str(Path.cwd()), rendered)
        self.assertIn('"file": "main.c"', rendered)

    def test_hardware_deployment_stages_remain_distinct_and_unknown(self) -> None:
        finding = _finding(category="hardware-security", rule_id="FUSE-HW-001", file="board.net")
        report = _report(finding)
        context = build_reasoning_context(report, "FUSE-001-1")
        stages = context["deployment_stages"]
        self.assertEqual(
            [stage["stage"] for stage in stages],
            [
                "configured",
                "build_included",
                "linked",
                "runtime_executed",
                "physically_populated",
                "externally_accessible",
            ],
        )
        self.assertTrue(all(stage["state"] == "UNKNOWN" for stage in stages))

    def test_validated_findings_are_marked_as_fuse_confirmed(self) -> None:
        finding = _finding()
        finding["validation_status"] = "validated"
        context = build_reasoning_context(_report(finding), "FUSE-001-1")
        self.assertEqual(context["evidence_state"]["confirmed"][0]["kind"], "fuse_validation")  # type: ignore[index]

    def test_deduplicates_matching_build_facts(self) -> None:
        report = _report(_finding())
        report["project_context"] = {
            "configuration_files": [],
            "settings": [
                {"path": "src/main.c", "name": "DEBUG_ENABLED", "value": "true", "line": 12},
                {"path": "src/main.c", "name": "DEBUG_ENABLED", "value": "true", "line": 12},
            ],
        }
        context = build_reasoning_context(report, "FUSE-001-1")
        self.assertEqual(len(context["build_evidence"]), 1)  # type: ignore[arg-type]

    def test_truncates_to_context_budget_and_records_category(self) -> None:
        report = _report(_finding(evidence="line " * 2_000))
        context = build_reasoning_context(
            report,
            "FUSE-001-1",
            ReasoningContextLimits(max_context_chars=2_048, max_text_chars=800, max_snippet_chars=1_200),
        )
        serialized = json.dumps(context, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
        self.assertLessEqual(len(serialized), 2_048)
        self.assertTrue(context["context_truncated"])

    def test_rejects_missing_duplicate_and_unsupported_findings(self) -> None:
        with self.assertRaisesRegex(ValueError, "not found"):
            build_reasoning_context(_report(_finding()), "missing")
        with self.assertRaisesRegex(ValueError, "duplicated"):
            build_reasoning_context(_report(_finding(), _finding()), "FUSE-001-1")
        report = _report(_finding())
        report["schema_version"] = "1.10"
        with self.assertRaisesRegex(ValueError, "schema_version 1.11"):
            build_reasoning_context(report, "FUSE-001-1")

    def test_report_loader_rejects_duplicate_json_keys(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "report.json"
            path.write_text('{"schema_version":"1.11","schema_version":"1.11"}', encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "duplicate JSON key"):
                load_scan_report(path)

    def test_cli_writes_context_and_refuses_input_overwrite(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            report_path = Path(directory) / "findings.json"
            output_path = Path(directory) / "context.json"
            report_path.write_text(json.dumps(_report(_finding())), encoding="utf-8")
            self.assertEqual(
                main(
                    [
                        "reasoning-context",
                        str(report_path),
                        "--finding",
                        "FUSE-001-1",
                        "--output",
                        str(output_path),
                        "--max-context-chars",
                        "2048",
                    ],
                    _show_banner=False,
                ),
                0,
            )
            self.assertEqual(json.loads(output_path.read_text(encoding="utf-8"))["finding"]["id"], "FUSE-001-1")
            before = report_path.read_text(encoding="utf-8")
            stderr = io.StringIO()
            with redirect_stderr(stderr):
                status = main(
                    [
                        "reasoning-context",
                        str(report_path),
                        "--finding",
                        "FUSE-001-1",
                        "--output",
                        str(report_path),
                    ],
                    _show_banner=False,
                )
            self.assertEqual(status, 2)
            self.assertIn("must not replace", stderr.getvalue())
            self.assertEqual(report_path.read_text(encoding="utf-8"), before)


if __name__ == "__main__":
    unittest.main()
