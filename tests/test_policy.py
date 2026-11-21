from __future__ import annotations

import json
import subprocess
import tempfile
import unittest
from dataclasses import replace
from io import StringIO
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from jsonschema import Draft202012Validator

from vigil_fuse.analyzer_runtime import AnalyzerOutputLimitError
from vigil_fuse.cli import main
from vigil_fuse.model import VexReview
from vigil_fuse.policy import (
    BUILTIN_POLICY,
    OpaInfo,
    _normalize_decision,
    evaluate_policies,
    policy_input,
    policy_results_json,
    resolve_policy_files,
    serialize_policy_input,
)
from vigil_fuse.scanner import scan


def _decision(
    status: str,
    *,
    violations: list[dict[str, object]] | None = None,
    unknowns: list[dict[str, object]] | None = None,
) -> dict[str, object]:
    return {
        "policy_id": "org.example.test",
        "status": status,
        "violations": violations or [],
        "unknowns": unknowns or [],
        "mappings": [],
    }


def _opa_envelope(value: object) -> str:
    return json.dumps({"result": [{"expressions": [{"value": value}]}]})


class PolicyInputTests(unittest.TestCase):
    def make_result(self, root: Path, source: str = "int main(void) { return 0; }\n"):
        root.mkdir(parents=True, exist_ok=True)
        (root / "main.c").write_text(source, encoding="utf-8")
        return scan(root)

    def test_input_is_deterministic_and_excludes_local_paths_and_source_text(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            result = self.make_result(Path(temporary))
            serialized = serialize_policy_input(policy_input(result))

        self.assertEqual(serialized, serialize_policy_input(policy_input(result)))
        document = json.loads(serialized)
        self.assertEqual("1.0", document["schema_version"])
        self.assertNotIn(temporary, serialized)
        self.assertNotIn("int main", serialized)
        self.assertNotIn("file", document["findings"][0] if document["findings"] else {})

    def test_input_schema_accepts_normalized_scan(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            document = policy_input(self.make_result(Path(temporary)))
        schema_path = (
            Path(__file__).parents[1]
            / "src"
            / "vigil_fuse"
            / "schemas"
            / "policy-input-1.0.schema.json"
        )
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
        Draft202012Validator.check_schema(schema)
        Draft202012Validator(schema).validate(document)

    def test_disabled_rule_is_unknown_not_a_pass(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "main.c").write_text("int main(void) { return 0; }\n", encoding="utf-8")
            result = scan(root, disabled_rules=("FUSE005",))

        self.assertEqual("unknown", policy_input(result)["evidence"]["plaintext_mqtt"]["status"])

    def test_debug_net_candidate_does_not_claim_external_exposure(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            document = policy_input(self.make_result(Path(temporary)))
        self.assertEqual("unknown", document["evidence"]["debug_interface_exposure"]["status"])

    def test_conflicting_high_finding_and_vex_evidence_is_unknown(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "tls.py").write_text(
                'requests.get("https://device.example", verify=False)\n', encoding="utf-8"
            )
            result = scan(root)
        finding = next(item for item in result.findings if item.rule_id == "FUSE003")
        conflicting = replace(
            finding,
            applicability="applicable",
            vex_review=VexReview(state="not_affected"),
        )
        document = policy_input(replace(result, findings=(conflicting,)))
        signal = document["evidence"]["unresolved_high_findings"]

        self.assertEqual("uncertain", signal["status"])
        self.assertEqual([finding.fingerprint], signal["evidence_refs"])

    def test_bundled_reference_policy_resolves_from_package_data(self) -> None:
        modules = resolve_policy_files(BUILTIN_POLICY)
        self.assertEqual(1, len(modules))
        self.assertEqual("production_iot.rego", modules[0].name)


class PolicyEvaluationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        root = Path(self.temporary.name)
        self.target = root / "target"
        self.target.mkdir()
        (self.target / "main.c").write_text("int main(void) { return 0; }\n", encoding="utf-8")
        self.result = scan(self.target)
        self.policy = root / "policy.rego"
        self.policy.write_text("package fuse.policy\n", encoding="utf-8")

    def evaluate_with(
        self, output: str, returncode: int = 0, result=None
    ) -> tuple[dict[str, object], list[dict[str, object]]]:
        captured_inputs: list[dict[str, object]] = []
        capabilities = {
            "builtins": [
                {"name": "count"},
                {"name": "http.send"},
                {"name": "net.lookup_ip_addr"},
                {"name": "opa.runtime"},
                {"name": "time.now_ns"},
            ],
            "future_keywords": ["if", "in", "contains"],
        }

        def run_opa(command: list[str], *, timeout: int, cwd: Path | None = None):
            if "capabilities" in command:
                return subprocess.CompletedProcess(command, 0, json.dumps(capabilities), "")
            input_path = Path(command[command.index("--input") + 1])
            captured_inputs.append(json.loads(input_path.read_text(encoding="utf-8")))
            capability_path = Path(command[command.index("--capabilities") + 1])
            restricted = json.loads(capability_path.read_text(encoding="utf-8"))
            builtin_names = {item["name"] for item in restricted["builtins"]}
            self.assertEqual([], restricted["allow_net"])
            self.assertNotIn("http.send", builtin_names)
            self.assertNotIn("net.lookup_ip_addr", builtin_names)
            self.assertNotIn("opa.runtime", builtin_names)
            self.assertNotIn("time.now_ns", builtin_names)
            return subprocess.CompletedProcess(command, returncode, output, "")

        with (
            patch("vigil_fuse.policy.inspect_opa", return_value=OpaInfo("opa", "1.0.0")),
            patch("vigil_fuse.policy._run_opa", side_effect=run_opa),
        ):
            document = evaluate_policies(self.policy, result or self.result)
        return document, captured_inputs

    def test_pass_fail_and_unknown_decisions(self) -> None:
        cases = (
            (_decision("pass"), "pass"),
            (
                _decision(
                    "fail",
                    violations=[
                        {"rule": "no_plaintext_mqtt", "evidence_refs": [], "message": "Observed."}
                    ],
                ),
                "fail",
            ),
            (
                _decision(
                    "unknown",
                    unknowns=[
                        {
                            "rule": "tls_verification_required",
                            "evidence_refs": [],
                            "message": "Unknown.",
                        }
                    ],
                ),
                "unknown",
            ),
        )
        for decision, expected in cases:
            with self.subTest(expected=expected):
                document, _ = self.evaluate_with(_opa_envelope(decision))
                self.assertEqual(expected, document["evaluations"][0]["status"])
                schema_path = (
                    Path(__file__).parents[1]
                    / "src"
                    / "vigil_fuse"
                    / "schemas"
                    / "policy-result-1.0.schema.json"
                )
                schema = json.loads(schema_path.read_text(encoding="utf-8"))
                Draft202012Validator(schema).validate(document)

    def test_missing_evidence_is_delivered_to_rego_as_unknown(self) -> None:
        root = self.target
        result = scan(root, disabled_rules=("FUSE005",))
        unknown = _decision(
            "unknown",
            unknowns=[
                {"rule": "no_plaintext_mqtt", "evidence_refs": [], "message": "Evidence missing."}
            ],
        )
        document, captured = self.evaluate_with(_opa_envelope(unknown), result=result)

        self.assertEqual("unknown", document["status"])
        self.assertEqual("unknown", captured[0]["evidence"]["plaintext_mqtt"]["status"])
        self.assertEqual("unknown", policy_input(result)["evidence"]["plaintext_mqtt"]["status"])

    def test_conflicting_decision_status_is_normalized_to_unknown(self) -> None:
        result = _normalize_decision(
            _decision(
                "pass",
                violations=[{"rule": "deny", "evidence_refs": [], "message": "Observed."}],
            ),
            set(),
        )
        self.assertEqual("unknown", result["status"])
        self.assertEqual("conflicting_result", result["reason"])

    def test_malformed_rego_is_unknown(self) -> None:
        document, _ = self.evaluate_with("", returncode=1)
        self.assertEqual("unknown", document["evaluations"][0]["status"])
        self.assertEqual("evaluation_error", document["evaluations"][0]["reason"])

    def test_malformed_opa_json_is_unknown(self) -> None:
        document, _ = self.evaluate_with("not-json")
        self.assertEqual("unknown", document["evaluations"][0]["status"])
        self.assertEqual("invalid_output", document["evaluations"][0]["reason"])

    def test_evaluation_timeout_is_unknown(self) -> None:
        with (
            patch("vigil_fuse.policy.inspect_opa", return_value=OpaInfo("opa", "1.0.0")),
            patch(
                "vigil_fuse.policy._run_opa",
                side_effect=[
                    subprocess.CompletedProcess(
                        ["opa", "capabilities"],
                        0,
                        json.dumps({"builtins": [], "future_keywords": []}),
                        "",
                    ),
                    subprocess.TimeoutExpired(["opa", "eval"], 5),
                ],
            ),
        ):
            document = evaluate_policies(self.policy, self.result)
        self.assertEqual("unknown", document["evaluations"][0]["status"])
        self.assertEqual("evaluation_timeout", document["evaluations"][0]["reason"])

    def test_opa_unavailable_is_unknown(self) -> None:
        with patch("vigil_fuse.policy.inspect_opa", return_value=OpaInfo(None, None)):
            document = evaluate_policies(self.policy, self.result)
        self.assertFalse(document["engine"]["available"])
        self.assertEqual("unknown", document["evaluations"][0]["status"])
        self.assertEqual("opa_unavailable", document["evaluations"][0]["reason"])

    def test_duplicate_policy_ids_are_rejected(self) -> None:
        second = self.policy.parent / "second.rego"
        second.write_text("package fuse.policy\n", encoding="utf-8")
        output = _opa_envelope(_decision("pass"))

        with (
            patch("vigil_fuse.policy.inspect_opa", return_value=OpaInfo("opa", "1.0.0")),
            patch(
                "vigil_fuse.policy._run_opa",
                side_effect=[
                    subprocess.CompletedProcess(
                        ["opa", "capabilities"],
                        0,
                        json.dumps({"builtins": [], "future_keywords": []}),
                        "",
                    ),
                    subprocess.CompletedProcess(["opa", "eval"], 0, output, ""),
                    subprocess.CompletedProcess(["opa", "eval"], 0, output, ""),
                ],
            ),
        ):
            with self.assertRaisesRegex(ValueError, "duplicate policy IDs"):
                evaluate_policies(self.policy.parent, self.result)

    def test_policy_directory_discovery_is_bounded(self) -> None:
        from vigil_fuse import policy as policy_module

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "one.txt").write_text("", encoding="utf-8")
            (root / "two.txt").write_text("", encoding="utf-8")
            with patch.object(policy_module, "MAX_POLICY_DIRECTORY_ENTRIES", 1):
                with self.assertRaisesRegex(ValueError, "traversal limit"):
                    resolve_policy_files(root)

    def test_oversized_opa_output_is_unknown(self) -> None:
        with (
            patch("vigil_fuse.policy.inspect_opa", return_value=OpaInfo("opa", "1.0.0")),
            patch(
                "vigil_fuse.policy._run_opa",
                side_effect=[
                    subprocess.CompletedProcess(
                        ["opa", "capabilities"],
                        0,
                        json.dumps({"builtins": [], "future_keywords": []}),
                        "",
                    ),
                    AnalyzerOutputLimitError("too much output"),
                ],
            ),
        ):
            document = evaluate_policies(self.policy, self.result)
        self.assertEqual("unknown", document["evaluations"][0]["status"])
        self.assertEqual("output_limit", document["evaluations"][0]["reason"])

    def test_cli_writes_unknown_policy_result_without_opa(self) -> None:
        output_dir = self.policy.parent / "reports"
        with patch("vigil_fuse.policy.inspect_opa", return_value=OpaInfo(None, None)):
            code = main(
                [
                    "scan",
                    str(self.target),
                    "--policy",
                    str(self.policy),
                    "--output-dir",
                    str(output_dir),
                ]
            )
        self.assertEqual(2, code)
        self.assertTrue((output_dir / "findings.json").is_file())
        policy_report = json.loads((output_dir / "policy-results.json").read_text(encoding="utf-8"))
        self.assertEqual("unknown", policy_report["status"])

    def test_normal_scan_does_not_probe_or_require_opa(self) -> None:
        output_dir = self.policy.parent / "normal-reports"
        with patch("vigil_fuse.policy.inspect_opa", side_effect=AssertionError("unexpected probe")):
            code = main(["scan", str(self.target), "--output-dir", str(output_dir)])
        self.assertEqual(0, code)
        self.assertFalse((output_dir / "policy-results.json").exists())

    def test_doctor_reports_optional_opa_status_and_version(self) -> None:
        output = StringIO()
        ghidra = SimpleNamespace(
            status="unavailable",
            version=None,
            launcher=None,
            java_version=None,
            java_executable=None,
            detail="not installed",
        )
        with (
            patch("vigil_fuse.cli.inspect_tools", return_value=()),
            patch("vigil_fuse.cli.inspect_ghidra", return_value=ghidra),
            patch("vigil_fuse.cli.inspect_opa", return_value=OpaInfo("opa", "1.22.4")),
            patch("vigil_fuse.cli.sys.stdout", output),
        ):
            code = main(["doctor"])
        self.assertEqual(0, code)
        self.assertIn("OPA/Rego: AVAILABLE", output.getvalue())
        self.assertIn("OPA version: 1.22.4", output.getvalue())
        self.assertIn("policy engine: optional", output.getvalue())

    def test_policy_report_json_is_versioned_and_deterministic(self) -> None:
        document, _ = self.evaluate_with(_opa_envelope(_decision("pass")))
        first = policy_results_json(document)
        self.assertEqual(first, policy_results_json(document))
        self.assertEqual("1.0", json.loads(first)["schema_version"])


if __name__ == "__main__":
    unittest.main()
