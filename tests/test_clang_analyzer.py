from __future__ import annotations

import copy
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from vigil_fuse.analyzer_runtime import AnalyzerOutputLimitError
from vigil_fuse.clang_analyzer import analyze, inspect_clang, validate_evidence

CORPUS = Path(__file__).parent / "fixtures" / "semantic_c"
NATIVE = shutil.which(os.environ.get("FUSE_CLANG_TEST_EXECUTABLE", "fuse-clang-analyzer"))


def document() -> dict:
    return {
        "schema_version": "1.0",
        "tool": "fuse-clang-analyzer",
        "clang_version": "18.1.3",
        "status": "completed",
        "translation_units": [{"file": "boundary/macro.c", "parsed": True}],
        "diagnostic_count": 0,
        "limitations": [],
        "observations": [
            {
                "kind": "call",
                "name": "strcpy",
                "file": "boundary/macro.c",
                "line": 3,
                "column": 23,
                "spelling_file": "boundary/macro.c",
                "spelling_line": 2,
                "function": "copy",
                "definition": False,
                "arguments": [
                    {"expression": "out", "literal": False, "integer_constant": False},
                    {"expression": '"macro"', "literal": True, "integer_constant": False},
                ],
            }
        ],
    }


class SemanticContractTests(unittest.TestCase):
    def test_valid_document_and_published_schema(self) -> None:
        import jsonschema

        schema = Path(__file__).parents[1] / "src/vigil_fuse/schemas/clang-evidence.schema.json"
        jsonschema.validate(document(), json.loads(schema.read_text()))
        validate_evidence(document(), CORPUS.resolve(), {"boundary/macro.c"})

    def test_reject_untrusted_fields_types_paths_and_limits(self) -> None:
        mutations = [
            lambda d: d.update(severity="high"),
            lambda d: d.update(schema_version="2"),
            lambda d: d.update(diagnostic_count=True),
            lambda d: d.update(diagnostic_count=65),
            lambda d: d.update(observations=[d["observations"][0]] * 1025),
            lambda d: d.update(translation_units=[]),
            lambda d: d.update(limitations=["x"] * 17),
            lambda d: d["translation_units"][0].update(file="boundary/indirect.c"),
            lambda d: d["translation_units"][0].update(parsed=False),
            lambda d: d["observations"][0].update(file="../outside.c"),
            lambda d: d["observations"][0].update(spelling_file="C:/outside.c"),
            lambda d: d["observations"][0].update(line=True),
            lambda d: d["observations"][0].update(name="x" * 257),
            lambda d: d["observations"][0].update(arguments=[{}]),
        ]
        for mutate in mutations:
            with self.subTest(mutation=mutate):
                value = copy.deepcopy(document())
                mutate(value)
                with self.assertRaises((ValueError, OSError)):
                    validate_evidence(value, CORPUS.resolve(), {"boundary/macro.c"})

    def test_absence_and_failed_probe_are_not_ready(self) -> None:
        with patch("vigil_fuse.clang_analyzer.shutil.which", return_value=None):
            self.assertEqual(
                analyze(CORPUS, CORPUS / "compile_commands.json").status.status, "unavailable"
            )
        with (
            patch("vigil_fuse.clang_analyzer.shutil.which", return_value="native"),
            patch(
                "vigil_fuse.clang_analyzer._run",
                return_value=subprocess.CompletedProcess([], 0, "{}"),
            ),
        ):
            self.assertEqual(inspect_clang()[1].status, "incompatible")

    def test_successful_probe_requires_valid_version_and_database_support(self) -> None:
        probe = {
            "tool": "fuse-clang-analyzer",
            "schema_version": "1.0",
            "clang_version": "18.1.3",
            "compile_commands": True,
        }
        for change, expected in (
            ({}, "completed"),
            ({"compile_commands": False}, "incompatible"),
            ({"clang_version": "\x1b[31m"}, "incompatible"),
        ):
            with (
                self.subTest(change=change),
                patch("vigil_fuse.clang_analyzer.shutil.which", return_value="native"),
                patch(
                    "vigil_fuse.clang_analyzer._run",
                    return_value=subprocess.CompletedProcess([], 0, json.dumps(probe | change)),
                ),
            ):
                self.assertEqual(inspect_clang()[1].status, expected)

    def test_changed_source_cannot_be_accepted(self) -> None:
        from vigil_fuse.model import AnalyzerStatus

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "boundary").mkdir()
            source = root / "boundary/macro.c"
            source.write_text("void original(void) {}")
            database = root / "compile_commands.json"
            database.write_text(
                json.dumps(
                    [{"directory": ".", "file": "boundary/macro.c", "arguments": ["ignored"]}]
                )
            )

            def changed(*args, **kwargs):
                source.write_text("void replaced(void) {}")
                return subprocess.CompletedProcess([], 0, json.dumps(document()))

            with (
                patch(
                    "vigil_fuse.clang_analyzer.inspect_clang",
                    return_value=("native", AnalyzerStatus("Clang", "completed", "18.1.3")),
                ),
                patch("vigil_fuse.clang_analyzer._run", side_effect=changed),
            ):
                self.assertEqual(analyze(root, database).status.status, "failed")

    def test_python_bounds_database_before_starting_native_process(self) -> None:
        from vigil_fuse.model import AnalyzerStatus

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "input.c"
            source.write_text("void input(void) {}")
            database = root / "compile_commands.json"
            entries = [
                {"directory": ".", "file": "input.c", "arguments": ["clang"] * 129},
            ]
            with (
                patch(
                    "vigil_fuse.clang_analyzer.inspect_clang",
                    return_value=("native", AnalyzerStatus("Clang", "completed", "18.1.3")),
                ),
                patch("vigil_fuse.clang_analyzer._run") as run,
            ):
                database.write_text(json.dumps(entries))
                self.assertEqual(analyze(root, database).status.status, "failed")
                run.assert_not_called()
                entries[0] = {"directory": ".", "file": "input.txt", "arguments": ["clang"]}
                (root / "input.txt").write_text("plain text")
                database.write_text(json.dumps(entries))
                self.assertEqual(analyze(root, database).status.status, "failed")
                run.assert_not_called()

    def test_bounded_failures_are_contained(self) -> None:
        from vigil_fuse.model import AnalyzerStatus

        cases = [
            (subprocess.TimeoutExpired("native", 65), "timeout"),
            (AnalyzerOutputLimitError("large"), "failed"),
            (subprocess.CompletedProcess([], 0, '{"tool":1,"tool":2}'), "failed"),
            (subprocess.CompletedProcess([], 2, ""), "failed"),
        ]
        for output, expected in cases:
            with (
                self.subTest(expected=expected),
                patch(
                    "vigil_fuse.clang_analyzer.inspect_clang",
                    return_value=("native", AnalyzerStatus("Clang", "completed", "18.1.3")),
                ),
                patch("vigil_fuse.clang_analyzer._run") as run,
            ):
                if isinstance(output, Exception):
                    run.side_effect = output
                else:
                    run.return_value = output
                self.assertEqual(
                    analyze(CORPUS, CORPUS / "compile_commands.json").status.status, expected
                )


@unittest.skipUnless(NATIVE, "Optional native LLVM analyzer not installed")
class NativeSemanticTests(unittest.TestCase):
    def test_real_ast_corpus(self) -> None:
        result = analyze(CORPUS, CORPUS / "compile_commands.json", executable=NATIVE)
        self.assertEqual(result.status.status, "completed", result)
        calls = {(item["file"], item["name"]) for item in result.sensitive_calls}
        expected = json.loads((CORPUS / "expected_calls.json").read_text())
        self.assertEqual(
            calls, {(file, name) for file, names in expected.items() for name in names}
        )
        self.assertIn(("unsafe/strcpy_literal.c", "strcpy"), calls)
        self.assertIn(("unsafe/plain_http.c", "esp_http_client_init"), calls)
        self.assertIn(("secure/tls_verified.c", "mbedtls_ssl_conf_authmode"), calls)
        self.assertIn(("secure/validated_ota.c", "esp_secure_boot_verify_signature"), calls)
        self.assertFalse(
            any(
                file in {"boundary/not_calls.c", "boundary/indirect.c", "secure/bounded_copy.c"}
                for file, _ in calls
            )
        )
        macro = next(item for item in result.sensitive_calls if item["file"] == "boundary/macro.c")
        self.assertEqual((macro["line"], macro["spelling_line"]), (3, 2))
        self.assertTrue(
            any(item["name"] == "<unresolved>" for item in result.evidence["observations"])
        )
        self.assertTrue(
            any(item["function"] == "firmware::copy" for item in result.sensitive_calls)
        )
        memory = {name for file, name in calls if file == "boundary/memory.c"}
        self.assertEqual(
            memory,
            {
                "memcpy",
                "memmove",
                "strcat",
                "sprintf",
                "vsprintf",
                "gets",
                "sscanf",
                "scanf",
                "fscanf",
            },
        )
        by_name = {item["name"]: item for item in result.sensitive_calls}
        self.assertEqual(by_name["memcpy"]["destination_expression"], "out")
        self.assertEqual(by_name["memcpy"]["size_expression"], "4")
        self.assertEqual(by_name["scanf"]["destination_expression"], "out")
        self.assertEqual(by_name["fscanf"]["destination_expression"], "out")

    def test_selected_build_and_macro_definitions(self) -> None:
        for enabled in (0, 1):
            result = analyze(
                CORPUS,
                CORPUS / f"compile_context/compile_commands_{enabled}.json",
                executable=NATIVE,
                present_sources=(CORPUS / "compile_context/absent.c",),
            )
            self.assertEqual(result.status.status, "completed", result)
            self.assertEqual(len(result.sensitive_calls), enabled)
            self.assertIn({"file": "compile_context/absent.c", "state": "PRESENT"}, result.coverage)
            self.assertIn(
                {"file": "compile_context/toggle.c", "state": "BUILD_INCLUDED"}, result.coverage
            )

    def test_hostile_flags_parse_errors_and_budget(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "input.c"
            source.write_text("void broken( {", encoding="utf-8")
            database = root / "compile_commands.json"
            entry = {
                "directory": ".",
                "file": "input.c",
                "arguments": ["untrusted-script", "-c", "input.c"],
            }
            database.write_text(json.dumps([entry]))
            result = analyze(root, database, executable=NATIVE)
            self.assertEqual(result.status.status, "partial", result)
            self.assertEqual(result.coverage[0]["state"], "UNKNOWN")
            self.assertFalse(result.evidence["observations"])
            for flag in ("@response", "-fplugin=evil", "-Xclang", "-include", "-I/", "-o"):
                entry["arguments"] = ["untrusted-script", flag]
                database.write_text(json.dumps([entry]))
                self.assertEqual(analyze(root, database, executable=NATIVE).status.status, "failed")
            entry["arguments"] = ["ignored", "-c", "input.c"]
            source.write_text(
                "extern void api(void);\nvoid many(void) {\n" + "api();\n" * 1500 + "}\n"
            )
            database.write_text(json.dumps([entry]))
            result = analyze(root, database, executable=NATIVE)
            self.assertEqual(result.status.status, "partial")
            self.assertEqual(len(result.evidence["observations"]), 1024)
            source.write_text("#warning bounded diagnostic\n" * 100 + "void ok(void) {}\n")
            database.write_text(json.dumps([entry]))
            result = analyze(root, database, executable=NATIVE)
            self.assertEqual(result.status.status, "partial")
            self.assertEqual(result.evidence["diagnostic_count"], 64)


@unittest.skipUnless(NATIVE, "Optional native LLVM analyzer not installed")
class NativeDoctorTests(unittest.TestCase):
    def test_doctor_reports_only_a_probed_analyzer_as_available(self) -> None:
        version = inspect_clang(NATIVE)[1].version
        environment = os.environ.copy()
        environment["PATH"] = str(Path(NATIVE).parent) + os.pathsep + environment.get("PATH", "")
        result = subprocess.run(
            [sys.executable, "-m", "vigil_fuse", "doctor"],
            check=False,
            capture_output=True,
            text=True,
            env=environment,
            timeout=10,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Clang semantic analyzer: available", result.stdout)
        self.assertIn(f"LLVM/Clang version: {version}", result.stdout)
        self.assertIn("compile_commands support: available", result.stdout)


if __name__ == "__main__":
    unittest.main()
