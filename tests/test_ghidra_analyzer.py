from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
from unittest.mock import patch

from jsonschema import Draft202012Validator

from vigil_fuse import ghidra_analyzer
from vigil_fuse.cli import main
from vigil_fuse.ghidra_analyzer import GhidraProbe


class GhidraMetadataRedactionTests(unittest.TestCase):
    def test_url_derived_metadata_cannot_retain_truncated_credentials(self):
        for key in ("name", "function", "symbol"):
            for label in (
                "s_mqtt://fixture-user:partial-secret_00400080",
                "s_http___user_secret_08000000",
            ):
                with self.subTest(key=key, label=label):
                    normalized = ghidra_analyzer._normalized_json_value({key: label})
                    self.assertEqual({key: "[redacted URL-derived name]"}, normalized)
        self.assertEqual(
            {"name": "connect_broker"},
            ghidra_analyzer._normalized_json_value({"name": "connect_broker"}),
        )
        self.assertEqual(
            {"value": "http://device.example"},
            ghidra_analyzer._normalized_json_value(
                {"value": "http://user:secret@device.example/path"}
            ),
        )


def _bounded(records: list[dict[str, object]] | None = None) -> dict[str, object]:
    values = records or []
    return {
        "records": values,
        "observed": len(values),
        "reported": len(values),
        "truncated": False,
        "observed_is_lower_bound": False,
    }


def _document(digest: str, input_format: str, byte_size: int) -> dict[str, object]:
    return {
        "schema_version": "1.0",
        "tool": {"name": "Ghidra", "version": "12.2"},
        "input": {"sha256": digest, "format": input_format, "byte_size": byte_size},
        "analysis": {
            "status": "completed",
            "timeout_occurred": False,
            "loader": "Portable Executable (PE)" if input_format == "PE" else input_format,
            "processor": "x86",
            "language_id": "x86:LE:32:default",
            "compiler_spec": "windows",
            "endianness": "little",
            "pointer_size_bytes": 4,
            "image_base": "00400000",
            "entry_points": ["00401000"],
            "warnings": [],
            "errors": [],
        },
        "memory_blocks": _bounded(),
        "functions": _bounded(),
        "symbols": _bounded(),
        "imports": _bounded(),
        "exports": _bounded(),
        "strings": _bounded(
            [
                {"address": "00402000", "value": "mqtt://broker.example:1883", "redacted": False},
                {
                    "address": "00401000",
                    "value": "http://device.example/update?token=sample-secret",
                    "redacted": False,
                },
                {"address": "00403000", "value": "password=private-value", "redacted": True},
            ]
        ),
        "cross_references": _bounded(
            [
                {
                    "string_address": "00401000",
                    "from_address": "00400020",
                    "function": "download_update",
                    "function_entry_address": "00400010",
                    "reference_type": "DATA",
                },
                {
                    "string_address": "00402000",
                    "from_address": "00400030",
                    "function": "connect_broker",
                    "function_entry_address": "00400028",
                    "reference_type": "DATA",
                },
            ]
        ),
        "api_references": _bounded(),
        "limits": {
            "max_functions": 2048,
            "max_symbols": 1024,
            "max_imports": 1024,
            "max_exports": 1024,
            "max_strings": 1024,
            "max_string_scan_items": 100000,
            "max_cross_references": 2048,
            "max_api_references": 512,
            "max_memory_blocks": 256,
            "max_name_chars": 128,
            "max_string_chars": 256,
            "max_output_bytes": 8 * 1024 * 1024,
        },
        "truncation": {
            "memory_blocks": False,
            "functions": False,
            "symbols": False,
            "imports": False,
            "exports": False,
            "strings": False,
            "cross_references": False,
            "api_references": False,
        },
    }


def _probe(root: Path) -> GhidraProbe:
    install = root / "ghidra"
    utility = install / "Ghidra" / "Framework" / "Utility" / "lib" / "Utility.jar"
    utility.parent.mkdir(parents=True, exist_ok=True)
    utility.write_bytes(b"fixture")
    java = root / "java"
    java.write_bytes(b"")
    return GhidraProbe(
        status="available",
        install_dir=install,
        version="12.2",
        launcher=install
        / "support"
        / ("analyzeHeadless.bat" if os.name == "nt" else "analyzeHeadless"),
        java_executable=java,
        java_version="25",
        detail="Ghidra 12.2 Headless Analyzer and Java 25 are available.",
    )


def _script_args(command: list[str]) -> tuple[list[str], Path, str, str, int]:
    argument_file = Path(command[1][1:])
    arguments = [
        json.loads(line) for line in argument_file.read_text(encoding="utf-8").splitlines()
    ]
    index = arguments.index("FuseExport.java")
    output_path = Path(arguments[index + 1])
    digest = arguments[index + 2]
    input_format = arguments[index + 3]
    size = int(arguments[index + 4])
    return arguments, output_path, digest, input_format, size


def _fake_runner(command: list[str], **_: object) -> subprocess.CompletedProcess[str]:
    arguments, raw_output, digest, input_format, size = _script_args(command)
    del arguments
    raw_output.write_text(
        json.dumps(_document(digest, input_format, size)),
        encoding="utf-8",
    )
    return subprocess.CompletedProcess(command, 0, "", "")


class GhidraDiscoveryTests(unittest.TestCase):
    def test_missing_installation_is_unavailable(self) -> None:
        probe = ghidra_analyzer.inspect_ghidra(environ={}, which=lambda _: None)
        self.assertEqual("unavailable", probe.status)

    def test_invalid_explicit_installation_does_not_fall_back_to_environment(self) -> None:
        probe = ghidra_analyzer.inspect_ghidra(
            "missing-ghidra",
            environ={"GHIDRA_INSTALL_DIR": "some-other-install"},
            which=lambda _: None,
        )
        self.assertEqual("unavailable", probe.status)
        self.assertIn("does not exist", probe.detail)

    def test_detects_supported_installation_and_java(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            install = root / "ghidra_12.2_PUBLIC"
            launcher = (
                install
                / "support"
                / ("analyzeHeadless.bat" if os.name == "nt" else "analyzeHeadless")
            )
            launcher.parent.mkdir(parents=True)
            launcher.write_text("", encoding="utf-8")
            properties = install / "Ghidra" / "application.properties"
            properties.parent.mkdir()
            properties.write_text(
                "application.version=12.2\napplication.java.min=25\napplication.java.max=\n",
                encoding="utf-8",
            )
            java = root / ("java.exe" if os.name == "nt" else "java")
            java.write_text("", encoding="utf-8")
            completed = subprocess.CompletedProcess(
                [str(java), "-version"], 0, "", 'openjdk version "25.0.1" 2026-01-01 LTS'
            )
            with patch.object(ghidra_analyzer, "_run", return_value=completed) as run:
                probe = ghidra_analyzer.inspect_ghidra(
                    install,
                    environ={},
                    which=lambda name: str(java) if name == "java" else None,
                )
        self.assertEqual("available", probe.status)
        self.assertEqual("12.2", probe.version)
        self.assertEqual("25", probe.java_version)
        self.assertIsNotNone(probe.launcher)
        self.assertIn("JAVA_TOOL_OPTIONS", run.call_args.kwargs["environment_exclude"])

    def test_missing_headless_launcher_is_unavailable(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            install = Path(temporary) / "ghidra"
            properties = install / "Ghidra" / "application.properties"
            properties.parent.mkdir(parents=True)
            properties.write_text("application.version=12.2\n", encoding="utf-8")
            probe = ghidra_analyzer.inspect_ghidra(install, environ={}, which=lambda _: None)
        self.assertEqual("unavailable", probe.status)
        self.assertIn("launcher is missing", probe.detail)

    def test_prefers_launcher_for_current_host_when_archive_has_both(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            support = Path(temporary) / "ghidra" / "support"
            support.mkdir(parents=True)
            windows_launcher = support / "analyzeHeadless.bat"
            unix_launcher = support / "analyzeHeadless"
            windows_launcher.write_text("@echo off\n", encoding="utf-8")
            unix_launcher.write_text("#!/bin/sh\n", encoding="utf-8")

            for host_name, expected in (
                ("nt", windows_launcher),
                ("posix", unix_launcher),
            ):
                with (
                    self.subTest(host=host_name),
                    patch.object(ghidra_analyzer.os, "name", host_name),
                ):
                    self.assertEqual(expected, ghidra_analyzer._headless_launcher(support.parent))

    def test_unsupported_ghidra_release_is_incompatible(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            install = Path(temporary) / "ghidra"
            launcher = (
                install
                / "support"
                / ("analyzeHeadless.bat" if os.name == "nt" else "analyzeHeadless")
            )
            launcher.parent.mkdir(parents=True)
            launcher.write_text("", encoding="utf-8")
            properties = install / "Ghidra" / "application.properties"
            properties.parent.mkdir()
            properties.write_text(
                "application.version=12.1\napplication.java.min=21\n", encoding="utf-8"
            )
            probe = ghidra_analyzer.inspect_ghidra(install, environ={}, which=lambda _: None)
        self.assertEqual("incompatible", probe.status)
        self.assertEqual("12.1", probe.version)

    def test_java_missing_and_incompatible_are_distinguished(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            install = root / "ghidra"
            launcher = (
                install
                / "support"
                / ("analyzeHeadless.bat" if os.name == "nt" else "analyzeHeadless")
            )
            launcher.parent.mkdir(parents=True)
            launcher.write_text("", encoding="utf-8")
            properties = install / "Ghidra" / "application.properties"
            properties.parent.mkdir()
            properties.write_text(
                "application.version=12.2\napplication.java.min=25\n", encoding="utf-8"
            )
            missing = ghidra_analyzer.inspect_ghidra(install, environ={}, which=lambda _: None)
            java = root / ("java.exe" if os.name == "nt" else "java")
            java.write_text("", encoding="utf-8")
            completed = subprocess.CompletedProcess(
                [str(java), "-version"], 0, "", 'openjdk version "21.0.2" 2024-01-16'
            )
            with patch.object(ghidra_analyzer, "_run", return_value=completed):
                incompatible = ghidra_analyzer.inspect_ghidra(
                    install,
                    environ={},
                    which=lambda name: str(java) if name == "java" else None,
                )
        self.assertEqual("unavailable", missing.status)
        self.assertEqual("incompatible", incompatible.status)


class GhidraAdapterTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.probe = _probe(self.root)
        self.binary = self.root / "firmware Ω board.elf"
        self.binary.write_bytes(b"\x7fELF" + bytes(128))
        self.output = self.root / "results"

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _runner(
        self,
        *,
        document_factory: object | None = None,
        return_code: int = 0,
        write_artifact: bool = True,
        captured: list[Path] | None = None,
    ) -> object:
        def run(command: list[str], **_: object) -> subprocess.CompletedProcess[str]:
            arguments, raw_output, digest, input_format, size = _script_args(command)
            if captured is not None:
                captured.append(Path(command[1][1:]).parent)
                captured.append(
                    Path(next(item for item in arguments if item.endswith("input.bin")))
                )
            if write_artifact:
                factory = document_factory or _document
                document = factory(digest, input_format, size)  # type: ignore[operator]
                raw_output.write_text(json.dumps(document), encoding="utf-8")
            return subprocess.CompletedProcess(command, return_code, "", "")

        return run

    def test_analyzes_elf_with_argument_file_and_no_original_path(self) -> None:
        captured: list[Path] = []
        with (
            patch.object(ghidra_analyzer, "inspect_ghidra", return_value=self.probe),
            patch.object(ghidra_analyzer, "_run", side_effect=self._runner(captured=captured)),
        ):
            result = ghidra_analyzer.analyze_ghidra(
                self.binary,
                self.output,
                configured_install_dir=self.probe.install_dir,
            )
        self.assertEqual("completed", result.status.status)
        self.assertEqual(
            {"FUSE-BIN-001", "FUSE-BIN-002"}, {item.rule_id for item in result.findings}
        )
        self.assertFalse(captured[0].exists())
        self.assertFalse(captured[1].exists())
        argument_file = captured[0].parent / "java.args"
        self.assertFalse(argument_file.exists())
        artifact = self.output / "ghidra-analysis.json"
        report = json.loads(artifact.read_text(encoding="utf-8"))
        self.assertNotIn("sample-secret", artifact.read_text(encoding="utf-8"))
        self.assertNotIn("private-value", artifact.read_text(encoding="utf-8"))
        self.assertEqual(
            "http://device.example",
            next(
                item["value"]
                for item in report["strings"]["records"]
                if item["value"].startswith("http:")
            ),
        )
        self.assertEqual(
            hashlib.sha256(artifact.read_bytes()).hexdigest(), result.artifacts[0].sha256
        )
        schema_path = (
            Path(__file__).parents[1]
            / "src"
            / "vigil_fuse"
            / "schemas"
            / "ghidra-analysis.schema.json"
        )
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
        Draft202012Validator.check_schema(schema)
        Draft202012Validator(schema).validate(report)

    def test_secure_tls_and_mqtts_references_produce_no_plaintext_findings(self) -> None:
        def secure_document(digest: str, input_format: str, size: int) -> dict[str, object]:
            document = _document(digest, input_format, size)
            strings = document["strings"]
            references = document["cross_references"]
            assert isinstance(strings, dict)
            assert isinstance(references, dict)
            strings["records"] = [
                {
                    "address": "00401000",
                    "value": "http://unreferenced.example/update",
                    "redacted": False,
                },
                {
                    "address": "00401500",
                    "value": "mqtt://unreferenced.example:1883",
                    "redacted": False,
                },
                {
                    "address": "00402000",
                    "value": "https://device.example/update",
                    "redacted": False,
                },
                {"address": "00403000", "value": "mqtts://broker.example:8883", "redacted": False},
            ]
            strings["reported"] = 4
            strings["observed"] = 4
            references["records"] = [
                {
                    "string_address": "00402000",
                    "from_address": "00400020",
                    "function": "download_update",
                    "function_entry_address": "00400010",
                    "reference_type": "DATA",
                },
                {
                    "string_address": "00403000",
                    "from_address": "00400030",
                    "function": "connect_broker",
                    "function_entry_address": "00400028",
                    "reference_type": "DATA",
                },
            ]
            references["reported"] = 2
            references["observed"] = 2
            return document

        with (
            patch.object(ghidra_analyzer, "inspect_ghidra", return_value=self.probe),
            patch.object(
                ghidra_analyzer,
                "_run",
                side_effect=self._runner(document_factory=secure_document),
            ),
        ):
            result = ghidra_analyzer.analyze_ghidra(self.binary, self.output)

        self.assertEqual("completed", result.status.status)
        self.assertEqual((), result.findings)

    def test_invalid_raw_binary_is_unsupported_without_explicit_architecture(self) -> None:
        raw = self.root / "raw-image.bin"
        raw.write_bytes(b"raw bytes")
        with patch.object(ghidra_analyzer, "inspect_ghidra", return_value=self.probe):
            result = ghidra_analyzer.analyze_ghidra(raw, self.output)
        self.assertEqual("unsupported", result.status.status)
        self.assertIn("--ghidra-language", result.status.detail or "")

    def test_raw_binary_arguments_are_explicit_and_vectorized(self) -> None:
        raw = self.root / "raw-image.bin"
        raw.write_bytes(b"raw bytes")
        seen: list[list[str]] = []

        def run(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
            arguments, raw_output, digest, input_format, size = _script_args(command)
            seen.append(arguments)
            raw_output.write_text(
                json.dumps(_document(digest, input_format, size)), encoding="utf-8"
            )
            return subprocess.CompletedProcess(command, 0, "", "")

        with (
            patch.object(ghidra_analyzer, "inspect_ghidra", return_value=self.probe),
            patch.object(ghidra_analyzer, "_run", side_effect=run),
        ):
            result = ghidra_analyzer.analyze_ghidra(
                raw,
                self.output,
                language="ARM:LE:32:v8",
                base_address="0x1000",
                compiler_spec="default",
            )
        self.assertEqual("completed", result.status.status)
        self.assertIn("BinaryLoader", seen[0])
        self.assertIn("ARM:LE:32:v8", seen[0])
        self.assertIn("0x1000", seen[0])
        self.assertIn("default", seen[0])

    def test_malformed_missing_and_schema_invalid_outputs_fail_visibly(self) -> None:
        for mode, expected in (
            ("missing", "without producing"),
            ("malformed", "malformed"),
            ("schema", "invalid"),
        ):
            with self.subTest(mode=mode):
                output = self.root / mode

                def run(command: list[str], **_: object) -> subprocess.CompletedProcess[str]:
                    arguments, raw_output, digest, input_format, size = _script_args(command)
                    if mode == "malformed":
                        raw_output.write_text("{bad json", encoding="utf-8")
                    elif mode == "schema":
                        document = _document(digest, input_format, size)
                        document["schema_version"] = "9.9"
                        raw_output.write_text(json.dumps(document), encoding="utf-8")
                    return subprocess.CompletedProcess(command, 0, "", "")

                with (
                    patch.object(ghidra_analyzer, "inspect_ghidra", return_value=self.probe),
                    patch.object(ghidra_analyzer, "_run", side_effect=run),
                ):
                    result = ghidra_analyzer.analyze_ghidra(self.binary, output)
                self.assertEqual("failed", result.status.status)
                self.assertIn(expected, result.status.detail or "")

    def test_timeout_process_failure_and_output_overflow_are_visible(self) -> None:
        failures = (
            (subprocess.TimeoutExpired(["java"], 2), "timeout"),
            (ghidra_analyzer.AnalyzerOutputLimitError("overflow"), "failed"),
        )
        for error, status in failures:
            with self.subTest(status=status, error=type(error).__name__):
                with (
                    patch.object(ghidra_analyzer, "inspect_ghidra", return_value=self.probe),
                    patch.object(ghidra_analyzer, "_run", side_effect=error),
                ):
                    result = ghidra_analyzer.analyze_ghidra(self.binary, self.output)
                self.assertEqual(status, result.status.status)

        with (
            patch.object(ghidra_analyzer, "inspect_ghidra", return_value=self.probe),
            patch.object(
                ghidra_analyzer,
                "_run",
                side_effect=self._runner(return_code=7),
            ),
        ):
            failed_exit = ghidra_analyzer.analyze_ghidra(self.binary, self.output)
        self.assertEqual("failed", failed_exit.status.status)
        self.assertIn("code 7", failed_exit.status.detail or "")

    def test_truncated_analysis_is_partial_and_reported(self) -> None:
        def partial_document(digest: str, input_format: str, size: int) -> dict[str, object]:
            document = _document(digest, input_format, size)
            analysis = document["analysis"]
            assert isinstance(analysis, dict)
            analysis["status"] = "partial"
            groups = document["strings"]
            assert isinstance(groups, dict)
            groups["truncated"] = True
            groups["observed_is_lower_bound"] = True
            groups["observed"] = groups["reported"] + 1
            truncation = document["truncation"]
            assert isinstance(truncation, dict)
            truncation["strings"] = True
            return document

        with (
            patch.object(ghidra_analyzer, "inspect_ghidra", return_value=self.probe),
            patch.object(
                ghidra_analyzer,
                "_run",
                side_effect=self._runner(document_factory=partial_document),
            ),
        ):
            result = ghidra_analyzer.analyze_ghidra(self.binary, self.output)
        self.assertEqual("partial", result.status.status)
        report = json.loads((self.output / "ghidra-analysis.json").read_text(encoding="utf-8"))
        self.assertTrue(report["strings"]["truncated"])
        self.assertTrue(report["truncation"]["strings"])

    def test_docker_sandbox_never_falls_back_to_host(self) -> None:
        with patch.object(ghidra_analyzer, "analyzer_sandbox_active", return_value=True):
            result = ghidra_analyzer.analyze_ghidra(self.binary, self.output)
        self.assertEqual("unsupported", result.status.status)
        self.assertIn("no host fallback", result.status.detail or "")


class GhidraCliTests(unittest.TestCase):
    def test_doctor_and_plan_show_ghidra_without_analyzing(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            binary = root / "fixture.elf"
            binary.write_bytes(b"\x7fELF" + bytes(64))
            probe = _probe(root)
            stdout = StringIO()
            stderr = StringIO()
            with (
                patch("vigil_fuse.cli.inspect_ghidra", return_value=probe),
                redirect_stdout(stdout),
                redirect_stderr(stderr),
            ):
                doctor_exit = main(["doctor", "--ghidra-install-dir", str(probe.install_dir)])
            with (
                patch("vigil_fuse.cli.inspect_ghidra", return_value=probe),
                redirect_stdout(stdout := StringIO()),
                redirect_stderr(stderr := StringIO()),
            ):
                plan_exit = main(
                    [
                        "scan",
                        str(binary),
                        "--ghidra",
                        "--ghidra-install-dir",
                        str(probe.install_dir),
                        "--plan",
                        "--format",
                        "json",
                    ]
                )
        plan = json.loads(stdout.getvalue())
        ghidra_stage = next(stage for stage in plan["stages"] if stage["name"] == "ghidra")
        self.assertEqual(0, doctor_exit)
        self.assertEqual(0, plan_exit)
        self.assertEqual("planned", ghidra_stage["status"])
        self.assertFalse(plan["executed"])

    def test_cli_report_contains_analyzer_status_artifact_and_findings(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            binary = root / "fixture.elf"
            binary.write_bytes(b"\x7fELF" + bytes(64))
            output = root / "report-output"
            probe = _probe(root)
            with (
                patch("vigil_fuse.cli.inspect_ghidra", return_value=probe),
                patch.object(ghidra_analyzer, "inspect_ghidra", return_value=probe),
                patch.object(ghidra_analyzer, "_run", side_effect=_fake_runner),
                redirect_stdout(StringIO()),
                redirect_stderr(StringIO()),
            ):
                result_code = main(
                    [
                        "scan",
                        str(binary),
                        "--ghidra",
                        "--ghidra-install-dir",
                        str(probe.install_dir),
                        "--output-dir",
                        str(output),
                        "--format",
                        "json",
                    ]
                )
            report = json.loads((output / "findings.json").read_text(encoding="utf-8"))
            schema = json.loads(
                (
                    Path(__file__).parents[1]
                    / "src"
                    / "vigil_fuse"
                    / "schemas"
                    / "fuse-report-1.11.schema.json"
                ).read_text(encoding="utf-8")
            )
        Draft202012Validator(schema).validate(report)
        self.assertEqual(0, result_code)
        self.assertEqual("1.11", report["schema_version"])
        self.assertEqual(2, report["summary"]["finding_count"])
        self.assertTrue(report["summary"]["analysis_performed"])
        self.assertEqual(
            "completed",
            next(
                item["status"]
                for item in report["coverage"]["analyzers"]
                if item["name"] == "ghidra"
            ),
        )
        self.assertEqual("ghidra-analysis.json", report["artifacts"][0]["path"])


if __name__ == "__main__":
    unittest.main()
