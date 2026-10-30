from __future__ import annotations

import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from vigil_fuse.analyzers import (
    generate_sbom,
    identify_firmware,
    osv_findings,
    scan_git_history,
    scan_vulnerabilities,
)
from vigil_fuse.analyzer_runtime import AnalyzerOutputLimitError, _run
from vigil_fuse.dependency_analyzers import _cvss_v3_score, _source_location


class OSVNormalizationTests(unittest.TestCase):
    def test_relative_osv_paths_resolve_from_scan_target(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary)
            nested = target / "sub"
            nested.mkdir()
            (nested / "Cargo.lock").touch()

            location = _source_location("sub/Cargo.lock", target)

        self.assertEqual("sub/Cargo.lock", location)

    def test_cvss_v31_vector_scores_map_to_severity_without_guessing(self) -> None:
        critical = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        medium = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N"
        self.assertEqual(9.8, _cvss_v3_score(critical))
        self.assertEqual(6.5, _cvss_v3_score(medium))

    def test_matches_dependency_and_deduplicates_alias_group(self) -> None:
        document = {
            "results": [
                {
                    "source": {"path": "/project/Cargo.lock", "type": "lockfile"},
                    "packages": [
                        {
                            "package": {
                                "name": "example-crate",
                                "version": "1.2.3",
                                "ecosystem": "crates.io",
                            },
                            "vulnerabilities": [
                                {
                                    "id": "GHSA-aaaa-bbbb-cccc",
                                    "aliases": ["CVE-2026-12345"],
                                    "summary": "Example vulnerability",
                                    "severity": [{"type": "CVSS_V3", "score": "8.1"}],
                                    "references": [
                                        {"type": "WEB", "url": "https://example.org/advisory"}
                                    ],
                                },
                                {
                                    "id": "CVE-2026-12345",
                                    "aliases": ["GHSA-aaaa-bbbb-cccc"],
                                    "summary": "Same advisory under its alias",
                                },
                            ],
                            "groups": [{"ids": ["GHSA-aaaa-bbbb-cccc", "CVE-2026-12345"]}],
                        }
                    ],
                }
            ]
        }
        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary)
            (target / "Cargo.lock").touch()
            findings = osv_findings(document, target, "osv-scanner 2.3.0")

        self.assertEqual(1, len(findings))
        finding = findings[0]
        self.assertEqual("CVE-2026-12345", finding.rule_id.removeprefix("OSV-"))
        self.assertEqual("high", finding.severity)
        self.assertEqual("high", finding.confidence)
        self.assertEqual("Cargo.lock", finding.file)
        self.assertIsNone(finding.start_line)
        self.assertEqual("osv-scanner 2.3.0", finding.rule_version)
        self.assertIn("https://osv.dev/vulnerability/CVE-2026-12345", finding.references)
        self.assertIn("https://example.org/advisory", finding.references)

    def test_unknown_advisory_severity_is_not_guessed(self) -> None:
        document = {
            "results": [
                {
                    "source": {"path": "package-lock.json", "type": "lockfile"},
                    "packages": [
                        {
                            "package": {"name": "p", "version": "1", "ecosystem": "npm"},
                            "vulnerabilities": [{"id": "GHSA-aaaa-bbbb-cccc"}],
                        }
                    ],
                }
            ]
        }
        finding = osv_findings(document, Path.cwd(), None)[0]
        self.assertEqual("unknown", finding.severity)
        self.assertIn("no advisory severity score was supplied", finding.evidence)

    def test_cvss_v4_vector_is_preserved_without_v3_score_mapping(self) -> None:
        vector = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H"
        document = {
            "results": [
                {
                    "source": {"path": "package-lock.json", "type": "lockfile"},
                    "packages": [
                        {
                            "package": {"name": "p", "version": "1", "ecosystem": "npm"},
                            "vulnerabilities": [
                                {
                                    "id": "GHSA-aaaa-bbbb-cccc",
                                    "severity": [{"type": "CVSS_V4", "score": vector}],
                                }
                            ],
                        }
                    ],
                }
            ]
        }

        finding = osv_findings(document, Path.cwd(), None)[0]

        self.assertEqual("unknown", finding.severity)
        self.assertEqual("cvss-vector", finding.severity_basis)
        self.assertIsNone(finding.severity_score)
        self.assertEqual(vector, finding.severity_vector)
        self.assertEqual("4.0", finding.severity_version)


class OptionalAnalyzerTests(unittest.TestCase):
    def test_subprocess_input_is_closed_to_prevent_interactive_waits(self) -> None:
        completed = _run(
            [sys.executable, "-c", "import sys; print(sys.stdin.read())"],
            timeout=5,
        )

        self.assertEqual(0, completed.returncode)
        self.assertEqual("", completed.stdout.strip())

    def test_subprocess_output_is_capped_while_streaming(self) -> None:
        with self.assertRaises(AnalyzerOutputLimitError):
            _run(
                [sys.executable, "-c", "import sys; sys.stdout.write('x' * 12000000)"],
                timeout=10,
            )

    def test_syft_generates_hashed_cyclonedx_artifact(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            target = root / "project"
            target.mkdir()
            output = target / "reports"

            def run(command: list[str]) -> subprocess.CompletedProcess[str]:
                path = Path(command[-1].split("=", 1)[1])
                path.write_text(
                    json.dumps({"bomFormat": "CycloneDX", "components": [{"name": "x"}]}),
                    encoding="utf-8",
                )
                return subprocess.CompletedProcess(command, 0, "", "")

            with (
                patch("vigil_fuse.dependency_analyzers.shutil.which", return_value="syft"),
                patch("vigil_fuse.dependency_analyzers._tool_version", return_value="syft 1.54.0"),
                patch("vigil_fuse.dependency_analyzers._run", side_effect=run) as mocked_run,
            ):
                result = generate_sbom(target, output)
            artifact_hash = hashlib.sha256(
                (output / "components.cdx.json").read_bytes()
            ).hexdigest()

        self.assertEqual("completed", result.status.status)
        self.assertEqual("syft 1.54.0", result.status.version)
        self.assertEqual("components.cdx.json", result.artifacts[0].path)
        self.assertEqual(artifact_hash, result.artifacts[0].sha256)
        self.assertIn(f"dir:{target.resolve()}", mocked_run.call_args.args[0])
        self.assertIn("--exclude", mocked_run.call_args.args[0])

    def test_osv_exit_code_one_is_valid_when_findings_are_returned(self) -> None:
        document = {
            "results": [
                {
                    "source": {"path": "/target/package-lock.json", "type": "lockfile"},
                    "packages": [
                        {
                            "package": {"name": "demo", "version": "1.0", "ecosystem": "npm"},
                            "vulnerabilities": [
                                {
                                    "id": "GHSA-aaaa-bbbb-cccc",
                                    "database_specific": {"severity": "HIGH"},
                                }
                            ],
                        }
                    ],
                }
            ]
        }
        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary) / "target"
            target.mkdir()
            (target / "package-lock.json").touch()
            output = target / "reports"
            completed = subprocess.CompletedProcess(
                [], 1, json.dumps(document), "found vulnerability"
            )
            with (
                patch("vigil_fuse.dependency_analyzers.shutil.which", return_value="osv-scanner"),
                patch(
                    "vigil_fuse.dependency_analyzers._tool_version",
                    return_value="osv-scanner 2.3.0",
                ),
                patch("vigil_fuse.dependency_analyzers._run", return_value=completed) as mocked_run,
            ):
                result = scan_vulnerabilities(target, output)
            output_exists = (output / "osv-results.json").is_file()
            osv_command = mocked_run.call_args.args[0]

        self.assertEqual("completed", result.status.status)
        self.assertEqual(1, result.status.findings)
        self.assertEqual("high", result.findings[0].severity)
        self.assertTrue(output_exists)
        self.assertEqual("osv-results.json", result.artifacts[0].path)
        self.assertIn("--x-exclude", osv_command)
        self.assertIn("g:reports/**", osv_command)

    def test_osv_no_package_sources_is_partial_without_a_fake_results_artifact(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            target = root / "target"
            target.mkdir()
            output = root / "reports"
            completed = subprocess.CompletedProcess(
                [],
                128,
                "",
                "No package sources found, --help for usage information.",
            )
            with (
                patch("vigil_fuse.dependency_analyzers.shutil.which", return_value="osv-scanner"),
                patch(
                    "vigil_fuse.dependency_analyzers._tool_version",
                    return_value="osv-scanner version: 2.7.0",
                ),
                patch("vigil_fuse.dependency_analyzers._run", return_value=completed),
            ):
                result = scan_vulnerabilities(target, output)

        self.assertEqual("partial", result.status.status)
        self.assertEqual(0, result.status.findings)
        self.assertIn("matching was not performed", result.status.detail or "")
        self.assertEqual((), result.findings)
        self.assertEqual((), result.artifacts)
        self.assertFalse((output / "osv-results.json").exists())

    def test_strict_no_network_mode_uses_osv_offline_flag(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            target = root / "target"
            target.mkdir()
            (target / "package-lock.json").touch()
            completed = subprocess.CompletedProcess([], 0, '{"results":[]}', "")
            with (
                patch("vigil_fuse.dependency_analyzers.shutil.which", return_value="osv-scanner"),
                patch(
                    "vigil_fuse.dependency_analyzers._tool_version",
                    return_value="OSV-Scanner 2.3.0",
                ),
                patch("vigil_fuse.dependency_analyzers._run", return_value=completed) as mocked_run,
            ):
                result = scan_vulnerabilities(target, root / "reports", no_network=True)
            command = mocked_run.call_args.args[0]

        self.assertEqual("completed", result.status.status)
        self.assertIn("--offline", command)
        self.assertNotIn("--offline-vulnerabilities", command)

    def test_binwalk_identifies_only_and_never_receives_extraction_flag(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            firmware = root / "image.bin"
            firmware.write_bytes(b"image")
            output = root / "reports"
            completed = subprocess.CompletedProcess([], 0, "offset | signature\n", "")
            with (
                patch("vigil_fuse.firmware_analyzer.shutil.which", return_value="binwalk"),
                patch("vigil_fuse.firmware_analyzer._tool_version", return_value="Binwalk v3"),
                patch("vigil_fuse.firmware_analyzer._run", return_value=completed) as mocked_run,
            ):
                result = identify_firmware(firmware, output)

        self.assertEqual("completed", result.status.status)
        self.assertEqual("Binwalk v3", result.status.version)
        command = mocked_run.call_args.args[0]
        self.assertEqual(["binwalk", str(firmware.resolve())], command)
        self.assertFalse(any(argument in {"-e", "--extract", "-Me"} for argument in command))
        self.assertIn("no extraction", result.status.detail.lower())

    def test_binwalk_report_truncation_is_reported_as_partial(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            firmware = root / "image.bin"
            firmware.write_bytes(b"image")
            output = root / "reports"
            completed = subprocess.CompletedProcess([], 0, "0123456789", "")
            with (
                patch("vigil_fuse.firmware_analyzer.shutil.which", return_value="binwalk"),
                patch("vigil_fuse.firmware_analyzer._tool_version", return_value="Binwalk v3"),
                patch("vigil_fuse.firmware_analyzer.MAX_BINWALK_REPORT_BYTES", 8),
                patch("vigil_fuse.firmware_analyzer._run", return_value=completed),
            ):
                result = identify_firmware(firmware, output)
            saved_report = (output / "firmware-identification.txt").read_bytes()

        self.assertEqual("partial", result.status.status)
        self.assertEqual("Binwalk v3", result.status.version)
        self.assertEqual(b"01234567", saved_report)
        self.assertIn("truncated", result.status.detail.lower())


class GitHistoryAnalyzerTests(unittest.TestCase):
    @staticmethod
    def _git_metadata(root: Path, *, shallow: str = "false"):
        commit = "b" * 40

        def command(_target: Path, *arguments: str) -> subprocess.CompletedProcess[str]:
            values = {
                ("rev-parse", "--show-toplevel"): str(root),
                ("rev-parse", "HEAD"): commit,
                ("rev-list", "--count", "HEAD"): "3",
                ("rev-parse", "--is-shallow-repository"): shallow,
            }
            return subprocess.CompletedProcess([], 0, values[arguments], "")

        return command

    def test_history_report_omits_secret_and_commit_author_fields(self) -> None:
        secret = "s3cr3t-history-value-123456"
        report = [
            {
                "RuleID": "aws-access-token",
                "File": "src/config.h",
                "StartLine": 17,
                "Commit": "a" * 40,
                "Date": "2025-06-01T12:30:00Z",
                "Secret": secret,
                "Match": f"TOKEN={secret}",
                "Author": "Private Author",
                "Email": "person@example.invalid",
                "Message": "contains private information",
            }
        ]
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with (
                patch(
                    "vigil_fuse.history_analyzer.shutil.which",
                    side_effect=lambda name: f"{name}.exe",
                ),
                patch("vigil_fuse.history_analyzer._tool_version", return_value="gitleaks 8.30.0"),
                patch(
                    "vigil_fuse.history_analyzer._git_command", side_effect=self._git_metadata(root)
                ),
                patch(
                    "vigil_fuse.history_analyzer._run",
                    return_value=subprocess.CompletedProcess([], 0, json.dumps(report), ""),
                ) as run,
            ):
                result = scan_git_history(root, root / "reports")
            saved = (root / "reports" / "git-history-findings.json").read_text(encoding="utf-8")
            finding = json.dumps(result.findings[0].to_dict())
            command = run.call_args.args[0]

        self.assertEqual("completed", result.status.status)
        self.assertEqual(1, result.status.findings)
        self.assertEqual("historical-secret-exposure", result.findings[0].category)
        self.assertEqual("unknown", result.findings[0].severity)
        self.assertEqual("medium", result.findings[0].confidence)
        for sensitive in (
            secret,
            "Private Author",
            "person@example.invalid",
            "contains private information",
        ):
            self.assertNotIn(sensitive, saved)
            self.assertNotIn(sensitive, finding)
        self.assertIn("--redact=100", command)
        self.assertIn("--report-path=-", command)
        self.assertEqual("git-history-findings.json", result.artifacts[0].path)

    def test_shallow_history_is_partial_and_says_history_is_incomplete(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with (
                patch(
                    "vigil_fuse.history_analyzer.shutil.which",
                    side_effect=lambda name: f"{name}.exe",
                ),
                patch("vigil_fuse.history_analyzer._tool_version", return_value="gitleaks 8.30.0"),
                patch(
                    "vigil_fuse.history_analyzer._git_command",
                    side_effect=self._git_metadata(root, shallow="true"),
                ),
                patch(
                    "vigil_fuse.history_analyzer._run",
                    return_value=subprocess.CompletedProcess([], 0, "[]", ""),
                ),
            ):
                result = scan_git_history(root, root / "reports")
            saved = json.loads(
                (root / "reports" / "git-history-findings.json").read_text(encoding="utf-8")
            )

        self.assertEqual("partial", result.status.status)
        self.assertIn("shallow", result.status.detail)
        self.assertEqual("shallow", saved["history_completeness"])
        self.assertTrue(saved["secrets_redacted"])

    def test_history_scan_rejects_a_repository_subdirectory(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            nested = root / "nested"
            nested.mkdir()
            with (
                patch(
                    "vigil_fuse.history_analyzer.shutil.which",
                    side_effect=lambda name: f"{name}.exe",
                ),
                patch("vigil_fuse.history_analyzer._tool_version", return_value="gitleaks 8.30.0"),
                patch(
                    "vigil_fuse.history_analyzer._git_command",
                    return_value=subprocess.CompletedProcess([], 0, str(root), ""),
                ),
                patch("vigil_fuse.history_analyzer._run") as run,
            ):
                result = scan_git_history(nested, root / "reports")

        self.assertEqual("skipped", result.status.status)
        self.assertIn("repository root", result.status.detail)
        run.assert_not_called()

    def test_missing_gitleaks_is_reported_as_unavailable(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)

            def which(name: str) -> str | None:
                return "git.exe" if name == "git" else None

            with (
                patch("vigil_fuse.history_analyzer.shutil.which", side_effect=which),
                patch("vigil_fuse.history_analyzer._run") as run,
            ):
                result = scan_git_history(root, root / "reports")

        self.assertEqual("unavailable", result.status.status)
        self.assertIn("Gitleaks", result.status.detail)
        run.assert_not_called()


if __name__ == "__main__":
    unittest.main()
