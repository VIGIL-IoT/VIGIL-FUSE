from __future__ import annotations

import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from vigil_fuse.analyzers import (
    _cvss_v3_score,
    _source_location,
    generate_sbom,
    identify_firmware,
    osv_findings,
    scan_vulnerabilities,
)


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
                                    "references": [{"type": "WEB", "url": "https://example.org/advisory"}],
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


class OptionalAnalyzerTests(unittest.TestCase):
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

            with patch("vigil_fuse.analyzers.shutil.which", return_value="syft"), \
                 patch("vigil_fuse.analyzers._tool_version", return_value="syft 1.54.0"), \
                 patch("vigil_fuse.analyzers._run", side_effect=run) as mocked_run:
                result = generate_sbom(target, output)
            artifact_hash = hashlib.sha256((output / "components.cdx.json").read_bytes()).hexdigest()

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
                            "vulnerabilities": [{"id": "GHSA-aaaa-bbbb-cccc", "database_specific": {"severity": "HIGH"}}],
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
            completed = subprocess.CompletedProcess([], 1, json.dumps(document), "found vulnerability")
            with patch("vigil_fuse.analyzers.shutil.which", return_value="osv-scanner"), \
                 patch("vigil_fuse.analyzers._tool_version", return_value="osv-scanner 2.3.0"), \
                 patch("vigil_fuse.analyzers._run", return_value=completed) as mocked_run:
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

    def test_binwalk_identifies_only_and_never_receives_extraction_flag(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            firmware = root / "image.bin"
            firmware.write_bytes(b"image")
            output = root / "reports"
            completed = subprocess.CompletedProcess([], 0, "offset | signature\n", "")
            with patch("vigil_fuse.analyzers.shutil.which", return_value="binwalk"), \
                 patch("vigil_fuse.analyzers._tool_version", return_value="Binwalk v3"), \
                 patch("vigil_fuse.analyzers._run", return_value=completed) as mocked_run:
                result = identify_firmware(firmware, output)

        self.assertEqual("partial", result.status.status)
        command = mocked_run.call_args.args[0]
        self.assertEqual(["binwalk", str(firmware.resolve())], command)
        self.assertFalse(any(argument in {"-e", "--extract", "-Me"} for argument in command))
        self.assertIn("no extraction", result.status.detail.lower())


if __name__ == "__main__":
    unittest.main()
