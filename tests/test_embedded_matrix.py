from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

from scripts.run_embedded_ghidra_matrix import TARGETS, analyze, build_controlled


class EmbeddedMatrixTests(unittest.TestCase):
    def test_build_controls_cover_optimization_negative_and_stripping(self):
        for target in TARGETS:
            with self.subTest(target=target), tempfile.TemporaryDirectory() as temporary:
                work = Path(temporary)
                (work / "compiler-version.txt").write_text("controlled compiler version")
                with (
                    patch("subprocess.run"),
                    patch("subprocess.check_output", return_value="compiler version"),
                ):
                    cases, metadata = build_controlled(target, work)
                self.assertEqual(11 + 2 * (target == "cortex_m4"), len(cases))
                self.assertEqual({"O0", "O1", "O2", "Os"}, {c["optimization"] for c in cases})
                self.assertEqual(2, sum(c["stripped"] and c["format"] == "ELF" for c in cases))
                self.assertTrue(any(c["kind"] == "unreferenced" for c in cases))
                self.assertTrue(metadata["commands"])
                for case in cases:
                    if case["format"] == "raw":
                        self.assertEqual("ARM:LE:32:Cortex", case["language"])
                        self.assertEqual("0x08000000", case["base_address"])
                        self.assertTrue(case["experimental"])

    def test_failed_cli_is_failed_coverage_even_when_no_findings(self):
        with tempfile.TemporaryDirectory() as temporary:
            work = Path(temporary)
            binary = work / "sample.elf"
            binary.write_bytes(b"\x7fELF")
            process = Mock(returncode=1)
            process.poll.return_value = 1
            with patch("subprocess.Popen", return_value=process):
                record = analyze(
                    {"id": "secure", "kind": "secure", "format": "ELF"},
                    binary,
                    work,
                    work / "ghidra",
                    300,
                )
            self.assertEqual("failed", record["status"])
            self.assertFalse(record["schemas_valid"])
            self.assertEqual([], record["rule_ids"])
            self.assertTrue(record["temporary_cleanup"])
