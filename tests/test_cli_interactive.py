from io import StringIO
from pathlib import Path
import unittest
from unittest.mock import patch

from vigil_fuse.cli import _interactive_launch, main


class TTYBuffer(StringIO):
    def isatty(self) -> bool:
        return True


class InteractiveLaunchTests(unittest.TestCase):
    def test_declining_scan_leaves_current_folder_unscanned(self) -> None:
        output = TTYBuffer()
        target = Path("/workspace/project")
        with (
            patch("vigil_fuse.cli.Path.cwd", return_value=target),
            patch("builtins.input", return_value="n"),
            patch("vigil_fuse.cli.sys.stderr", output),
        ):
            code = _interactive_launch()

        self.assertEqual(0, code)
        self.assertIn(str(target), output.getvalue())
        self.assertIn("Scan cancelled.", output.getvalue())

    def test_accepting_scan_dispatches_explicit_current_target(self) -> None:
        target = Path("/workspace/project")
        with (
            patch("vigil_fuse.cli.Path.cwd", return_value=target),
            patch("builtins.input", side_effect=["yes", "1"]),
            patch("vigil_fuse.cli.main", return_value=0) as dispatch,
            patch("vigil_fuse.cli.sys.stderr", TTYBuffer()),
        ):
            code = _interactive_launch()

        self.assertEqual(0, code)
        dispatch.assert_called_once_with(
            ["scan", str(target)], _show_banner=False, _prompt_for_pdf=True
        )

    def test_ghidra_choice_asks_for_one_binary_and_runs_fuse_analysis(self) -> None:
        target = Path("/workspace/project")
        output = TTYBuffer()
        with (
            patch("vigil_fuse.cli.Path.cwd", return_value=target),
            patch("builtins.input", side_effect=["yes", "5", "firmware.elf"]),
            patch("vigil_fuse.cli.main", return_value=0) as dispatch,
            patch("vigil_fuse.cli.sys.stderr", output),
        ):
            code = _interactive_launch()

        self.assertEqual(0, code)
        self.assertIn("does not export decompiled pseudocode", output.getvalue())
        dispatch.assert_called_once_with(
            ["scan", str(target / "firmware.elf"), "--ghidra"],
            _show_banner=False,
            _prompt_for_pdf=True,
        )

    def test_no_argument_tty_launch_shows_banner_before_prompt(self) -> None:
        output = TTYBuffer()
        with (
            patch("vigil_fuse.cli.sys.stdin", TTYBuffer()),
            patch("vigil_fuse.cli.sys.stdout", TTYBuffer()),
            patch("vigil_fuse.cli.sys.stderr", output),
            patch("vigil_fuse.cli.show_banner") as banner,
            patch("vigil_fuse.cli._interactive_launch", return_value=0) as launch,
        ):
            code = main([])

        self.assertEqual(0, code)
        banner.assert_called_once_with()
        launch.assert_called_once_with()


if __name__ == "__main__":
    unittest.main()
