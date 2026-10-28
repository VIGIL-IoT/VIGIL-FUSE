from contextlib import redirect_stderr
from io import StringIO
import os
import unittest
from unittest.mock import patch

from vigil_fuse.terminal import show_banner


class TerminalBannerTests(unittest.TestCase):
    def test_interactive_banner_is_branded_and_honors_no_color(self) -> None:
        class TTYBuffer(StringIO):
            def isatty(self) -> bool:
                return True

        output = TTYBuffer()
        with patch.dict(os.environ, {"NO_COLOR": ""}), redirect_stderr(output):
            show_banner()

        banner = output.getvalue()
        self.assertIn("FUSE", banner)
        self.assertIn("Firmware & Unified Security Engine", banner)
        self.assertIn("A VIGIL Project", banner)
        self.assertIn("firmware  ->  security evidence", banner)
        self.assertNotIn("\x1b[", banner)

    def test_non_interactive_banner_is_silent(self) -> None:
        output = StringIO()
        with redirect_stderr(output):
            show_banner()
        self.assertEqual("", output.getvalue())


if __name__ == "__main__":
    unittest.main()
