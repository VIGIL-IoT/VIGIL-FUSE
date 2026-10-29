from contextlib import redirect_stderr
from io import StringIO
import os
import unittest
from unittest.mock import patch

from vigil_fuse.terminal import show_banner
from vigil_fuse.text_safety import safe_terminal_text


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

    def test_untrusted_control_and_bidirectional_characters_are_visible_escapes(self) -> None:
        value = "name\x1b[2J\t\r\u202efile"

        rendered = safe_terminal_text(value)

        self.assertEqual(r"name\x1b[2J\t\r\u202efile", rendered)
        self.assertNotIn("\x1b", rendered)
        self.assertNotIn("\u202e", rendered)


if __name__ == "__main__":
    unittest.main()
