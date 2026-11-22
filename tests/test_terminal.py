from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
import json
import os
import re
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from vigil_fuse.cli import main
from vigil_fuse.terminal import read_command, show_banner
from vigil_fuse.text_safety import safe_terminal_text


class TTYBuffer(StringIO):
    def __init__(self, encoding="utf-8"):
        super().__init__()
        self._encoding = encoding

    @property
    def encoding(self):
        return self._encoding

    def isatty(self):
        return True


class TerminalBannerTests(unittest.TestCase):
    def render(self, width=80, encoding="utf-8", no_color=False):
        output = TTYBuffer(encoding)
        environment = {"TERM": "xterm-256color"}
        if no_color:
            environment["NO_COLOR"] = ""
        with (
            patch.dict(os.environ, environment, clear=True),
            patch(
                "vigil_fuse.terminal.shutil.get_terminal_size",
                return_value=os.terminal_size((width, 24)),
            ),
            redirect_stdout(TTYBuffer()),
            redirect_stderr(output),
        ):
            show_banner()
        return output.getvalue()

    def test_read_command_uses_shell_prompt(self):
        with patch("builtins.input", return_value="/scan") as prompt:
            self.assertEqual("/scan", read_command())
        prompt.assert_called_once_with("fuse > ")

    def test_unicode_color_identity(self):
        banner = self.render()
        plain = re.sub(r"\x1b\[[0-9;]*m", "", banner)
        self.assertIn("███████", plain)
        self.assertIn("Firmware & Unified Security Engine", plain)
        self.assertIn("VIGIL", plain)
        self.assertIn("\x1b[38;2;", banner)
        self.assertNotIn("\x1b[48;", banner)

    def test_banner_contents_are_centered(self):
        banner = self.render(width=80, no_color=True)
        for label in ("Firmware & Unified Security Engine", "by VIGIL", "Static evidence."):
            line = next(line for line in banner.splitlines() if label in line)
            content = line[1:-1]
            self.assertLessEqual(
                abs(len(content) - len(content.lstrip()) - (len(content) - len(content.rstrip()))),
                1,
            )
        logo = next(line for line in banner.splitlines() if "███████" in line)
        self.assertGreater(len(logo) - len(logo.lstrip("│ ")), 10)

    def test_no_color_and_legacy_encoding(self):
        for encoding in ("utf-8", "cp1252", "ascii"):
            with self.subTest(encoding=encoding):
                banner = self.render(encoding=encoding, no_color=True)
                self.assertNotIn("\x1b[", banner)
                banner.encode(encoding)
        self.assertIn("FFFFFF", self.render(encoding="ascii", no_color=True))

    def test_narrow_identity_fits(self):
        banner = self.render(width=25, no_color=True)
        self.assertTrue(banner.startswith("FUSE by VIGIL\n"))
        self.assertTrue(all(len(line) <= 25 for line in banner.splitlines()))

    def test_redirected_either_stream_is_silent(self):
        for stdout, stderr in ((StringIO(), TTYBuffer()), (TTYBuffer(), StringIO())):
            with redirect_stdout(stdout), redirect_stderr(stderr):
                show_banner()
            self.assertEqual("", stderr.getvalue())

    def test_explicit_structured_commands_have_no_decoration(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "main.c").write_text("int main(void) { return 0; }\n")
            for format_name in ("json", "sarif"):
                out, err = TTYBuffer(), TTYBuffer()
                with redirect_stdout(out), redirect_stderr(err):
                    code = main(["scan", str(root), "--format", format_name])
                self.assertEqual(0, code)
                self.assertNotIn("\x1b[", out.getvalue() + err.getvalue())
                self.assertNotIn("████", out.getvalue() + err.getvalue())
                json.loads(out.getvalue())

    def test_untrusted_control_and_bidirectional_characters_are_visible_escapes(self):
        self.assertEqual(
            r"name\x1b[2J\t\r\u202efile", safe_terminal_text("name\x1b[2J\t\r\u202efile")
        )
