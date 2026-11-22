from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from vigil_fuse.cli import main
from vigil_fuse.cliui import (
    COMMANDS,
    REGISTRY,
    Session,
    completions,
    composer_rule,
    parse_input,
    run_session,
)


class TTYBuffer(StringIO):
    def isatty(self) -> bool:
        return True


class InteractiveTests(unittest.TestCase):
    def test_registry_and_completion(self) -> None:
        self.assertEqual(len(COMMANDS), len(REGISTRY))
        self.assertEqual([c.name for c in completions("/do")], ["doctor"])
        self.assertEqual(completions("/scan arg"), [])
        self.assertIn("scan", [c.name for c in completions("/sc")])

    def test_composer_rules_fit_and_support_ascii(self) -> None:
        for width in (30, 40, 80, 120):
            self.assertEqual(composer_rule(width, "utf-8"), "â”€" * (width - 1))
            self.assertEqual(composer_rule(width, "ascii"), "-" * (width - 1))

    def test_parse_quotes_and_windows_paths(self) -> None:
        self.assertEqual(
            parse_input('/scan "C:\\My Projects\\Firmware"'), ["/scan", "C:\\My Projects\\Firmware"]
        )
        self.assertEqual(parse_input("/scan 'a b/Âµ'"), ["/scan", "a b/Âµ"])
        with self.assertRaises(ValueError):
            parse_input('/scan "unfinished')

    def test_session_commands_and_dispatch(self) -> None:
        calls = []

        def dispatch(argv, **kwargs):
            calls.append(argv)
            return 0

        with tempfile.TemporaryDirectory() as directory, redirect_stdout(StringIO()) as output:
            session = Session(Path(directory))
            self.assertTrue(session.execute("", dispatch))
            session.execute("/unknown", dispatch)
            self.assertIn("Unknown command", output.getvalue())
            session.execute('/target "' + directory + '"', dispatch)
            self.assertEqual(session.target, Path(directory).resolve())
            session.execute("/target missing-directory", dispatch)
            self.assertEqual(session.target, Path(directory).resolve())
            session.execute("/profile esp-idf", dispatch)
            session.execute("/scan", dispatch)
            session.execute("/plan .", dispatch)
            session.execute("/doctor", dispatch)
            self.assertEqual(
                calls,
                [
                    ["scan", str(session.target), "--profile", "esp-idf"],
                    ["scan", ".", "--profile", "esp-idf", "--plan"],
                    ["doctor"],
                ],
            )
            self.assertFalse(session.execute("/exit", dispatch))

    def test_result_callback_and_findings_without_rescan(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory)
            (target / "sample.py").write_text('print("hello")\n', encoding="utf-8")
            session = Session(target)
            with redirect_stdout(StringIO()):
                code = main(
                    ["scan", str(target)], _show_banner=False, _result_callback=session.save_result
                )
            self.assertIn(code, (0, 2))
            self.assertIsNotNone(session.result)
            with redirect_stdout(StringIO()) as output:
                session.execute("/findings", lambda *args, **kwargs: self.fail("rescanned"))
            self.assertIn("findings", output.getvalue())

    def test_interactive_scan_shows_summary_and_report_paths(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory)
            (target / "device.py").write_text('password = "device-value-123"\n', encoding="utf-8")
            session = Session(target)
            with redirect_stdout(StringIO()) as output, redirect_stderr(StringIO()):
                session.execute("/scan", main)
            text = output.getvalue()
            self.assertIn("Reconnoitering project files", text)
            self.assertIn("1 findings to review", text)
            self.assertIn(str(target.resolve() / ".fuse-results" / "findings.txt"), text)
            self.assertNotIn("Potential impact:", text)
            self.assertTrue((target / ".fuse-results" / "findings.json").is_file())

    def test_incomplete_scan_is_not_presented_as_clean(self) -> None:
        from dataclasses import replace
        from vigil_fuse.scanner import scan

        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory)
            (target / "device.py").write_text("print(1)\n", encoding="utf-8")
            result = replace(scan(target), discovery_complete=False)
            with redirect_stdout(StringIO()) as output:
                Session(target).save_result(result, None)
            self.assertIn("review incomplete coverage", output.getvalue())
            self.assertIn("Some analysis was incomplete", output.getvalue())

    def test_scan_progress_stops_on_error(self) -> None:
        from vigil_fuse.cliui import ScanProgress

        with patch.dict("os.environ", {"TERM": "xterm"}), redirect_stdout(TTYBuffer()) as output:
            with self.assertRaises(RuntimeError), ScanProgress():
                raise RuntimeError("failed")
        self.assertIn("\r", output.getvalue())

    def test_narrow_footer_clear_and_exit(self) -> None:
        session = Session(Path("a-very-long-target-name-for-testing"))
        for width in (30, 40, 80, 120):
            self.assertLessEqual(len(session.footer(width)), width)
        with (
            patch("vigil_fuse.cliui.sys.stdout", TTYBuffer()) as output,
            patch.dict("os.environ", {"TERM": "xterm"}),
        ):
            if os.name == "nt":
                with patch("vigil_fuse.cliui.os.system", return_value=0) as clear:
                    session.execute("/clear", lambda *a, **k: 0)
                clear.assert_called_once_with("cls")
                self.assertEqual(output.getvalue(), "")
            else:
                session.execute("/clear", lambda *a, **k: 0)
                self.assertIn("\x1b[2J", output.getvalue())

    def test_windows_clear_works_without_ansi_term_support(self) -> None:
        session = Session(Path.cwd())
        with (
            patch("vigil_fuse.cliui.sys.stdout", TTYBuffer()) as output,
            patch("vigil_fuse.cliui.os.name", "nt"),
            patch("vigil_fuse.cliui.os.system", return_value=0) as clear,
            patch.dict("os.environ", {"TERM": "dumb"}),
        ):
            session.execute("/clear", lambda *a, **k: 0)
        clear.assert_called_once_with("cls")
        self.assertEqual(output.getvalue(), "")

    def test_dispatch_restores_interrupt_handler_on_error(self) -> None:
        import signal

        session = Session(Path.cwd())
        before = signal.getsignal(signal.SIGINT)
        with redirect_stdout(StringIO()):
            session.execute("/doctor --bad-option", main)
        self.assertIs(signal.getsignal(signal.SIGINT), before)
        self.assertEqual(session.last_result, "exit 2")

    def test_invalid_input_does_not_dispatch(self) -> None:
        session = Session(Path.cwd())
        with redirect_stdout(StringIO()) as output:
            session.execute('/scan "unterminated', lambda *a, **k: self.fail("dispatched"))
            session.execute("/profile missing", lambda *a, **k: self.fail("dispatched"))
        self.assertIn("Unclosed quote", output.getvalue())
        self.assertIn("Choose a profile", output.getvalue())

    def test_eof_and_interrupt(self) -> None:
        with (
            patch.dict("os.environ", {"TERM": "dumb"}),
            patch("builtins.input", side_effect=[KeyboardInterrupt, EOFError]),
            redirect_stdout(StringIO()) as output,
        ):
            self.assertEqual(run_session(lambda *a, **k: 0), 0)
            self.assertIn("Cancelled.", output.getvalue())

    def test_no_argument_tty_launch_shows_banner(self) -> None:
        with (
            patch("vigil_fuse.cli.sys.stdin", TTYBuffer()),
            patch("vigil_fuse.cli.sys.stdout", TTYBuffer()),
            patch("vigil_fuse.cli.sys.stderr", TTYBuffer()),
            patch("vigil_fuse.cli.show_banner") as banner,
            patch("vigil_fuse.cli._interactive_shell", return_value=0) as launch,
        ):
            self.assertEqual(main([]), 0)
            banner.assert_called_once_with()
            launch.assert_called_once_with()

    def test_non_tty_shows_help(self) -> None:
        with patch("vigil_fuse.cli.sys.stdin", StringIO()), redirect_stdout(StringIO()) as output:
            self.assertEqual(main([]), 0)
            self.assertIn("usage:", output.getvalue())


if __name__ == "__main__":
    unittest.main()
