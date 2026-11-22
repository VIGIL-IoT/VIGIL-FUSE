"""Interactive adapter for the existing FUSE command line."""

from __future__ import annotations

from dataclasses import dataclass
import os
import signal
from pathlib import Path
import shutil
import sys
import threading
from typing import Callable

from .. import __version__
from ..model import ScanResult
from ..profiles import PROFILES
from ..text_safety import safe_terminal_text


@dataclass(frozen=True)
class Command:
    name: str
    group: str
    usage: str
    description: str


COMMANDS = (
    Command("scan", "Scanning", "[target] [options]", "Scan a target"),
    Command("plan", "Scanning", "[target] [options]", "Preview scan stages"),
    Command("profile", "Scanning", "[name]", "Show or select a profile"),
    Command("sbom", "Analysis", "[target] [options]", "Scan with SBOM generation"),
    Command(
        "vulnerabilities", "Analysis", "[target] [options]", "Scan dependencies for vulnerabilities"
    ),
    Command("firmware", "Analysis", "<image> [options]", "Scan a firmware image"),
    Command("ghidra", "Analysis", "<binary> [options]", "Analyze one binary with Ghidra"),
    Command("findings", "Review", "", "Review the latest scan findings"),
    Command("baseline", "Review", "<action> [options]", "Run a baseline command"),
    Command("target", "Session", "[directory]", "Show or change the current target"),
    Command("status", "Session", "", "Show session status"),
    Command("doctor", "Session", "[options]", "Check analyzer availability"),
    Command("tools", "Session", "", "Check analyzer availability"),
    Command("clear", "Session", "", "Clear the terminal"),
    Command("version", "Session", "", "Show the FUSE version"),
    Command("help", "Session", "", "Show commands"),
    Command("exit", "Session", "", "Exit the session"),
)
REGISTRY = {command.name: command for command in COMMANDS}

_SCAN_THOUGHTS = (
    "Reconnoitering",
    "Snooping",
    "Enumerating",
    "Poking",
    "Scrutinizing",
    "Sideeyeing",
    "Sifting",
    "Judging",
    "Parsing",
    "Snitching",
    "Fingerprinting",
    "Roasting",
    "Dissecting",
    "Overthinking",
    "Correlating",
    "Grilling",
    "Auditing",
    "Hexorcising",
    "Synthesizing",
    "Panicking",
    "Asking the bits what they saw",
    "Giving config files the side-eye",
    "Separating risky from just weird",
    "Reading the firmware tea leaves",
    "Checking the usual hiding spots",
    "Interrogating suspicious strings",
    "Counting findings, not vibes",
    "Politely asking code to explain itself",
)


def parse_input(line: str) -> list[str]:
    """Split quotes without interpreting Windows backslashes as escapes."""
    words: list[str] = []
    word: list[str] = []
    quote = ""
    started = False
    for char in line:
        if quote:
            if char == quote:
                quote = ""
            else:
                word.append(char)
        elif char in "\"'":
            quote = char
            started = True
        elif char.isspace():
            if started:
                words.append("".join(word))
                word = []
                started = False
        else:
            word.append(char)
            started = True
    if quote:
        raise ValueError("Unclosed quote")
    if started:
        words.append("".join(word))
    return words


def completions(text: str) -> list[Command]:
    if not text.startswith("/") or any(char.isspace() for char in text):
        return []
    return [command for command in COMMANDS if command.name.startswith(text[1:].lower())]


def composer_rule(width: int, encoding: str) -> str:
    try:
        "â”€".encode(encoding)
        character = "â”€"
    except (UnicodeEncodeError, LookupError):
        character = "-"
    return character * max(width - 1, 0)


def _print(value: object = "") -> None:
    text = safe_terminal_text(str(value))
    encoding = sys.stdout.encoding
    if encoding:
        text = text.encode(encoding, errors="backslashreplace").decode(encoding)
    print(text)


class ScanProgress:
    """Animate playful status copy while scan analysis runs."""

    def __init__(self, optional: bool = False) -> None:
        self.optional = optional

    def __enter__(self) -> ScanProgress:
        self.stop = threading.Event()
        self.animated = sys.stdout.isatty() and os.environ.get("TERM") != "dumb"
        if self.animated:
            self.thread = threading.Thread(target=self._animate, daemon=True)
            self.thread.start()
        else:
            _print(
                "Running requested optional analysis..."
                if self.optional
                else "Reconnoitering project files and checking security rules..."
            )
        return self

    def _animate(self) -> None:
        frames = "|/-\\"
        messages = (
            ("Consulting optional tools", "Seeing what the extras found", "Waiting on the helpers")
            if self.optional
            else _SCAN_THOUGHTS
        )
        tick = 0
        while not self.stop.is_set():
            text = f"\r  {frames[tick % len(frames)]} {messages[(tick // 12) % len(messages)]}..."
            sys.stdout.write(text.ljust(64))
            sys.stdout.flush()
            tick += 1
            self.stop.wait(0.1)

    def __exit__(self, *args: object) -> None:
        self.stop.set()
        if self.animated:
            self.thread.join()
            sys.stdout.write("\r" + " " * 64 + "\r")
            sys.stdout.flush()


def present_scan_result(result: ScanResult, output: Path | None) -> None:
    incomplete = (
        not result.analysis_performed
        or not result.discovery_complete
        or bool(result.files_skipped or result.limits_reached)
        or any(
            item.status in {"partial", "failed", "timeout", "unavailable", "incompatible"}
            for item in result.analyzers
        )
    )
    _print("\nScan finished" + (" - review incomplete coverage" if incomplete else ""))
    _print(f"  {result.files_scanned} files checked, {len(result.findings)} findings to review")
    if result.findings:
        counts = {
            level: sum(f.severity == level for f in result.findings)
            for level in ("critical", "high", "medium", "low", "info")
        }
        _print(
            "  Severity: "
            + ", ".join(f"{count} {level}" for level, count in counts.items() if count)
        )
    _print("  Findings are security signals, not confirmed exploits. Use /findings to review them.")
    if incomplete:
        _print("  Some analysis was incomplete. Check the report coverage section for details.")
    if output is not None:
        if output.is_dir():
            _print("  Reports saved:")
            for name in ("findings.txt", "findings.json", "findings.sarif"):
                _print(f"    {output / name}")
        else:
            _print(f"  Report saved: {output}")


@dataclass
class Session:
    target: Path
    profile: str | None = None
    last_action: str | None = None
    last_result: str | None = None
    result: ScanResult | None = None
    output: Path | None = None

    def save_result(self, result: ScanResult, output: Path | None) -> None:
        self.result = result
        self.output = output
        present_scan_result(result, output)

    def footer(self, width: int) -> str:
        name = safe_terminal_text(self.target.name or str(self.target))
        suffix = f" | profile: {self.profile or 'config'} | ready"
        prefix = "target: "
        if len(prefix) + len(name) + len(suffix) > width:
            suffix = " | ready"
        available = max(0, width - len(prefix) - len(suffix))
        if len(name) > available:
            name = ("..." + name[-(available - 3) :]) if available > 3 else name[:available]
        return (prefix + name + suffix)[:width]

    def help(self) -> None:
        previous = ""
        for command in COMMANDS:
            if command.group != previous:
                _print(f"\n{command.group}")
                previous = command.group
            label = f"/{command.name} {command.usage}".rstrip()
            _print(f"  {label}: {command.description}")

    def status(self) -> None:
        _print(
            f"FUSE {__version__}\nTarget: {self.target}\nProfile: {self.profile or 'config default'}"
        )
        if self.last_action:
            _print(f"Last action: {self.last_action}\nLast result: {self.last_result}")
        if self.result is not None:
            _print(f"Findings: {len(self.result.findings)}")
            _print(f"Scan profile: {self.result.profile}")
        if self.output is not None:
            _print(f"Output: {self.output}")

    def findings(self) -> None:
        if self.result is None:
            _print("No scan result in this session.")
            return
        _print(f"{len(self.result.findings)} findings")
        for finding in self.result.findings:
            location = (
                f"{finding.file}:{finding.start_line}" if finding.start_line else finding.file
            )
            _print(
                f"\n{finding.severity.upper()} / {finding.confidence} confidence\n"
                f"{finding.rule_id}: {finding.title}\n{location}\n"
                f"What this means: {finding.explanation}\n"
                f"What to do: {finding.remediation}"
            )

    def execute(self, line: str, dispatch: Callable[..., int]) -> bool:
        try:
            words = parse_input(line)
            if not words:
                return True
            name = words[0][1:].lower() if words[0].startswith("/") else ""
            if name not in REGISTRY:
                raise ValueError("Unknown command. Type /help for available commands.")
            args = words[1:]
            if name in {"help", "status", "findings", "clear", "version", "exit", "tools"} and args:
                raise ValueError(f"/{name} takes no arguments")
            if name == "exit":
                return False
            if name == "help":
                self.help()
            elif name == "status":
                self.status()
            elif name == "findings":
                self.findings()
            elif name == "version":
                _print(f"FUSE {__version__}")
            elif name == "clear":
                if sys.stdout.isatty() and (os.name == "nt" or os.environ.get("TERM") != "dumb"):
                    if os.name == "nt":
                        if os.system("cls") != 0:
                            _print("Clear failed in this terminal.")
                    else:
                        print("\033[2J\033[H", end="", flush=True)
                else:
                    _print("Clear is unavailable in this terminal.")
            elif name == "target":
                if len(args) > 1:
                    raise ValueError("Usage: /target [directory]")
                if args:
                    path = Path(args[0]).expanduser().resolve()
                    if not path.is_dir():
                        raise ValueError("Target must be an existing directory")
                    self.target = path
                _print(f"Target: {self.target}")
            elif name == "profile":
                if len(args) > 1 or (args and args[0] not in PROFILES):
                    raise ValueError("Choose a profile: " + ", ".join(PROFILES))
                if args:
                    self.profile = args[0]
                _print(f"Profile: {self.profile or 'config default'}")
                if not args:
                    _print("Available: " + ", ".join(PROFILES))
            else:
                argv: list[str]
                if name in {"doctor", "tools", "baseline"}:
                    argv = ["doctor" if name == "tools" else name, *args]
                else:
                    if name in {"firmware", "ghidra"} and (not args or args[0].startswith("-")):
                        raise ValueError(f"/{name} requires an input file")
                    target = (
                        args.pop(0) if args and not args[0].startswith("-") else str(self.target)
                    )
                    argv = ["scan", target, *args]
                    if (
                        self.profile
                        and "--profile" not in args
                        and not any(arg.startswith("--profile=") for arg in args)
                    ):
                        argv.extend(["--profile", self.profile])
                    flag = {
                        "plan": "--plan",
                        "sbom": "--sbom",
                        "vulnerabilities": "--vulnerabilities",
                        "firmware": "--firmware",
                        "ghidra": "--ghidra",
                    }.get(name)
                    if flag:
                        argv.append(flag)
                self.last_action = name
                self.last_result = "running"
                # Avoid interrupting analyzer workers whose cleanup may still be in progress.
                previous_handler = signal.signal(signal.SIGINT, signal.SIG_IGN)
                try:
                    try:
                        code = dispatch(
                            argv,
                            _show_banner=False,
                            _result_callback=self.save_result,
                            _interactive_scan=argv[0] == "scan" and name != "plan",
                        )
                    except SystemExit as error:
                        code = error.code if isinstance(error.code, int) else 2
                finally:
                    signal.signal(signal.SIGINT, previous_handler)
                self.last_result = "completed" if code == 0 else f"exit {code}"
        except (ValueError, OSError) as error:
            _print(f"Error: {error}")
        return True


def run_session(dispatch: Callable[..., int]) -> int:
    session = Session(Path.cwd())
    _print(f"Current target: {session.target}")
    _print("Type /help for commands.")
    use_prompt = False
    try:
        if os.environ.get("TERM") == "dumb":
            raise ImportError
        from prompt_toolkit import PromptSession
        from prompt_toolkit.completion import Completer, Completion
        from prompt_toolkit.history import InMemoryHistory
        from prompt_toolkit.output import ColorDepth

        class CommandHistory(InMemoryHistory):
            def append_string(self, string: str) -> None:
                # Keep paths and option values out of history.
                name = string.strip().split(maxsplit=1)[0] if string.strip() else ""
                if name.startswith("/") and name[1:].lower() in REGISTRY:
                    super().append_string(name)

        class CommandCompleter(Completer):
            def get_completions(self, document, complete_event):  # type: ignore[no-untyped-def]
                text = document.text_before_cursor
                for command in completions(text):
                    yield Completion(
                        "/" + command.name,
                        start_position=-len(text),
                        display_meta=command.description,
                    )

        prompt: PromptSession[str] = PromptSession(
            history=CommandHistory(), completer=CommandCompleter(), complete_while_typing=True
        )
        use_prompt = True
    except ImportError:
        _print("Basic input mode; install vigil-fuse[cliui] for completion and command history.")
    while True:
        try:
            if not use_prompt:
                _print(session.footer(shutil.get_terminal_size((80, 24)).columns))
            line = (
                prompt.prompt(
                    lambda: [
                        (
                            "fg:#ef4444",
                            composer_rule(
                                shutil.get_terminal_size((80, 24)).columns,
                                sys.stdout.encoding or "ascii",
                            ),
                        ),
                        ("", "\n> "),
                    ],
                    color_depth=ColorDepth.DEPTH_1_BIT if "NO_COLOR" in os.environ else None,
                    bottom_toolbar=lambda: [
                        (
                            "fg:#3b82f6",
                            composer_rule(
                                shutil.get_terminal_size((80, 24)).columns,
                                sys.stdout.encoding or "ascii",
                            ),
                        ),
                        ("", "\n" + session.footer(shutil.get_terminal_size((80, 24)).columns - 1)),
                    ],
                )
                if use_prompt
                else input("> ")
            )
            if not session.execute(line, dispatch):
                return 0
        except EOFError:
            _print()
            return 0
        except KeyboardInterrupt:
            _print("\nCancelled.")
