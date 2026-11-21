from __future__ import annotations

import os
import shutil
import sys
from collections.abc import Iterable

from . import __version__

# Skew each row to the right toward the top to give the block-art letters
# an italic appearance. This remains portable terminal text rather than
# relying on ANSI italic, which most terminals do not apply to box glyphs.
_UNICODE_MARK = (
    "     ███████╗██╗   ██╗███████╗███████╗",
    "    ██╔════╝██║   ██║██╔════╝██╔════╝",
    "   █████╗  ██║   ██║███████╗█████╗  ",
    "  ██╔══╝  ██║   ██║╚════██║██╔══╝  ",
    " ██║     ╚██████╔╝███████║███████╗",
    "╚═╝      ╚═════╝ ╚══════╝╚══════╝",
)
_ASCII_MARK = (
    "    FFFFFF   U   U   SSSSS   EEEEEE",
    "   F        U   U  S        E",
    "  FFFFF    U   U   SSSS    EEEEE",
    " F        U   U      S    E",
    "F         UUU   SSSSS   EEEEEE",
)
_STOPS = ((220, 38, 38), (251, 113, 133), (167, 139, 250), (96, 165, 250), (55, 48, 255))
_RESET = "\033[0m"


def _letter_spaced_mark(mark: tuple[str, ...], gap: int) -> tuple[str, ...]:
    """Add breathing room between F / U / S / E without changing the glyphs."""
    result = []
    for row, line in enumerate(mark):
        skew = len(mark) - row - 1
        glyphs = line[skew:]
        # Fixed-width segments from the original 33-column FUSE block artwork.
        letters = (glyphs[:8], glyphs[8:17], glyphs[17:25], glyphs[25:])
        result.append(" " * skew + (" " * gap).join(letters))
    return tuple(result)


def supports_color() -> bool:
    return (
        sys.stdout.isatty()
        and sys.stderr.isatty()
        and "NO_COLOR" not in os.environ
        and os.environ.get("TERM") != "dumb"
    )


def _fg(hex_color: str, enabled: bool) -> str:
    if not enabled:
        return ""
    rgb = bytes.fromhex(hex_color.lstrip("#"))
    return f"\033[38;2;{rgb[0]};{rgb[1]};{rgb[2]}m"


def _paint(value: str, color: str, enabled: bool, *, bold: bool = False) -> str:
    if not enabled:
        return value
    return ("\033[1m" if bold else "") + _fg(color, True) + value + _RESET


def _gradient_line(line: str, enabled: bool, width: int) -> str:
    if not enabled:
        return line
    pieces = []
    last_rgb = None
    for x, char in enumerate(line):
        position = x / max(width - 1, 1) * (len(_STOPS) - 1)
        index = min(int(position), len(_STOPS) - 2)
        fraction = position - index
        a, b = _STOPS[index], _STOPS[index + 1]
        rgb = tuple(round(a[i] * (1 - fraction) + b[i] * fraction) for i in range(3))
        if rgb != last_rgb:
            pieces.append(f"\033[38;2;{rgb[0]};{rgb[1]};{rgb[2]}m")
            last_rgb = rgb
        pieces.append(char)
    pieces.append(_RESET)
    return "".join(pieces)


def show_banner() -> None:
    """Render a responsive, text-only welcome screen to stderr.

    Preserves the existing show_banner() API and non-TTY behavior.
    """
    if not sys.stdout.isatty() or not sys.stderr.isatty():
        return

    columns = shutil.get_terminal_size(fallback=(80, 24)).columns
    encoding = sys.stderr.encoding or "ascii"
    mark: tuple[str, ...]
    try:
        "".join(_UNICODE_MARK).encode(encoding)
        mark = _UNICODE_MARK
        unicode_ok = True
    except (LookupError, UnicodeEncodeError):
        mark = _ASCII_MARK
        unicode_ok = False

    # Keep the original italic pixel font, but separate the four letters.
    # On narrower terminals, use a one-cell gap so the logo still fits.
    if unicode_ok:
        mark = _letter_spaced_mark(mark, gap=2 if columns >= 50 else 1)

    color = supports_color()
    if columns < 40:
        lines = [
            _paint("FUSE by VIGIL", "#A78BFA", color, bold=True),
            _paint(f"v{__version__}  |  local security", "#94A3B8", color),
            _paint("Static evidence. Explicit coverage."[:columns], "#94A3B8", color),
        ]
        print("\n".join(lines) + "\n", file=sys.stderr)
        return

    # A clean, modern terminal frame. Width is bounded so the screen does not
    # become a full-width dashboard on large displays.
    inner = min(columns - 4, 68)
    frame_color = "#6065D9"
    rule = "─" if unicode_ok else "-"
    top_left, top_right, bottom_left, bottom_right, side = (
        ("╭", "╮", "╰", "╯", "│") if unicode_ok else ("+", "+", "+", "+", "|")
    )

    def frame(text: str = "", *, tint: str = "#CBD5E1") -> str:
        # Visible text only; never pass ANSI sequences into the width calculation.
        text = text[: inner - 4]
        left = (inner - len(text) - 2) // 2
        right = inner - len(text) - 2 - left
        return (
            _paint(side, frame_color, color)
            + " " * (left + 1)
            + _paint(text, tint, color)
            + " " * (right + 1)
            + _paint(side, frame_color, color)
        )

    lines = [""]
    lines.append(_paint(top_left + rule * inner + top_right, frame_color, color))
    lines.append(frame())

    logo_width = max(map(len, mark))
    if columns >= logo_width + 6:
        for art_line in mark:
            # Render logo without truncating or wrapping inside the frame.
            left = (inner - logo_width - 2) // 2
            right = inner - len(art_line) - 2 - left
            lines.append(
                _paint(side, frame_color, color)
                + " " * (left + 1)
                + _gradient_line(art_line, color, logo_width)
                + " " * (right + 1)
                + _paint(side, frame_color, color)
            )
    else:
        lines.append(frame("FUSE", tint="#A78BFA"))

    lines.extend(
        [
            frame(),
            frame("Firmware & Unified Security Engine", tint="#E2E8F0"),
            frame(
                f"A VIGIL Project   {'•' if unicode_ok else '|'}   v{__version__}",
                tint="#94A3B8",
            ),
            frame("Static evidence. Explicit coverage.", tint="#94A3B8"),
            frame(),
            _paint(bottom_left + rule * inner + bottom_right, frame_color, color),
            _paint("  LOCAL ANALYSIS  /  Type /help to begin", "#60A5FA", color),
            "",
        ]
    )
    print("\n".join(lines), file=sys.stderr)


def _unicode_available() -> bool:
    encoding = sys.stderr.encoding or "ascii"
    try:
        "".join(_UNICODE_MARK).encode(encoding)
        return True
    except (LookupError, UnicodeEncodeError):
        return False


def _rule(length: int, color: str, *, enabled: bool, unicode_ok: bool) -> str:
    character = "─" if unicode_ok else "-"
    return _paint(character * max(length, 1), color, enabled)


def show_prompt_top() -> None:
    """Draw the red upper rule (used by the plain-input fallback)."""
    width = max(10, shutil.get_terminal_size(fallback=(80, 24)).columns - 2)
    print(
        _rule(width, "#DC2626", enabled=supports_color(), unicode_ok=_unicode_available()),
        file=sys.stderr,
    )


def show_prompt_bottom() -> None:
    """Draw the blue lower rule (used by the plain-input fallback)."""
    width = max(10, shutil.get_terminal_size(fallback=(80, 24)).columns - 2)
    print(
        _rule(width, "#60A5FA", enabled=supports_color(), unicode_ok=_unicode_available()),
        file=sys.stderr,
    )


_PROMPT_HISTORY = None


def read_command(commands: Iterable[tuple[str, str]] = ()) -> str:
    """Read one command between red and blue rules, directly beside each other.

    prompt_toolkit's bottom_toolbar is deliberately not used here: it anchors
    to the *bottom of the terminal window*, not beneath the active input.
    The non-full-screen three-row layout keeps both rules next to the cursor.
    """
    if not sys.stdin.isatty() or not sys.stdout.isatty() or os.environ.get("TERM") == "dumb":
        return input("fuse > ")

    try:
        from prompt_toolkit.application import Application, get_app
        from prompt_toolkit.buffer import Buffer
        from prompt_toolkit.completion import Completer, Completion
        from prompt_toolkit.formatted_text import StyleAndTextTuples
        from prompt_toolkit.history import InMemoryHistory
        from prompt_toolkit.key_binding import KeyBindings
        from prompt_toolkit.key_binding.key_processor import KeyPressEvent
        from prompt_toolkit.layout import Dimension, HSplit, Layout, Window
        from prompt_toolkit.layout.controls import BufferControl, FormattedTextControl
        from prompt_toolkit.layout.processors import BeforeInput
        from prompt_toolkit.output import ColorDepth
    except ImportError:
        # The core scanner still works if the optional UI library is missing.
        show_prompt_top()
        command = input("❯ " if _unicode_available() else "> ")
        show_prompt_bottom()
        return command

    global _PROMPT_HISTORY
    if _PROMPT_HISTORY is None:
        _PROMPT_HISTORY = InMemoryHistory()

    command_list = tuple(commands)
    command_names = {name.casefold() for name, _ in command_list}

    class CommandCompleter(Completer):
        def get_completions(self, document, complete_event):  # type: ignore[no-untyped-def]
            text = document.text_before_cursor
            if not text.startswith("/") or any(char.isspace() for char in text):
                return
            prefix = text[1:].casefold()
            for name, description in command_list:
                if name.startswith(prefix):
                    yield Completion(
                        "/" + name,
                        start_position=-len(text),
                        display_meta=description,
                    )

    use_color = supports_color()
    red_style = "fg:#dc2626" if use_color else ""
    blue_style = "fg:#60a5fa" if use_color else ""
    cursor_style = "fg:#fb7185 bold" if use_color else ""
    text_style = "fg:#e2e8f0" if use_color else ""
    glyph = "─" if _unicode_available() else "-"
    prompt_symbol = "❯ " if _unicode_available() else "> "

    def line_fragments(style: str) -> StyleAndTextTuples:
        # Use the active prompt's width; adapt when Windows Terminal resizes.
        width = max(1, get_app().output.get_size().columns - 2)
        return [(style, glyph * width)]

    buffer = Buffer(multiline=False, history=_PROMPT_HISTORY)
    editor = Window(
        BufferControl(
            buffer=buffer,
            completer=CommandCompleter(),
            complete_while_typing=True,
            input_processors=[BeforeInput(prompt_symbol, style=cursor_style)],
        ),
        height=1,
        dont_extend_height=True,
        style=text_style,
    )
    layout = HSplit(
        [
            Window(
                FormattedTextControl(lambda: line_fragments(red_style)),
                height=1,
                dont_extend_height=True,
            ),
            editor,
            Window(
                FormattedTextControl(lambda: line_fragments(blue_style)),
                height=1,
                dont_extend_height=True,
            ),
        ],
        height=Dimension.exact(3),
    )

    keys = KeyBindings()

    @keys.add("enter")
    def accept(event: KeyPressEvent) -> None:
        command = buffer.text
        name = command.strip().split(maxsplit=1)[0] if command.strip() else ""
        if name.startswith("/") and name[1:].casefold() in command_names:
            _PROMPT_HISTORY.append_string(name)
        event.app.exit(result=command)

    @keys.add("c-c")
    def interrupt(event: KeyPressEvent) -> None:
        event.app.exit(exception=KeyboardInterrupt())

    @keys.add("c-d")
    def end_of_file(event: KeyPressEvent) -> None:
        if not buffer.text:
            event.app.exit(exception=EOFError())
        else:
            buffer.delete(1)

    app: Application[str] = Application(
        layout=Layout(layout, focused_element=editor),
        key_bindings=keys,
        full_screen=False,
        erase_when_done=False,
        color_depth=ColorDepth.TRUE_COLOR if use_color else ColorDepth.DEPTH_1_BIT,
    )
    return app.run()
