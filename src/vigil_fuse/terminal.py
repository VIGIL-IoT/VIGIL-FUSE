from __future__ import annotations

import os
import shutil
import sys

from . import __version__

_UNICODE_MARK = (
    "███████╗ ██╗   ██╗ ███████╗ ███████╗",
    "██╔════╝ ██║   ██║ ██╔════╝ ██╔════╝",
    "█████╗   ██║   ██║ ███████╗ █████╗",
    "██╔══╝   ██║   ██║ ╚════██║ ██╔══╝",
    "██║      ╚██████╔╝ ███████║ ███████╗",
    "╚═╝       ╚═════╝  ╚══════╝ ╚══════╝",
)
_ASCII_MARK = (
    "FFFFFF   U   U   SSSSS   EEEEEE",
    "F        U   U  S        E",
    "FFFFF    U   U   SSSS    EEEEE",
    "F        U   U      S    E",
    "F         UUU   SSSSS   EEEEEE",
)


def supports_color() -> bool:
    return (
        sys.stdout.isatty()
        and sys.stderr.isatty()
        and "NO_COLOR" not in os.environ
        and os.environ.get("TERM") != "dumb"
    )


def show_banner() -> None:
    """Render the startup identity without changing the terminal background."""
    if not sys.stdout.isatty() or not sys.stderr.isatty():
        return
    width = shutil.get_terminal_size(fallback=(80, 24)).columns
    encoding = sys.stderr.encoding or "ascii"
    try:
        "".join(_UNICODE_MARK).encode(encoding)
        mark: tuple[str, ...] = _UNICODE_MARK
    except (LookupError, UnicodeEncodeError):
        mark = _ASCII_MARK
    accent, foreground, muted, reset = (
        ("\033[38;2;203;166;247m", "\033[38;2;205;214;244m", "\033[38;2;147;153;178m", "\033[0m")
        if supports_color()
        else ("", "", "", "")
    )
    compact = width < 44
    lines = [f"{accent}{'FUSE' if compact else chr(10).join('  ' + line for line in mark)}{reset}"]
    if width >= 34:
        lines.append(f"{foreground}Firmware & Unified Security Engine{reset}")
    else:
        lines.extend(
            [f"{foreground}Firmware & Unified{reset}", f"{foreground}Security Engine{reset}"]
        )
    if width >= 36:
        lines.append(f"{muted}Static evidence. Explicit coverage.{reset}")
    lines.append(f"{muted}A VIGIL Project | v{__version__}{reset}")
    print("\n".join(lines), file=sys.stderr)
