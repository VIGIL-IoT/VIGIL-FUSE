from __future__ import annotations

import os
import sys

from . import __version__


def show_banner() -> None:
    """Show a small original FUSE circuit illustration on an interactive terminal."""
    if not sys.stderr.isatty():
        return

    red = ""
    reset = ""
    if "NO_COLOR" not in os.environ:
        red = "\033[38;2;217;43;33m"
        reset = "\033[0m"

    print(
        f"{red}      +-----+   +-----+   +-----+   +-----+\n"
        "      |  F  |---|  U  |---|  S  |---|  E  |\n"
        "      +--+--+   +--+--+   +--+--+   +--+--+\n"
        f"         firmware  ->  security evidence{reset}\n"
        f"  FUSE {__version__}  |  Firmware & Unified Security Engine\n"
        "  A VIGIL Project",
        file=sys.stderr,
    )
