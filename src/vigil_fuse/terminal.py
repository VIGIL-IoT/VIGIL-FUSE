from __future__ import annotations

import os
import sys

from . import __version__


def show_banner() -> None:
    """Show the FUSE wordmark on an interactive terminal."""
    if not sys.stderr.isatty():
        return

    red = ""
    reset = ""
    if "NO_COLOR" not in os.environ:
        red = "\033[38;2;217;43;33m"
        reset = "\033[0m"

    print(
        f"{red}  FFFFF   U   U   SSSSS  EEEEE\n"
        "  F       U   U  S       E\n"
        "  FFFF    U   U   SSSS   EEEE\n"
        "  F       U   U      S  E\n"
        f"  F        UUU   SSSSS  EEEEE{reset}\n"
        f"  Firmware & Unified Security Engine\n"
        f"  A VIGIL Project  |  v{__version__}",
        file=sys.stderr,
    )
