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
        f"{red}  FFFFFF   U   U   SSSSS   EEEEEE\n"
        "  F        U   U  S        E\n"
        "  FFFFF    U   U   SSSS    EEEEE\n"
        "  F        U   U      S    E\n"
        "  F         UUU   SSSSS   EEEEEE\n"
        f"  ----------------------------------{reset}\n"
        f"  Firmware & Unified Security Engine\n"
        f"  A VIGIL Project  |  v{__version__}",
        file=sys.stderr,
    )
