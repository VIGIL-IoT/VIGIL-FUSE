from __future__ import annotations

import os
from pathlib import Path

MANAGED_TOOL_IDS = frozenset({"syft", "osv-scanner", "gitleaks"})


def managed_tool_directory() -> Path:
    override = os.environ.get("VIGIL_FUSE_TOOLS_DIR")
    if override:
        return Path(override).expanduser()
    if os.name == "nt":
        root = os.environ.get("LOCALAPPDATA")
        return (
            Path(root).expanduser() / "Vigil-FUSE" / "Tools"
            if root
            else Path.home() / "AppData" / "Local" / "Vigil-FUSE" / "Tools"
        )
    root = os.environ.get("XDG_DATA_HOME")
    return (
        (Path(root).expanduser() if root else Path.home() / ".local" / "share")
        / "vigil-fuse"
        / "tools"
    )


def resolve_managed_tool(name: str) -> str | None:
    if name not in MANAGED_TOOL_IDS:
        return None
    executable = name if os.name != "nt" or name.endswith(".exe") else f"{name}.exe"
    path = managed_tool_directory() / executable
    return str(path) if path.is_file() and not path.is_symlink() else None
