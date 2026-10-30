"""Resolve paths inside a selected project while refusing symlink traversal."""

from __future__ import annotations

import os
from pathlib import Path


def resolve_inside_directory(root: Path, candidate: Path) -> tuple[Path, str]:
    """Return a canonical in-root path and relative label without following links.

    ``samefile`` identifies the target directory even when the operating system
    exposes it through an alias, such as macOS' ``/var`` path or a Windows 8.3
    short name. The lexical suffix is checked for symlinks before returning the
    canonical path, so an alias to the root does not weaken in-target link checks.
    The caller remains responsible for requiring the final path to exist and to
    have the expected file type.
    """
    root_path = root.resolve(strict=True)
    supplied = Path(candidate).expanduser()
    if ".." in supplied.parts:
        raise ValueError("path contains a parent traversal segment")
    lexical = supplied if supplied.is_absolute() else root_path / supplied
    lexical = Path(os.path.abspath(lexical))

    cursor = lexical
    suffix: list[str] = []
    while True:
        try:
            matches_root = os.path.samefile(cursor, root_path)
        except OSError:
            matches_root = False
        if matches_root:
            if cursor.is_symlink():
                raise ValueError("path passes through a symbolic link")
            break
        if cursor == cursor.parent:
            raise ValueError("path is outside the selected directory")
        suffix.append(cursor.name)
        cursor = cursor.parent

    relative = Path(*reversed(suffix)) if suffix else Path()
    checked = cursor
    for part in relative.parts:
        if part in {"", "."}:
            continue
        checked = checked / part
        if checked.is_symlink():
            raise ValueError("path passes through a symbolic link")

    resolved = root_path / relative
    return resolved, relative.as_posix() or "."
