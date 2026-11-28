"""Reject filesystem aliases and write outputs without mutating existing inodes."""

from __future__ import annotations

import errno
import os
import stat
import tempfile
from pathlib import Path

_FILE_ATTRIBUTE_REPARSE_POINT = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)


def _absolute(path: Path) -> Path:
    return Path(os.path.abspath(os.fspath(Path(path).expanduser())))


def _is_alias(info: os.stat_result) -> bool:
    return stat.S_ISLNK(info.st_mode) or bool(
        getattr(info, "st_file_attributes", 0) & _FILE_ATTRIBUTE_REPARSE_POINT
    )


def is_path_alias(path: Path) -> bool:
    """Return true for symlinks, junctions, mount points, and other reparse points."""
    try:
        info = os.lstat(path)
    except FileNotFoundError:
        return False
    except OSError:
        return True
    return _is_alias(info)


def _path_prefixes(path: Path) -> list[Path]:
    prefixes: list[Path] = []
    cursor = path
    while True:
        prefixes.append(cursor)
        if cursor == cursor.parent:
            break
        cursor = cursor.parent
    return list(reversed(prefixes))


def assert_no_path_aliases(path: Path, *, allow_missing: bool = False) -> Path:
    """Reject aliases in every existing component without resolving through them."""
    absolute = _absolute(path)
    prefixes = _path_prefixes(absolute)
    for index, prefix in enumerate(prefixes):
        try:
            info = os.lstat(prefix)
        except FileNotFoundError:
            if allow_missing:
                continue
            raise
        if _is_alias(info):
            raise ValueError(f"Path contains a symbolic link or reparse point: {prefix}")
        if index < len(prefixes) - 1 and not stat.S_ISDIR(info.st_mode):
            raise NotADirectoryError(f"Path parent is not a directory: {prefix}")
    return absolute


def ensure_safe_directory(path: Path) -> Path:
    """Create a directory tree one component at a time, rejecting aliases."""
    absolute = _absolute(path)
    prefixes = _path_prefixes(absolute)
    for prefix in prefixes:
        try:
            info = os.lstat(prefix)
        except FileNotFoundError:
            try:
                prefix.mkdir()
            except FileExistsError:
                pass
            info = os.lstat(prefix)
        if _is_alias(info):
            raise ValueError(f"Directory contains a symbolic link or reparse point: {prefix}")
        if not stat.S_ISDIR(info.st_mode):
            raise NotADirectoryError(f"Output parent is not a directory: {prefix}")
    return absolute


def _validate_output_file(path: Path) -> None:
    try:
        info = os.lstat(path)
    except FileNotFoundError:
        return
    if _is_alias(info):
        raise OSError(errno.ELOOP, "Refusing to replace a symbolic link or reparse point", path)
    if not stat.S_ISREG(info.st_mode):
        raise OSError(errno.EINVAL, "Output path is not a regular file", path)
    if info.st_nlink > 1:
        raise OSError(errno.EMLINK, "Refusing to overwrite a hard-linked output file", path)


def safe_write_bytes(path: Path, content: bytes) -> Path:
    """Write complete content to a new sibling, then atomically replace the output."""
    requested = Path(path).expanduser()
    if not requested.name:
        raise ValueError("Output path must name a file")
    parent = ensure_safe_directory(requested.parent)
    destination = parent / requested.name
    _validate_output_file(destination)

    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{destination.name}.", suffix=".tmp", dir=parent
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as output:
            output.write(content)
            output.flush()
            os.fsync(output.fileno())
        assert_no_path_aliases(parent)
        _validate_output_file(destination)
        os.replace(temporary, destination)
        return destination
    finally:
        temporary.unlink(missing_ok=True)


def safe_write_text(path: Path, content: str, *, encoding: str = "utf-8") -> Path:
    """Write text through the same alias-safe atomic replacement path."""
    return safe_write_bytes(path, content.encode(encoding))


def resolve_inside_directory(root: Path, candidate: Path) -> tuple[Path, str]:
    """Return a canonical in-root path, rejecting aliases that escape the root."""
    assert_no_path_aliases(root)
    root_path = root.resolve(strict=True)
    supplied = Path(candidate).expanduser()
    if ".." in supplied.parts:
        raise ValueError("path contains a parent traversal segment")
    lexical = supplied if supplied.is_absolute() else root_path / supplied
    lexical = _absolute(lexical)
    had_alias = any(is_path_alias(prefix) for prefix in _path_prefixes(lexical))
    try:
        canonical = lexical.resolve(strict=False)
    except (OSError, RuntimeError) as error:
        raise ValueError("path contains a symbolic link or reparse point") from error
    try:
        relative = canonical.relative_to(root_path)
    except ValueError as error:
        if had_alias:
            raise ValueError(
                "path contains a symbolic link or reparse point that escapes the selected directory"
            ) from error
        raise ValueError("path is outside the selected directory") from error
    return root_path / relative, relative.as_posix() or "."
