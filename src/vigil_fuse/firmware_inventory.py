from __future__ import annotations

import fnmatch
import os
import time
from collections import Counter
from pathlib import Path

from .model import FirmwareCandidate, FirmwareCandidateInventory
from .text_safety import safe_report_text

FIRMWARE_EXTENSIONS = frozenset({
    ".bin", ".dfu", ".elf", ".hex", ".img", ".mot", ".ota", ".rom", ".srec", ".uf2", ".fw",
    ".bin.gz", ".elf.gz", ".hex.gz", ".ota.gz", ".uf2.gz",
})
SKIP_DIRECTORY_NAMES = frozenset({
    ".git", ".hg", ".svn", ".venv", "venv", "node_modules", "__pycache__", ".tox",
    ".mypy_cache", ".pytest_cache", ".fuse-results", "fuse-results",
})
MAX_REPORTED_CANDIDATES = 500


def _firmware_extension(path: Path) -> str:
    name = path.name.casefold()
    for extension in sorted(FIRMWARE_EXTENSIONS, key=len, reverse=True):
        if name.endswith(extension):
            return extension
    return path.suffix.casefold()


def inspect_firmware_candidates(
    target: Path,
    *,
    exclude: tuple[str, ...] = (),
    deadline: float,
    max_paths: int,
    max_directories: int,
) -> FirmwareCandidateInventory:
    """Inventory firmware-like extensions and sizes only. Never opens binary contents."""
    if target.is_file():
        extension = _firmware_extension(target)
        if extension not in FIRMWARE_EXTENSIONS:
            return FirmwareCandidateInventory(scope="single-file")
        try:
            size = target.stat().st_size
        except OSError:
            return FirmwareCandidateInventory(
                status="partial",
                scope="single-file",
                limitations=("The selected file size could not be read.",),
            )
        return FirmwareCandidateInventory(
            status="complete",
            scope="single-file",
            candidate_count=1,
            extension_counts={extension: 1},
            candidates=(FirmwareCandidate(target.name, extension.lstrip("."), size),),
        )
    if not target.is_dir():
        return FirmwareCandidateInventory(scope="directory")

    counts: Counter[str] = Counter()
    candidates: list[FirmwareCandidate] = []
    limitations: list[str] = []
    paths_seen = 0
    directories_seen = 0
    complete = True

    def on_error(_: OSError) -> None:
        nonlocal complete
        complete = False
        limitations.append("One or more directories could not be inventoried.")

    for directory, names, filenames in os.walk(target, topdown=True, followlinks=False, onerror=on_error):
        directories_seen += 1
        if directories_seen > max_directories or time.monotonic() >= deadline:
            complete = False
            limitations.append("Firmware candidate inventory reached a directory or time limit.")
            break
        current = Path(directory)
        kept: list[str] = []
        for name in names:
            child = current / name
            if child.is_symlink():
                continue
            if name.casefold() in SKIP_DIRECTORY_NAMES:
                continue
            kept.append(name)
        names[:] = sorted(kept)
        for filename in sorted(filenames):
            paths_seen += 1
            if paths_seen > max_paths or time.monotonic() >= deadline:
                complete = False
                limitations.append("Firmware candidate inventory reached a path or time limit.")
                break
            path = current / filename
            if path.is_symlink() or not path.is_file():
                continue
            relative = path.relative_to(target).as_posix()
            if any(fnmatch.fnmatchcase(relative, pattern) for pattern in exclude):
                continue
            extension = _firmware_extension(path)
            if extension not in FIRMWARE_EXTENSIONS:
                continue
            counts[extension] += 1
            if len(candidates) < MAX_REPORTED_CANDIDATES:
                try:
                    size = path.stat().st_size
                except OSError:
                    complete = False
                    limitations.append(f"The candidate size could not be read for {relative}.")
                    continue
                candidates.append(
                    FirmwareCandidate(
                        path=safe_report_text(relative, limit=1000) or "unknown-path",
                        format=extension.lstrip("."),
                        byte_size=size,
                    )
                )
        if not complete:
            break

    count_total = sum(counts.values())
    omitted = max(0, count_total - len(candidates))
    if omitted:
        limitations.append(f"The path list is capped at {MAX_REPORTED_CANDIDATES} entries; extension counts include all discovered candidates.")
    return FirmwareCandidateInventory(
        status="complete" if complete else "partial",
        scope="bounded filename and size inventory across source and common output directories",
        candidate_count=count_total,
        extension_counts=dict(sorted(counts.items())),
        candidates=tuple(candidates),
        omitted_count=omitted,
        limitations=tuple(dict.fromkeys(limitations)),
    )
