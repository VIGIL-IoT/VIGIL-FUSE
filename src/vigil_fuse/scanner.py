from __future__ import annotations

import fnmatch
import hashlib
import os
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from . import __version__
from .model import AnalyzerStatus, ScanResult, SourceFile
from .profiles import ScanProfile, get_profile
from .rules.registry import RULES

MAX_FILE_BYTES = 2 * 1024 * 1024
SKIPPED_DIRECTORIES = {
    ".git", ".hg", ".svn", ".venv", "venv", "node_modules", "build", "dist",
    "__pycache__", ".tox", ".mypy_cache", ".pytest_cache", ".fuse-results", "fuse-results",
}


def _timestamp() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _display_path(path: Path, base: Path) -> str:
    return path.name if path == base else path.relative_to(base).as_posix()


def _selected(path: Path, base: Path, include: tuple[str, ...], exclude: tuple[str, ...]) -> bool:
    rel = _display_path(path, base)
    if include and not any(fnmatch.fnmatchcase(rel, pattern) for pattern in include):
        return False
    return not any(fnmatch.fnmatchcase(rel, pattern) for pattern in exclude)


def _candidate_paths(
    target: Path,
    profile: ScanProfile,
    include: tuple[str, ...],
    exclude: tuple[str, ...],
) -> tuple[list[Path], int]:
    if target.is_file():
        discovered = [target] if profile.supports(target) else []
        return [p for p in discovered if _selected(p, target, include, exclude)], len(discovered)

    selected: list[Path] = []
    discovered_count = 0
    for directory, names, filenames in os.walk(target, topdown=True, followlinks=False):
        current = Path(directory)
        names[:] = sorted(
            name for name in names
            if name not in SKIPPED_DIRECTORIES and not (current / name).is_symlink()
        )
        for filename in sorted(filenames):
            path = current / filename
            if path.is_symlink() or not profile.supports(path):
                continue
            discovered_count += 1
            if _selected(path, target, include, exclude):
                selected.append(path)
    return selected, discovered_count


def _load_source(path: Path, base: Path, max_file_bytes: int) -> tuple[SourceFile | None, str | None]:
    try:
        with path.open("rb") as source:
            data = source.read(max_file_bytes + 1)
    except OSError:
        return None, "read_error"
    if len(data) > max_file_bytes:
        return None, "too_large"
    try:
        text = data.decode("utf-8-sig")
    except UnicodeDecodeError:
        return None, "not_utf8"
    if "\x00" in text:
        return None, "binary_or_nul"
    return SourceFile(
        path=_display_path(path, base),
        text=text,
        sha256=hashlib.sha256(data).hexdigest(),
    ), None


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def scan(
    target: str | Path = ".",
    *,
    profile: str = "generic",
    include: tuple[str, ...] = (),
    exclude: tuple[str, ...] = (),
    disabled_rules: tuple[str, ...] = (),
    max_file_bytes: int = MAX_FILE_BYTES,
    firmware_image: bool = False,
    sbom_input: bool = False,
) -> ScanResult:
    requested = Path(target).expanduser()
    if not requested.exists():
        raise FileNotFoundError(f"Target does not exist: {requested}")
    if not requested.is_file() and not requested.is_dir():
        raise ValueError(f"Target is not a file or directory: {requested}")
    if firmware_image and not requested.is_file():
        raise ValueError("--firmware requires a single firmware image file")
    if sbom_input and not requested.is_file():
        raise ValueError("SBOM input must be a single file")
    if firmware_image and sbom_input:
        raise ValueError("A target cannot be both a firmware image and an SBOM")
    if not 1 <= max_file_bytes <= 100 * 1024 * 1024:
        raise ValueError("max_file_bytes must be between 1 and 104857600")

    profile_info = get_profile(profile)
    available = tuple(rule.id for rule in RULES)
    unknown_rules = set(disabled_rules) - set(available)
    if unknown_rules:
        raise ValueError(f"Unknown rule IDs: {', '.join(sorted(unknown_rules))}")
    enabled_rules = tuple(rule for rule in RULES if rule.id not in disabled_rules)
    started_at = _timestamp()

    base = requested
    manifest = hashlib.sha256()
    if sbom_input:
        candidates, files_discovered = [], 0
        manifest.update(
            f"{requested.name}\0{_sha256_file(requested)}\n".encode("utf-8")
        )
    else:
        candidates, files_discovered = _candidate_paths(
            requested, profile_info, include, exclude
        )
    findings = []
    skipped = Counter()
    files_scanned = 0

    if firmware_image:
        manifest.update(
            f"{requested.name}\0{_sha256_file(requested)}\n".encode("utf-8")
        )

    for path in candidates:
        source, reason = _load_source(path, base, max_file_bytes)
        display_path = _display_path(path, base)
        if source is None:
            skipped[reason or "read_error"] += 1
            manifest.update(f"{display_path}\0skip:{reason}\n".encode("utf-8"))
            continue
        files_scanned += 1
        manifest.update(f"{source.path}\0{source.sha256}\n".encode("utf-8"))
        for rule in enabled_rules:
            findings.extend(rule.scan(source))

    findings.sort(key=lambda item: (item.file.casefold(), item.start_line, item.rule_id))
    analyzer_status = (
        AnalyzerStatus(
            name="fuse-native",
            status="completed" if files_scanned and enabled_rules else "skipped",
            version=__version__,
            detail=(
                "Native rules completed."
                if files_scanned and enabled_rules
                else "SBOM input is routed to inventory/advisory analyzers; native text rules were skipped."
                if sbom_input
                else "No selected text files or no enabled rules."
            ),
            findings=len(findings),
        ),
    )
    target_kind = (
        "firmware-image"
        if firmware_image
        else "sbom"
        if sbom_input
        else "directory"
        if requested.is_dir()
        else "source-file"
        if profile_info.supports(requested)
        else "unsupported-file"
    )
    return ScanResult(
        target=str(target),
        target_kind=target_kind,
        profile=profile_info.name,
        started_at=started_at,
        completed_at=_timestamp(),
        input_manifest_sha256=manifest.hexdigest(),
        files_discovered=files_discovered,
        files_selected=len(candidates),
        files_filtered=files_discovered - len(candidates),
        files_scanned=files_scanned,
        files_skipped_by_reason=dict(sorted(skipped.items())),
        rules_available=available,
        rules_enabled=tuple(rule.id for rule in enabled_rules),
        analyzers=analyzer_status,
        findings=tuple(findings),
    )
