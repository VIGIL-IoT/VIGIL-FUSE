from __future__ import annotations

from pathlib import Path, PureWindowsPath


def validate_target_label(value: object) -> str:
    """Validate an explicit report label without accepting an absolute path."""
    if not isinstance(value, str):
        raise ValueError("target label must be a string")
    label = value.strip()
    if not label:
        raise ValueError("target label cannot be empty")
    if len(label) > 120:
        raise ValueError("target label must be 120 characters or fewer")
    if not all(character.isprintable() for character in label):
        raise ValueError("target label cannot contain control characters")
    if "\\" in label or label.startswith("/") or PureWindowsPath(label).drive:
        raise ValueError("target label must be a shareable name, not an absolute or local path")
    if any(part in {"", ".", ".."} for part in label.split("/")):
        raise ValueError("target label cannot contain empty or traversal path segments")
    return label


def report_target_label(target: str | Path, label: str | None = None) -> str:
    """Return a caller-selected label or the target basename without its absolute path."""
    if label is not None:
        return validate_target_label(label)
    resolved = Path(target).expanduser().resolve()
    return resolved.name or "."
