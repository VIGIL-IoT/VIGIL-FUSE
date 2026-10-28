from __future__ import annotations

import unicodedata


_BIDI_CONTROLS = {
    "LRE",
    "RLE",
    "PDF",
    "LRO",
    "RLO",
    "LRI",
    "RLI",
    "FSI",
    "PDI",
}


def safe_report_text(value: object, *, limit: int) -> str | None:
    """Bound external text and remove terminal and bidirectional control characters."""
    if not isinstance(value, str):
        return None
    cleaned = "".join(
        " " if unicodedata.category(character) == "Cc" else ""
        if unicodedata.bidirectional(character) in _BIDI_CONTROLS
        else character
        for character in value
    )
    normalized = " ".join(cleaned.split())
    return normalized[:limit] or None
