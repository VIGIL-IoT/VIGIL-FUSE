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
        " "
        if unicodedata.category(character) == "Cc"
        else ""
        if unicodedata.bidirectional(character) in _BIDI_CONTROLS
        else character
        for character in value
    )
    normalized = " ".join(cleaned.split())
    return normalized[:limit] or None


def safe_terminal_text(value: object) -> str:
    """Make untrusted text safe to display without executing terminal controls."""
    if not isinstance(value, str):
        return ""
    output: list[str] = []
    for character in value:
        if character == "\n":
            output.append(character)
        elif character == "\t":
            output.append(r"\t")
        elif character == "\r":
            output.append(r"\r")
        elif unicodedata.category(character) == "Cc":
            codepoint = ord(character)
            output.append(f"\\x{codepoint:02x}" if codepoint <= 0xFF else f"\\u{codepoint:04x}")
        elif unicodedata.bidirectional(character) in _BIDI_CONTROLS:
            output.append(f"\\u{ord(character):04x}")
        else:
            output.append(character)
    return "".join(output)
