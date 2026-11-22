"""Shared offset-preserving C source masking for static inspection."""

from __future__ import annotations


def mask_c(text: str) -> tuple[str, bool]:
    """Mask comments and quoted literals while preserving offsets and newlines."""
    masked = list(text)
    i = 0
    complete = True
    while i < len(text):
        start = i
        if text.startswith("//", i):
            end = text.find("\n", i + 2)
            i = len(text) if end < 0 else end
        elif text.startswith("/*", i):
            end = text.find("*/", i + 2)
            if end < 0:
                i = len(text)
                complete = False
            else:
                i = end + 2
        elif text[i] in "\"'":
            quote = text[i]
            i += 1
            while i < len(text) and text[i] != quote:
                i += 2 if text[i] == "\\" else 1
            if i >= len(text):
                i = len(text)
                complete = False
            else:
                i += 1
        else:
            i += 1
            continue
        for position in range(start, i):
            if masked[position] != "\n":
                masked[position] = " "
    return "".join(masked), complete
