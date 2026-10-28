from __future__ import annotations

import json
from pathlib import Path

MAX_SBOM_DETECTION_BYTES = 50 * 1024 * 1024
_SBOM_FILENAMES = (
    "bom.json",
    "bom.xml",
)
_SBOM_SUFFIXES = (
    ".cdx.json",
    ".cdx.xml",
    ".spdx.json",
    ".spdx.yml",
    ".spdx.rdf.xml",
    ".spdx.rdf",
)


def is_sbom_candidate(path: Path) -> bool:
    """Return whether a filename convention suggests an SBOM input."""
    name = path.name.casefold()
    return (
        name.endswith(".spdx")
        or name in _SBOM_FILENAMES
        or name.endswith(_SBOM_SUFFIXES)
    )


def is_sbom_file(path: Path) -> bool:
    """Recognize common CycloneDX/SPDX files without trusting the filename alone."""
    try:
        size = path.stat().st_size
        if size > MAX_SBOM_DETECTION_BYTES:
            return False
        with path.open("rb") as source:
            data = source.read(MAX_SBOM_DETECTION_BYTES + 1)
    except OSError:
        return False
    if len(data) > MAX_SBOM_DETECTION_BYTES:
        return False

    name = path.name.casefold()
    if name.endswith(".spdx"):
        prefix = data[:4096].decode("utf-8-sig", errors="ignore").lstrip()
        return prefix.startswith("SPDXVersion:")

    try:
        document = json.loads(data)
    except (json.JSONDecodeError, UnicodeDecodeError, RecursionError):
        document = None
    if isinstance(document, dict):
        if document.get("bomFormat") == "CycloneDX":
            return True
        if isinstance(document.get("spdxVersion"), str) and document["spdxVersion"].startswith("SPDX-"):
            return True

    if name in _SBOM_FILENAMES or name.endswith(_SBOM_SUFFIXES):
        prefix = data[:65536].decode("utf-8-sig", errors="ignore").casefold()
        return (
            "cyclonedx.org/schema" in prefix
            or "<spdxdocument" in prefix
            or "spdxversion" in prefix
        )
    return False
