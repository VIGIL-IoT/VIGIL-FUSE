from __future__ import annotations

import re
from collections.abc import Iterable

from ..model import Finding, SourceFile
from .base import RuleDefinition, is_test_path, iter_code_lines

_PEM_MARKER = re.compile(
    r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----"
)


def _scan(source: SourceFile, rule: RuleDefinition) -> Iterable[Finding]:
    if is_test_path(source.path):
        return
    for line_number, line in iter_code_lines(source.text, source.path):
        match = _PEM_MARKER.search(line)
        if match:
            yield rule.finding(
                source,
                line_number,
                line[: match.start()] + "[PRIVATE KEY MATERIAL REDACTED]",
            )


RULE = RuleDefinition(
    id="FUSE002",
    title="Private key PEM marker embedded in scanned file",
    severity="high",
    confidence="high",
    category="secrets",
    explanation=(
        "A PEM private-key boundary marker is present. FUSE detects the marker but "
        "does not validate the key or determine whether the file is deployed."
    ),
    potential_impact=(
        "If this is a usable private key shipped with a product, compromise of one copy "
        "may allow impersonation or decryption wherever that key is trusted."
    ),
    remediation=(
        "Remove the key from source and firmware, rotate or revoke it, and generate or "
        "provision unique keys through a protected process."
    ),
    scanner=_scan,
    version="1.1.0",
    references=("https://cwe.mitre.org/data/definitions/321.html",),
    prefilter=lambda source: "-----BEGIN" in source.text,
)
