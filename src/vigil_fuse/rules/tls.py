from __future__ import annotations

import re
from collections.abc import Iterable

from ..model import Finding, SourceFile
from .base import RuleDefinition, code_without_string_literals, is_test_path, iter_code_lines

_BYPASS_PATTERNS = (
    re.compile(r"(?i)\bverify\s*=\s*false\b"),
    re.compile(r"(?i)\bcheck_hostname\s*=\s*false\b"),
    re.compile(r"\bCERT_NONE\b"),
    re.compile(r"(?i)\binsecure_skip_verify\s*[:=]\s*true\b"),
    re.compile(r"(?i)\bInsecureSkipVerify\s*:\s*true\b"),
    re.compile(r"(?i)\.\s*setInsecure\s*\(\s*\)"),
)


def _scan(source: SourceFile, rule: RuleDefinition) -> Iterable[Finding]:
    if is_test_path(source.path):
        return
    for line_number, line in iter_code_lines(source.text, source.path):
        code = code_without_string_literals(line)
        for pattern in _BYPASS_PATTERNS:
            match = pattern.search(code)
            if match:
                yield rule.finding(source, line_number, match.group(0))
                break


RULE = RuleDefinition(
    id="FUSE003",
    title="TLS peer verification appears disabled",
    severity="high",
    confidence="high",
    category="transport-security",
    explanation=(
        "The source contains an explicit setting or API commonly used to bypass TLS "
        "certificate or hostname verification. FUSE does not establish that this path runs."
    ),
    potential_impact=(
        "If used for a network connection, disabling verification can allow an active "
        "attacker to impersonate the peer and intercept or alter traffic."
    ),
    remediation=(
        "Enable certificate-chain and hostname verification, install the correct trust "
        "anchor, and use a test-only override that cannot enter production builds."
    ),
    scanner=_scan,
    version="1.1.0",
    references=("https://cwe.mitre.org/data/definitions/295.html",),
)
