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
_BYPASS_PREFILTER_TOKENS = (
    "verify", "check_hostname", "cert_none", "insecure_skip_verify", "insecureskipverify", "setinsecure",
)
_TLS_CONTEXT = re.compile(
    r"(?i)(?:\b(?:tls|ssl|https|certificate|certificates|cert_verify|verify_peer|peer_verification)\b|https?://)"
)


def _may_contain_tls_bypass(source: SourceFile) -> bool:
    lowered = source.text.casefold()
    return any(token in lowered for token in _BYPASS_PREFILTER_TOKENS)


def _has_tls_context(source: SourceFile, line: str) -> bool:
    if _TLS_CONTEXT.search(source.path) or _TLS_CONTEXT.search(line):
        return True
    code = "\n".join(
        code_without_string_literals(candidate)
        for _, candidate in iter_code_lines(source.text, source.path)
    )
    return bool(_TLS_CONTEXT.search(code))


def _scan(source: SourceFile, rule: RuleDefinition) -> Iterable[Finding]:
    if is_test_path(source.path):
        return
    for line_number, line in iter_code_lines(source.text, source.path):
        code = code_without_string_literals(line)
        for index, pattern in enumerate(_BYPASS_PATTERNS):
            match = pattern.search(code)
            if match and index == 0 and not _has_tls_context(source, line):
                continue
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
    version="1.2.0",
    references=("https://cwe.mitre.org/data/definitions/295.html",),
    prefilter=_may_contain_tls_bypass,
)
