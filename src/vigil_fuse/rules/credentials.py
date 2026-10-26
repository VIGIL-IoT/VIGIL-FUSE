from __future__ import annotations

import re
from collections.abc import Iterable

from ..model import Finding, SourceFile
from .base import RuleDefinition, is_localization_path, is_test_path, iter_code_lines

_SECRET_NAME = r"(?:password|passwd|pwd|secret|token|api[_-]?key|access[_-]?token|auth[_-]?token)"
_ASSIGNMENT = re.compile(
    r"(?i)\b[\w.-]*" + _SECRET_NAME +
    r"[\w.-]*\b\s*(?:=|:)\s*(?P<quote>[\"'])(?P<value>[^\"'\r\n]{4,})(?P=quote)"
)
_C_DEFINE = re.compile(
    r"(?i)^\s*#\s*define\s+[\w]*" + _SECRET_NAME +
    r"[\w]*\s+(?P<quote>[\"'])(?P<value>[^\"'\r\n]{4,})(?P=quote)"
)
_ENV_ASSIGNMENT = re.compile(
    r"(?i)^\s*(?:export\s+)?[\w.-]*" + _SECRET_NAME +
    r"[\w.-]*\s*=\s*(?P<value>(?![\"'])[^\s#]{4,})\s*(?:#.*)?$"
)
_PLACEHOLDER = re.compile(
    r"(?i)^(?:your(?:[_ -])|change[_-]?me|replace[_-]?me|example|placeholder|dummy|"
    r"fake|mock|fixture|redacted|test|none|null|undefined|sample|x{3,}|\*+|<[^>]+>|"
    r"\$\{[^}]+\}|%\w+%)"
)
_NON_SECRET_LABEL = re.compile(
    r"(?i)^(?:(?:enter|set|change|reset|update|new|old|current|wrong|invalid|incorrect|confirm)\s+)?"
    r"(?:password|passwd|secret|token|api[ _-]?key)"
    r"(?:\s+(?:is\s+)?(?:required|invalid|incorrect|missing|empty|not set|failed))?[.!:]?$"
)


def _is_placeholder_or_label(value: str) -> bool:
    normalized = value.strip()
    return bool(_PLACEHOLDER.match(normalized) or _NON_SECRET_LABEL.fullmatch(normalized))


def _scan(source: SourceFile, rule: RuleDefinition) -> Iterable[Finding]:
    basename = source.path.replace("\\", "/").rsplit("/", 1)[-1].lower()
    is_env_file = basename == ".env" or basename.startswith(".env.")
    if is_localization_path(source.path) or (is_test_path(source.path) and not is_env_file):
        return
    for line_number, line in iter_code_lines(source.text, source.path):
        matches = list(_ASSIGNMENT.finditer(line)) + list(_C_DEFINE.finditer(line))
        if is_env_file:
            matches.extend(_ENV_ASSIGNMENT.finditer(line))
        match = next(
            (item for item in matches if not _is_placeholder_or_label(item.group("value"))),
            None,
        )
        if not match:
            continue
        redacted = line
        for item in sorted(matches, key=lambda value: value.start("value"), reverse=True):
            redacted = (
                redacted[: item.start("value")]
                + "[REDACTED]"
                + redacted[item.end("value") :]
            )
        yield rule.finding(source, line_number, redacted)


RULE = RuleDefinition(
    id="FUSE001",
    title="Credential-like literal assigned in source",
    severity="medium",
    confidence="high",
    category="secrets",
    explanation=(
        "A credential-related name is assigned a literal value. Quoted assignments are "
        "checked in source/configuration, and plain values are also checked in .env files. "
        "FUSE cannot determine whether the value is valid or used."
    ),
    potential_impact=(
        "If the value is an active credential and the code or firmware is distributed, "
        "an unauthorized party may recover it and access the associated service or device."
    ),
    remediation=(
        "Remove the literal, rotate the value if it was exposed, and provision secrets "
        "through a deployment-specific secret store or protected device provisioning flow."
    ),
    scanner=_scan,
    version="1.1.0",
    references=("https://cwe.mitre.org/data/definitions/798.html",),
)
