from __future__ import annotations

import ast
import re
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import PurePosixPath

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
    "verify",
    "check_hostname",
    "cert_none",
    "insecure_skip_verify",
    "insecureskipverify",
    "setinsecure",
)
_TLS_CONTEXT = re.compile(
    r"(?i)(?:\b(?:tls|ssl|https|certificate|certificates|cert_verify|verify_peer|peer_verification)\b|https?://)"
)
_PYTHON_HTTP_CALLS = frozenset(
    {
        "get",
        "options",
        "head",
        "post",
        "put",
        "patch",
        "delete",
        "request",
        "Session",
        "Client",
        "AsyncClient",
    }
)
_C_SOURCE_SUFFIXES = frozenset({".c", ".h", ".cc", ".cpp", ".cxx", ".hh", ".hpp", ".hxx", ".ino"})
_PREPROCESSOR_BRANCH = re.compile(
    r"^\s*#\s*(?P<directive>if|ifdef|ifndef|elif|else|endif)\b(?P<expression>.*)$"
)


@dataclass
class _PreprocessorFrame:
    prior_branch_active: bool | None
    branch_active: bool | None


def _literal_condition(expression: str) -> bool | None:
    value = expression.strip()
    if value == "1":
        return True
    if value == "0":
        return False
    return None


def _inactive_cpp_lines(source: SourceFile) -> set[int]:
    suffix = PurePosixPath(source.path.replace("\\", "/")).suffix.casefold()
    if suffix not in _C_SOURCE_SUFFIXES:
        return set()

    inactive: set[int] = set()
    frames: list[_PreprocessorFrame] = []
    for line_number, line in iter_code_lines(source.text, source.path):
        match = _PREPROCESSOR_BRANCH.match(line)
        if match:
            directive = match.group("directive").casefold()
            expression = match.group("expression")
            if directive in {"if", "ifdef", "ifndef"}:
                condition = _literal_condition(expression) if directive == "if" else None
                frames.append(_PreprocessorFrame(condition, condition))
            elif directive == "elif" and frames:
                frame = frames[-1]
                condition = _literal_condition(expression)
                if frame.prior_branch_active is True:
                    frame.branch_active = False
                elif frame.prior_branch_active is False:
                    frame.branch_active = condition
                else:
                    frame.branch_active = None
                if frame.prior_branch_active is True or condition is True:
                    frame.prior_branch_active = True
                elif frame.prior_branch_active is False and condition is False:
                    frame.prior_branch_active = False
                else:
                    frame.prior_branch_active = None
            elif directive == "else" and frames:
                frame = frames[-1]
                if frame.prior_branch_active is True:
                    frame.branch_active = False
                elif frame.prior_branch_active is False:
                    frame.branch_active = True
                else:
                    frame.branch_active = None
            elif directive == "endif" and frames:
                frames.pop()
            continue

        if any(frame.branch_active is False for frame in frames):
            inactive.add(line_number)
    return inactive


def _qualified_name(node: ast.expr) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        prefix = _qualified_name(node.value)
        return f"{prefix}.{node.attr}" if prefix else node.attr
    return ""


def _python_tls_bypass_lines(source: SourceFile) -> set[int] | None:
    if PurePosixPath(source.path.replace("\\", "/")).suffix.casefold() != ".py":
        return None
    try:
        tree = ast.parse(source.text, filename=source.path)
    except (SyntaxError, TypeError, ValueError, RecursionError):
        return None

    lines: set[int] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        qualified_name = _qualified_name(node.func)
        parts = qualified_name.split(".")
        if len(parts) < 2 or parts[0] not in {"requests", "httpx"}:
            continue
        if parts[-1] not in _PYTHON_HTTP_CALLS:
            continue
        for keyword in node.keywords:
            if (
                keyword.arg == "verify"
                and isinstance(keyword.value, ast.Constant)
                and keyword.value.value is False
            ):
                lines.add(keyword.value.lineno)
    return lines


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
    python_bypass_lines = _python_tls_bypass_lines(source)
    inactive_cpp_lines = _inactive_cpp_lines(source)
    for line_number, line in iter_code_lines(source.text, source.path):
        if line_number in inactive_cpp_lines:
            continue
        code = code_without_string_literals(line)
        for index, pattern in enumerate(_BYPASS_PATTERNS):
            match = pattern.search(code)
            if (
                match
                and index == 0
                and not _has_tls_context(source, line)
                and (python_bypass_lines is None or line_number not in python_bypass_lines)
            ):
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
    version="1.4.0",
    references=("https://cwe.mitre.org/data/definitions/295.html",),
    prefilter=_may_contain_tls_bypass,
)
