from __future__ import annotations

import re
from collections.abc import Iterable

from ..model import Finding, SourceFile
from .base import (
    RuleDefinition,
    code_without_string_literals,
    is_localization_path,
    is_test_path,
    iter_code_lines,
)

_SECRET_NAME = r"(?:password|passwd|pwd|user[_-]?pass|secret|token|api[_-]?key|access[_-]?token|auth[_-]?token)"
_C_STRING_PREFIX = r"(?:u8|u|U|L)?"
_ASSIGNMENT = re.compile(
    r"(?i)\b(?P<name>[\w.-]*"
    + _SECRET_NAME
    + r"[\w.-]*)\b\s*(?:=|:)\s*"
    + _C_STRING_PREFIX
    + r"(?P<quote>[\"'])(?P<value>[^\"'\r\n]{4,})(?P=quote)"
)
_C_DEFINE = re.compile(
    r"(?i)^\s*#\s*define\s+(?P<name>[\w]*"
    + _SECRET_NAME
    + r"[\w]*)\s+"
    + _C_STRING_PREFIX
    + r"(?P<quote>[\"'])(?P<value>[^\"'\r\n]{4,})(?P=quote)"
)
_SECRET_COMPARISON = re.compile(
    r"(?i)\b(?P<name>[\w.-]*(?:"
    + _SECRET_NAME
    + r")[\w.-]*)\b\s*(?:==|!=)\s*"
    + _C_STRING_PREFIX
    + r"(?P<quote>[\"'])(?P<value>[^\"'\r\n]{4,})(?P=quote)"
)
_ENV_ASSIGNMENT = re.compile(
    r"(?i)^\s*(?:export\s+)?(?P<name>[\w.-]*"
    + _SECRET_NAME
    + r"[\w.-]*)\s*=\s*(?P<value>(?![\"'])[^\s#]{4,})\s*(?:#.*)?$"
)
_PLACEHOLDER = re.compile(
    r"(?i)^(?:your(?:[_ -])|change[_-]?me|replace[_-]?me|example|placeholder|dummy|"
    r"fake|mock|fixture|redacted|test|none|null|undefined|sample|x{3,}|\*+|<[^>]+>|"
    r"\$\{[^}]+\}|%\w+%)"
)
_COMMON_EXAMPLE_PLACEHOLDER = re.compile(
    r"(?i)^(?:\.{4,}|your(?:pass(?:word|wd)?|psk(?:here)?|ssid)|"
    r"wifi[_ -]?password|write[_ -]?api[_ -]?key|read[_ -]?api[_ -]?key)$"
)
_COMPUTED_VALUE = re.compile(r"(?s)(?:\$\([^)]*\)|\$\{[^}]*\}|`[^`]*`|%[A-Z_][A-Z0-9_]*%)")
_BITBAKE_METADATA_ASSIGNMENT = re.compile(
    r"(?i)^\s*(?:SUMMARY|DESCRIPTION|HOMEPAGE|LICENSE|SECTION|AUTHOR|MAINTAINER|BUGTRACKER|SRC_URI)"
    r"(?:\[[^\]]+\])?(?::[^\s=]+)?\s*="
)
_HASH_DEMO_PATH = re.compile(r"(?:^|/)hash/examples/(?:md5|sha1)(?:/|$)")
_HASH_DEMO_BUILDER = re.compile(r"\b(?:MD5Builder|SHA1Builder)\b")
_XML_DISABLED_ACCOUNTS = re.compile(
    r"(?i)<accounts\b[^>]*\b(?:enabled|use)\s*=\s*([\"'])(?:no|false|0)\1"
)
_XML_DISABLED_ACCOUNT = re.compile(
    r"(?i)<account\b[^>]*\b(?:enabled|use)\s*=\s*([\"'])(?:no|false|0)\1"
)
_XML_ACCOUNTS_END = re.compile(r"(?i)</accounts\s*>")
_NON_SECRET_LABEL = re.compile(
    r"(?i)^(?:(?:enter|set|change|reset|update|new|old|current|wrong|invalid|incorrect|confirm)\s+)?"
    r"(?:password|passwd|secret|token|api[ _-]?key)"
    r"(?:\s+(?:is\s+)?(?:required|invalid|incorrect|missing|empty|not set|failed))?[.!:]?$"
)
_NON_SECRET_NAME_SUFFIX = re.compile(
    r"(?i)(?:^|[_-]|(?<=[a-z0-9]))"
    r"(?:file|filename|path|characteristic|uuid|label|prompt|message|title|description|placeholder|text|reserved)$"
)
_TINY_SRP_PASSWD_HEADER = re.compile(r"(?i)(?:^|/)tinysrp/t_pwd\.h$")
_EXPRESSION_CONTINUATION = re.compile(r"(?i)^\s*(?:\+|\.|\|\||&&|\?|\b(?:or|and|if)\b)")
_NMEA_SENTENCE_TOKEN = re.compile(r"^\$?(?:GP|GN|GL|GA|GB|BD|II|HE|HC|EC|SD|IN|TI)[A-Z]{3}$")
_NMEA_PARSER_CONTEXT = re.compile(r"(?i)\b(?:NMEA|GPGGA|GPGSA)\b")
_SECRET_PREFILTER_TOKENS = (
    "password",
    "passwd",
    "pwd",
    "userpass",
    "user_pass",
    "user-pass",
    "secret",
    "token",
    "api_key",
    "api-key",
    "apikey",
    "access_token",
    "access-token",
    "accesstoken",
    "auth_token",
    "auth-token",
    "authtoken",
)


def _may_contain_secret_assignment(source: SourceFile) -> bool:
    lowered = source.text.casefold()
    return any(token in lowered for token in _SECRET_PREFILTER_TOKENS)


def _is_placeholder_or_label(value: str) -> bool:
    normalized = value.strip()
    return bool(
        _PLACEHOLDER.match(normalized)
        or _COMMON_EXAMPLE_PLACEHOLDER.fullmatch(normalized)
        or _NON_SECRET_LABEL.fullmatch(normalized)
    )


def _is_hash_tutorial_value(match: re.Match[str], source: SourceFile) -> bool:
    path = source.path.replace("\\", "/").casefold()
    if not _HASH_DEMO_PATH.search(path) or not _HASH_DEMO_BUILDER.search(source.text):
        return False
    if "password" not in match.group("name").casefold():
        return False
    value = match.group("value").strip()
    if value.casefold() in {"hello world", "hello, world", "hello-world"}:
        return True
    if not match.group("name").casefold().endswith("ashex") or not re.fullmatch(
        r"[0-9a-fA-F]+", value
    ):
        return False
    try:
        decoded = bytes.fromhex(value).decode("ascii").casefold()
    except (ValueError, UnicodeDecodeError):
        return False
    return decoded in {"hello world", "hello, world", "hello-world"}


def _is_secret_literal(match: re.Match[str], line: str, source: SourceFile) -> bool:
    path = source.path.replace("\\", "/")
    if (
        _TINY_SRP_PASSWD_HEADER.search(path)
        and _C_DEFINE.match(line)
        and match.group("name").casefold() == "default_passwd"
        and match.group("value").strip().casefold() == "tpasswd"
    ):
        # TinySRP uses this macro as the default password database filename.
        return False
    if _NON_SECRET_NAME_SUFFIX.search(match.group("name")):
        return False
    value = match.group("value").strip()
    name = match.group("name").strip("_.-").casefold()
    is_nmea_parser_token = (
        name == "token"
        and re.search(r"(?i)\.\s*token\s*=", line)
        and _NMEA_SENTENCE_TOKEN.fullmatch(value)
        and _NMEA_PARSER_CONTEXT.search(source.text)
    )
    if is_nmea_parser_token or _is_placeholder_or_label(value):
        return False
    if _COMPUTED_VALUE.search(match.group("value")) or _is_hash_tutorial_value(match, source):
        return False
    return not _EXPRESSION_CONTINUATION.match(line[match.end() :])


def _scan(source: SourceFile, rule: RuleDefinition) -> Iterable[Finding]:
    basename = source.path.replace("\\", "/").rsplit("/", 1)[-1].lower()
    is_env_file = basename == ".env" or basename.startswith(".env.")
    is_bitbake_metadata = basename.endswith((".bb", ".bbappend", ".inc"))
    is_xml = basename.endswith(".xml")
    if is_localization_path(source.path) or (is_test_path(source.path) and not is_env_file):
        return
    disabled_accounts = False
    for line_number, line in iter_code_lines(source.text, source.path):
        if is_xml:
            if disabled_accounts:
                if _XML_ACCOUNTS_END.search(line):
                    disabled_accounts = False
                continue
            if _XML_DISABLED_ACCOUNTS.search(line):
                disabled_accounts = not bool(_XML_ACCOUNTS_END.search(line))
                continue
            if _XML_DISABLED_ACCOUNT.search(line):
                continue
        if is_bitbake_metadata and _BITBAKE_METADATA_ASSIGNMENT.match(line):
            continue
        matches = (
            list(_ASSIGNMENT.finditer(line))
            + list(_C_DEFINE.finditer(line))
            + list(_SECRET_COMPARISON.finditer(line))
        )
        if is_env_file:
            matches.extend(_ENV_ASSIGNMENT.finditer(line))
        code_line = code_without_string_literals(line)
        matches = [
            item for item in matches if code_line[item.start("name") : item.end("name")].strip()
        ]
        match = next(
            (item for item in matches if _is_secret_literal(item, line, source)),
            None,
        )
        if not match:
            continue
        redacted = line
        for item in sorted(matches, key=lambda value: value.start("value"), reverse=True):
            redacted = (
                redacted[: item.start("value")] + "[REDACTED]" + redacted[item.end("value") :]
            )
        yield rule.finding(source, line_number, redacted)


RULE = RuleDefinition(
    id="FUSE001",
    title="Credential-like literal in source",
    severity="medium",
    confidence="high",
    category="secrets",
    explanation=(
        "A credential-related name is assigned a literal or compared with one. Quoted "
        "assignments and comparisons include C and C++ character-prefixed string literals. "
        "Plain values are also checked in .env files. "
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
    version="1.9.0",
    references=("https://cwe.mitre.org/data/definitions/798.html",),
    prefilter=_may_contain_secret_assignment,
)
