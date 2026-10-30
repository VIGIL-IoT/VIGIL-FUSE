from __future__ import annotations

from dataclasses import dataclass
import hashlib
import re
from pathlib import PurePosixPath
from typing import Callable, Iterable

from ..model import Confidence, Finding, Severity, SourceFile

Scanner = Callable[[SourceFile, "RuleDefinition"], Iterable[Finding]]
Prefilter = Callable[[SourceFile], bool]


@dataclass(frozen=True)
class RuleDefinition:
    id: str
    title: str
    severity: Severity
    confidence: Confidence
    category: str
    explanation: str
    potential_impact: str
    remediation: str
    scanner: Scanner
    version: str = "1.0.0"
    references: tuple[str, ...] = ()
    prefilter: Prefilter | None = None

    def finding(self, source: SourceFile, line: int, evidence: str) -> Finding:
        evidence = " ".join(evidence.strip().split())
        if len(evidence) > 240:
            evidence = evidence[:237] + "..."
        fingerprint_source = f"{self.id}\0{source.path}\0{line}\0{evidence}"
        fingerprint = hashlib.sha256(fingerprint_source.encode("utf-8")).hexdigest()
        return Finding(
            id=f"{self.id}:{source.path}:{line}",
            fingerprint=fingerprint,
            rule_id=self.id,
            rule_version=self.version,
            analyzer="fuse-native",
            title=self.title,
            severity=self.severity,
            confidence=self.confidence,
            category=self.category,
            file=source.path,
            start_line=line,
            end_line=line,
            evidence=evidence,
            explanation=self.explanation,
            potential_impact=self.potential_impact,
            remediation=self.remediation,
            references=self.references,
            applicability="candidate" if source.generated_config else "unknown",
            validation_method="generated-config" if source.generated_config else "static",
        )

    def scan(self, source: SourceFile) -> Iterable[Finding]:
        return self.scanner(source, self)

    def may_scan(self, source: SourceFile) -> bool:
        """Return false only when a cheap rule-owned prefilter proves no match is possible."""
        return self.prefilter(source) if self.prefilter is not None else True


def is_comment_line(line: str) -> bool:
    stripped = line.lstrip()
    if stripped.startswith("#") and re.match(
        r"#\s*(?:define|undef|if|ifdef|ifndef|elif|else|endif|include|pragma|error|line)\b",
        stripped,
        re.IGNORECASE,
    ):
        return False
    return stripped.startswith(("#", "//", "/*", "*", ";", "<!--"))


def iter_code_lines(text: str, path: str) -> Iterable[tuple[int, str]]:
    """Yield source lines with comments and standalone docstrings removed.

    The small lexer is shared by rules so URLs inside block comments and comment
    continuations do not become findings. Quoted strings remain available to rules
    that need to inspect configured values.
    """
    suffix = PurePosixPath(path.replace("\\", "/")).suffix.casefold()
    simple_markers: tuple[str, ...] = ("'", '"', "`", "//", "/*", "<!--", "#")
    if suffix in {".ini", ".cfg", ".conf"}:
        simple_markers = (*simple_markers, ";")
    in_block: str | None = None
    in_triple_string: str | None = None
    strip_triple_string = False
    directive = re.compile(
        r"^\s*#\s*(?:define|undef|if|ifdef|ifndef|elif|else|endif|include|pragma|error|line)\b",
        re.IGNORECASE,
    )

    for line_number, line in enumerate(text.splitlines(), start=1):
        if (
            in_block is None
            and in_triple_string is None
            and not any(marker in line for marker in simple_markers)
        ):
            yield line_number, line
            continue

        code: list[str] = []
        index = 0
        quote: str | None = None
        escaped = False
        is_preprocessor = bool(directive.match(line))

        while index < len(line):
            if in_block:
                end = line.find(in_block, index)
                if end < 0:
                    break
                index = end + len(in_block)
                in_block = None
                continue

            if in_triple_string:
                end = line.find(in_triple_string, index)
                if end < 0:
                    if not strip_triple_string:
                        code.extend(line[index:])
                    break
                if not strip_triple_string:
                    code.extend(line[index : end + 3])
                index = end + len(in_triple_string)
                in_triple_string = None
                strip_triple_string = False
                continue

            char = line[index]
            if quote:
                code.append(char)
                if escaped:
                    escaped = False
                elif char == "\\":
                    escaped = True
                elif char == quote:
                    quote = None
                index += 1
                continue

            if line.startswith(("'''", '"""'), index):
                in_triple_string = line[index : index + 3]
                strip_triple_string = not "".join(code).strip()
                if not strip_triple_string:
                    code.append(in_triple_string)
                index += 3
                continue
            if char in {"'", '"', "`"}:
                quote = char
                code.append(char)
                index += 1
                continue
            if line.startswith("/*", index):
                in_block = "*/"
                index += 2
                continue
            if line.startswith("<!--", index):
                in_block = "-->"
                index += 4
                continue
            if line.startswith("//", index):
                break
            if char == "#" and not is_preprocessor:
                break
            if char == ";" and suffix in {".ini", ".cfg", ".conf"}:
                break

            code.append(char)
            index += 1

        yield line_number, "".join(code)


def code_without_string_literals(line: str) -> str:
    """Keep code identifiers while blanking quoted text for code-pattern rules."""
    if not any(quote in line for quote in ("'", '"', "`")):
        return line
    output = list(line)
    quote: str | None = None
    escaped = False
    for index, char in enumerate(line):
        if quote:
            output[index] = " "
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = None
        elif char in {"'", '"', "`"}:
            quote = char
            output[index] = " "
    return "".join(output)


_TEST_DIRECTORY_NAMES = frozenset(
    {
        "test",
        "tests",
        "spec",
        "specs",
        "__tests__",
        "testdata",
        "test_data",
        "fixtures",
        "fixture",
        "test_certs",
        "test-certs",
        "test_certificates",
        "unit_test",
        "unit_tests",
        "integration_test",
        "integration_tests",
        "selftest",
        "oeqa",
    }
)
_TEST_BASENAME = re.compile(r"(?i)(?:^|[._-])(?:test|tests|spec|specs|pytest)(?:[._-]|$)")


def is_test_path(path: str) -> bool:
    """Identify test-only source paths without suppressing ordinary examples."""
    parts = PurePosixPath(path.replace("\\", "/")).parts
    if any(part.casefold() in _TEST_DIRECTORY_NAMES for part in parts[:-1]):
        return True
    basename = PurePosixPath(path.replace("\\", "/")).name
    stem = PurePosixPath(basename).stem
    return bool(
        stem.casefold().startswith(("test_", "pytest_", "spec_")) or _TEST_BASENAME.search(stem)
    )


_LOCALIZATION_NAMES = frozenset(
    {
        "lang",
        "language",
        "languages",
        "locale",
        "locales",
        "translation",
        "translations",
        "i18n",
        "l10n",
    }
)


def is_localization_path(path: str) -> bool:
    parts = PurePosixPath(path.replace("\\", "/")).parts
    for part in parts:
        name = PurePosixPath(part.casefold()).stem
        tokens = re.split(r"[^a-z0-9]+", name)
        if any(token in _LOCALIZATION_NAMES for token in tokens):
            return True
    return False


def is_kconfig_input_path(path: str) -> bool:
    basename = PurePosixPath(path.replace("\\", "/")).name.casefold()
    return (
        basename == "sdkconfig"
        or basename.startswith("sdkconfig.")
        or basename in {".config", "defconfig", "kconfig", "kconfig.projbuild"}
        or basename.startswith("kconfig.")
        or basename.endswith((".config", ".defconfig"))
    )


_ENDPOINT_TOKENS = frozenset(
    {
        "api",
        "http",
        "https",
        "rest",
        "mqtt",
        "broker",
        "server",
        "endpoint",
        "service",
        "cloud",
        "ota",
        "safeboot",
        "update",
        "firmware",
        "upload",
        "download",
        "gateway",
        "host",
        "listen",
        "base",
        "web",
        "websocket",
        "socket",
        "proxy",
    }
)
_METADATA_TOKENS = frozenset(
    {
        "license",
        "licence",
        "copyright",
        "homepage",
        "website",
        "documentation",
        "docs",
        "schema",
        "support",
        "author",
        "vendor",
        "source",
        "project",
        "contact",
        "forum",
        "wiki",
        "repository",
        "help",
    }
)
_ENDPOINT_CONTEXT_PATH_TOKENS = frozenset(
    {
        "broker",
        "cloud",
        "endpoint",
        "firmware",
        "gateway",
        "mqtt",
        "ota",
        "server",
        "service",
        "update",
    }
)
_NETWORK_CALL = re.compile(
    r"(?i)\b(?:requests?\.(?:get|post|put|patch|delete|request)|"
    r"urllib\.request\.urlopen|urlopen|axios\.(?:get|post|put|patch|delete)|"
    r"fetch|esp_http_client|http(?:s)?client\.(?:begin|get|post|put|send|request|connect)|"
    r"http\.begin|client\.(?:begin|connect|request|download)|openConnection)\s*(?:\(|\b)"
)
_ASSIGNMENT_BEFORE_VALUE = re.compile(
    r"(?i)(?:['\"]?)(?P<name>[a-z_][a-z0-9_.-]*)(?:['\"]?)\s*(?:=|:)\s*['\"]?\s*$"
)


def is_endpoint_context(line: str, value_start: int, path: str) -> bool:
    """Require an endpoint-specific key or a recognizable network call."""
    if _NETWORK_CALL.search(line):
        return True

    assignment = _ASSIGNMENT_BEFORE_VALUE.search(line[:value_start])
    if not assignment:
        return False
    tokens = set(re.findall(r"[a-z0-9]+", assignment.group("name").casefold()))
    if tokens & _METADATA_TOKENS:
        return False
    if tokens & _ENDPOINT_TOKENS:
        return True

    # Generic url/uri keys only count when the containing path identifies the
    # service or transport. A bare website or project metadata URL is ignored.
    path_tokens = set(re.findall(r"[a-z0-9]+", path.casefold()))
    return bool(tokens & {"url", "uri", "address"} and path_tokens & _ENDPOINT_CONTEXT_PATH_TOKENS)
