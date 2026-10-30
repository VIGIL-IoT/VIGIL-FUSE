from __future__ import annotations

import re
from collections.abc import Iterable
from ipaddress import ip_address
from urllib.parse import urlsplit

from ..model import Finding, SourceFile
from .base import RuleDefinition, is_endpoint_context, is_test_path, iter_code_lines

_HTTP_URL = re.compile(r"(?i)\bhttp:" + r"//[^\s\"'<>]+")
_RESERVED_EXAMPLE_DOMAINS = frozenset({"example.com", "example.net", "example.org"})
_RESERVED_DOMAIN_SUFFIXES = (".example", ".invalid", ".test", ".localhost")
_EXPECTED_REDIRECT = re.compile(r"(?i)\bexpect\w*.{0,50}\b301\b")
_HTTPS_REDIRECT_STATUS = re.compile(r"(?i)HTTP_CODE_MOVED_PERMANENTLY")


def _is_loopback(host: str) -> bool:
    if host.lower() == "localhost" or host.lower().endswith(".localhost"):
        return True
    try:
        return ip_address(host).is_loopback
    except ValueError:
        return False


def _is_reserved_example_host(host: str) -> bool:
    normalized = host.casefold().rstrip(".")
    return (
        normalized in _RESERVED_EXAMPLE_DOMAINS
        or any(
            normalized == suffix[1:] or normalized.endswith(suffix)
            for suffix in _RESERVED_DOMAIN_SUFFIXES
        )
        or any(normalized.endswith("." + domain) for domain in _RESERVED_EXAMPLE_DOMAINS)
    )


def _is_example_private_address(host: str, path: str) -> bool:
    if "examples" not in path.replace("\\", "/").casefold().split("/"):
        return False
    try:
        address = ip_address(host)
    except ValueError:
        return False
    return address.is_private or address.is_reserved


def _is_expected_https_redirect_example(source: SourceFile, line_number: int) -> bool:
    lines = source.text.splitlines()
    start = max(0, line_number - 5)
    stop = min(len(lines), line_number + 8)
    context = "\n".join(lines[start:stop])
    return bool(_EXPECTED_REDIRECT.search(context) and _HTTPS_REDIRECT_STATUS.search(context))


def _scan(source: SourceFile, rule: RuleDefinition) -> Iterable[Finding]:
    if is_test_path(source.path):
        return
    for line_number, line in iter_code_lines(source.text, source.path):
        match = _HTTP_URL.search(line)
        if not match:
            continue
        if not is_endpoint_context(line, match.start(), source.path):
            continue
        try:
            host = urlsplit(match.group(0)).hostname
        except ValueError:
            continue
        if (
            not host
            or _is_loopback(host)
            or host.casefold() in {"ip", "host", "example"}
            or any(token in host for token in ("%", "$", "{", "}"))
            or _is_reserved_example_host(host)
            or _is_example_private_address(host, source.path)
            or _is_expected_https_redirect_example(source, line_number)
        ):
            continue
        yield rule.finding(source, line_number, "http:" + f"//{host}")


RULE = RuleDefinition(
    id="FUSE004",
    title="Non-loopback HTTP endpoint configured",
    severity="medium",
    confidence="high",
    category="transport-security",
    explanation=(
        "A non-loopback URL explicitly uses HTTP. This indicates an unencrypted endpoint "
        "in source or configuration, but does not prove the endpoint is reachable or used."
    ),
    potential_impact=(
        "If the endpoint carries sensitive data over an untrusted network, traffic may be "
        "observed or modified in transit."
    ),
    remediation=(
        "Use HTTPS with certificate verification for the service and confirm that the "
        "device rejects invalid certificates."
    ),
    scanner=_scan,
    version="1.2.0",
    references=("https://cwe.mitre.org/data/definitions/319.html",),
    prefilter=lambda source: "http:" in source.text.casefold(),
)
