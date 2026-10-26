from __future__ import annotations

import re
from collections.abc import Iterable
from ipaddress import ip_address
from urllib.parse import urlsplit

from ..model import Finding, SourceFile
from .base import RuleDefinition, is_endpoint_context, is_test_path, iter_code_lines

_HTTP_URL = re.compile(r"(?i)\bhttp:" + r"//[^\s\"'<>]+")

def _is_loopback(host: str) -> bool:
    if host.lower() == "localhost" or host.lower().endswith(".localhost"):
        return True
    try:
        return ip_address(host).is_loopback
    except ValueError:
        return False


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
    version="1.1.0",
    references=("https://cwe.mitre.org/data/definitions/319.html",),
)
