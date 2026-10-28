from __future__ import annotations

import re
from collections.abc import Iterable
from ipaddress import ip_address
from urllib.parse import urlsplit

from ..model import Finding, SourceFile
from .base import RuleDefinition, is_endpoint_context, is_test_path, iter_code_lines

_MQTT_URL = re.compile(r"(?i)\bmqtt:" + r"//[^\s\"'<>]+")


def _scan(source: SourceFile, rule: RuleDefinition) -> Iterable[Finding]:
    if is_test_path(source.path):
        return
    for line_number, line in iter_code_lines(source.text, source.path):
        match = _MQTT_URL.search(line)
        if not match:
            continue
        if not is_endpoint_context(line, match.start(), source.path):
            continue
        try:
            host = urlsplit(match.group(0)).hostname
        except ValueError:
            continue
        if not host or host.casefold() in {"ip", "host", "example", "localhost"}:
            continue
        if any(token in host for token in ("%", "$", "{", "}")):
            continue
        try:
            if ip_address(host).is_loopback:
                continue
        except ValueError:
            pass
        yield rule.finding(source, line_number, "mqtt:" + f"//{host}")


RULE = RuleDefinition(
    id="FUSE005",
    title="Plaintext MQTT broker URI configured",
    severity="medium",
    confidence="high",
    category="transport-security",
    explanation=(
        "The MQTT URI explicitly selects the plaintext transport scheme. FUSE cannot determine whether "
        "the connection is made or whether separate protections exist at another layer."
    ),
    potential_impact=(
        "If used across an untrusted network, MQTT messages and credentials may be observed "
        "or modified in transit."
    ),
    remediation=(
        "Use a TLS-protected MQTT connection (commonly `mqtts://` or an explicitly "
        "configured TLS transport), verify the broker certificate, and protect credentials."
    ),
    scanner=_scan,
    version="1.1.0",
    references=("https://cwe.mitre.org/data/definitions/319.html",),
    prefilter=lambda source: "mqtt:" in source.text.casefold(),
)
