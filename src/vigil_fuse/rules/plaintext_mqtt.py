from __future__ import annotations

import re
from collections.abc import Iterable
from urllib.parse import urlsplit

from ..model import Finding, SourceFile
from .base import RuleDefinition, is_comment_line

_MQTT_URL = re.compile(r"(?i)\bmqtt:" + r"//[^\s\"'<>]+")


def _scan(source: SourceFile, rule: RuleDefinition) -> Iterable[Finding]:
    for line_number, line in enumerate(source.text.splitlines(), start=1):
        if is_comment_line(line):
            continue
        match = _MQTT_URL.search(line)
        if not match:
            continue
        try:
            host = urlsplit(match.group(0)).hostname
        except ValueError:
            continue
        if host:
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
    references=("https://cwe.mitre.org/data/definitions/319.html",),
)
