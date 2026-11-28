from __future__ import annotations

import re
from collections.abc import Iterable
from pathlib import PurePosixPath

from ..model import Finding, SourceFile
from .base import RuleDefinition


def _supported(source: SourceFile) -> bool:
    name = PurePosixPath(source.path).name.casefold()
    return name == "dockerfile" or name.startswith("dockerfile.")


def _scan(source: SourceFile, rule: RuleDefinition) -> Iterable[Finding]:
    if not _supported(source):
        return
    for line_number, line in enumerate(source.text.splitlines(), 1):
        # Only an explicit, literal latest tag is recognized; no variable expansion.
        match = re.fullmatch(
            r"\s*(?i:FROM)\s+(?:--platform=\S+\s+)?([a-zA-Z0-9._/-]+:latest)(?:\s+(?i:AS)\s+[a-zA-Z0-9._-]+)?\s*(?:#.*)?",
            line,
        )
        if match:
            yield rule.finding(source, line_number, "Dockerfile FROM uses an explicit latest tag")


RULE = RuleDefinition(
    id="FUSE-SW002",
    title="Dockerfile uses a mutable latest image tag",
    severity="low",
    confidence="high",
    category="container-configuration",
    explanation="A Dockerfile FROM instruction explicitly references the mutable latest tag. FUSE does not pull or inspect the image.",
    potential_impact="The image selected by future builds may change without a source change.",
    remediation="Pin a reviewed image digest and update it through a controlled process.",
    scanner=_scan,
    prefilter=lambda source: _supported(source) and ":latest" in source.text.casefold(),
)
