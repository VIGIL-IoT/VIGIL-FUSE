from __future__ import annotations

from dataclasses import dataclass
import hashlib
import re
from typing import Callable, Iterable

from ..model import Confidence, Finding, Severity, SourceFile

Scanner = Callable[[SourceFile, "RuleDefinition"], Iterable[Finding]]


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
        )

    def scan(self, source: SourceFile) -> Iterable[Finding]:
        return self.scanner(source, self)


def is_comment_line(line: str) -> bool:
    stripped = line.lstrip()
    if stripped.startswith("#") and re.match(
        r"#\s*(?:define|undef|if|ifdef|ifndef|elif|else|endif|include|pragma|error|line)\b",
        stripped,
        re.IGNORECASE,
    ):
        return False
    return stripped.startswith(("#", "//", "/*", "*", ";", "<!--"))
