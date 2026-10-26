from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

Severity = Literal["critical", "high", "medium", "low", "info", "unknown"]
Confidence = Literal["high", "medium", "low"]


@dataclass(frozen=True)
class SourceFile:
    """Decoded source text and its scan-root-relative display path."""

    path: str
    text: str
    sha256: str = ""


@dataclass(frozen=True)
class AnalyzerStatus:
    name: str
    status: Literal["completed", "partial", "unavailable", "skipped", "failed"]
    version: str | None = None
    detail: str | None = None
    findings: int = 0


@dataclass(frozen=True)
class AnalysisArtifact:
    """A report or inventory emitted by an analyzer."""

    path: str
    media_type: str
    sha256: str


@dataclass(frozen=True)
class Finding:
    id: str
    fingerprint: str
    rule_id: str
    rule_version: str
    analyzer: str
    title: str
    severity: Severity
    confidence: Confidence
    category: str
    file: str
    start_line: int | None
    end_line: int | None
    evidence: str
    explanation: str
    potential_impact: str
    remediation: str
    references: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, object]:
        return {
            "id": self.id,
            "fingerprint": self.fingerprint,
            "rule_id": self.rule_id,
            "rule_version": self.rule_version,
            "analyzer": self.analyzer,
            "title": self.title,
            "severity": self.severity,
            "confidence": self.confidence,
            "category": self.category,
            "location": {
                "file": self.file,
                "start_line": self.start_line,
                "end_line": self.end_line,
            },
            "evidence": self.evidence,
            "explanation": self.explanation,
            "potential_impact": self.potential_impact,
            "remediation": self.remediation,
            "references": list(self.references),
        }


@dataclass(frozen=True)
class ScanResult:
    target: str
    target_kind: str
    profile: str
    started_at: str
    completed_at: str
    input_manifest_sha256: str
    files_discovered: int
    files_selected: int
    files_filtered: int
    files_scanned: int
    files_skipped_by_reason: dict[str, int]
    rules_available: tuple[str, ...]
    rules_enabled: tuple[str, ...]
    analyzers: tuple[AnalyzerStatus, ...]
    findings: tuple[Finding, ...]
    artifacts: tuple[AnalysisArtifact, ...] = ()

    @property
    def files_skipped(self) -> int:
        return sum(self.files_skipped_by_reason.values())

    @property
    def analysis_performed(self) -> bool:
        return (self.files_scanned > 0 and bool(self.rules_enabled)) or any(
            analyzer.status in {"completed", "partial"} and analyzer.name != "fuse-native"
            for analyzer in self.analyzers
        )
