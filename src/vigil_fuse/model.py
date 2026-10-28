from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

Severity = Literal["critical", "high", "medium", "low", "info", "unknown"]
Confidence = Literal["high", "medium", "low"]
Applicability = Literal["unknown", "candidate", "applicable", "not_applicable"]
ValidationMethod = Literal[
    "static", "generated-config", "advisory-match", "external-tool", "lab", "operator-guided"
]
ValidationStatus = Literal["not-validated", "validated", "not-applicable"]
SeverityBasis = Literal["rule", "upstream-label", "cvss-score", "cvss-vector", "unknown"]


@dataclass(frozen=True)
class SourceFile:
    """Decoded source text and its scan-root-relative display path."""

    path: str
    text: str
    sha256: str = ""
    byte_size: int = 0
    generated_config: bool = False


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
class HardwareArtifact:
    """A recognized hardware design or manufacturing file, not a security finding."""

    path: str
    category: str
    format: str


@dataclass(frozen=True)
class HardwareInventory:
    """Presence-only inventory of hardware artifacts in the selected target scope."""

    scope: str
    artifacts: tuple[HardwareArtifact, ...] = ()
    complete: bool = True

    @property
    def category_counts(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for artifact in self.artifacts:
            counts[artifact.category] = counts.get(artifact.category, 0) + 1
        return dict(sorted(counts.items()))


@dataclass(frozen=True)
class PlatformIOEnvironment:
    """Allow-listed metadata for one declared PlatformIO environment."""

    name: str
    platform: str | None = None
    board: str | None = None
    frameworks: tuple[str, ...] = ()
    build_type: str | None = None
    upload_protocol: str | None = None
    debug_tool: str | None = None
    extends: str | None = None


@dataclass(frozen=True)
class PlatformIOInventory:
    status: Literal["not-detected", "parsed", "partial", "invalid"] = "not-detected"
    path: str | None = None
    sha256: str | None = None
    byte_size: int = 0
    default_environments: tuple[str, ...] = ()
    selected_environments: tuple[str, ...] = ()
    environments: tuple[PlatformIOEnvironment, ...] = ()
    limitations: tuple[str, ...] = ()


@dataclass(frozen=True)
class CompilationDatabaseInventory:
    """Metadata-only index of a compile_commands.json file. Commands are never run."""

    status: Literal["not-detected", "indexed", "partial", "invalid"] = "not-detected"
    path: str | None = None
    sha256: str | None = None
    byte_size: int = 0
    entry_count: int = 0
    unique_translation_units: int = 0
    in_target_source_count: int = 0
    external_source_count: int = 0
    compiler_families: dict[str, int] = field(default_factory=dict)
    malformed_entries: int = 0
    limitations: tuple[str, ...] = ()


@dataclass(frozen=True)
class HardwareBOMComponent:
    reference: str
    name: str
    quantity: int
    footprint: str | None = None
    manufacturer: str | None = None
    part_number: str | None = None
    description: str | None = None


@dataclass(frozen=True)
class HardwareBOMInventory:
    status: Literal["not-requested", "imported", "partial", "invalid"] = "not-requested"
    source_path: str | None = None
    sha256: str | None = None
    byte_size: int = 0
    format: str | None = None
    component_count: int = 0
    quantity_total: int = 0
    components: tuple[HardwareBOMComponent, ...] = ()
    limitations: tuple[str, ...] = ()


@dataclass(frozen=True)
class DependencyComponent:
    name: str
    version: str
    ecosystem: str
    purl: str | None = None


@dataclass(frozen=True)
class VexReview:
    state: str
    justification: str | None = None
    detail: str | None = None


@dataclass(frozen=True)
class VexImport:
    status: Literal["not-requested", "imported", "partial", "invalid"] = "not-requested"
    source_path: str | None = None
    sha256: str | None = None
    byte_size: int = 0
    product_purl: str | None = None
    record_count: int = 0
    matched_findings: int = 0
    unmatched_records: int = 0
    limitations: tuple[str, ...] = ()


@dataclass(frozen=True)
class ProvenanceRecord:
    status: Literal["not-requested", "unverified", "subject-match", "subject-mismatch", "invalid"] = "not-requested"
    source_path: str | None = None
    sha256: str | None = None
    byte_size: int = 0
    predicate_type: str | None = None
    builder_id: str | None = None
    build_type: str | None = None
    subject_name: str | None = None
    subject_sha256: str | None = None
    signature_verified: bool = False
    limitations: tuple[str, ...] = ()


@dataclass(frozen=True)
class ContextArtifact:
    """A bounded, selected build-context file recorded by a platform adapter."""

    path: str
    role: str
    sha256: str | None
    byte_size: int


@dataclass(frozen=True)
class ContextSetting:
    """A small allow-listed setting read from selected generated configuration."""

    name: str
    value: str
    path: str
    line: int


@dataclass(frozen=True)
class ConfigurationDefault:
    """A candidate ESP-IDF defaults file in the observed processing order."""

    path: str
    order: int
    target_specific: bool
    state: Literal["present", "missing", "outside-target", "unreadable"]
    sha256: str | None = None
    byte_size: int = 0


@dataclass(frozen=True)
class ConfigurationOrigin:
    """Evidence describing the selected ESP-IDF config and defaults provenance."""

    status: Literal["not-inspected", "selected", "candidates-only", "partial", "unresolved"] = "not-inspected"
    selected_sdkconfig: str | None = None
    selected_sdkconfig_source: Literal["cmake-cache", "project-default", "unresolved", "none"] = "none"
    defaults_source: Literal["cmake-cache", "conventional-candidate", "unavailable", "not-applicable"] = "not-applicable"
    defaults_order_resolved: bool = False
    default_files: tuple[ConfigurationDefault, ...] = ()
    limitations: tuple[str, ...] = ()


@dataclass(frozen=True)
class ResolvedComponent:
    """An ESP-IDF component version recorded in dependencies.lock."""

    name: str
    version: str
    source_type: str
    direct: bool
    component_hash: str | None = None
    compatible_targets: tuple[str, ...] = ()
    dependencies: tuple[str, ...] = ()


@dataclass(frozen=True)
class ComponentLockInventory:
    """Validated metadata from an ESP-IDF Component Manager lock file."""

    status: Literal[
        "not-detected", "partial", "parser-unavailable", "invalid",
        "target-matches", "target-mismatch", "target-unverified",
    ] = "not-detected"
    path: str | None = None
    sha256: str | None = None
    byte_size: int = 0
    lock_version: str | None = None
    target: str | None = None
    selected_target_match: bool | None = None
    manifest_hash: str | None = None
    manifest_freshness: Literal["unverified", "missing"] = "unverified"
    direct_dependencies: tuple[str, ...] = ()
    components: tuple[ResolvedComponent, ...] = ()
    limitations: tuple[str, ...] = ()


@dataclass(frozen=True)
class ProjectContext:
    """Evidence about a selected ESP-IDF or Zephyr project/build context."""

    framework: str | None = None
    status: str = "not-detected"
    project_detected: bool = False
    build_dir: str | None = None
    target: str | None = None
    board: str | None = None
    framework_version: str | None = None
    evidence: tuple[str, ...] = ()
    configuration_files: tuple[ContextArtifact, ...] = ()
    settings: tuple[ContextSetting, ...] = ()
    configuration_origin: ConfigurationOrigin = ConfigurationOrigin()
    component_lock: ComponentLockInventory = ComponentLockInventory()
    limitations: tuple[str, ...] = ()


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
    applicability: Applicability = "unknown"
    validation_method: ValidationMethod = "static"
    validation_status: ValidationStatus = "not-validated"
    severity_basis: SeverityBasis = "rule"
    severity_score: float | None = None
    severity_vector: str | None = None
    severity_version: str | None = None
    component: DependencyComponent | None = None
    vex_review: VexReview | None = None

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
            "applicability": self.applicability,
            "validation_method": self.validation_method,
            "validation_status": self.validation_status,
            "severity_basis": self.severity_basis,
            "severity_score": self.severity_score,
            "severity_vector": self.severity_vector,
            "severity_version": self.severity_version,
            "component": (
                {
                    "name": self.component.name,
                    "version": self.component.version,
                    "ecosystem": self.component.ecosystem,
                    "purl": self.component.purl,
                }
                if self.component
                else None
            ),
            "vex_review": (
                {
                    "state": self.vex_review.state,
                    "justification": self.vex_review.justification,
                    "detail": self.vex_review.detail,
                }
                if self.vex_review
                else None
            ),
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
    unsupported_file_types: dict[str, int] = field(default_factory=dict)
    hardware_inventory: HardwareInventory = HardwareInventory(scope="single-file")
    project_context: ProjectContext = ProjectContext()
    platformio_inventory: PlatformIOInventory = PlatformIOInventory()
    compilation_database: CompilationDatabaseInventory = CompilationDatabaseInventory()
    hardware_bom: HardwareBOMInventory = HardwareBOMInventory()
    product_purl: str | None = None
    vex_import: VexImport = VexImport()
    provenance: ProvenanceRecord = ProvenanceRecord()
    network_policy: str = "not-requested"
    source_bytes_read: int = 0
    discovery_complete: bool = True
    limits_reached: tuple[str, ...] = ()
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
