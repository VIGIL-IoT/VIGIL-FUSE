"""Backward-compatible entry points for FUSE's optional analyzer adapters."""

from .analyzer_runtime import (
    AdapterResult,
    AnalyzerOutputLimitError,
    inspect_tools,
)
from .dependency_analyzers import (
    generate_sbom,
    osv_findings,
    scan_vulnerabilities,
)
from .firmware_analyzer import identify_firmware
from .history_analyzer import scan_git_history

__all__ = (
    "AdapterResult",
    "AnalyzerOutputLimitError",
    "generate_sbom",
    "identify_firmware",
    "inspect_tools",
    "osv_findings",
    "scan_git_history",
    "scan_vulnerabilities",
)
