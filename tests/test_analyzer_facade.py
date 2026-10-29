from __future__ import annotations

from vigil_fuse import analyzers
from vigil_fuse import analyzer_runtime, dependency_analyzers, firmware_analyzer, history_analyzer


def test_analyzer_facade_preserves_explicit_public_adapter_exports() -> None:
    expected = {
        "AdapterResult": analyzer_runtime.AdapterResult,
        "AnalyzerOutputLimitError": analyzer_runtime.AnalyzerOutputLimitError,
        "generate_sbom": dependency_analyzers.generate_sbom,
        "identify_firmware": firmware_analyzer.identify_firmware,
        "inspect_tools": analyzer_runtime.inspect_tools,
        "osv_findings": dependency_analyzers.osv_findings,
        "scan_git_history": history_analyzer.scan_git_history,
        "scan_vulnerabilities": dependency_analyzers.scan_vulnerabilities,
    }

    assert set(analyzers.__all__) == set(expected)
    for name, implementation in expected.items():
        assert getattr(analyzers, name) is implementation
