import importlib
import json
import subprocess
from pathlib import Path
from unittest.mock import patch

import pytest

from vigil_fuse.analyzer_runtime import AnalyzerOutputLimitError
from vigil_fuse.reasoning.context import build_context, load_report
from vigil_fuse.reporting import to_json
from vigil_fuse.scanner import scan


@pytest.mark.parametrize("name", ["semgrep", "codeql", "iac", "secrets", "container_image"])
@pytest.mark.parametrize("failure", ["timeout", "overflow", "invalid", "exit"])
def test_requested_adapter_failures_never_mean_clean(tmp_path: Path, name: str, failure: str):
    module = importlib.import_module("vigil_fuse.software_" + name)
    config = tmp_path / "rules.qls"
    config.write_text("rules: []", encoding="utf-8")
    database = tmp_path / "database"
    database.mkdir()
    source = tmp_path / "source"
    source.mkdir()
    runner = "run_bounded_host_tool" if name in {"semgrep", "codeql"} else "_run"
    version = "inspect_tool_version" if name in {"semgrep", "codeql"} else "_tool_version"
    error = (
        subprocess.TimeoutExpired("tool", 180)
        if failure == "timeout"
        else AnalyzerOutputLimitError("bounded")
        if failure == "overflow"
        else None
    )
    with (
        patch.object(module, version, return_value="fixture"),
        patch.object(
            module,
            runner,
            side_effect=error,
            return_value=subprocess.CompletedProcess(
                [], 1 if failure == "exit" else 0, "invalid", "PRIVATE_DIAGNOSTIC"
            ),
        ),
    ):
        if name in {"semgrep", "codeql"}:
            with patch.object(module.shutil, "which", return_value="tool"):
                result = (
                    module.run_semgrep(source, config, no_network=False)
                    if name == "semgrep"
                    else module.run_codeql(source, database, config, no_network=False)
                )
        else:
            with (
                patch.object(
                    module, "analyzer_sandbox_active", return_value=name != "container_image"
                ),
                patch.object(module, "resolve_analyzer_executable", return_value="tool"),
            ):
                result = (
                    module.run_trivy_config(source)
                    if name == "iac"
                    else module.run_trivy_secrets(source)
                    if name == "secrets"
                    else module.run_trivy_image("local:test")
                )
    assert result.status.status == ("timeout" if failure == "timeout" else "failed")
    assert not result.findings
    assert "PRIVATE_DIAGNOSTIC" not in repr(result)


def test_trivy_secret_is_withheld_from_reasoning(tmp_path: Path):
    from dataclasses import replace
    from vigil_fuse.software_secrets import parse_trivy_secrets

    value = "private short credential"
    raw = {
        "SchemaVersion": 2,
        "Results": [
            {
                "Target": "app.py",
                "Secrets": [
                    {
                        "RuleID": "generic-api-key",
                        "Severity": "HIGH",
                        "StartLine": 1,
                        "EndLine": 1,
                        "Match": value,
                        "Code": {"Lines": [value]},
                    }
                ],
            }
        ],
    }
    (tmp_path / "app.py").write_text("pass\n", encoding="utf-8")
    findings = parse_trivy_secrets(json.dumps(raw), tmp_path, "fixture")
    report = load_report(to_json(replace(scan(tmp_path), findings=findings)).encode())
    context = build_context(report, report["findings"][0])
    assert value not in json.dumps(report)
    assert value not in json.dumps(context)
    assert "secret-finding" in context["redacted_categories"]
