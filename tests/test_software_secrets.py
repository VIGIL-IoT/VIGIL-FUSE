from __future__ import annotations

import json
import subprocess
from pathlib import Path
from unittest.mock import patch

import pytest

from vigil_fuse.cli import main
from vigil_fuse.analyzer_runtime import AdapterResult
from vigil_fuse.model import AnalyzerStatus
from vigil_fuse.software_secrets import parse_trivy_secrets, run_trivy_secrets

_SECRET = "AKIAIOSFODNN7EXAMPLE"


def _report(target: str = "/fuse/input/config/credentials.env") -> dict[str, object]:
    return {
        "SchemaVersion": 2,
        "Results": [
            {
                "Target": target,
                "Secrets": [
                    {
                        "RuleID": "aws-access-key-id",
                        "Category": "AWS",
                        "Severity": "HIGH",
                        "Title": "AWS Access Key ID",
                        "StartLine": 4,
                        "EndLine": 4,
                        "Match": f"AWS_ACCESS_KEY_ID={_SECRET}",
                        "Code": {"Lines": [{"Number": 4, "Content": f"key={_SECRET}"}]},
                    }
                ],
            }
        ],
    }


def test_trivy_secret_parser_discards_match_and_source_snippets(tmp_path: Path) -> None:
    findings = parse_trivy_secrets(json.dumps(_report()), tmp_path, "Trivy test")

    assert len(findings) == 1
    finding = findings[0]
    assert finding.analyzer == "trivy-secrets"
    assert finding.engine_rule_id == "aws-access-key-id"
    assert finding.file == "config/credentials.env"
    assert finding.start_line == finding.end_line == 4
    assert finding.severity == "high"
    assert finding.external_severity == "HIGH"
    assert finding.severity_basis == "upstream-label"
    assert _SECRET not in repr(finding)


@pytest.mark.parametrize(
    "target", ["/fuse/input/../outside", "../outside", "C:/outside", "/etc/passwd"]
)
def test_trivy_secret_parser_rejects_paths_outside_target(tmp_path: Path, target: str) -> None:
    with pytest.raises(ValueError):
        parse_trivy_secrets(json.dumps(_report(target)), tmp_path, "test")


def test_trivy_secret_parser_rejects_duplicate_keys_and_malformed_lines(tmp_path: Path) -> None:
    with pytest.raises(ValueError):
        parse_trivy_secrets('{"SchemaVersion":2,"Results":[],"Results":[]}', tmp_path, "test")
    malformed = _report()
    result = malformed["Results"][0]  # type: ignore[index]
    result["Secrets"][0]["StartLine"] = 0  # type: ignore[index]
    with pytest.raises(ValueError):
        parse_trivy_secrets(json.dumps(malformed), tmp_path, "test")


def test_trivy_secrets_requires_sandbox_and_uses_offline_safe_flags(tmp_path: Path) -> None:
    with (
        patch("vigil_fuse.software_secrets.analyzer_sandbox_active", return_value=False),
        patch("vigil_fuse.software_secrets._run") as runner,
    ):
        assert run_trivy_secrets(tmp_path).status.status == "skipped"
        runner.assert_not_called()

    completed = subprocess.CompletedProcess([], 0, json.dumps(_report()), "")
    with (
        patch("vigil_fuse.software_secrets.analyzer_sandbox_active", return_value=True),
        patch("vigil_fuse.software_secrets.resolve_analyzer_executable", return_value="trivy"),
        patch("vigil_fuse.software_secrets._tool_version", return_value="Version: test"),
        patch("vigil_fuse.software_secrets._run", return_value=completed) as runner,
    ):
        result = run_trivy_secrets(tmp_path)

    command = runner.call_args.args[0]
    assert command[:2] == ["trivy", "fs"]
    assert command[command.index("--scanners") + 1] == "secret"
    assert {"--config=", "--ignorefile=", "--secret-config="} <= set(command)
    assert {
        "--skip-db-update",
        "--skip-check-update",
        "--skip-version-check",
        "--disable-telemetry",
    } <= set(command)
    assert result.status.status == "partial"
    assert result.status.version == "Version: test"
    assert _SECRET not in repr(result)


def test_trivy_secrets_are_exposed_as_an_explicit_plan_stage(tmp_path: Path, capsys) -> None:
    with (
        patch("vigil_fuse.cli.shutil.which", return_value="docker"),
        patch("vigil_fuse.cli._optional_analyzer_available", return_value=True),
    ):
        result = main(
            [
                "scan",
                str(tmp_path),
                "--plan",
                "--format",
                "json",
                "--trivy-secrets",
                "--analyzer-sandbox",
                "docker",
                "--sandbox-image",
                "trivy=sha256:" + "a" * 64,
            ],
            _show_banner=False,
        )

    plan = json.loads(capsys.readouterr().out)
    stage = next(item for item in plan["stages"] if item["name"] == "trivy-secrets")
    assert result == 0
    assert stage["requested"] is True
    assert stage["status"] == "planned"
    assert plan["executed"] is False


def test_cli_routes_trivy_secret_findings_and_only_persists_redacted_evidence(
    tmp_path: Path,
) -> None:
    target = tmp_path / "source"
    target.mkdir()
    output = tmp_path / "report"
    findings = parse_trivy_secrets(json.dumps(_report()), target, "test")
    result = AdapterResult(
        AnalyzerStatus("trivy-secrets", "partial", detail="coverage is partial", findings=1),
        findings=findings,
    )
    captured = []
    with (
        patch(
            "vigil_fuse.cli.shutil.which",
            side_effect=lambda name: "docker" if name == "docker" else None,
        ),
        patch("vigil_fuse.cli.run_trivy_secrets", return_value=result) as run_secrets,
    ):
        exit_code = main(
            [
                "scan",
                str(target),
                "--trivy-secrets",
                "--analyzer-sandbox",
                "docker",
                "--sandbox-image",
                "trivy=sha256:" + "a" * 64,
                "--output-dir",
                str(output),
            ],
            _show_banner=False,
            _result_callback=lambda report, _: captured.append(report),
        )

    assert exit_code == 2
    run_secrets.assert_called_once()
    report = json.loads((output / "findings.json").read_text(encoding="utf-8"))
    assert report["software_security"]["lanes"]["trivy_secrets"] == "partial"
    persisted = "".join(
        path.read_text(encoding="utf-8") for path in output.iterdir() if path.is_file()
    )
    assert _SECRET not in persisted
