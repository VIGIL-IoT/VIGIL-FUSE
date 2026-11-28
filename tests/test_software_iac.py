import json
import subprocess
from pathlib import Path
from unittest.mock import patch

import pytest

from vigil_fuse.software_iac import parse_trivy, run_trivy_config


def document(path: str = "/fuse/input/Dockerfile") -> dict:
    return {
        "SchemaVersion": 2,
        "Results": [
            {
                "Target": path,
                "Misconfigurations": [
                    {
                        "ID": "AVD-DS-0002",
                        "Severity": "HIGH",
                        "Status": "FAIL",
                        "Message": "SECRET_NOT_STORED",
                        "CauseMetadata": {"StartLine": 3, "EndLine": 3},
                    }
                ],
            }
        ],
    }


def test_config_normalization_and_unsafe_paths(tmp_path: Path) -> None:
    findings = parse_trivy(json.dumps(document()), tmp_path, "test")
    assert findings[0].engine_rule_id == "AVD-DS-0002"
    assert findings[0].severity == "high"
    assert findings[0].file == "Dockerfile"
    assert "SECRET_NOT_STORED" not in repr(findings)
    with pytest.raises(ValueError):
        parse_trivy(json.dumps(document("../outside")), tmp_path, None)


def test_trivy_requires_sandbox_and_reports_partial(tmp_path: Path) -> None:
    with (
        patch("vigil_fuse.software_iac.analyzer_sandbox_active", return_value=False),
        patch("vigil_fuse.software_iac._run") as runner,
    ):
        assert run_trivy_config(tmp_path).status.status == "skipped"
        runner.assert_not_called()
    with (
        patch("vigil_fuse.software_iac.analyzer_sandbox_active", return_value=True),
        patch("vigil_fuse.software_iac.resolve_analyzer_executable", return_value="trivy"),
        patch("vigil_fuse.software_iac._tool_version", return_value="test"),
        patch(
            "vigil_fuse.software_iac._run",
            return_value=subprocess.CompletedProcess([], 0, json.dumps(document()), ""),
        ) as runner,
    ):
        result = run_trivy_config(tmp_path)
        assert result.status.status == "partial"
        assert len(result.findings) == 1
        assert "--skip-check-update" in runner.call_args.args[0]
