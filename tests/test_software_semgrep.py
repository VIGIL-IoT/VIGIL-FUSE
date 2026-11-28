import json
import subprocess
from pathlib import Path
from unittest.mock import patch

import pytest

from vigil_fuse.software_semgrep import parse_semgrep, run_semgrep


def result(path: str = "app.py") -> dict:
    return {
        "version": "1.0",
        "results": [
            {
                "check_id": "python.example.rule",
                "path": path,
                "start": {"line": 3},
                "end": {"line": 3},
                "extra": {
                    "severity": "WARNING",
                    "message": "SECRET_DO_NOT_STORE",
                    "metadata": {"cwe": ["CWE-78: Command Injection"]},
                },
            }
        ],
        "errors": [],
    }


def test_normalizes_without_persisting_source_or_message(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text("pass\n", encoding="utf-8")
    findings, partial = parse_semgrep(json.dumps(result()), tmp_path, "test")
    assert not partial
    assert findings[0].analyzer == "semgrep"
    assert findings[0].severity == "medium"
    assert findings[0].applicability == "candidate"
    assert findings[0].references == ("https://cwe.mitre.org/data/definitions/78.html",)
    assert "SECRET_DO_NOT_STORE" not in repr(findings)


def test_rejects_untrusted_outputs(tmp_path: Path) -> None:
    for data in (
        '{"results":[],"results":[],"errors":[]}',
        "{",
        json.dumps(result("../outside.py")),
    ):
        with pytest.raises(ValueError):
            parse_semgrep(data, tmp_path, "test")


def test_optional_execution_and_strict_offline(tmp_path: Path) -> None:
    config = tmp_path / "rules.yml"
    config.write_text("rules: []", encoding="utf-8")
    with (
        patch("vigil_fuse.software_semgrep.shutil.which", return_value="semgrep"),
        patch("vigil_fuse.software_semgrep.inspect_tool_version", return_value="1.0"),
        patch(
            "vigil_fuse.software_semgrep.run_bounded_host_tool",
            return_value=subprocess.CompletedProcess([], 0, json.dumps(result()), ""),
        ) as invoke,
    ):
        assert run_semgrep(tmp_path, config, no_network=True).status.status == "skipped"
        invoke.assert_not_called()
        analysis = run_semgrep(tmp_path, config, no_network=False)
        assert analysis.status.status == "partial"
        assert len(analysis.findings) == 1
        assert analysis.status.configuration_sha256 is not None
        assert "--metrics=off" in invoke.call_args.args[0]


def test_remote_rule_inheritance_is_rejected_before_semgrep_runs(tmp_path: Path) -> None:
    config = tmp_path / "rules.yml"
    config.write_text("extends: p/security-audit\nrules: []\n", encoding="utf-8")

    with (
        patch("vigil_fuse.software_semgrep.shutil.which", return_value="semgrep"),
        patch("vigil_fuse.software_semgrep.inspect_tool_version", return_value="1.0"),
        patch("vigil_fuse.software_semgrep.run_bounded_host_tool") as invoke,
    ):
        result = run_semgrep(tmp_path, config, no_network=False)

    assert result.status.status == "failed"
    invoke.assert_not_called()
