"""Exercise the evidence handoff without an external lab or live analyzer."""

from __future__ import annotations

import hashlib
import json
from importlib.resources import files
from pathlib import Path
from typing import Any
from unittest.mock import patch

from jsonschema import Draft202012Validator

from vigil_fuse.baseline import create_baseline
from vigil_fuse.cli import main
from vigil_fuse.policy import OpaInfo
from vigil_fuse.reasoning.config import ReasoningConfig
from vigil_fuse.reasoning.engine import reason_report


def test_scan_policy_context_reasoning_and_baseline_preserve_canonical_evidence(
    tmp_path: Path,
) -> None:
    target = tmp_path / "project"
    target.mkdir()
    (target / "main.c").write_text('const char *endpoint = "http://device.local";\n')
    output = tmp_path / "reports"
    with (
        patch("vigil_fuse.policy.inspect_opa", return_value=OpaInfo(None, None)),
        patch("vigil_fuse.reasoning.ollama.Ollama._request") as model_request,
    ):
        assert (
            main(
                [
                    "scan",
                    str(target),
                    "--no-network",
                    "--no-sbom",
                    "--no-vulnerabilities",
                    "--no-firmware",
                    "--no-ghidra",
                    "--no-git-history",
                    "--policy",
                    "reference:production-iot",
                    "--output-dir",
                    str(output),
                ]
            )
            == 2  # Missing OPA preserves UNKNOWN and its documented exit status.
        )
        model_request.assert_not_called()
    canonical = output / "findings.json"
    raw = canonical.read_bytes()
    report = json.loads(raw)
    assert report["coverage"]["discovery_complete"] is True
    assert report["summary"]["files_scanned"] == 1
    assert {f["rule_id"] for f in report["findings"]} == {"FUSE004"}
    assert report["findings"][0]["applicability"] == "unknown"
    assert json.loads((output / "policy-results.json").read_bytes())["status"] == "unknown"
    assert (output / "findings.txt").is_file()
    assert json.loads((output / "findings.sarif").read_bytes())["version"] == "2.1.0"
    schema = json.loads(
        files("vigil_fuse").joinpath("schemas/fuse-report-1.12.schema.json").read_text()
    )
    Draft202012Validator(schema).validate(report)
    context_path = tmp_path / "context.json"
    assert (
        main(
            [
                "reasoning-context",
                str(canonical),
                "--finding",
                report["findings"][0]["id"],
                "--output",
                str(context_path),
            ]
        )
        == 0
    )
    context = json.loads(context_path.read_bytes())
    context_schema = json.loads(
        files("vigil_fuse").joinpath("schemas/reasoning-context-v1.schema.json").read_text()
    )
    Draft202012Validator(context_schema).validate(context)

    def explain(packet: dict[str, Any]) -> bytes:
        return json.dumps(
            {
                "summary": "Static evidence requires review.",
                "reasoning": "Runtime behavior remains unknown.",
                "missing_evidence": [
                    {"item": "Runtime validation is missing.", "importance": "high"}
                ],
                "recommended_checks": ["Review the selected source."],
                "remediation": [],
                "limitations": ["Static evidence does not establish runtime behavior."],
                "evidence_ids": [packet["evidence"]["supported"][0]["id"]],
                "unknown_evidence_ids": [item["id"] for item in packet["evidence"]["unknown"]],
            }
        ).encode()

    with (
        patch(
            "vigil_fuse.reasoning.ollama.Ollama.inspect",
            return_value={"available": True, "installed": True},
        ),
        patch("vigil_fuse.reasoning.ollama.Ollama.generate", side_effect=explain),
    ):
        artifact = reason_report(raw, ReasoningConfig())
    assert artifact["findings"][0]["reasoning_status"] == "completed"
    assert artifact["findings"][0]["severity"] == report["findings"][0]["severity"]
    assert artifact["source_report_sha256"] == hashlib.sha256(raw).hexdigest()
    assert create_baseline(canonical, tmp_path / "baseline.json") == 0
    assert canonical.read_bytes() == raw
