from __future__ import annotations

import json
import subprocess
from pathlib import Path
from unittest.mock import patch

from jsonschema import Draft202012Validator
from vigil_fuse.analyzer_runtime import AdapterResult
from vigil_fuse.cli import main
from vigil_fuse.model import AnalyzerStatus, DependencyComponent, Finding, SoftwareComponent
from vigil_fuse.software_container_image import run_trivy_image


def _trivy_report() -> dict[str, object]:
    return {
        "SchemaVersion": 2,
        "ArtifactType": "container_image",
        "Results": [
            {
                "Target": "private-registry.invalid/team/api:release",
                "Type": "npm",
                "Packages": [
                    {
                        "Name": "demo",
                        "Version": "1.2.0",
                        "Type": "npm",
                        "Identifier": {"PURL": "pkg:npm/demo@1.2.0"},
                    }
                ],
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": "CVE-2026-12345",
                        "PkgName": "demo",
                        "InstalledVersion": "1.2.0",
                        "FixedVersion": "1.2.1",
                        "PkgType": "npm",
                        "PkgIdentifier": {"PURL": "pkg:npm/demo@1.2.0"},
                        "Severity": "HIGH",
                        "CweIDs": ["CWE-79", "bad"],
                        "PrimaryURL": "https://example.invalid/advisory/CVE-2026-12345",
                        "References": ["http://unsafe.invalid/ignore"],
                    }
                ],
            }
        ],
    }


def test_trivy_image_adapter_uses_local_only_offline_contract() -> None:
    completed = subprocess.CompletedProcess(["trivy"], 0, json.dumps(_trivy_report()), "")
    with (
        patch("vigil_fuse.software_container_image.shutil.which", return_value="trivy"),
        patch(
            "vigil_fuse.software_container_image._tool_version",
            return_value="Version: 0.test",
        ),
        patch("vigil_fuse.software_container_image._run", return_value=completed) as run,
    ):
        result = run_trivy_image("demo:1.2.0")

    command = run.call_args.args[0]
    assert command[command.index("--image-src") + 1] == "docker"
    assert command[command.index("--scanners") + 1] == "vuln"
    assert {
        "--offline-scan",
        "--skip-db-update",
        "--skip-java-db-update",
        "--skip-check-update",
        "--skip-vex-repo-update",
        "--disable-telemetry",
        "--skip-version-check",
    } <= set(command)
    assert command[-1] == "demo:1.2.0"
    assert result.status.status == "completed"
    assert result.status.version == "Version: 0.test"
    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.rule_id == "TRIVY-CVE-2026-12345"
    assert finding.engine_rule_id == "CVE-2026-12345"
    assert finding.severity == "high"
    assert finding.external_severity == "HIGH"
    assert finding.severity_basis == "upstream-label"
    assert finding.cwe == ("CWE-79",)
    assert finding.component == DependencyComponent("demo", "1.2.0", "npm", "pkg:npm/demo@1.2.0")
    assert finding.applicability == "unknown"
    assert finding.validation_status == "not-validated"
    assert result.software_components == (
        SoftwareComponent("demo", "1.2.0", "npm", "pkg:npm/demo@1.2.0", "Trivy local image report"),
    )
    assert "private-registry" not in finding.evidence
    assert all(url.startswith("https://") for url in finding.references)


def test_trivy_image_adapter_rejects_bad_reference_and_duplicate_json() -> None:
    with patch("vigil_fuse.software_container_image.shutil.which", return_value="trivy"):
        invalid = run_trivy_image("demo:1.2.0; malicious")
    assert invalid.status.status == "failed"
    assert invalid.status.detail == "Image reference has unsupported syntax."

    completed = subprocess.CompletedProcess(
        ["trivy"],
        0,
        '{"ArtifactType":"container_image","Results":[],"Results":[]}',
        "",
    )
    with (
        patch("vigil_fuse.software_container_image.shutil.which", return_value="trivy"),
        patch("vigil_fuse.software_container_image._tool_version", return_value="test"),
        patch("vigil_fuse.software_container_image._run", return_value=completed),
    ):
        duplicate = run_trivy_image("demo:1.2.0")
    assert duplicate.status.status == "failed"
    assert duplicate.findings == ()


def test_container_image_cli_reports_lane_and_redacts_image_reference(tmp_path: Path) -> None:
    target = tmp_path / "project"
    target.mkdir()
    (target / "main.py").write_text("print('ok')\n", encoding="utf-8")
    output = tmp_path / "reports"
    finding = Finding(
        id="TRIVY:CVE-2026-12345:demo@1.2.0:hash",
        fingerprint="a" * 64,
        rule_id="TRIVY-CVE-2026-12345",
        rule_version="1",
        analyzer="trivy",
        title="Container image advisory match: demo@1.2.0 (CVE-2026-12345)",
        severity="high",
        confidence="high",
        category="dependency-vulnerability",
        file="container-image",
        start_line=None,
        end_line=None,
        evidence="Trivy matched npm package demo@1.2.0; reachability is unknown.",
        explanation="Advisory match only.",
        potential_impact="Unknown.",
        remediation="Review the advisory.",
        validation_method="advisory-match",
        component=DependencyComponent("demo", "1.2.0", "npm"),
    )
    adapter = AdapterResult(
        AnalyzerStatus("trivy-image", "completed", findings=1),
        findings=(finding,),
        software_components=(SoftwareComponent("demo", "1.2.0", "npm"),),
    )
    with patch("vigil_fuse.cli.run_trivy_image", return_value=adapter) as run:
        assert (
            main(
                [
                    "scan",
                    str(target),
                    "--container-image",
                    "private-registry.invalid/team/api:release",
                    "--output-dir",
                    str(output),
                    "--format",
                    "json",
                ],
                _show_banner=False,
            )
            == 0
        )

    assert run.called
    report = json.loads((output / "findings.json").read_text(encoding="utf-8"))
    schema_path = Path(__file__).parents[1] / "src/vigil_fuse/schemas/fuse-report-1.15.schema.json"
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    Draft202012Validator(schema).validate(report)
    assert report["software_security"]["lanes"]["container_image"] == "completed"
    assert report["software_security"]["dependency_inventory"]["advisory_match_count"] == 1
    serialized = json.dumps(report)
    assert "private-registry.invalid" not in serialized
    assert report["software_security"]["dependency_inventory"]["status"] == "completed"
