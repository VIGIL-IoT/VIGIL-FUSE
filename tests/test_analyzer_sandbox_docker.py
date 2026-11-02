from __future__ import annotations

import json
import os
import subprocess
import tempfile
from pathlib import Path

import pytest

from vigil_fuse.cli import main


def test_docker_sandbox_integration_with_local_fixture_image() -> None:
    image = os.environ.get("FUSE_SANDBOX_SMOKE_IMAGE")
    if not image:
        pytest.skip("Set FUSE_SANDBOX_SMOKE_IMAGE to a locally built fixture image ID")

    with tempfile.TemporaryDirectory() as temporary:
        target = Path(temporary) / "embedded-project"
        target.mkdir()
        (target / "main.c").write_text("int main(void) { return 0; }\n", encoding="utf-8")
        output = target / ".fuse-results"
        output.mkdir()
        previous_report = output / "previous-report.json"
        previous_report.write_text('{"old":true}\n', encoding="utf-8")

        exit_code = main(
            [
                "scan",
                str(target),
                "--sbom",
                "--analyzer-sandbox",
                "docker",
                "--sandbox-image",
                f"syft={image}",
                "--output-dir",
                str(output),
                "--format",
                "json",
            ]
        )

        assert exit_code == 0
        report = json.loads((output / "findings.json").read_text(encoding="utf-8"))
        syft = next(item for item in report["coverage"]["analyzers"] if item["name"] == "syft")
        assert syft["status"] == "completed"
        assert "Docker sandbox:" in syft["detail"]
        assert previous_report.read_text(encoding="utf-8") == '{"old":true}\n'

        sbom_path = output / "components.cdx.json"
        sbom = json.loads(sbom_path.read_text(encoding="utf-8"))
        assert sbom["bomFormat"] == "CycloneDX"
        assert report["artifacts"][0]["path"] == "components.cdx.json"
        assert report["artifacts"][0]["sha256"]

        remaining = subprocess.run(
            [
                "docker",
                "ps",
                "--all",
                "--filter",
                "name=vigil-fuse-analyzer-",
                "--format",
                "{{.Names}}",
            ],
            check=True,
            capture_output=True,
            text=True,
        )
        assert not remaining.stdout.strip()
