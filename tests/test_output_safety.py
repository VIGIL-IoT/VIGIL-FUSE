from __future__ import annotations

import os
import subprocess
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
from pathlib import Path
from unittest.mock import patch

import pytest

from vigil_fuse.cli import main
from vigil_fuse.dependency_analyzers import generate_sbom
from vigil_fuse.path_safety import safe_write_bytes


def _link_sentinel(alias: Path, sentinel: Path) -> None:
    sentinel.write_text("outside sentinel\n", encoding="utf-8")
    try:
        os.link(sentinel, alias)
    except OSError as error:
        pytest.skip(f"hard links are unavailable on this filesystem: {error}")


def _project(tmp_path: Path) -> Path:
    target = tmp_path / "project"
    target.mkdir()
    (target / "main.c").write_text("int main(void) { return 0; }\n", encoding="utf-8")
    (target / "bom.csv").write_text("Reference,Value,Footprint\nU1,MCU,QFN-32\n", encoding="utf-8")
    return target


def test_safe_writer_refuses_hard_link_without_mutating_its_other_name(tmp_path: Path) -> None:
    sentinel = tmp_path / "outside.txt"
    output = tmp_path / "reports" / "findings.json"
    output.parent.mkdir()
    _link_sentinel(output, sentinel)

    with pytest.raises(OSError, match="hard-linked"):
        safe_write_bytes(output, b'{"safe": true}\n')

    assert sentinel.read_text(encoding="utf-8") == "outside sentinel\n"
    assert output.read_text(encoding="utf-8") == "outside sentinel\n"
    assert os.path.samefile(output, sentinel)


@pytest.mark.parametrize(
    "artifact_name",
    [
        "findings.json",
        "findings.txt",
        "findings.sarif",
        "FUSE_SCAN_PROVENANCE.json",
        "CITATION.cff",
        "hardware-bom.cdx.json",
    ],
)
def test_fixed_report_and_bom_writers_refuse_hard_links(tmp_path: Path, artifact_name: str) -> None:
    target = _project(tmp_path)
    output = tmp_path / "reports"
    output.mkdir()
    alias = output / artifact_name
    sentinel = tmp_path / f"outside-{artifact_name}"
    _link_sentinel(alias, sentinel)
    arguments = ["scan", str(target), "--output-dir", str(output)]
    if artifact_name == "hardware-bom.cdx.json":
        arguments.extend(["--hardware-bom", "bom.csv"])

    with redirect_stdout(StringIO()), redirect_stderr(StringIO()) as stderr:
        exit_code = main(arguments)

    assert exit_code == 2
    assert "hard-linked" in stderr.getvalue()
    assert sentinel.read_text(encoding="utf-8") == "outside sentinel\n"
    assert alias.read_text(encoding="utf-8") == "outside sentinel\n"
    assert os.path.samefile(alias, sentinel)


def test_explicit_output_refuses_hard_link_without_mutating_its_other_name(
    tmp_path: Path,
) -> None:
    target = _project(tmp_path)
    output = tmp_path / "explicit.json"
    sentinel = tmp_path / "outside-explicit.json"
    _link_sentinel(output, sentinel)

    with redirect_stdout(StringIO()), redirect_stderr(StringIO()) as stderr:
        exit_code = main(["scan", str(target), "--format", "json", "--output", str(output)])

    assert exit_code == 2
    assert "hard-linked" in stderr.getvalue()
    assert sentinel.read_text(encoding="utf-8") == "outside sentinel\n"
    assert os.path.samefile(output, sentinel)


def test_policy_report_refuses_hard_link_without_mutating_its_other_name(
    tmp_path: Path,
) -> None:
    target = _project(tmp_path)
    output = tmp_path / "reports"
    output.mkdir()
    policy = tmp_path / "policy.rego"
    policy.write_text("package test\n", encoding="utf-8")
    policy_output = output / "policy-results.json"
    sentinel = tmp_path / "outside-policy.json"
    _link_sentinel(policy_output, sentinel)

    with (
        patch("vigil_fuse.cli.evaluate_policies", return_value={"status": "pass"}),
        redirect_stdout(StringIO()),
        redirect_stderr(StringIO()) as stderr,
    ):
        exit_code = main(
            ["scan", str(target), "--policy", str(policy), "--output-dir", str(output)]
        )

    assert exit_code == 2
    assert "hard-linked" in stderr.getvalue()
    assert sentinel.read_text(encoding="utf-8") == "outside sentinel\n"
    assert os.path.samefile(policy_output, sentinel)


def test_host_syft_cannot_write_through_a_hard_link(tmp_path: Path) -> None:
    target = _project(tmp_path)
    output = tmp_path / "reports"
    output.mkdir()
    alias = output / "components.cdx.json"
    sentinel = tmp_path / "outside-sbom.json"
    _link_sentinel(alias, sentinel)
    document = '{"bomFormat":"CycloneDX","specVersion":"1.6","version":1,"components":[]}'

    def fake_syft(command: list[str], **_: object) -> subprocess.CompletedProcess[str]:
        # Model the old file-output behavior, which would follow a hard link.
        for argument in command:
            if argument.startswith("cyclonedx-json="):
                Path(argument.split("=", 1)[1]).write_text(document, encoding="utf-8")
        return subprocess.CompletedProcess(command, 0, document, "")

    with (
        patch("vigil_fuse.dependency_analyzers.resolve_analyzer_executable", return_value="syft"),
        patch("vigil_fuse.dependency_analyzers._tool_version", return_value="syft test"),
        patch("vigil_fuse.dependency_analyzers.analyzer_sandbox_active", return_value=False),
        patch("vigil_fuse.dependency_analyzers._run", side_effect=fake_syft) as run,
    ):
        result = generate_sbom(target, output)

    assert result.status.status == "failed"
    assert "hard-linked" in (result.status.detail or "")
    assert sentinel.read_text(encoding="utf-8") == "outside sentinel\n"
    assert alias.read_text(encoding="utf-8") == "outside sentinel\n"
    assert os.path.samefile(alias, sentinel)
    assert run.call_args.args[0][-2:] == ["--output", "cyclonedx-json"]
