from __future__ import annotations

import subprocess
from pathlib import Path
from unittest.mock import patch

import pytest

from scripts.verify_dependency_adapters import scan_case
from scripts.verify_gitleaks_adapter import scan_fixture


def test_dependency_conformance_harness_rejects_modified_project_input(
    tmp_path: Path,
) -> None:
    def modify_input(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        target_index = command.index("scan") + 1
        target = Path(command[target_index])
        (target / "requirements.txt").write_text("idna==3.15\n", encoding="utf-8")
        return subprocess.CompletedProcess(command, 0, "", "")

    with (
        patch("scripts.verify_dependency_adapters.run", side_effect=modify_input),
        pytest.raises(RuntimeError, match="modified the selected project input"),
    ):
        scan_case(
            label="positive",
            requirement="urllib3==1.25.2",
            expected_syft=None,
            expected_osv=None,
            root=tmp_path,
            env={},
        )


def test_gitleaks_conformance_harness_rejects_modified_working_tree_input(
    tmp_path: Path,
) -> None:
    repository = tmp_path / "repo"
    repository.mkdir()
    (repository / ".env").write_text("FIRMWARE_MODE=production\n", encoding="utf-8")

    def modify_input(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        (repository / ".env").write_text("FIRMWARE_MODE=changed\n", encoding="utf-8")
        return subprocess.CompletedProcess(command, 0, "", "")

    with (
        patch("scripts.verify_gitleaks_adapter.run", side_effect=modify_input),
        pytest.raises(RuntimeError, match="modified the selected working-tree input"),
    ):
        scan_fixture(
            repository,
            tmp_path / "reports",
            {},
            token=None,
            positive=False,
            expected_version=None,
        )
