from __future__ import annotations

import os
from pathlib import Path
from unittest.mock import patch

import pytest

from scripts.verify_binwalk_adapter import configure_binwalk_environment


def test_configure_binwalk_environment_adds_explicit_executable_directory(
    tmp_path: Path,
) -> None:
    executable = tmp_path / "binwalk.exe"
    executable.write_bytes(b"synthetic executable path placeholder")
    env = {"PATH": "existing-path"}

    resolved = configure_binwalk_environment(executable, env)

    assert resolved == executable.resolve()
    assert env["PATH"].split(os.pathsep) == [str(tmp_path.resolve()), "existing-path"]


def test_configure_binwalk_environment_rejects_missing_explicit_executable(
    tmp_path: Path,
) -> None:
    env = {"PATH": "existing-path"}

    with pytest.raises(FileNotFoundError, match="does not exist"):
        configure_binwalk_environment(tmp_path / "missing-binwalk", env)

    assert env["PATH"] == "existing-path"


def test_configure_binwalk_environment_uses_path_when_no_override_is_given() -> None:
    with patch("scripts.verify_binwalk_adapter.shutil.which", return_value="/tools/binwalk"):
        resolved = configure_binwalk_environment(None, {"PATH": "/tools"})

    assert resolved == Path("/tools/binwalk")
