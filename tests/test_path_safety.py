from __future__ import annotations

import os
import stat
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

from vigil_fuse.path_safety import (
    _is_alias,
    assert_no_path_aliases,
    ensure_safe_directory,
    safe_write_bytes,
)
from vigil_fuse.scanner import scan
from vigil_fuse.project_identity import inspect_project_identity
from vigil_fuse.repo_dna import inspect_repository
from vigil_fuse.setup.manager import install_asset, load_manifest


def test_windows_reparse_attribute_is_recognized_as_an_alias() -> None:
    info = SimpleNamespace(st_mode=stat.S_IFDIR, st_file_attributes=0x400)

    assert _is_alias(info)  # type: ignore[arg-type]


@pytest.mark.skipif(os.name != "nt", reason="Windows junction behavior is platform-specific")
def test_junctions_are_pruned_and_rejected_for_targets_outputs_and_installs(
    tmp_path: Path,
) -> None:
    target = tmp_path / "project"
    outside = tmp_path / "outside"
    target.mkdir()
    outside.mkdir()
    (target / "main.c").write_text("int main(void) { return 0; }\n", encoding="utf-8")
    (outside / "lib.rs").write_text("fn outside() {}\n", encoding="utf-8")
    junction = target / "external"
    environment = os.environ.copy()
    environment["FUSE_JUNCTION_PATH"] = str(junction)
    environment["FUSE_JUNCTION_TARGET"] = str(outside)
    created = subprocess.run(
        [
            "powershell.exe",
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            "New-Item -ItemType Junction -Path $env:FUSE_JUNCTION_PATH "
            "-Target $env:FUSE_JUNCTION_TARGET | Out-Null",
        ],
        check=False,
        capture_output=True,
        text=True,
        env=environment,
    )
    assert created.returncode == 0, created.stderr.strip()

    result = scan(target)
    assert result.files_scanned == 1
    assert not result.discovery_complete
    with pytest.raises(ValueError, match="reparse-point targets"):
        scan(junction)
    with pytest.raises(ValueError, match="reparse-point targets"):
        inspect_project_identity(junction)
    with pytest.raises(ValueError, match="filesystem aliases"):
        inspect_repository(junction)
    identity = inspect_project_identity(target)
    repository = inspect_repository(target)
    assert not identity.complete
    assert any("reparse points were excluded" in item for item in identity.limitations)
    assert not repository["complete"]
    assert "Rust" not in repository["languages"]
    with pytest.raises(ValueError, match="reparse point"):
        assert_no_path_aliases(junction / "new-report.json")
    with pytest.raises(ValueError, match="reparse point"):
        safe_write_bytes(junction / "new-report.json", b"report")
    with pytest.raises(ValueError, match="reparse point"):
        ensure_safe_directory(junction / "managed-tools")
    syft = next(spec for spec in load_manifest() if spec.id == "syft")
    asset = next(iter(syft.assets.values()))
    with pytest.raises(ValueError, match="reparse point"):
        install_asset(junction / "managed-tools", asset, syft)
