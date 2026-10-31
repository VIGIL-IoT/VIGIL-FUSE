from __future__ import annotations

import hashlib
from pathlib import Path
import stat
import tarfile
from unittest.mock import MagicMock, patch
import zipfile

import pytest

from scripts.install_ci_analyzers import (
    ReleaseAsset,
    assets_for_platform,
    download_verified,
    extract_binary,
)


def test_platform_assets_are_pinned_for_supported_runner_targets() -> None:
    cases = (
        ("Linux", "X64", "syft", "osv-scanner", "gitleaks"),
        ("Linux", "ARM64", "syft", "osv-scanner", "gitleaks"),
        ("Darwin", "x86_64", "syft", "osv-scanner", "gitleaks"),
        ("Darwin", "arm64", "syft", "osv-scanner", "gitleaks"),
        ("Windows", "AMD64", "syft", "osv-scanner", "gitleaks"),
    )
    for system, machine, *expected_tools in cases:
        assets = assets_for_platform(system, machine)
        assert tuple(asset.tool for asset in assets) == tuple(expected_tools)
        assert all(len(asset.sha256) == 64 for asset in assets)


def test_unsupported_runner_platform_fails_closed() -> None:
    with pytest.raises(ValueError, match="Unsupported CI analyzer platform"):
        assets_for_platform("Plan9", "x86_64")


def test_release_download_is_removed_when_digest_does_not_match(tmp_path: Path) -> None:
    payload = b"not the pinned release bytes"
    response = MagicMock()
    response.headers = {}
    response.read.side_effect = [payload, b""]
    response.__enter__.return_value = response
    download = tmp_path / "tool.release"
    asset = ReleaseAsset(
        tool="gitleaks",
        url="https://example.invalid/tool.zip",
        sha256="0" * 64,
        archive_format=None,
        member_name=None,
        executable_name="gitleaks",
    )

    with patch("scripts.install_ci_analyzers.urlopen", return_value=response):
        with pytest.raises(ValueError, match="SHA-256 mismatch"):
            download_verified(asset, download)

    assert not download.exists()


def test_oversized_partial_download_is_removed(tmp_path: Path) -> None:
    response = MagicMock()
    response.headers = {}
    response.read.side_effect = [b"exceeds-limit", b""]
    response.__enter__.return_value = response
    download = tmp_path / "tool.release"
    asset = ReleaseAsset(
        tool="gitleaks",
        url="https://example.invalid/tool.zip",
        sha256="0" * 64,
        archive_format=None,
        member_name=None,
        executable_name="gitleaks",
    )

    with (
        patch("scripts.install_ci_analyzers.urlopen", return_value=response),
        patch("scripts.install_ci_analyzers.MAX_DOWNLOAD_BYTES", 4),
        pytest.raises(ValueError, match="download limit"),
    ):
        download_verified(asset, download)

    assert not download.exists()


def test_zip_extraction_selects_only_the_pinned_regular_binary(tmp_path: Path) -> None:
    archive_path = tmp_path / "gitleaks.zip"
    binary = tmp_path / "gitleaks.exe"
    expected = b"verified synthetic executable"
    with zipfile.ZipFile(archive_path, mode="w") as archive:
        archive.writestr("gitleaks.exe", expected)
        archive.writestr("README.txt", b"not selected")
        link = zipfile.ZipInfo("nested/gitleaks.exe")
        link.create_system = 3
        link.external_attr = (stat.S_IFLNK | 0o777) << 16
        archive.writestr(link, "../../outside.exe")

    asset = ReleaseAsset(
        tool="gitleaks",
        url="https://example.invalid/gitleaks.zip",
        sha256="0" * 64,
        archive_format="zip",
        member_name="gitleaks.exe",
        executable_name="gitleaks.exe",
    )
    extract_binary(asset, archive_path, binary)

    assert binary.read_bytes() == expected


def test_tar_extraction_rejects_non_regular_binary_member(tmp_path: Path) -> None:
    archive_path = tmp_path / "syft.tar.gz"
    binary = tmp_path / "syft"
    with tarfile.open(archive_path, mode="w:gz") as archive:
        link = tarfile.TarInfo("syft")
        link.type = tarfile.SYMTYPE
        link.linkname = "../../outside"
        archive.addfile(link)

    asset = ReleaseAsset(
        tool="syft",
        url="https://example.invalid/syft.tar.gz",
        sha256="0" * 64,
        archive_format="tar.gz",
        member_name="syft",
        executable_name="syft",
    )
    with pytest.raises(ValueError, match="lacks one regular binary"):
        extract_binary(asset, archive_path, binary)
    assert not binary.exists()


def test_download_digest_matches_exact_asset_bytes(tmp_path: Path) -> None:
    payload = b"exact pinned release bytes"
    response = MagicMock()
    response.headers = {"Content-Length": str(len(payload))}
    response.read.side_effect = [payload, b""]
    response.__enter__.return_value = response
    download = tmp_path / "tool.release"
    asset = ReleaseAsset(
        tool="osv-scanner",
        url="https://example.invalid/osv-scanner",
        sha256=hashlib.sha256(payload).hexdigest(),
        archive_format=None,
        member_name=None,
        executable_name="osv-scanner",
    )

    with patch("scripts.install_ci_analyzers.urlopen", return_value=response):
        download_verified(asset, download)

    assert download.read_bytes() == payload
