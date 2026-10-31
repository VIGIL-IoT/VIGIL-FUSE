"""Install SHA-256-pinned analyzer releases for the cross-platform CI smoke check."""

from __future__ import annotations

import argparse
import hashlib
import os
import platform
import stat
import tarfile
import zipfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import IO
from urllib.request import Request, urlopen

MAX_DOWNLOAD_BYTES = 256 * 1024 * 1024
MAX_EXECUTABLE_BYTES = 256 * 1024 * 1024
DOWNLOAD_TIMEOUT_SECONDS = 60
READ_CHUNK_BYTES = 1024 * 1024


@dataclass(frozen=True)
class ReleaseAsset:
    tool: str
    url: str
    sha256: str
    archive_format: str | None
    member_name: str | None
    executable_name: str


def _asset(
    tool: str,
    filename: str,
    digest: str,
    *,
    archive_format: str | None,
    member_name: str | None,
    executable_name: str,
) -> ReleaseAsset:
    if tool == "syft":
        url = f"https://github.com/anchore/syft/releases/download/v1.55.0/{filename}"
    elif tool == "osv-scanner":
        url = f"https://github.com/google/osv-scanner/releases/download/v2.7.0/{filename}"
    elif tool == "gitleaks":
        url = f"https://github.com/gitleaks/gitleaks/releases/download/v8.30.0/{filename}"
    else:
        raise ValueError(f"Unknown analyzer tool: {tool}")
    return ReleaseAsset(
        tool=tool,
        url=url,
        sha256=digest,
        archive_format=archive_format,
        member_name=member_name,
        executable_name=executable_name,
    )


ASSETS_BY_PLATFORM: dict[tuple[str, str], tuple[ReleaseAsset, ...]] = {
    ("linux", "x86_64"): (
        _asset(
            "syft",
            "syft_1.55.0_linux_amd64.tar.gz",
            "bb65249542db5fedeeb4d3f9b018b75e7264dbfbbb10486f044581a92f90490d",
            archive_format="tar.gz",
            member_name="syft",
            executable_name="syft",
        ),
        _asset(
            "osv-scanner",
            "osv-scanner_linux_amd64",
            "160c6253e2922e9e0a6a9771c5c4c40a4b3c6090b34a3cdd5e80c96cc2e4218b",
            archive_format=None,
            member_name=None,
            executable_name="osv-scanner",
        ),
        _asset(
            "gitleaks",
            "gitleaks_8.30.0_linux_x64.tar.gz",
            "79a3ab579b53f71efd634f3aaf7e04a0fa0cf206b7ed434638d1547a2470a66e",
            archive_format="tar.gz",
            member_name="gitleaks",
            executable_name="gitleaks",
        ),
    ),
    ("linux", "arm64"): (
        _asset(
            "syft",
            "syft_1.55.0_linux_arm64.tar.gz",
            "929bd163db2d7cd2255d3bcb8967208079813d7b46b0c952f7b794d8e2c7d304",
            archive_format="tar.gz",
            member_name="syft",
            executable_name="syft",
        ),
        _asset(
            "osv-scanner",
            "osv-scanner_linux_arm64",
            "4061ef4c021ed3c47f203b818f337e351336cc5cd67c0274fc36bd1dfc728dd7",
            archive_format=None,
            member_name=None,
            executable_name="osv-scanner",
        ),
        _asset(
            "gitleaks",
            "gitleaks_8.30.0_linux_arm64.tar.gz",
            "b4cbbb6ddf7d1b2a603088cd03a4e3f7ce48ee7fd449b51f7de6ee2906f5fa2f",
            archive_format="tar.gz",
            member_name="gitleaks",
            executable_name="gitleaks",
        ),
    ),
    ("darwin", "x86_64"): (
        _asset(
            "syft",
            "syft_1.55.0_darwin_amd64.tar.gz",
            "e2e5831cbabaec9a36fe65c34755c1113982c842a685edce3ce0b54a0ded8003",
            archive_format="tar.gz",
            member_name="syft",
            executable_name="syft",
        ),
        _asset(
            "osv-scanner",
            "osv-scanner_darwin_amd64",
            "e82c5df7ab0a42dff29a1cd0660711447b56b4c0483ff66ad8634df10fd81a45",
            archive_format=None,
            member_name=None,
            executable_name="osv-scanner",
        ),
        _asset(
            "gitleaks",
            "gitleaks_8.30.0_darwin_x64.tar.gz",
            "ca221d012d247080c2f6f61f4b7a83bffa2453806b0c195c795bbe9a8c775ed5",
            archive_format="tar.gz",
            member_name="gitleaks",
            executable_name="gitleaks",
        ),
    ),
    ("darwin", "arm64"): (
        _asset(
            "syft",
            "syft_1.55.0_darwin_arm64.tar.gz",
            "1217c258bd5eb91ef3189cf22a82e02f9cac07e4ce934350f428e93aff674625",
            archive_format="tar.gz",
            member_name="syft",
            executable_name="syft",
        ),
        _asset(
            "osv-scanner",
            "osv-scanner_darwin_arm64",
            "d4926ef8da134332543be276dff157e4c170f99ad91fc48e89448a8816bdf70b",
            archive_format=None,
            member_name=None,
            executable_name="osv-scanner",
        ),
        _asset(
            "gitleaks",
            "gitleaks_8.30.0_darwin_arm64.tar.gz",
            "b251ab2bcd4cd8ba9e56ff37698c033ebf38582b477d21ebd86586d927cf87e7",
            archive_format="tar.gz",
            member_name="gitleaks",
            executable_name="gitleaks",
        ),
    ),
    ("windows", "x86_64"): (
        _asset(
            "syft",
            "syft_1.55.0_windows_amd64.zip",
            "ada4c9b93af575f479ce80fce6629897272a2d41f300a14bc49bace020767ca2",
            archive_format="zip",
            member_name="syft.exe",
            executable_name="syft.exe",
        ),
        _asset(
            "osv-scanner",
            "osv-scanner_windows_amd64.exe",
            "9964ed64ec9a387391eb4cc006ad5c531154821aef29b793e02c448de4686438",
            archive_format=None,
            member_name=None,
            executable_name="osv-scanner.exe",
        ),
        _asset(
            "gitleaks",
            "gitleaks_8.30.0_windows_x64.zip",
            "54fe94f644b832dd08e8c3a5915efb3bfa862386d59fb27ca0792cb687a83573",
            archive_format="zip",
            member_name="gitleaks.exe",
            executable_name="gitleaks.exe",
        ),
    ),
}


def normalize_platform(system: str, machine: str) -> tuple[str, str]:
    normalized_system = {
        "linux": "linux",
        "darwin": "darwin",
        "windows": "windows",
    }.get(system.casefold())
    normalized_machine = {
        "amd64": "x86_64",
        "x64": "x86_64",
        "x86_64": "x86_64",
        "aarch64": "arm64",
        "arm64": "arm64",
    }.get(machine.casefold())
    if normalized_system is None or normalized_machine is None:
        raise ValueError(f"Unsupported CI analyzer platform: {system}/{machine}")
    return normalized_system, normalized_machine


def assets_for_platform(system: str, machine: str) -> tuple[ReleaseAsset, ...]:
    key = normalize_platform(system, machine)
    assets = ASSETS_BY_PLATFORM.get(key)
    if assets is None:
        raise ValueError(f"No pinned analyzer assets are available for {system}/{machine}")
    return assets


def download_verified(asset: ReleaseAsset, destination: Path) -> None:
    if len(asset.sha256) != 64 or any(
        character not in "0123456789abcdef" for character in asset.sha256
    ):
        raise ValueError(f"Invalid pinned digest for {asset.tool}")
    digest = hashlib.sha256()
    total = 0
    created = False
    request = Request(asset.url, headers={"User-Agent": "VIGIL-FUSE-CI/1.0"})
    try:
        with urlopen(request, timeout=DOWNLOAD_TIMEOUT_SECONDS) as response:
            content_length = response.headers.get("Content-Length")
            if content_length is not None and int(content_length) > MAX_DOWNLOAD_BYTES:
                raise ValueError(f"{asset.tool} release asset exceeds the download limit")
            with destination.open("xb") as output:
                created = True
                while chunk := response.read(READ_CHUNK_BYTES):
                    total += len(chunk)
                    if total > MAX_DOWNLOAD_BYTES:
                        raise ValueError(f"{asset.tool} release asset exceeds the download limit")
                    digest.update(chunk)
                    output.write(chunk)
        if digest.hexdigest() != asset.sha256:
            raise ValueError(f"SHA-256 mismatch for pinned {asset.tool} release asset")
    except BaseException:
        if created:
            destination.unlink(missing_ok=True)
        raise


def _copy_bounded(source: IO[bytes], destination: Path) -> None:
    written = 0
    created = False
    try:
        with destination.open("xb") as output:
            created = True
            while chunk := source.read(READ_CHUNK_BYTES):
                written += len(chunk)
                if written > MAX_EXECUTABLE_BYTES:
                    raise ValueError("Analyzer executable exceeds the extraction limit")
                output.write(chunk)
    except BaseException:
        if created:
            destination.unlink(missing_ok=True)
        raise


def extract_binary(asset: ReleaseAsset, archive_path: Path, destination: Path) -> None:
    if asset.archive_format is None or asset.member_name is None:
        raise ValueError(f"{asset.tool} has no archive member to extract")
    if asset.archive_format == "tar.gz":
        with tarfile.open(archive_path, mode="r:gz") as archive:
            tar_matches = [
                member
                for member in archive.getmembers()
                if PurePosixPath(member.name).name == asset.member_name and member.isfile()
            ]
            if len(tar_matches) != 1:
                raise ValueError(f"Pinned {asset.tool} archive lacks one regular binary")
            stream = archive.extractfile(tar_matches[0])
            if stream is None:
                raise ValueError(f"Could not read {asset.tool} from its pinned archive")
            with stream:
                _copy_bounded(stream, destination)
    elif asset.archive_format == "zip":
        with zipfile.ZipFile(archive_path) as archive:
            zip_matches = [
                member
                for member in archive.infolist()
                if PurePosixPath(member.filename.replace("\\", "/")).name == asset.member_name
                and not member.is_dir()
                and not stat.S_ISLNK(member.external_attr >> 16)
            ]
            if len(zip_matches) != 1:
                raise ValueError(f"Pinned {asset.tool} archive lacks one regular binary")
            with archive.open(zip_matches[0]) as stream:
                _copy_bounded(stream, destination)
    else:
        raise ValueError(f"Unsupported analyzer archive format: {asset.archive_format}")


def install_assets(directory: Path, assets: tuple[ReleaseAsset, ...]) -> None:
    if directory.is_symlink():
        raise ValueError("Refusing to install analyzer binaries through a symbolic-link directory")
    directory.mkdir(parents=True, exist_ok=True)
    for asset in assets:
        executable = directory / asset.executable_name
        if executable.exists() or executable.is_symlink():
            raise ValueError(f"Refusing to overwrite existing analyzer executable: {asset.tool}")
        download_path = directory / f"{asset.tool}.release"
        download_verified(asset, download_path)
        try:
            if asset.archive_format is None:
                with download_path.open("rb") as stream:
                    _copy_bounded(stream, executable)
            else:
                extract_binary(asset, download_path, executable)
        finally:
            download_path.unlink(missing_ok=True)
        if os.name != "nt":
            executable.chmod(0o755)


def add_to_github_path(directory: Path) -> None:
    github_path = os.environ.get("GITHUB_PATH")
    if github_path:
        with Path(github_path).open("a", encoding="utf-8") as output:
            output.write(str(directory.resolve()) + os.linesep)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path, required=True)
    args = parser.parse_args()

    system, machine = platform.system(), platform.machine()
    assets = assets_for_platform(system, machine)
    install_assets(args.directory, assets)
    add_to_github_path(args.directory)
    print(
        "Installed SHA-256-pinned Syft 1.55.0, OSV-Scanner 2.7.0, and Gitleaks 8.30.0 "
        f"for {system}/{machine}."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
