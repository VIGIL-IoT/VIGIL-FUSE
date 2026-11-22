"""Install the manifest-pinned analyzers for CI smoke checks."""

from __future__ import annotations

import argparse
import os
import platform
from pathlib import Path

from vigil_fuse.setup.manager import (
    ToolAsset,
    assets_for_platform,
    install_asset,
    load_manifest,
    download_verified,
    extract_binary,
    normalize_platform,
)

ReleaseAsset = ToolAsset
__all__ = [
    "ReleaseAsset",
    "assets_for_platform",
    "download_verified",
    "extract_binary",
    "install_assets",
    "main",
    "normalize_platform",
]


def install_assets(directory: Path, assets: tuple[ToolAsset, ...]) -> None:
    if directory.is_symlink():
        raise ValueError("Refusing to install analyzer binaries through a symbolic-link directory")
    specs = {spec.id: spec for spec in load_manifest()}
    for asset in assets:
        spec = specs.get(asset.tool)
        if spec is None:
            raise ValueError(f"Unknown analyzer tool: {asset.tool}")
        install_asset(directory, asset, spec)


def add_to_github_path(directory: Path) -> None:
    github_path = os.environ.get("GITHUB_PATH")
    if github_path:
        with Path(github_path).open("a", encoding="utf-8") as output:
            output.write(str(directory.resolve()) + os.linesep)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path, required=True)
    args = parser.parse_args()
    assets = assets_for_platform(platform.system(), platform.machine())
    install_assets(args.directory, assets)
    add_to_github_path(args.directory)
    names = ", ".join(f"{asset.tool} {asset.version}" for asset in assets)
    print(f"Installed SHA-256-pinned {names}.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
