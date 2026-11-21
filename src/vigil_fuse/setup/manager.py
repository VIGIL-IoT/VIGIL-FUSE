from __future__ import annotations

import hashlib
import json
import os
import platform
import re
import shutil
import stat
import subprocess
import tarfile
import tempfile
import zipfile
from dataclasses import dataclass
from importlib.resources import files
from pathlib import Path, PurePosixPath
from typing import IO, Any, Callable
from urllib.parse import urlparse
from urllib.request import Request, urlopen

_CATEGORIES = {"CORE", "RECOMMENDED", "OPTIONAL_HEAVY", "RESEARCH"}
_VERSION = re.compile(r"(?<!\d)(\d+)(?:\.(\d+))?(?:\.(\d+))?(?!\d)")
_MAX_DOWNLOAD_BYTES = 256 * 1024 * 1024
_MAX_EXECUTABLE_BYTES = 256 * 1024 * 1024
_DOWNLOAD_TIMEOUT_SECONDS = 60
_READ_CHUNK_BYTES = 1024 * 1024
_MANAGED_TOOLS = frozenset({"syft", "osv-scanner", "gitleaks"})


@dataclass(frozen=True)
class ToolAsset:
    tool: str
    url: str
    sha256: str
    archive_format: str | None
    member_name: str | None
    executable_name: str
    version: str = "0.0.0"


@dataclass(frozen=True)
class ToolSpec:
    id: str
    display_name: str
    category: str
    platforms: tuple[str, ...]
    architectures: tuple[str, ...]
    version_command: tuple[str, ...] | None
    minimum_version: str | None
    install_method: str
    download_source: str
    checksum_source: str | None
    doctor_capability: str
    executable_names: tuple[str, ...]
    assets: dict[str, ToolAsset]


@dataclass(frozen=True)
class ToolCheck:
    id: str
    display_name: str
    category: str
    status: str
    version: str | None = None
    executable: str | None = None
    source: str | None = None
    capability: str = ""
    detail: str = ""


def _require_text(value: object, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"Tool manifest field {field!r} must be a non-empty string")
    return value


def _asset_from_json(tool_id: str, key: str, value: object, publisher: str) -> ToolAsset:
    if not isinstance(value, dict):
        raise ValueError(f"Tool manifest asset {tool_id}/{key} must be an object")
    url = _require_text(value.get("url"), "asset.url")
    parsed = urlparse(url)
    if parsed.scheme != "https" or parsed.hostname != "github.com":
        raise ValueError(
            f"Tool manifest asset {tool_id}/{key} must use an official HTTPS release URL"
        )
    if not parsed.path.startswith(f"/{publisher}/releases/download/"):
        raise ValueError(f"Tool manifest asset {tool_id}/{key} is outside its declared publisher")
    digest = _require_text(value.get("sha256"), "asset.sha256").lower()
    if len(digest) != 64 or any(character not in "0123456789abcdef" for character in digest):
        raise ValueError(f"Tool manifest asset {tool_id}/{key} has an invalid SHA-256 digest")
    archive_format = value.get("archive_format")
    member_name = value.get("member_name")
    if archive_format not in (None, "zip", "tar.gz"):
        raise ValueError(f"Tool manifest asset {tool_id}/{key} has an unsupported archive format")
    if archive_format is not None and not isinstance(member_name, str):
        raise ValueError(f"Tool manifest asset {tool_id}/{key} is missing its archive member")
    if archive_format is None and member_name is not None:
        raise ValueError(f"Tool manifest asset {tool_id}/{key} has an unexpected archive member")
    executable_name = _require_text(value.get("executable_name"), "asset.executable_name")
    if Path(executable_name).name != executable_name or executable_name in {".", ".."}:
        raise ValueError(f"Tool manifest asset {tool_id}/{key} has an invalid executable name")
    version = _require_text(value.get("version"), "asset.version")
    if _VERSION.search(version) is None:
        raise ValueError(f"Tool manifest asset {tool_id}/{key} has an invalid version")
    return ToolAsset(tool_id, url, digest, archive_format, member_name, executable_name, version)


def load_manifest(path: Path | None = None) -> tuple[ToolSpec, ...]:
    """Read and validate the packaged tool catalog, or a test catalog."""
    try:
        raw = (
            path.read_text(encoding="utf-8")
            if path is not None
            else files("vigil_fuse").joinpath("setup", "tools.json").read_text(encoding="utf-8")
        )
        document = json.loads(raw)
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ValueError(f"Could not read the FUSE tool manifest: {error}") from error
    if not isinstance(document, dict) or document.get("schema_version") != 1:
        raise ValueError("Unsupported FUSE tool manifest schema")
    rows = document.get("tools")
    if not isinstance(rows, list):
        raise ValueError("FUSE tool manifest must contain a tools array")
    result: list[ToolSpec] = []
    seen: set[str] = set()
    for row in rows:
        if not isinstance(row, dict):
            raise ValueError("FUSE tool manifest entries must be objects")
        tool_id = _require_text(row.get("id"), "id")
        if tool_id in seen:
            raise ValueError(f"Duplicate FUSE tool manifest id: {tool_id}")
        seen.add(tool_id)
        category = _require_text(row.get("category"), "category")
        if category not in _CATEGORIES:
            raise ValueError(f"Invalid category for {tool_id}: {category}")
        platforms = row.get("platforms")
        architectures = row.get("architectures")
        if not isinstance(platforms, list) or not all(isinstance(item, str) for item in platforms):
            raise ValueError(f"Tool manifest platforms for {tool_id} must be a string array")
        if not isinstance(architectures, list) or not all(
            isinstance(item, str) for item in architectures
        ):
            raise ValueError(f"Tool manifest architectures for {tool_id} must be a string array")
        command = row.get("version_command")
        if command is not None and (
            not isinstance(command, list) or not all(isinstance(item, str) for item in command)
        ):
            raise ValueError(f"Tool manifest version_command for {tool_id} must be a string array")
        minimum = row.get("minimum_version")
        if minimum is not None and (
            not isinstance(minimum, str) or _VERSION.search(minimum) is None
        ):
            raise ValueError(f"Tool manifest minimum_version for {tool_id} is invalid")
        method = _require_text(row.get("install_method"), "install_method")
        if method not in {"manual", "pinned_release"}:
            raise ValueError(f"Unsupported install method for {tool_id}: {method}")
        source = _require_text(row.get("download_source"), "download_source")
        if urlparse(source).scheme != "https":
            raise ValueError(f"Tool manifest source for {tool_id} must use HTTPS")
        publisher_value = row.get("publisher")
        publisher = publisher_value if isinstance(publisher_value, str) else ""
        raw_assets = row.get("assets", {})
        if not isinstance(raw_assets, dict):
            raise ValueError(f"Tool manifest assets for {tool_id} must be an object")
        assets = {
            key: _asset_from_json(tool_id, key, value, publisher)
            for key, value in raw_assets.items()
        }
        names = row.get("executable_names", [tool_id])
        if not isinstance(names, list) or not all(isinstance(item, str) for item in names):
            raise ValueError(f"Tool manifest executable_names for {tool_id} must be a string array")
        result.append(
            ToolSpec(
                id=tool_id,
                display_name=_require_text(row.get("display_name"), "display_name"),
                category=category,
                platforms=tuple(platforms),
                architectures=tuple(architectures),
                version_command=tuple(command) if command is not None else None,
                minimum_version=minimum,
                install_method=method,
                download_source=source,
                checksum_source=(
                    row["checksum_source"] if isinstance(row.get("checksum_source"), str) else None
                ),
                doctor_capability=_require_text(row.get("doctor_capability"), "doctor_capability"),
                executable_names=tuple(names),
                assets=assets,
            )
        )
    return tuple(result)


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
        raise ValueError(f"Unsupported FUSE platform: {system}/{machine}")
    return normalized_system, normalized_machine


def assets_for_platform(
    system: str, machine: str, *, manifest: tuple[ToolSpec, ...] | None = None
) -> tuple[ToolAsset, ...]:
    key = "/".join(normalize_platform(system, machine))
    selected = tuple(
        tool.assets[key]
        for tool in (manifest or load_manifest())
        if tool.category == "RECOMMENDED" and key in tool.assets
    )
    if not selected:
        raise ValueError(f"No pinned recommended-tool assets are available for {system}/{machine}")
    return selected


def managed_tool_directory() -> Path:
    override = os.environ.get("VIGIL_FUSE_TOOLS_DIR")
    if override:
        return Path(override).expanduser()
    if os.name == "nt":
        root = os.environ.get("LOCALAPPDATA")
        return (
            Path(root).expanduser() / "Vigil-FUSE" / "Tools"
            if root
            else Path.home() / "AppData" / "Local" / "Vigil-FUSE" / "Tools"
        )
    root = os.environ.get("XDG_DATA_HOME")
    return (
        (Path(root).expanduser() if root else Path.home() / ".local" / "share")
        / "vigil-fuse"
        / "tools"
    )


def _version_tuple(text: str | None) -> tuple[int, int, int] | None:
    if text is None:
        return None
    match = _VERSION.search(text)
    if match is None:
        return None
    return int(match.group(1)), int(match.group(2) or 0), int(match.group(3) or 0)


def _executable_candidates(spec: ToolSpec) -> tuple[str, ...]:
    names = spec.executable_names or (spec.id,)
    if os.name == "nt":
        return (
            tuple(
                name if Path(name).suffix.casefold() == ".exe" else name + ".exe" for name in names
            )
            + names
        )
    return names


def _find_executable(
    spec: ToolSpec,
    *,
    which: Callable[[str], str | None] = shutil.which,
    managed_directory: Path | None = None,
) -> str | None:
    for name in _executable_candidates(spec):
        found = which(name)
        if found:
            return found
    if spec.id not in _MANAGED_TOOLS:
        return None
    directory = managed_directory or managed_tool_directory()
    for name in _executable_candidates(spec):
        candidate = directory / name
        if candidate.is_file() and not candidate.is_symlink():
            return str(candidate)
    return None


def resolve_managed_tool(name: str) -> str | None:
    spec = next((item for item in load_manifest() if item.id == name), None)
    return _find_executable(spec, which=lambda _: None) if spec is not None else None


def _probe_version(executable: str, spec: ToolSpec) -> tuple[str | None, str | None]:
    commands = [spec.version_command] if spec.version_command is not None else []
    if spec.id == "binwalk":
        commands.append(("--help",))
    if not commands:
        return None, "No version command is defined for this tool."
    from ..analyzer_runtime import AnalyzerOutputLimitError, _run

    for arguments in commands:
        try:
            result = _run(
                [executable, *arguments],
                timeout=5,
                output_limit_bytes=64 * 1024,
            )
        except (OSError, subprocess.TimeoutExpired, AnalyzerOutputLimitError) as error:
            return None, f"Version check failed: {type(error).__name__}."
        output = (result.stdout + "\n" + result.stderr).strip()
        if result.returncode == 0 or (spec.id == "binwalk" and _VERSION.search(output)):
            match = _VERSION.search(output)
            if match:
                return match.group(0), None
    return None, "The tool did not return a recognized version."


def _compare_versions(left: str, right: str) -> int | None:
    left_tuple, right_tuple = _version_tuple(left), _version_tuple(right)
    if left_tuple is None or right_tuple is None:
        return None
    return (left_tuple > right_tuple) - (left_tuple < right_tuple)


def inspect_tool(
    spec: ToolSpec,
    *,
    system: str | None = None,
    machine: str | None = None,
    which: Any = shutil.which,
    managed_directory: Path | None = None,
) -> ToolCheck:
    current_system = (system or platform.system()).casefold()
    current_machine = (machine or platform.machine()).casefold()
    if current_system == "darwin":
        current_system = "darwin"
    elif current_system == "windows":
        current_system = "windows"
    elif current_system == "linux":
        current_system = "linux"
    architecture = {"amd64": "x86_64", "x64": "x86_64", "aarch64": "arm64", "arm64": "arm64"}.get(
        current_machine, current_machine
    )
    if current_system not in spec.platforms:
        return ToolCheck(
            spec.id,
            spec.display_name,
            spec.category,
            "UNSUPPORTED",
            capability=spec.doctor_capability,
            detail="Unsupported operating system.",
        )
    executable = _find_executable(spec, which=which, managed_directory=managed_directory)
    if executable is None:
        status = "OPTIONAL" if spec.category in {"OPTIONAL_HEAVY", "RESEARCH"} else "MISSING"
        if (
            spec.install_method == "pinned_release"
            and f"{current_system}/{architecture}" not in spec.assets
        ):
            status = "UNSUPPORTED"
        return ToolCheck(
            spec.id,
            spec.display_name,
            spec.category,
            status,
            capability=spec.doctor_capability,
            detail=f"Install guidance: {spec.download_source}",
        )
    version, error = _probe_version(executable, spec)
    if error is not None:
        return ToolCheck(
            spec.id,
            spec.display_name,
            spec.category,
            "BROKEN",
            executable=executable,
            capability=spec.doctor_capability,
            detail=error,
        )
    if spec.minimum_version and _compare_versions(version or "", spec.minimum_version) == -1:
        return ToolCheck(
            spec.id,
            spec.display_name,
            spec.category,
            "WRONG_VERSION",
            version,
            executable,
            capability=spec.doctor_capability,
            detail=f"Requires {spec.minimum_version} or newer.",
        )
    source = None
    try:
        directory = managed_directory or managed_tool_directory()
        metadata = _read_install_metadata(directory)
        item = metadata.get("tools", {}).get(spec.id, {})
        if Path(executable).resolve() == (directory / Path(executable).name).resolve():
            source = item.get("source") if isinstance(item, dict) else None
    except (OSError, ValueError):
        pass
    return ToolCheck(
        spec.id,
        spec.display_name,
        spec.category,
        "AVAILABLE",
        version,
        executable,
        source,
        spec.doctor_capability,
    )


def inspect_environment(*, include_research: bool = True) -> tuple[ToolCheck, ...]:
    specs = load_manifest()
    return tuple(
        inspect_tool(spec)
        for spec in specs
        if spec.id != "ghidra" and (include_research or spec.category != "RESEARCH")
    )


def inspect_tools() -> tuple[tuple[str, str | None, str | None], ...]:
    checks = {item.id: item for item in inspect_environment(include_research=False)}
    return tuple(
        (checks[name].display_name, checks[name].executable, checks[name].version)
        for name in ("syft", "osv-scanner", "binwalk", "gitleaks")
    )


def powershell_executable(
    *, system: str | None = None, which: Callable[[str], str | None] = shutil.which
) -> str | None:
    if (system or platform.system()).casefold() != "windows":
        return None
    return which("powershell") or which("pwsh")


def download_verified(asset: ToolAsset, destination: Path) -> None:
    if len(asset.sha256) != 64 or any(
        character not in "0123456789abcdef" for character in asset.sha256
    ):
        raise ValueError(f"Invalid pinned digest for {asset.tool}")
    digest = hashlib.sha256()
    total = 0
    created = False
    request = Request(asset.url, headers={"User-Agent": "VIGIL-FUSE-setup/1.0"})
    try:
        parsed = urlparse(asset.url)
        if parsed.scheme != "https" or parsed.hostname != "github.com":
            raise ValueError(f"Refusing non-HTTPS or untrusted source for {asset.tool}")
        with urlopen(request, timeout=_DOWNLOAD_TIMEOUT_SECONDS) as response:
            final = urlparse(response.geturl())
            if final.scheme != "https" or final.hostname not in {
                "github.com",
                "release-assets.githubusercontent.com",
            }:
                raise ValueError(f"Unexpected download publisher for {asset.tool}")
            content_length = response.headers.get("Content-Length")
            if content_length is not None and int(content_length) > _MAX_DOWNLOAD_BYTES:
                raise ValueError(f"{asset.tool} release asset exceeds the download limit")
            with destination.open("xb") as output:
                created = True
                while chunk := response.read(_READ_CHUNK_BYTES):
                    total += len(chunk)
                    if total > _MAX_DOWNLOAD_BYTES:
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
            while chunk := source.read(_READ_CHUNK_BYTES):
                written += len(chunk)
                if written > _MAX_EXECUTABLE_BYTES:
                    raise ValueError("Analyzer executable exceeds the extraction limit")
                output.write(chunk)
    except BaseException:
        if created:
            destination.unlink(missing_ok=True)
        raise


def extract_binary(asset: ToolAsset, archive_path: Path, destination: Path) -> None:
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


def _read_install_metadata(directory: Path) -> dict[str, Any]:
    path = directory / "install-record.json"
    if not path.exists():
        return {"schema_version": 1, "tools": {}}
    if path.is_symlink() or path.stat().st_size > 64 * 1024:
        raise ValueError("Invalid FUSE tool install record")
    value = json.loads(path.read_text(encoding="utf-8"))
    if (
        not isinstance(value, dict)
        or value.get("schema_version") != 1
        or not isinstance(value.get("tools"), dict)
    ):
        raise ValueError("Invalid FUSE tool install record")
    return value


def _write_install_metadata(directory: Path, tool_id: str, asset: ToolAsset, version: str) -> None:
    record_path = directory / "install-record.json"
    if record_path.is_symlink():
        raise ValueError("Refusing to write a FUSE tool record through a symbolic link")
    metadata = _read_install_metadata(directory)
    metadata["tools"][tool_id] = {"version": version, "source": asset.url, "sha256": asset.sha256}
    fd, temporary_name = tempfile.mkstemp(prefix="install-record-", suffix=".tmp", dir=directory)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as output:
            json.dump(metadata, output, indent=2)
            output.write("\n")
        os.replace(temporary_name, record_path)
    finally:
        Path(temporary_name).unlink(missing_ok=True)


def _verify_executable(path: Path, asset: ToolAsset, spec: ToolSpec) -> str:
    version, error = _probe_version(str(path), spec)
    if error or version is None:
        raise ValueError(f"Downloaded {spec.display_name} did not report a valid version: {error}")
    if _compare_versions(version, asset.version) != 0:
        raise ValueError(
            f"Downloaded {spec.display_name} reported {version}, expected {asset.version}"
        )
    if spec.minimum_version and _compare_versions(version, spec.minimum_version) == -1:
        raise ValueError(f"Pinned {spec.display_name} version {version} is below its minimum")
    return version


def install_asset(
    directory: Path,
    asset: ToolAsset,
    spec: ToolSpec,
    *,
    upgrade: bool = False,
) -> Path:
    if directory.is_symlink():
        raise ValueError("Refusing to install analyzer binaries through a symbolic-link directory")
    directory.mkdir(parents=True, exist_ok=True)
    destination = directory / asset.executable_name
    if destination.is_symlink():
        raise ValueError(f"Refusing to replace symbolic-link executable for {asset.tool}")
    if destination.exists():
        existing_version, error = _probe_version(str(destination), spec)
        comparison = _compare_versions(existing_version or "", asset.version)
        if error is None and comparison is not None and comparison >= 0:
            return destination
        if not upgrade:
            raise ValueError(
                f"{asset.tool} already exists; use --upgrade to replace the managed copy"
            )
    with tempfile.TemporaryDirectory(prefix="vigil-fuse-", dir=directory) as temporary:
        staging = Path(temporary)
        download_path = staging / f"{asset.tool}.release"
        binary_path = staging / asset.executable_name
        download_verified(asset, download_path)
        if asset.archive_format is None:
            with download_path.open("rb") as stream:
                _copy_bounded(stream, binary_path)
        else:
            extract_binary(asset, download_path, binary_path)
        version = _verify_executable(binary_path, asset, spec)
        if os.name != "nt":
            binary_path.chmod(0o755)
        os.replace(binary_path, destination)
        _write_install_metadata(directory, spec.id, asset, version)
    return destination


def setup_tools(
    category: str,
    *,
    upgrade: bool = False,
    directory: Path | None = None,
) -> tuple[tuple[str, str], ...]:
    """Install missing pinned recommended tools; return per-tool outcomes."""
    if category not in {"RECOMMENDED", "OPTIONAL_HEAVY"}:
        raise ValueError(f"Unsupported install category: {category}")
    selected_directory = directory or managed_tool_directory()
    normalized = normalize_platform(platform.system(), platform.machine())
    results: list[tuple[str, str]] = []
    for spec in load_manifest():
        if spec.category != category:
            continue
        check = inspect_tool(spec, managed_directory=selected_directory)
        if check.status == "AVAILABLE" and not upgrade:
            results.append((spec.display_name, f"reused {check.version} at {check.executable}"))
            continue
        if (
            check.status == "AVAILABLE"
            and upgrade
            and check.executable
            and Path(check.executable).resolve()
            != (selected_directory / Path(check.executable).name).resolve()
        ):
            results.append(
                (
                    spec.display_name,
                    f"system installation {check.version} left unchanged; manage upgrades with its installer",
                )
            )
            continue
        if spec.install_method != "pinned_release":
            results.append(
                (
                    spec.display_name,
                    f"manual installation required; impact: {spec.doctor_capability}; "
                    f"recovery: {spec.download_source}",
                )
            )
            continue
        asset = spec.assets.get("/".join(normalized))
        if asset is None:
            results.append((spec.display_name, f"unsupported on {normalized[0]}/{normalized[1]}"))
            continue
        managed = selected_directory / asset.executable_name
        managed_version: str | None = None
        if managed.is_file() and not managed.is_symlink():
            version, error = _probe_version(str(managed), spec)
            if error is None and _compare_versions(version or "", asset.version) in {0, 1}:
                managed_version = version
        if (
            check.executable
            and Path(check.executable).resolve() != managed.resolve()
            and check.status in {"BROKEN", "WRONG_VERSION"}
        ):
            results.append(
                (
                    spec.display_name,
                    f"{check.status.lower()} system installation left unchanged; "
                    f"impact: {spec.doctor_capability}; recovery: {spec.download_source}",
                )
            )
            continue
        if managed_version is not None:
            results.append((spec.display_name, f"reused {managed_version} at {managed}"))
            continue
        try:
            path = install_asset(selected_directory, asset, spec, upgrade=upgrade)
        except (OSError, ValueError, tarfile.TarError, zipfile.BadZipFile, TimeoutError) as error:
            results.append(
                (
                    spec.display_name,
                    f"failed: {error}; impact: {spec.doctor_capability}; "
                    f"recovery: retry when online or use {spec.download_source}",
                )
            )
        else:
            results.append((spec.display_name, f"installed {asset.version} at {path}"))
    return tuple(results)


def setup_plan(
    category: str, *, system: str | None = None, machine: str | None = None
) -> tuple[str, ...]:
    if category not in _CATEGORIES:
        raise ValueError(f"Unknown setup category: {category}")
    selected: list[str] = []
    for spec in load_manifest():
        if spec.category != category:
            continue
        check = inspect_tool(spec, system=system, machine=machine)
        selected.append(
            f"{spec.display_name}: {check.status}; {spec.install_method}; {check.detail or spec.doctor_capability}"
        )
    return tuple(selected)
