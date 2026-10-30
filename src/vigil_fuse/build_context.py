from __future__ import annotations

import configparser
import glob
import hashlib
import json
import os
import shlex
from pathlib import Path
from typing import Any

from .model import (
    CompilationDatabaseInventory,
    PlatformIOConfigArtifact,
    PlatformIOEnvironment,
    PlatformIOInventory,
)
from .text_safety import safe_report_text

MAX_PLATFORMIO_BYTES = 2 * 1024 * 1024
MAX_PLATFORMIO_CONFIG_FILES = 64
MAX_PLATFORMIO_CONFIG_DEPTH = 8
MAX_PLATFORMIO_TOTAL_BYTES = 10 * 1024 * 1024
MAX_COMPILATION_DATABASE_BYTES = 20 * 1024 * 1024
MAX_COMPILATION_DATABASE_ENTRIES = 100_000


def _select_project_file(root: Path, supplied: str | Path, option: str) -> tuple[Path, str]:
    root_path = root.resolve(strict=True)
    requested = Path(supplied).expanduser()
    candidate = requested if requested.is_absolute() else root_path / requested
    lexical = Path(os.path.abspath(candidate))
    try:
        relative = lexical.relative_to(root_path)
    except ValueError as error:
        raise ValueError(f"{option} must resolve inside the scan target directory") from error
    cursor = root_path
    for part in relative.parts:
        cursor = cursor / part
        if cursor.is_symlink():
            raise ValueError(f"{option} cannot follow symbolic links")
    selected = lexical.resolve(strict=True)
    try:
        display = selected.relative_to(root_path).as_posix()
    except ValueError as error:
        raise ValueError(f"{option} must resolve inside the scan target directory") from error
    if not selected.is_file():
        raise ValueError(f"{option} must identify a regular file")
    return selected, safe_report_text(display, limit=1000) or "unknown-path"


def _read_bounded(path: Path, limit: int, option: str) -> bytes:
    try:
        size = path.stat().st_size
    except OSError as error:
        raise ValueError(f"{option} could not be inspected") from error
    if size > limit:
        raise ValueError(f"{option} exceeds the {limit}-byte limit")
    try:
        with path.open("rb") as stream:
            data = stream.read(limit + 1)
    except OSError as error:
        raise ValueError(f"{option} could not be read") from error
    if len(data) > limit:
        raise ValueError(f"{option} exceeds the {limit}-byte limit")
    return data


def _csv_values(value: str | None) -> tuple[str, ...]:
    if not value:
        return ()
    return tuple(
        cleaned for item in value.split(",") if (cleaned := safe_report_text(item, limit=240))
    )


def _load_platformio_config_graph(
    root: Path, root_config: Path, root_display: str
) -> tuple[dict[str, dict[str, str]], tuple[PlatformIOConfigArtifact, ...], list[str], bool]:
    """Merge a bounded PlatformIO extra_configs graph without expanding variables."""
    sections: dict[str, dict[str, str]] = {}
    artifacts: list[PlatformIOConfigArtifact] = []
    limitations: list[str] = []
    root_path = root.resolve(strict=True)
    visited: set[Path] = set()
    active: set[Path] = set()
    total_bytes = 0
    root_invalid = False

    def load(config_path: Path, depth: int, is_root: bool = False) -> None:
        nonlocal total_bytes, root_invalid
        if depth > MAX_PLATFORMIO_CONFIG_DEPTH:
            limitations.append(
                f"PlatformIO extra_configs depth exceeded {MAX_PLATFORMIO_CONFIG_DEPTH}; remaining includes were not inspected."
            )
            return
        lexical = Path(os.path.abspath(config_path))
        try:
            relative = lexical.relative_to(root_path)
        except ValueError:
            limitations.append(
                "A PlatformIO extra_configs entry resolved outside the scan target and was not read."
            )
            return
        cursor = root_path
        for part in relative.parts:
            cursor = cursor / part
            if cursor.is_symlink():
                limitations.append("A symbolic link in PlatformIO extra_configs was not followed.")
                return
        try:
            resolved = lexical.resolve(strict=True)
            display_path = resolved.relative_to(root_path).as_posix()
        except (OSError, ValueError):
            limitations.append(
                "A PlatformIO extra_configs entry was missing or outside the scan target."
            )
            return
        if resolved in active:
            limitations.append(
                "A cycle in PlatformIO extra_configs was detected; the repeated file was not read."
            )
            return
        if resolved in visited:
            return
        if len(artifacts) >= MAX_PLATFORMIO_CONFIG_FILES:
            limitations.append(
                f"PlatformIO extra_configs exceeded the {MAX_PLATFORMIO_CONFIG_FILES}-file limit."
            )
            return
        try:
            data = _read_bounded(resolved, MAX_PLATFORMIO_BYTES, "PlatformIO configuration")
        except ValueError as error:
            limitations.append(f"{display_path}: {error}")
            if is_root:
                root_invalid = True
            return
        if total_bytes + len(data) > MAX_PLATFORMIO_TOTAL_BYTES:
            limitations.append(
                f"PlatformIO configuration inputs exceeded the {MAX_PLATFORMIO_TOTAL_BYTES}-byte total limit."
            )
            if is_root:
                root_invalid = True
            return
        total_bytes += len(data)
        artifacts.append(
            PlatformIOConfigArtifact(
                path=safe_report_text(display_path, limit=1000) or "unknown-path",
                sha256=hashlib.sha256(data).hexdigest(),
                byte_size=len(data),
            )
        )
        try:
            text = data.decode("utf-8-sig")
        except UnicodeDecodeError:
            limitations.append(f"{display_path} is not UTF-8 text and was not parsed.")
            if is_root:
                root_invalid = True
            visited.add(resolved)
            return
        parser = configparser.ConfigParser(interpolation=None, strict=False)
        try:
            parser.read_string(text)
        except configparser.Error as error:
            limitations.append(
                f"{display_path} parse failed ({type(error).__name__}); that file was not merged."
            )
            if is_root:
                root_invalid = True
            visited.add(resolved)
            return

        active.add(resolved)
        for section in parser.sections():
            sections.setdefault(section, {}).update(dict(parser.items(section, raw=True)))
        include_text = parser.get("platformio", "extra_configs", fallback="", raw=True)
        patterns = [line.strip() for line in include_text.splitlines() if line.strip()]
        for pattern in patterns:
            if "${" in pattern or "$PROJECT_DIR" in pattern or "%" in pattern:
                limitations.append(
                    f"{display_path} contains an unresolved extra_configs variable; that include was not expanded."
                )
                continue
            if "**" in pattern:
                limitations.append(
                    f"{display_path} uses recursive glob syntax in extra_configs; that include was not expanded."
                )
                continue
            pattern_path = Path(pattern).expanduser()
            lexical_pattern = (
                Path(os.path.abspath(pattern_path))
                if pattern_path.is_absolute()
                else Path(os.path.abspath(root_path / pattern_path))
            )
            try:
                lexical_pattern.relative_to(root_path)
            except ValueError:
                limitations.append(
                    f"{display_path} declares an extra_configs path outside the scan target; it was not read."
                )
                continue
            matches: list[Path] = []
            match_limit_exceeded = False
            for match in glob.iglob(str(lexical_pattern), recursive=False):
                matches.append(Path(match))
                if len(matches) > MAX_PLATFORMIO_CONFIG_FILES:
                    limitations.append(
                        f"{display_path} extra_configs pattern exceeded the {MAX_PLATFORMIO_CONFIG_FILES}-path match limit; none of its matches were merged."
                    )
                    match_limit_exceeded = True
                    break
            if match_limit_exceeded:
                continue
            regular_matches = sorted(
                (item for item in matches if item.is_file()),
                key=lambda item: item.as_posix().casefold(),
            )
            if not regular_matches:
                limitations.append(
                    f"{display_path} extra_configs pattern {safe_report_text(pattern, limit=240)!r} matched no files."
                )
            for included in regular_matches:
                if len(artifacts) >= MAX_PLATFORMIO_CONFIG_FILES:
                    limitations.append(
                        f"PlatformIO extra_configs exceeded the {MAX_PLATFORMIO_CONFIG_FILES}-file limit."
                    )
                    break
                load(included, depth + 1)
        active.remove(resolved)
        visited.add(resolved)

    load(root_config, 0, is_root=True)
    if not artifacts or artifacts[0].path != root_display:
        root_invalid = True
    return sections, tuple(artifacts), limitations, root_invalid


def inspect_platformio(
    root: Path,
    *,
    selected_environments: tuple[str, ...] = (),
    config_path: str | Path | None = None,
) -> PlatformIOInventory:
    """Read an allow-listed view of PlatformIO configuration without running it."""
    if not root.is_dir():
        return PlatformIOInventory()
    supplied = config_path if config_path is not None else Path("platformio.ini")
    candidate = Path(supplied).expanduser()
    if not candidate.is_absolute():
        candidate = root / candidate
    if config_path is None and not candidate.exists() and not candidate.is_symlink():
        if selected_environments:
            raise ValueError("--platformio-env requires a detectable platformio.ini file")
        return PlatformIOInventory()

    path, display = _select_project_file(root, supplied, "--platformio-config")
    merged_sections, config_artifacts, limitations, root_invalid = _load_platformio_config_graph(
        root, path, display
    )
    root_artifact = next((item for item in config_artifacts if item.path == display), None)
    if root_invalid or root_artifact is None:
        return PlatformIOInventory(
            status="invalid",
            path=display,
            sha256=root_artifact.sha256 if root_artifact else None,
            byte_size=root_artifact.byte_size if root_artifact else 0,
            configurations=config_artifacts,
            limitations=tuple(dict.fromkeys(limitations))
            or ("PlatformIO configuration could not be parsed.",),
        )

    base_values = merged_sections.get("env", {})
    sections = {
        section[4:]: section
        for section in merged_sections
        if section.casefold().startswith("env:") and section[4:]
    }
    resolved_sections: dict[str, dict[str, str]] = {}
    resolving: set[str] = set()

    def resolve_environment(name: str) -> dict[str, str]:
        if name in resolved_sections:
            return dict(resolved_sections[name])
        if name in resolving:
            limitations.append(f"Environment inheritance cycle includes {name}.")
            return {}
        section_name = sections.get(name)
        if section_name is None:
            limitations.append(f"Environment inheritance target {name} was not found.")
            return {}
        resolving.add(name)
        values = dict(base_values)
        own = dict(merged_sections[section_name])
        parent = own.get("extends", "").strip()
        if parent:
            parent_name = parent.removeprefix("env:")
            values.update(resolve_environment(parent_name))
        values.update(own)
        resolving.remove(name)
        resolved_sections[name] = dict(values)
        return values

    environments: list[PlatformIOEnvironment] = []
    for name in sorted(sections, key=str.casefold):
        values = resolve_environment(name)
        environments.append(
            PlatformIOEnvironment(
                name=safe_report_text(name, limit=240) or "unnamed",
                platform=safe_report_text(values.get("platform"), limit=240),
                board=safe_report_text(values.get("board"), limit=240),
                frameworks=_csv_values(values.get("framework")),
                build_type=safe_report_text(values.get("build_type"), limit=240),
                upload_protocol=safe_report_text(values.get("upload_protocol"), limit=240),
                debug_tool=safe_report_text(values.get("debug_tool"), limit=240),
                extends=safe_report_text(values.get("extends"), limit=240),
                source_dir=safe_report_text(
                    values.get("src_dir") or merged_sections.get("platformio", {}).get("src_dir"),
                    limit=500,
                ),
                source_filter=tuple(
                    cleaned
                    for line in values.get("build_src_filter", "").splitlines()
                    if (cleaned := safe_report_text(line.strip(), limit=500))
                ),
            )
        )

    default_environments = _csv_values(
        merged_sections.get("platformio", {}).get("default_envs", "")
    )
    available_names = {item.name for item in environments}
    if selected_environments:
        unknown = set(selected_environments) - available_names
        if unknown:
            raise ValueError("Unknown PlatformIO environment(s): " + ", ".join(sorted(unknown)))
        selected = tuple(name for name in selected_environments if name in available_names)
    elif default_environments:
        selected = tuple(name for name in default_environments if name in available_names)
        missing_defaults = set(default_environments) - available_names
        if missing_defaults:
            limitations.append(
                "One or more default environments are not declared: "
                + ", ".join(sorted(missing_defaults))
                + "."
            )
    else:
        selected = tuple(item.name for item in environments)

    if not environments:
        limitations.append("No [env:name] sections were found; no environment matrix was inferred.")
    return PlatformIOInventory(
        status="partial" if limitations else "parsed",
        path=display,
        sha256=root_artifact.sha256,
        byte_size=root_artifact.byte_size,
        default_environments=tuple(
            safe_report_text(name, limit=240) or "unnamed" for name in default_environments
        ),
        selected_environments=tuple(
            safe_report_text(name, limit=240) or "unnamed" for name in selected
        ),
        environments=tuple(environments),
        configurations=config_artifacts,
        limitations=tuple(dict.fromkeys(limitations)),
    )


def _compiler_family(command: list[str]) -> str:
    if not command:
        return "unknown"
    name = Path(command[0].replace("\\", "/")).name.casefold()
    if name.endswith(".exe"):
        name = name[:-4]
    if "clang-cl" in name:
        return "clang-cl"
    if "clang" in name:
        return "clang"
    if name in {"cl", "cl.exe"} or name.startswith("cl-"):
        return "msvc"
    if any(token in name for token in ("gcc", "g++", "cc", "c++", "icc", "icx", "xtensa", "riscv")):
        return "gcc-compatible"
    return "unknown"


def _entry_command(entry: dict[str, Any]) -> list[str]:
    arguments = entry.get("arguments")
    if (
        isinstance(arguments, list)
        and arguments
        and all(isinstance(item, str) for item in arguments)
    ):
        return arguments
    command = entry.get("command")
    if isinstance(command, str) and command:
        try:
            return shlex.split(command, posix=os.name != "nt")
        except ValueError:
            return []
    return []


def _is_within(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def inspect_compilation_database(
    root: Path,
    *,
    database_path: str | Path | None = None,
) -> CompilationDatabaseInventory:
    """Index a compilation database as data. No compiler or command is executed."""
    if not root.is_dir():
        return CompilationDatabaseInventory()
    supplied = database_path if database_path is not None else Path("compile_commands.json")
    candidate = Path(supplied).expanduser()
    if not candidate.is_absolute():
        candidate = root / candidate
    if database_path is None and not candidate.exists() and not candidate.is_symlink():
        return CompilationDatabaseInventory()

    path, display = _select_project_file(root, supplied, "--compile-commands")
    try:
        data = _read_bounded(
            path,
            MAX_COMPILATION_DATABASE_BYTES,
            "Compilation database",
        )
        document = json.loads(data)
    except (ValueError, json.JSONDecodeError, UnicodeDecodeError, RecursionError):
        return CompilationDatabaseInventory(
            status="invalid",
            path=display,
            sha256=hashlib.sha256(data).hexdigest() if "data" in locals() else None,
            byte_size=len(data) if "data" in locals() else 0,
            limitations=("Compilation database is not valid bounded UTF-8 JSON.",),
        )

    if not isinstance(document, list):
        return CompilationDatabaseInventory(
            status="invalid",
            path=display,
            sha256=hashlib.sha256(data).hexdigest(),
            byte_size=len(data),
            limitations=("Compilation database root must be an array.",),
        )
    root_path = root.resolve(strict=True)
    if len(document) > MAX_COMPILATION_DATABASE_ENTRIES:
        document = document[:MAX_COMPILATION_DATABASE_ENTRIES]
        entry_truncated = True
    else:
        entry_truncated = False

    families: dict[str, int] = {}
    units: set[str] = set()
    in_target = 0
    external = 0
    malformed = 0
    for entry in document:
        if not isinstance(entry, dict):
            malformed += 1
            continue
        source_name = entry.get("file")
        directory_value = entry.get("directory")
        if (
            not isinstance(source_name, str)
            or not source_name
            or not isinstance(directory_value, str)
        ):
            malformed += 1
            continue
        command = _entry_command(entry)
        if not command:
            malformed += 1
            continue
        family = _compiler_family(command)
        families[family] = families.get(family, 0) + 1
        directory = Path(directory_value).expanduser()
        if not directory.is_absolute():
            directory = path.parent / directory
        source = Path(source_name).expanduser()
        if not source.is_absolute():
            source = directory / source
        try:
            resolved_source = source.resolve(strict=False)
        except OSError:
            malformed += 1
            continue
        key = os.path.normcase(str(resolved_source))
        units.add(key)
        if _is_within(resolved_source, root_path):
            in_target += 1
        else:
            external += 1

    limitations: list[str] = []
    if malformed:
        limitations.append(f"{malformed} compilation database entr(y/ies) were not indexable.")
    if entry_truncated:
        limitations.append(
            f"Database entries exceeded the {MAX_COMPILATION_DATABASE_ENTRIES}-entry limit; the index is truncated."
        )
    if not document:
        limitations.append("Compilation database contains no entries.")
    return CompilationDatabaseInventory(
        status="partial" if limitations else "indexed",
        path=display,
        sha256=hashlib.sha256(data).hexdigest(),
        byte_size=len(data),
        entry_count=len(document),
        unique_translation_units=len(units),
        in_target_source_count=in_target,
        external_source_count=external,
        compiler_families=dict(sorted(families.items())),
        malformed_entries=malformed,
        limitations=tuple(limitations),
    )
