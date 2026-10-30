from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

from .esp_idf_lock import inspect_dependencies_lock
from .model import (
    AnalyzerStatus,
    ConfigurationDefault,
    ConfigurationOrigin,
    ContextArtifact,
    ContextSetting,
    ProjectContext,
    SourceFile,
)
from .path_safety import resolve_inside_directory

MAX_CONTEXT_FILE_BYTES = 4 * 1024 * 1024
_SAFE_METADATA_VALUE = re.compile(r"^[A-Za-z0-9_.+-]{1,120}$")
_ESP_IDF_SECURITY_OPTIONS = (
    "CONFIG_BOOTLOADER_SKIP_VALIDATE_ALWAYS",
    "CONFIG_BOOTLOADER_SKIP_VALIDATE_IN_DEEP_SLEEP",
)


def _read_limited(path: Path) -> bytes | None:
    if path.is_symlink() or not path.is_file():
        return None
    try:
        if path.stat().st_size > MAX_CONTEXT_FILE_BYTES:
            return None
        with path.open("rb") as stream:
            data = stream.read(MAX_CONTEXT_FILE_BYTES + 1)
    except OSError:
        return None
    if len(data) > MAX_CONTEXT_FILE_BYTES:
        return None
    return data


def _project_markers(root: Path, framework: str) -> tuple[bool, tuple[str, ...]]:
    evidence: list[str] = []
    cmake = root / "CMakeLists.txt"
    cmake_data = _read_limited(cmake)
    cmake_text = cmake_data.decode("utf-8", errors="ignore").casefold() if cmake_data else ""

    if framework == "esp-idf":
        if "project.cmake" in cmake_text and "idf_path" in cmake_text:
            evidence.append("CMakeLists.txt references the ESP-IDF project build system")
        elif "project.cmake" in cmake_text:
            evidence.append("CMakeLists.txt references project.cmake")
        for relative in ("idf_component.yml", "main/idf_component.yml"):
            path = root / relative
            if path.is_file() and not path.is_symlink():
                evidence.append(f"{relative} component manifest exists")
        return bool(evidence), tuple(evidence)

    if framework == "zephyr":
        if re.search(r"find_package\s*\(\s*zephyr\b", cmake_text):
            evidence.append("CMakeLists.txt requests the Zephyr CMake package")
        west = root / "west.yml"
        if west.is_file() and not west.is_symlink():
            evidence.append("west.yml manifest exists")
        prj_conf = root / "prj.conf"
        if prj_conf.is_file() and not prj_conf.is_symlink():
            evidence.append("prj.conf exists")
        return bool(
            "CMakeLists.txt requests the Zephyr CMake package" in evidence
            or ("west.yml manifest exists" in evidence and "prj.conf exists" in evidence)
        ), tuple(evidence)

    return False, ()


def detect_project_frameworks(target: str | Path) -> tuple[tuple[str, tuple[str, ...]], ...]:
    """Return bounded ESP-IDF and Zephyr project hints without selecting an analyzer."""
    root = Path(target).expanduser()
    if root.is_symlink() or not root.is_dir():
        return ()
    root = root.resolve(strict=True)
    hints = []
    for framework in ("esp-idf", "zephyr"):
        detected, evidence = _project_markers(root, framework)
        if detected:
            hints.append((framework, evidence))
    return tuple(hints)


def resolve_build_dir(root: Path, build_dir: str | Path) -> tuple[Path, str]:
    root_path = root.resolve(strict=True)
    supplied = Path(build_dir).expanduser()
    candidate = supplied if supplied.is_absolute() else root_path / supplied
    try:
        resolved, relative = resolve_inside_directory(root_path, candidate)
    except ValueError as error:
        if "symbolic link" in str(error):
            raise ValueError("--build-dir cannot pass through a symbolic link") from error
        raise ValueError("--build-dir must resolve inside the scan target directory") from error
    if not resolved.is_dir():
        raise ValueError("--build-dir must identify an existing directory")
    return resolved, relative


def _display(path: Path, root: Path) -> str:
    return path.relative_to(root).as_posix()


def _read_context_file(
    path: Path,
    root: Path,
    *,
    role: str,
    generated_config: bool = False,
) -> tuple[ContextArtifact, SourceFile | None, str | None]:
    relative = _display(path, root)
    cursor = root
    path_has_symlink = False
    for part in Path(relative).parts:
        cursor = cursor / part
        if cursor.is_symlink():
            path_has_symlink = True
            break
    if path_has_symlink:
        return (
            ContextArtifact(relative, role, None, 0),
            None,
            f"{relative} is a symbolic link and was not read",
        )
    try:
        size = path.stat().st_size
    except OSError:
        return ContextArtifact(relative, role, None, 0), None, f"{relative} could not be inspected"
    if size > MAX_CONTEXT_FILE_BYTES:
        return (
            ContextArtifact(relative, role, None, size),
            None,
            f"{relative} exceeds the 4 MiB context-file limit",
        )
    data = _read_limited(path)
    if data is None:
        return (
            ContextArtifact(relative, role, None, size),
            None,
            f"{relative} could not be read safely",
        )
    digest = hashlib.sha256(data).hexdigest()
    artifact = ContextArtifact(relative, role, digest, len(data))
    try:
        text = data.decode("utf-8-sig")
    except UnicodeDecodeError:
        return artifact, None, f"{relative} is not UTF-8 text"
    if "\x00" in text:
        return artifact, None, f"{relative} contains NUL bytes"
    source = SourceFile(
        path=relative,
        text=text,
        sha256=digest,
        byte_size=len(data),
        generated_config=generated_config,
    )
    return artifact, source, None


def _security_settings(source: SourceFile) -> tuple[ContextSetting, ...]:
    settings: list[ContextSetting] = []
    for line_number, line in enumerate(source.text.splitlines(), start=1):
        for name in _ESP_IDF_SECURITY_OPTIONS:
            kconfig = re.match(rf"^\s*{re.escape(name)}\s*=\s*([^\s#]+)", line)
            macro = re.match(rf"^\s*#\s*define\s+{re.escape(name)}\s+([^\s/]+)", line)
            match = kconfig or macro
            if not match:
                continue
            raw_value = match.group(1).strip().strip('"').casefold()
            value = (
                "enabled"
                if raw_value in {"y", "1", "yes", "true"}
                else ("disabled" if raw_value in {"n", "0", "no", "false"} else "unknown")
            )
            settings.append(ContextSetting(name, value, source.path, line_number))
    return tuple(settings)


def _safe_string(document: object, *keys: str) -> str | None:
    if not isinstance(document, dict):
        return None
    for key in keys:
        value = document.get(key)
        if isinstance(value, str) and _SAFE_METADATA_VALUE.fullmatch(value):
            return value
    return None


def _cmake_cache_values(source: SourceFile | None) -> dict[str, str]:
    if source is None:
        return {}
    values: dict[str, str] = {}
    for line in source.text.splitlines():
        if not line or line.startswith("//") or line.startswith("#"):
            continue
        match = re.match(r"^(SDKCONFIG|SDKCONFIG_DEFAULTS|IDF_TARGET):[^=]*=(.*)$", line)
        if match:
            values[match.group(1)] = match.group(2).strip()
    return values


def _safe_project_path(root: Path, value: str) -> tuple[Path | None, str | None]:
    """Resolve a configuration path inside the target without following symlinks."""
    if not value or "\x00" in value or "$" in value:
        return None, "unreadable"
    supplied = Path(value)
    candidate = supplied if supplied.is_absolute() else root / supplied
    try:
        resolved, relative = resolve_inside_directory(root, candidate)
    except ValueError as error:
        if "symbolic link" in str(error):
            return None, "unreadable"
        return None, "outside-target"
    if relative == ".":
        return None, "unreadable"
    return resolved, None


def _inspect_esp_idf_configuration_origin(
    root: Path,
    target: str | None,
    *,
    build_root: Path | None,
    cache_values: dict[str, str] | None = None,
) -> tuple[ConfigurationOrigin, tuple[ContextArtifact, ...], SourceFile | None, tuple[str, ...]]:
    """Describe selected sdkconfig provenance and ordered default-file candidates.

    Only a selected build's CMake cache can provide an observed SDKCONFIG or
    SDKCONFIG_DEFAULTS value. Conventional defaults are reported as candidates,
    because project CMake code or the build environment may override them.
    """
    values = cache_values or {}
    artifacts: list[ContextArtifact] = []
    defaults: list[ConfigurationDefault] = []
    warnings: list[str] = []
    limitations: list[str] = []
    default_list_value = values.get("SDKCONFIG_DEFAULTS")
    if build_root is not None and "SDKCONFIG_DEFAULTS" in values:
        defaults_source = "cmake-cache"
        bases = [item.strip().strip('"') for item in default_list_value.split(";") if item.strip()]
        order_resolved = target is not None or not bases
        if target is None and bases:
            limitations.append(
                "The CMake cache lists SDKCONFIG_DEFAULTS, but no selected target was resolved to order target-specific variants."
            )
    else:
        defaults_source = "conventional-candidate"
        conventional = root / "sdkconfig.defaults"
        conventional_exists = conventional.exists() or conventional.is_symlink()
        bases = ["sdkconfig.defaults"] if conventional_exists else []
        order_resolved = False
        limitations.append(
            "The conventional sdkconfig.defaults path is only a candidate; project CMake code or the build environment may select a different SDKCONFIG_DEFAULTS list."
        )

    default_candidates: list[tuple[str, bool]] = []
    for base in bases[:64]:
        default_candidates.append((base, False))
        if target:
            default_candidates.append((f"{base}.{target}", True))
    if len(bases) > 64:
        limitations.append("The SDKCONFIG_DEFAULTS list exceeded 64 entries and was truncated.")
        order_resolved = False

    for order, (value, target_specific) in enumerate(default_candidates, start=1):
        candidate, path_error = _safe_project_path(root, value)
        if candidate is None:
            state = path_error or "unreadable"
            display_path = "<outside-target>" if state == "outside-target" else "<unreadable-path>"
            defaults.append(ConfigurationDefault(display_path, order, target_specific, state))
            if state == "outside-target":
                limitations.append(
                    "One or more ESP-IDF defaults resolve outside the selected target and were not read."
                )
            continue
        display_path = _display(candidate, root)
        role = (
            f"ESP-IDF target-specific defaults candidate, order {order}"
            if target_specific
            else f"ESP-IDF defaults candidate, order {order}"
        )
        if not candidate.exists() and not candidate.is_symlink():
            defaults.append(ConfigurationDefault(display_path, order, target_specific, "missing"))
            artifacts.append(ContextArtifact(display_path, role, None, 0))
            continue
        artifact, source, warning = _read_context_file(
            candidate,
            root,
            role=role,
        )
        if source is None:
            exists = candidate.exists()
            state = "unreadable" if exists else "missing"
            defaults.append(ConfigurationDefault(display_path, order, target_specific, state))
            artifacts.append(artifact)
            if warning:
                warnings.append(warning)
                limitations.append(warning)
        else:
            defaults.append(
                ConfigurationDefault(
                    display_path,
                    order,
                    target_specific,
                    "present",
                    source.sha256,
                    source.byte_size,
                )
            )
            artifacts.append(artifact)

    if build_root is None:
        limitations.append(
            "No selected build directory was supplied, so active sdkconfig and target were not resolved."
        )
        return (
            ConfigurationOrigin(
                status="candidates-only",
                defaults_source=defaults_source,
                defaults_order_resolved=order_resolved,
                default_files=tuple(defaults),
                limitations=tuple(dict.fromkeys(limitations)),
            ),
            tuple(artifacts),
            None,
            tuple(warnings),
        )

    selected_value = values.get("SDKCONFIG")
    if selected_value:
        selected_source = "cmake-cache"
        selected_path, path_error = _safe_project_path(root, selected_value)
    else:
        selected_source = "project-default"
        selected_path, path_error = _safe_project_path(root, "sdkconfig")

    selected_relative: str | None = None
    selected_source_file: SourceFile | None = None
    selected_status = "unresolved"
    if selected_path is not None:
        selected_relative = _display(selected_path, root)
        artifact, selected_source_file, warning = _read_context_file(
            selected_path,
            root,
            role="selected ESP-IDF sdkconfig",
            generated_config=True,
        )
        artifacts.append(artifact)
        if selected_source_file is not None:
            selected_status = "selected"
        elif selected_path.exists():
            selected_status = "partial"
            if warning:
                warnings.append(warning)
                limitations.append(warning)
        else:
            limitations.append(
                "The selected sdkconfig path is not present; generated sdkconfig.h remains the only selected configuration evidence."
            )
    elif path_error == "outside-target":
        selected_source = "unresolved"
        limitations.append("The selected sdkconfig resolves outside the target and was not read.")
    else:
        selected_source = "unresolved"
        limitations.append("The selected sdkconfig path could not be resolved safely.")

    if defaults_source == "cmake-cache":
        limitations.append(
            "Default-file order follows the SDKCONFIG_DEFAULTS value observed in CMakeCache.txt; project CMake code or environment overrides are not evaluated."
        )
    elif not defaults:
        limitations.append(
            "No conventional sdkconfig.defaults file was found; a selected build may still use custom defaults."
        )
    if not order_resolved and target is None:
        limitations.append(
            "Target-specific defaults could not be ordered because the selected build target is unknown."
        )

    status = selected_status
    if status == "selected" and (warnings or path_error):
        status = "partial"
    return (
        ConfigurationOrigin(
            status=status,
            selected_sdkconfig=selected_relative,
            selected_sdkconfig_source=selected_source,
            defaults_source=defaults_source,
            defaults_order_resolved=order_resolved,
            default_files=tuple(defaults),
            limitations=tuple(dict.fromkeys(limitations)),
        ),
        tuple(artifacts),
        selected_source_file,
        tuple(warnings),
    )


def inspect_project_context(
    target: str | Path,
    framework: str,
    build_dir: str | Path | None = None,
) -> tuple[ProjectContext, tuple[SourceFile, ...], tuple[str, ...], AnalyzerStatus | None]:
    """Inspect known project markers and, only when selected, bounded generated build files.

    This adapter never runs a build system, west, a component manager, or a project script.
    """
    if framework not in {"esp-idf", "zephyr"}:
        return ProjectContext(), (), (), None
    root = Path(target).expanduser()
    if not root.is_dir():
        if build_dir is not None:
            raise ValueError("--build-dir requires a project directory target")
        return ProjectContext(framework=framework), (), (), None
    root = root.resolve(strict=True)

    detected, evidence = _project_markers(root, framework)
    limitations = [
        "Project markers identify a likely framework project but do not prove which build or image is deployed.",
        "FUSE did not invoke the framework build system or resolve dependency manifests.",
    ]
    if build_dir is None:
        status = "detected" if detected else "not-detected"
        component_lock = None
        lock_artifact = None
        lock_analyzer_status = None
        if framework == "esp-idf":
            component_lock, lock_artifact, lock_analyzer_status = inspect_dependencies_lock(
                root, None
            )
            origin, origin_artifacts, _, origin_warnings = _inspect_esp_idf_configuration_origin(
                root,
                None,
                build_root=None,
            )
            configuration_files = (
                *origin_artifacts,
                *((lock_artifact,) if lock_artifact is not None else ()),
            )
            limitations.extend(origin.limitations)
            limitations.extend(origin_warnings)
        else:
            origin = ConfigurationOrigin()
            configuration_files = (lock_artifact,) if lock_artifact is not None else ()
        if framework == "esp-idf":
            limitations.append("No selected generated ESP-IDF build configuration was supplied.")
        else:
            limitations.append("No selected Zephyr build output was supplied.")
        return (
            ProjectContext(
                framework=framework,
                status=status,
                project_detected=detected,
                evidence=evidence,
                configuration_files=configuration_files,
                configuration_origin=origin,
                component_lock=component_lock or ProjectContext().component_lock,
                limitations=tuple(limitations),
            ),
            (),
            (),
            lock_analyzer_status,
        )

    build_root, relative_build = resolve_build_dir(root, build_dir)
    configuration_files: list[ContextArtifact] = []
    generated_sources: list[SourceFile] = []
    warnings: list[str] = []
    target_value: str | None = None
    board_value: str | None = None
    version_value: str | None = None
    cache_values: dict[str, str] = {}

    if framework == "esp-idf":
        cache_path = build_root / "CMakeCache.txt"
        if cache_path.exists() or cache_path.is_symlink():
            artifact, cache_source, warning = _read_context_file(
                cache_path,
                root,
                role="ESP-IDF CMake cache metadata",
            )
            configuration_files.append(artifact)
            cache_values = _cmake_cache_values(cache_source)
            if warning:
                warnings.append(warning)

    if framework == "esp-idf":
        config_candidates = (
            (build_root / "config" / "sdkconfig.h", "generated ESP-IDF sdkconfig header"),
        )
        metadata_path = build_root / "project_description.json"
    else:
        config_candidates = (
            (build_root / "zephyr" / ".config", "generated Zephyr Kconfig configuration"),
            (
                build_root / "zephyr" / "include" / "generated" / "zephyr" / "autoconf.h",
                "generated Zephyr Kconfig header",
            ),
        )
        metadata_path = None

    for path, role in config_candidates:
        if path.exists() or path.is_symlink():
            artifact, source, warning = _read_context_file(
                path,
                root,
                role=role,
                generated_config=True,
            )
            configuration_files.append(artifact)
            if source is not None:
                generated_sources.append(source)
                if framework == "esp-idf":
                    for match in re.finditer(
                        r'^\s*#\s*define\s+CONFIG_IDF_TARGET\s+"([^"\r\n]+)"',
                        source.text,
                        re.MULTILINE,
                    ):
                        candidate_target = match.group(1)
                        target_value = (
                            candidate_target
                            if _SAFE_METADATA_VALUE.fullmatch(candidate_target)
                            else None
                        )
                        break
                else:
                    for key, variable in (
                        ("CONFIG_BOARD", "board_value"),
                        ("CONFIG_KERNELVERSION", "version_value"),
                    ):
                        match = re.search(
                            rf'^\s*{key}\s*=\s*"?([^"\r\n#]+)', source.text, re.MULTILINE
                        )
                        if match:
                            if variable == "board_value":
                                candidate_board = match.group(1).strip()
                                board_value = (
                                    candidate_board
                                    if _SAFE_METADATA_VALUE.fullmatch(candidate_board)
                                    else None
                                )
                            else:
                                candidate_version = match.group(1).strip()
                                version_value = (
                                    candidate_version
                                    if _SAFE_METADATA_VALUE.fullmatch(candidate_version)
                                    else None
                                )
            if warning:
                warnings.append(warning)
            # Prefer Zephyr's textual .config and do not process the equivalent header twice.
            break

    if metadata_path is not None and (metadata_path.exists() or metadata_path.is_symlink()):
        artifact, metadata_source, warning = _read_context_file(
            metadata_path,
            root,
            role="ESP-IDF generated project metadata",
        )
        configuration_files.append(artifact)
        if warning:
            warnings.append(warning)
        elif metadata_source is not None:
            try:
                document = json.loads(metadata_source.text)
            except (json.JSONDecodeError, RecursionError):
                warnings.append("project_description.json is not valid JSON")
            else:
                target_value = target_value or _safe_string(document, "target", "idf_target")
                version_value = _safe_string(document, "idf_ver", "idf_version")

    if framework == "esp-idf":
        target_value = target_value or (
            cache_values.get("IDF_TARGET")
            if cache_values.get("IDF_TARGET")
            and _SAFE_METADATA_VALUE.fullmatch(cache_values["IDF_TARGET"])
            else None
        )

    component_lock = None
    lock_analyzer_status = None
    if framework == "esp-idf":
        component_lock, lock_artifact, lock_analyzer_status = inspect_dependencies_lock(
            root,
            target_value,
        )
        if lock_artifact is not None:
            configuration_files.append(lock_artifact)

    if framework == "esp-idf":
        origin, origin_artifacts, selected_sdkconfig, origin_warnings = (
            _inspect_esp_idf_configuration_origin(
                root,
                target_value,
                build_root=build_root,
                cache_values=cache_values,
            )
        )
        configuration_files.extend(origin_artifacts)
        warnings.extend(origin_warnings)
        limitations.extend(origin.limitations)
        if selected_sdkconfig is not None:
            # The selected sdkconfig has the full Kconfig values. Prefer it over
            # sdkconfig.h to avoid duplicate findings for the same setting.
            generated_sources = [selected_sdkconfig]
    else:
        origin = ConfigurationOrigin()

    settings = (
        tuple(setting for source in generated_sources for setting in _security_settings(source))
        if framework == "esp-idf"
        else ()
    )
    has_generated_config = bool(generated_sources)
    status = (
        "generated-config-found"
        if has_generated_config and not warnings
        else ("partial" if has_generated_config or warnings else "build-selected")
    )
    limitations.extend(warnings)
    if not has_generated_config:
        limitations.append(
            "The selected build directory contains no recognized generated configuration."
        )
    if framework == "zephyr":
        limitations.append(
            "FUSE does not run Zephyr hardenconfig; its selected JSON output can be imported separately."
        )
    else:
        limitations.append(
            "Selected build configuration evidence does not prove which image was released or deployed."
        )

    context = ProjectContext(
        framework=framework,
        status=status,
        project_detected=detected,
        build_dir=relative_build,
        target=target_value,
        board=board_value,
        framework_version=version_value,
        evidence=evidence,
        configuration_files=tuple(configuration_files),
        settings=settings,
        configuration_origin=origin,
        component_lock=component_lock or ProjectContext().component_lock,
        limitations=tuple(limitations),
    )
    return context, tuple(generated_sources), tuple(warnings), lock_analyzer_status
