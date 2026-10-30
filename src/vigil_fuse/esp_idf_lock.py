from __future__ import annotations

import hashlib
import importlib.util
import re
from pathlib import Path

from .model import AnalyzerStatus, ComponentLockInventory, ContextArtifact, ResolvedComponent

MAX_LOCK_BYTES = 4 * 1024 * 1024
MAX_LOCK_COMPONENTS = 10_000
MAX_LOCK_YAML_EVENTS = 200_000
MAX_LOCK_YAML_DEPTH = 100
_SAFE_NAME = re.compile(r"^[A-Za-z0-9_.+-]+(?:/[A-Za-z0-9_.+-]+)?$")
_SAFE_VERSION = re.compile(r"^[A-Za-z0-9._+~*-]{1,120}$")
_SHA256 = re.compile(r"^[a-fA-F0-9]{64}$")


def lock_parser_available() -> bool:
    try:
        return importlib.util.find_spec("yaml") is not None
    except (ImportError, ValueError):
        return False


def _safe_name(value: object) -> str | None:
    if not isinstance(value, str) or len(value) > 180:
        return None
    return value if _SAFE_NAME.fullmatch(value) else None


def _safe_version(value: object) -> str | None:
    if not isinstance(value, (str, int, float)) or isinstance(value, bool):
        return None
    text = str(value)
    return text if _SAFE_VERSION.fullmatch(text) else None


def _source_type(value: object) -> str:
    if not isinstance(value, dict):
        return "unknown"
    source_type = value.get("type")
    if isinstance(source_type, str) and re.fullmatch(r"[A-Za-z0-9_.+-]{1,80}", source_type):
        return source_type.casefold()
    return "unknown"


def _read_lock(path: Path) -> tuple[bytes | None, str | None]:
    if path.is_symlink():
        return None, "dependencies.lock is a symbolic link and was not read"
    try:
        if not path.is_file():
            return None, "dependencies.lock is not a regular file"
        if path.stat().st_size > MAX_LOCK_BYTES:
            return None, "dependencies.lock exceeds the 4 MiB input limit"
        with path.open("rb") as stream:
            data = stream.read(MAX_LOCK_BYTES + 1)
    except OSError:
        return None, "dependencies.lock could not be read safely"
    if len(data) > MAX_LOCK_BYTES:
        return None, "dependencies.lock exceeds the 4 MiB input limit"
    return data, None


def _validate_yaml_bounds(yaml, text: str) -> None:
    """Reject YAML aliases and cap parser work before constructing the lock mapping."""
    event_count = 0
    depth = 0
    for event in yaml.parse(text, Loader=yaml.SafeLoader):
        event_count += 1
        if event_count > MAX_LOCK_YAML_EVENTS:
            raise ValueError("dependencies.lock exceeds the YAML event limit")
        if isinstance(event, yaml.AliasEvent):
            raise ValueError("YAML aliases are not supported in dependencies.lock")
        if isinstance(event, (yaml.MappingStartEvent, yaml.SequenceStartEvent)):
            depth += 1
            if depth > MAX_LOCK_YAML_DEPTH:
                raise ValueError("dependencies.lock exceeds the YAML nesting limit")
        elif isinstance(event, (yaml.MappingEndEvent, yaml.SequenceEndEvent)):
            depth -= 1


def _load_unique_yaml_mapping(yaml, text: str):
    class UniqueKeySafeLoader(yaml.SafeLoader):
        pass

    def construct_unique_mapping(loader, node, deep=False):
        loader.flatten_mapping(node)
        mapping = {}
        for key_node, value_node in node.value:
            key = loader.construct_object(key_node, deep=deep)
            try:
                duplicate = key in mapping
            except TypeError as error:
                raise yaml.constructor.ConstructorError(
                    "while constructing dependencies.lock",
                    node.start_mark,
                    "mapping keys must be hashable",
                    key_node.start_mark,
                ) from error
            if duplicate:
                raise yaml.constructor.ConstructorError(
                    "while constructing dependencies.lock",
                    node.start_mark,
                    f"duplicate mapping key {key!r}",
                    key_node.start_mark,
                )
            mapping[key] = loader.construct_object(value_node, deep=deep)
        return mapping

    UniqueKeySafeLoader.add_constructor(
        yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
        construct_unique_mapping,
    )
    return yaml.load(text, Loader=UniqueKeySafeLoader)


def inspect_dependencies_lock(
    project_root: Path,
    selected_target: str | None,
) -> tuple[ComponentLockInventory, ContextArtifact | None, AnalyzerStatus | None]:
    path = project_root / "dependencies.lock"
    if not path.exists() and not path.is_symlink():
        return ComponentLockInventory(), None, None

    relative = path.relative_to(project_root).as_posix()
    data, read_error = _read_lock(path)
    digest = hashlib.sha256(data).hexdigest() if data is not None else None
    try:
        byte_size = path.lstat().st_size
    except OSError:
        byte_size = len(data) if data is not None else 0
    artifact = ContextArtifact(
        path=relative,
        role="ESP-IDF resolved component lock file",
        sha256=digest,
        byte_size=byte_size,
    )

    if read_error is not None:
        inventory = ComponentLockInventory(
            status="partial",
            path=relative,
            sha256=digest,
            byte_size=byte_size,
            limitations=(read_error,),
        )
        return (
            inventory,
            artifact,
            AnalyzerStatus("esp-idf-dependencies", "partial", detail=read_error),
        )
    assert data is not None
    if not lock_parser_available():
        detail = "Install the optional PyYAML parser with vigil-fuse[esp-idf] to inspect dependencies.lock."
        inventory = ComponentLockInventory(
            status="parser-unavailable",
            path=relative,
            sha256=digest,
            byte_size=byte_size,
            limitations=(detail,),
        )
        return (
            inventory,
            artifact,
            AnalyzerStatus("esp-idf-dependencies", "unavailable", detail=detail),
        )

    try:
        import yaml
    except ImportError:
        detail = "PyYAML became unavailable while parsing dependencies.lock."
        inventory = ComponentLockInventory(
            status="parser-unavailable",
            path=relative,
            sha256=digest,
            byte_size=byte_size,
            limitations=(detail,),
        )
        return (
            inventory,
            artifact,
            AnalyzerStatus("esp-idf-dependencies", "unavailable", detail=detail),
        )
    try:
        lock_text = data.decode("utf-8-sig")
        _validate_yaml_bounds(yaml, lock_text)
        document = _load_unique_yaml_mapping(yaml, lock_text)
    except (UnicodeDecodeError, yaml.YAMLError, RecursionError, ValueError) as error:
        detail = f"dependencies.lock could not be parsed safely ({type(error).__name__})."
        inventory = ComponentLockInventory(
            status="invalid",
            path=relative,
            sha256=digest,
            byte_size=byte_size,
            limitations=(detail,),
        )
        return (
            inventory,
            artifact,
            AnalyzerStatus(
                "esp-idf-dependencies",
                "failed",
                version=getattr(yaml, "__version__", None),
                detail=detail,
            ),
        )

    if not isinstance(document, dict):
        detail = "dependencies.lock root must be a mapping."
        inventory = ComponentLockInventory(
            status="invalid",
            path=relative,
            sha256=digest,
            byte_size=byte_size,
            limitations=(detail,),
        )
        return (
            inventory,
            artifact,
            AnalyzerStatus(
                "esp-idf-dependencies",
                "failed",
                version=getattr(yaml, "__version__", None),
                detail=detail,
            ),
        )

    dependencies = document.get("dependencies")
    direct_raw = document.get("direct_dependencies")
    target = _safe_name(document.get("target"))
    version = _safe_version(document.get("version"))
    manifest_hash_raw = document.get("manifest_hash")
    manifest_hash = (
        manifest_hash_raw.lower()
        if isinstance(manifest_hash_raw, str) and _SHA256.fullmatch(manifest_hash_raw)
        else None
    )
    warnings: list[str] = []
    structural_warnings: list[str] = []
    direct_dependencies: set[str] = set()
    if isinstance(direct_raw, list):
        for item in direct_raw:
            name = _safe_name(item)
            if name is not None:
                direct_dependencies.add(name)
            else:
                structural_warnings.append("One direct dependency name has an unsupported format.")
    else:
        structural_warnings.append("direct_dependencies is not a list.")
    if version is None:
        structural_warnings.append("The lock file has no supported format version.")

    components: list[ResolvedComponent] = []
    if not isinstance(dependencies, dict):
        structural_warnings.append("dependencies is not a mapping.")
        dependencies = {}
    if len(dependencies) > MAX_LOCK_COMPONENTS:
        structural_warnings.append(
            f"dependencies exceeds the {MAX_LOCK_COMPONENTS}-component limit."
        )
    for raw_name, entry in list(dependencies.items())[:MAX_LOCK_COMPONENTS]:
        name = _safe_name(raw_name)
        if name is None or not isinstance(entry, dict):
            structural_warnings.append("A dependency entry has an unsupported name or shape.")
            continue
        component_version = _safe_version(entry.get("version"))
        if component_version is None:
            structural_warnings.append(f"Dependency {name} has no supported resolved version.")
            continue
        raw_hash = entry.get("component_hash")
        component_hash = (
            raw_hash.lower() if isinstance(raw_hash, str) and _SHA256.fullmatch(raw_hash) else None
        )
        targets_raw = entry.get("targets", [])
        compatible_targets = (
            tuple(
                target_name
                for target_name in (_safe_name(item) for item in targets_raw[:100])
                if target_name is not None
            )
            if isinstance(targets_raw, list)
            else ()
        )
        dependencies_raw = entry.get("dependencies", {})
        dependency_names = (
            tuple(
                sorted(
                    name_value
                    for name_value in (_safe_name(item) for item in dependencies_raw.keys())
                    if name_value is not None
                )
            )
            if isinstance(dependencies_raw, dict)
            else ()
        )
        components.append(
            ResolvedComponent(
                name=name,
                version=component_version,
                source_type=_source_type(entry.get("source")),
                direct=name in direct_dependencies,
                component_hash=component_hash,
                compatible_targets=compatible_targets,
                dependencies=dependency_names,
            )
        )

    selected_target_match = (
        target.casefold() == selected_target.casefold()
        if target is not None and selected_target is not None
        else None
    )
    if target is None:
        structural_warnings.append("The lock file has no supported target value.")
    elif selected_target is None:
        warnings.append(
            "The lock target could not be compared because no generated build target was selected."
        )
    elif selected_target_match is False:
        warnings.append("The lock target does not match the selected generated build target.")
    if manifest_hash is None:
        structural_warnings.append("The lock file has no valid SHA-256 manifest_hash.")

    warnings.extend(structural_warnings)
    status = (
        "partial"
        if structural_warnings
        else (
            "target-mismatch"
            if selected_target_match is False
            else ("target-matches" if selected_target_match is True else "target-unverified")
        )
    )
    limitations = [
        "Lock entries represent resolved components, not proof that components were built into a released image.",
        "The manifest_hash is retained but not recomputed because the component manager's canonical hash procedure is not part of this adapter.",
        *warnings,
    ]
    inventory = ComponentLockInventory(
        status=status,
        path=relative,
        sha256=digest,
        byte_size=byte_size,
        lock_version=version,
        target=target,
        selected_target_match=selected_target_match,
        manifest_hash=manifest_hash,
        manifest_freshness="unverified" if manifest_hash else "missing",
        direct_dependencies=tuple(sorted(direct_dependencies)),
        components=tuple(sorted(components, key=lambda item: item.name.casefold())),
        limitations=tuple(limitations),
    )
    analyzer_status = AnalyzerStatus(
        name="esp-idf-dependencies",
        status=(
            "partial" if structural_warnings or selected_target_match is False else "completed"
        ),
        version=getattr(yaml, "__version__", None),
        detail=(
            f"Parsed {len(components)} resolved component entries; target match is "
            f"{'yes' if selected_target_match else 'no' if selected_target_match is False else 'unverified'}; "
            "manifest freshness remains unverified."
        ),
        findings=0,
    )
    return inventory, artifact, analyzer_status
