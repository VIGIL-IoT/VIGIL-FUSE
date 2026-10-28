from __future__ import annotations

import fnmatch
import hashlib
import os
import time
from collections import Counter
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path

from . import __version__
from .build_context import inspect_compilation_database, inspect_platformio
from .hardware import classify_hardware_file
from .hardware_bom import inspect_hardware_bom
from .input_types import MAX_SBOM_DETECTION_BYTES
from .limits import (
    DEFAULT_MAX_DISCOVERED_DIRECTORIES,
    DEFAULT_MAX_DISCOVERED_PATHS,
    DEFAULT_MAX_FIRMWARE_BYTES,
    DEFAULT_MAX_SCAN_SECONDS,
    DEFAULT_MAX_SOURCE_BYTES,
    MAX_CONFIGURABLE_DISCOVERED_DIRECTORIES,
    MAX_CONFIGURABLE_DISCOVERED_PATHS,
    MAX_CONFIGURABLE_FIRMWARE_BYTES,
    MAX_CONFIGURABLE_SCAN_SECONDS,
    MAX_CONFIGURABLE_SOURCE_BYTES,
)
from .model import (
    AnalyzerStatus,
    HardwareArtifact,
    HardwareBOMInventory,
    HardwareInventory,
    ScanResult,
    SourceFile,
)
from .platform_context import inspect_project_context
from .profiles import ScanProfile, get_profile
from .rule_execution import (
    DEFAULT_RULE_TIMEOUT_SECONDS,
    IsolatedRuleExecutor,
    validate_rule_timeout,
)
from .rules.base import is_kconfig_input_path
from .rules.registry import RULES
from .target_labels import report_target_label
from .zephyr_hardening import inspect_hardening_report

MAX_FILE_BYTES = 2 * 1024 * 1024
MAX_DISCOVERED_PATHS = DEFAULT_MAX_DISCOVERED_PATHS
MAX_DISCOVERED_DIRECTORIES = DEFAULT_MAX_DISCOVERED_DIRECTORIES
MAX_TOTAL_SOURCE_BYTES = DEFAULT_MAX_SOURCE_BYTES
MAX_FIRMWARE_IMAGE_BYTES = DEFAULT_MAX_FIRMWARE_BYTES
MAX_SCAN_SECONDS = DEFAULT_MAX_SCAN_SECONDS
SKIPPED_DIRECTORIES = {
    ".git", ".hg", ".svn", ".venv", "venv", "node_modules", "build", "dist",
    "__pycache__", ".tox", ".mypy_cache", ".pytest_cache", ".fuse-results", "fuse-results",
}
_KCONFIG_RULE_IDS = frozenset({"FUSE006", "FUSE007"})


def _timestamp() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _display_path(path: Path, base: Path) -> str:
    return path.name if path == base else path.relative_to(base).as_posix()


def _selected(path: Path, base: Path, include: tuple[str, ...], exclude: tuple[str, ...]) -> bool:
    rel = _display_path(path, base)
    if include and not any(fnmatch.fnmatchcase(rel, pattern) for pattern in include):
        return False
    return not any(fnmatch.fnmatchcase(rel, pattern) for pattern in exclude)


def _file_type_label(path: Path) -> str:
    suffix = path.suffix.casefold()
    return suffix if suffix else "<no-extension>"


def _candidate_paths(
    target: Path,
    profile: ScanProfile,
    include: tuple[str, ...],
    exclude: tuple[str, ...],
    *,
    deadline: float,
    specialized_input: bool = False,
    max_discovered_paths: int = MAX_DISCOVERED_PATHS,
    max_discovered_directories: int = MAX_DISCOVERED_DIRECTORIES,
) -> tuple[list[Path], int, list[HardwareArtifact], bool, dict[str, int]]:
    unsupported_types: Counter[str] = Counter()
    if target.is_file():
        discovered = [target] if profile.supports(target) else []
        selected = [p for p in discovered if _selected(p, target, include, exclude)]
        if not discovered and not specialized_input and _selected(target, target, (), exclude):
            unsupported_types[_file_type_label(target)] += 1
        hardware = (
            classify_hardware_file(target, target.name)
            if _selected(target, target, (), exclude)
            else None
        )
        hardware_items = [hardware] if hardware is not None else []
        return selected, len(discovered), hardware_items, True, dict(sorted(unsupported_types.items()))

    selected: list[Path] = []
    hardware_items: list[HardwareArtifact] = []
    discovered_count = 0
    paths_seen = 0
    directories_seen = 0
    discovery_complete = True
    for directory, names, filenames in os.walk(target, topdown=True, followlinks=False):
        directories_seen += 1
        if directories_seen > max_discovered_directories or time.monotonic() >= deadline:
            discovery_complete = False
            break
        current = Path(directory)
        for name in names:
            library = current / name
            if (
                name.casefold().endswith(".pretty")
                and not library.is_symlink()
                and _selected(library, target, (), exclude)
            ):
                hardware_items.append(
                    HardwareArtifact(
                        _display_path(library, target),
                        "hardware-library",
                        "KiCad footprint library",
                    )
                )
        names[:] = sorted(
            name for name in names
            if name not in SKIPPED_DIRECTORIES and not (current / name).is_symlink()
        )
        for filename in sorted(filenames):
            if paths_seen >= max_discovered_paths or time.monotonic() >= deadline:
                discovery_complete = False
                break
            paths_seen += 1
            path = current / filename
            if path.is_symlink() or not path.is_file():
                continue
            relative = _display_path(path, target)
            if _selected(path, target, (), exclude):
                hardware = classify_hardware_file(path, relative)
                if hardware is not None:
                    hardware_items.append(hardware)
                if not profile.supports(path):
                    unsupported_types[_file_type_label(path)] += 1
            if not profile.supports(path):
                continue
            discovered_count += 1
            if _selected(path, target, include, exclude):
                selected.append(path)
        if not discovery_complete:
            break
    hardware_items.sort(key=lambda item: (item.path.casefold(), item.category))
    return (
        selected,
        discovered_count,
        hardware_items,
        discovery_complete,
        dict(sorted(unsupported_types.items())),
    )


def preview_discovery(
    target: str | Path,
    profile: str,
    include: tuple[str, ...] = (),
    exclude: tuple[str, ...] = (),
    *,
    budget_seconds: float = 15,
    max_discovered_paths: int = MAX_DISCOVERED_PATHS,
    max_discovered_directories: int = MAX_DISCOVERED_DIRECTORIES,
) -> dict[str, object]:
    """Summarize path selection without opening source files or invoking analyzers."""
    root = Path(target).expanduser()
    candidates, discovered, hardware, complete, unsupported = _candidate_paths(
        root,
        get_profile(profile),
        include,
        exclude,
        deadline=time.monotonic() + max(0.1, budget_seconds),
        max_discovered_paths=max_discovered_paths,
        max_discovered_directories=max_discovered_directories,
    )
    sample_limit = 100
    return {
        "files_discovered": discovered,
        "files_selected": len(candidates),
        "files_filtered": discovered - len(candidates),
        "selected_files_sample": [_display_path(path, root) for path in candidates[:sample_limit]],
        "selected_files_sample_limit": sample_limit,
        "selected_files_omitted": max(0, len(candidates) - sample_limit),
        "unsupported_file_types": unsupported,
        "unsupported_file_count": sum(unsupported.values()),
        "unsupported_file_inventory_complete": complete,
        "hardware_artifact_count": len(hardware),
        "hardware_category_counts": HardwareInventory(
            scope="directory" if root.is_dir() else "single-file",
            artifacts=tuple(hardware),
            complete=complete,
        ).category_counts,
        "discovery_complete": complete,
    }


def _report_target(target: Path, label: str | None = None) -> str:
    """Use a target label in shareable reports without exposing its absolute path."""
    return report_target_label(target, label)


def _load_source(
    path: Path, base: Path, max_file_bytes: int
) -> tuple[SourceFile | None, str | None, int]:
    try:
        with path.open("rb") as source:
            data = source.read(max_file_bytes + 1)
    except OSError:
        return None, "read_error", 0
    if len(data) > max_file_bytes:
        return None, "too_large", len(data)
    try:
        text = data.decode("utf-8-sig")
    except UnicodeDecodeError:
        return None, "not_utf8", len(data)
    if "\x00" in text:
        return None, "binary_or_nul", len(data)
    return SourceFile(
        path=_display_path(path, base),
        text=text,
        sha256=hashlib.sha256(data).hexdigest(),
        byte_size=len(data),
    ), None, len(data)


def _sha256_file(path: Path, *, max_bytes: int | None = None) -> str:
    digest = hashlib.sha256()
    total = 0
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            total += len(block)
            if max_bytes is not None and total > max_bytes:
                raise ValueError(f"Input exceeds the {max_bytes}-byte limit")
            digest.update(block)
    return digest.hexdigest()


def _manifest_skipped_paths(manifest, paths: list[Path], base: Path, reason: str) -> None:
    for path in paths:
        display_path = _display_path(path, base)
        manifest.update(f"{display_path}\0skip:{reason}\n".encode("utf-8"))


def scan(
    target: str | Path = ".",
    *,
    profile: str = "generic",
    include: tuple[str, ...] = (),
    exclude: tuple[str, ...] = (),
    disabled_rules: tuple[str, ...] = (),
    max_file_bytes: int = MAX_FILE_BYTES,
    max_firmware_bytes: int = MAX_FIRMWARE_IMAGE_BYTES,
    rule_timeout_seconds: float = DEFAULT_RULE_TIMEOUT_SECONDS,
    firmware_image: bool = False,
    sbom_input: bool = False,
    build_dir: str | Path | None = None,
    zephyr_hardening_report: str | Path | None = None,
    platformio_config: str | Path | None = None,
    platformio_environments: tuple[str, ...] = (),
    compile_commands: str | Path | None = None,
    hardware_bom: str | Path | None = None,
    target_label: str | None = None,
    max_discovered_paths: int = MAX_DISCOVERED_PATHS,
    max_discovered_directories: int = MAX_DISCOVERED_DIRECTORIES,
    max_source_bytes: int = MAX_TOTAL_SOURCE_BYTES,
    max_scan_seconds: int = MAX_SCAN_SECONDS,
) -> ScanResult:
    requested = Path(target).expanduser()
    if requested.is_symlink():
        raise ValueError("Symbolic-link targets are not followed; pass the resolved file or directory explicitly")
    if not requested.exists():
        raise FileNotFoundError(f"Target does not exist: {requested}")
    if not requested.is_file() and not requested.is_dir():
        raise ValueError(f"Target is not a file or directory: {requested}")
    shareable_target = _report_target(requested, target_label)
    if firmware_image and not requested.is_file():
        raise ValueError("--firmware requires a single firmware image file")
    if sbom_input and not requested.is_file():
        raise ValueError("SBOM input must be a single file")
    if firmware_image and sbom_input:
        raise ValueError("A target cannot be both a firmware image and an SBOM")
    if (platformio_config is not None or platformio_environments or compile_commands is not None or hardware_bom is not None) and not requested.is_dir():
        raise ValueError("PlatformIO, compilation database, and hardware BOM inputs require a project directory target")
    if hardware_bom is not None and (firmware_image or sbom_input):
        raise ValueError("--hardware-bom can only be used with a source project directory")
    if build_dir is not None and profile not in {"esp-idf", "zephyr"}:
        raise ValueError("--build-dir requires the esp-idf or zephyr profile")
    if build_dir is not None and not requested.is_dir():
        raise ValueError("--build-dir requires a project directory target")
    if build_dir is not None and (firmware_image or sbom_input):
        raise ValueError("--build-dir can only be used with a source project directory")
    if zephyr_hardening_report is not None:
        if profile != "zephyr":
            raise ValueError("--zephyr-hardening-report requires the zephyr profile")
        if build_dir is None:
            raise ValueError("--zephyr-hardening-report requires --build-dir")
        if not requested.is_dir() or firmware_image or sbom_input:
            raise ValueError("--zephyr-hardening-report requires a Zephyr source project directory")
    if not 1 <= max_file_bytes <= 100 * 1024 * 1024:
        raise ValueError("max_file_bytes must be between 1 and 104857600")
    if not 1 <= max_firmware_bytes <= MAX_CONFIGURABLE_FIRMWARE_BYTES:
        raise ValueError(
            f"max_firmware_bytes must be between 1 and {MAX_CONFIGURABLE_FIRMWARE_BYTES}"
        )
    for name, value, maximum in (
        ("max_discovered_paths", max_discovered_paths, MAX_CONFIGURABLE_DISCOVERED_PATHS),
        (
            "max_discovered_directories",
            max_discovered_directories,
            MAX_CONFIGURABLE_DISCOVERED_DIRECTORIES,
        ),
        ("max_source_bytes", max_source_bytes, MAX_CONFIGURABLE_SOURCE_BYTES),
        ("max_scan_seconds", max_scan_seconds, MAX_CONFIGURABLE_SCAN_SECONDS),
    ):
        if not isinstance(value, int) or isinstance(value, bool):
            raise ValueError(f"{name} must be an integer")
        if not 1 <= value <= maximum:
            raise ValueError(f"{name} must be between 1 and {maximum}")
    validate_rule_timeout(rule_timeout_seconds)

    profile_info = get_profile(profile)
    project_context, generated_config_sources, context_warnings, dependency_status = inspect_project_context(
        requested,
        profile,
        build_dir,
    )
    platformio_inventory = inspect_platformio(
        requested,
        selected_environments=platformio_environments,
        config_path=platformio_config,
    )
    compilation_database = inspect_compilation_database(
        requested,
        database_path=compile_commands,
    )
    hardware_bom_inventory = (
        inspect_hardware_bom(requested, hardware_bom)
        if hardware_bom is not None
        else HardwareBOMInventory()
    )
    hardening_artifact = None
    hardening_findings = ()
    hardening_status = None
    if zephyr_hardening_report is not None:
        hardening_artifact, hardening_findings, hardening_status = inspect_hardening_report(
            requested,
            build_dir,
            zephyr_hardening_report,
        )
        project_context = replace(
            project_context,
            configuration_files=(*project_context.configuration_files, hardening_artifact),
            evidence=(
                *project_context.evidence,
                hardening_status.detail or "Imported a Zephyr hardening report.",
            ),
            limitations=(
                *project_context.limitations,
                "Imported Zephyr hardening results apply to the selected build configuration and do not prove a released image uses it.",
            ),
        )
    available = tuple(rule.id for rule in RULES)
    unknown_rules = set(disabled_rules) - set(available)
    if unknown_rules:
        raise ValueError(f"Unknown rule IDs: {', '.join(sorted(unknown_rules))}")
    enabled_rules = tuple(rule for rule in RULES if rule.id not in disabled_rules)
    started_at = _timestamp()
    scan_deadline = time.monotonic() + max_scan_seconds

    base = requested
    manifest = hashlib.sha256()
    sbom_too_large = sbom_input and requested.stat().st_size > MAX_SBOM_DETECTION_BYTES
    hardware_items: list[HardwareArtifact] = []
    unsupported_file_types: dict[str, int] = {}
    if sbom_input:
        candidates, files_discovered = [], 0
        if sbom_too_large:
            manifest.update(f"{requested.name}\0skip:sbom_too_large\n".encode("utf-8"))
        else:
            manifest.update(
                f"{requested.name}\0{_sha256_file(requested, max_bytes=MAX_SBOM_DETECTION_BYTES)}\n".encode("utf-8")
            )
    else:
        (
            candidates,
            files_discovered,
            hardware_items,
            discovery_complete,
            unsupported_file_types,
        ) = _candidate_paths(
            requested,
            profile_info,
            include,
            exclude,
            deadline=scan_deadline,
            specialized_input=firmware_image,
            max_discovered_paths=max_discovered_paths,
            max_discovered_directories=max_discovered_directories,
        )
    if sbom_input:
        discovery_complete = True
    findings = []
    skipped = Counter()
    if sbom_too_large:
        skipped["sbom_too_large"] += 1
    files_scanned = 0
    files_scanned_bytes = 0
    limits_reached: set[str] = set()
    firmware_input_rejected = False
    rule_timeouts: dict[str, str] = {}
    rule_incomplete: dict[str, str] = {}
    rule_errors: dict[str, str] = {}
    disabled_after_error: set[str] = set()
    rule_finding_counts: Counter[str] = Counter()
    rule_runs: Counter[str] = Counter()
    rule_prefilter_skips: Counter[str] = Counter()
    platform_findings = 0
    if not discovery_complete:
        limits_reached.add("discovery-budget")

    if firmware_image:
        firmware_size = requested.stat().st_size
        if firmware_size > max_firmware_bytes:
            firmware_input_rejected = True
        else:
            try:
                image_hash = _sha256_file(requested, max_bytes=max_firmware_bytes)
            except ValueError:
                firmware_input_rejected = True
            else:
                manifest.update(f"{requested.name}\0{image_hash}\n".encode("utf-8"))
        if firmware_input_rejected:
            skipped["firmware_image_too_large"] += 1
            limits_reached.add("firmware-image-bytes")
            manifest.update(f"{requested.name}\0skip:firmware_image_too_large\n".encode("utf-8"))

    rule_executor = IsolatedRuleExecutor(rule_timeout_seconds)
    try:
        for index, path in enumerate(candidates):
            remaining_files = len(candidates) - index
            if time.monotonic() >= scan_deadline:
                skipped["scan_time_limit"] += remaining_files
                limits_reached.add("scan-time")
                _manifest_skipped_paths(manifest, candidates[index:], base, "scan_time_limit")
                break
            remaining_total_bytes = max_source_bytes - files_scanned_bytes
            try:
                file_size = path.stat().st_size
            except OSError:
                file_size = None
            display_path = _display_path(path, base)
            if file_size is not None and file_size > max_file_bytes:
                skipped["too_large"] += 1
                manifest.update(f"{display_path}\0skip:too_large\n".encode("utf-8"))
                continue
            if file_size is not None and file_size > remaining_total_bytes:
                skipped["total_source_bytes_limit"] += remaining_files
                limits_reached.add("total-source-bytes")
                _manifest_skipped_paths(
                    manifest, candidates[index:], base, "total_source_bytes_limit"
                )
                break
            if remaining_total_bytes <= 0:
                skipped["total_source_bytes_limit"] += remaining_files
                limits_reached.add("total-source-bytes")
                _manifest_skipped_paths(
                    manifest, candidates[index:], base, "total_source_bytes_limit"
                )
                break
            source, reason, bytes_read = _load_source(
                path,
                base,
                min(max_file_bytes, remaining_total_bytes),
            )
            files_scanned_bytes += bytes_read
            if files_scanned_bytes > max_source_bytes:
                skipped["total_source_bytes_limit"] += remaining_files
                limits_reached.add("total-source-bytes")
                _manifest_skipped_paths(
                    manifest, candidates[index:], base, "total_source_bytes_limit"
                )
                break
            if source is None:
                skipped[reason or "read_error"] += 1
                manifest.update(f"{display_path}\0skip:{reason}\n".encode("utf-8"))
                continue
            files_scanned += 1
            manifest.update(f"{source.path}\0{source.sha256}\n".encode("utf-8"))
            generated_esp_config_selected = profile == "esp-idf" and bool(generated_config_sources)
            source_rules_list = []
            for rule in enabled_rules:
                if rule.id in disabled_after_error:
                    continue
                if (
                    generated_esp_config_selected
                    and rule.id in _KCONFIG_RULE_IDS
                    and is_kconfig_input_path(source.path)
                ):
                    rule_prefilter_skips[rule.id] += 1
                    continue
                if not rule.may_scan(source):
                    rule_prefilter_skips[rule.id] += 1
                    continue
                source_rules_list.append(rule)
            source_rules = tuple(source_rules_list)
            execution = rule_executor.execute(
                source,
                tuple(rule.id for rule in source_rules),
                scan_deadline=scan_deadline,
            )
            findings.extend(execution.findings)
            rule_finding_counts.update(finding.rule_id for finding in execution.findings)
            rule_runs.update(execution.completed_rule_ids)
            for rule_id, detail in execution.timed_out.items():
                rule_timeouts.setdefault(rule_id, detail)
                disabled_after_error.add(rule_id)
            for rule_id, detail in execution.failed.items():
                rule_errors.setdefault(rule_id, detail)
                disabled_after_error.add(rule_id)
            if execution.scan_deadline_reached:
                limits_reached.add("scan-time")
                for rule_id in execution.unfinished_rule_ids:
                    rule_incomplete.setdefault(rule_id, "Not completed before the scan-wide time limit.")
                if index + 1 < len(candidates):
                    continue

        if build_dir is not None and time.monotonic() < scan_deadline:
            platform_rule_ids = {"FUSE006", "FUSE007"} if profile == "esp-idf" else set()
            enabled_platform_rules = tuple(
                rule for rule in enabled_rules
                if rule.id in platform_rule_ids and rule.id not in disabled_after_error
            )
            for source in generated_config_sources:
                if time.monotonic() >= scan_deadline:
                    limits_reached.add("scan-time")
                    for rule in enabled_platform_rules:
                        if rule.id in disabled_after_error:
                            continue
                        rule_incomplete.setdefault(rule.id, "Not completed before the scan-wide time limit.")
                    break
                manifest.update(f"build-context:{source.path}\0{source.sha256}\n".encode("utf-8"))
                active_platform_rules = tuple(
                    rule for rule in enabled_platform_rules
                    if rule.id not in disabled_after_error
                )
                execution = rule_executor.execute(
                    source,
                    tuple(rule.id for rule in active_platform_rules),
                    scan_deadline=scan_deadline,
                )
                findings.extend(
                    replace(
                        finding,
                        applicability="candidate",
                        validation_method="generated-config",
                    )
                    for finding in execution.findings
                )
                platform_findings += len(execution.findings)
                rule_finding_counts.update(finding.rule_id for finding in execution.findings)
                rule_runs.update(execution.completed_rule_ids)
                for rule_id, detail in execution.timed_out.items():
                    rule_timeouts.setdefault(rule_id, detail)
                    disabled_after_error.add(rule_id)
                for rule_id, detail in execution.failed.items():
                    rule_errors.setdefault(rule_id, detail)
                    disabled_after_error.add(rule_id)
                if execution.scan_deadline_reached:
                    limits_reached.add("scan-time")
                    for rule_id in execution.unfinished_rule_ids:
                        rule_incomplete.setdefault(rule_id, "Not completed before the scan-wide time limit.")
                    break
        elif build_dir is not None:
            platform_rule_ids = {"FUSE006", "FUSE007"} if profile == "esp-idf" else set()
            for rule_id in platform_rule_ids:
                if rule_id in {rule.id for rule in enabled_rules}:
                    rule_incomplete.setdefault(
                        rule_id,
                        "Build-context rules were not reached before the scan-wide time limit.",
                    )
    finally:
        rule_executor.close()

    native_findings_count = len(findings)
    findings.extend(hardening_findings)
    for artifact in project_context.configuration_files:
        if artifact.sha256:
            manifest.update(
                f"project-context-artifact:{artifact.path}\0{artifact.sha256}\n".encode("utf-8")
            )

    findings.sort(key=lambda item: (item.file.casefold(), item.start_line, item.rule_id))
    native_partial = not firmware_image and bool(
        limits_reached or skipped or rule_timeouts or rule_incomplete or rule_errors
    )
    native_detail = (
        "Native scan hit one or more resource limits; review coverage details."
        if limits_reached
        else "One or more selected files were skipped; review coverage details."
        if skipped
        else "One or more isolated rules timed out or failed; review per-rule analyzer statuses."
        if rule_timeouts or rule_incomplete or rule_errors
        else "Native rules completed."
        if files_scanned and enabled_rules
        else "SBOM input is routed to inventory/advisory analyzers; native text rules were skipped."
        if sbom_input
        else "No selected text files or no enabled rules."
    )
    analyzer_status = (
        AnalyzerStatus(
            name="sbom-input",
            status="skipped",
            detail="SBOM exceeds the 50 MiB input limit and was not parsed or hashed.",
        ),
    ) if sbom_too_large else (
        AnalyzerStatus(
            name="fuse-native",
            status=(
                "partial"
                if native_partial
                else "completed"
                if files_scanned and enabled_rules
                else "skipped"
            ),
            version=__version__,
            detail=native_detail,
            findings=native_findings_count,
        ),
    )
    if firmware_input_rejected:
        analyzer_status = (*analyzer_status, AnalyzerStatus(
            name="firmware-input",
            status="failed",
            detail=(
                f"Firmware image exceeds the configured {max_firmware_bytes}-byte limit; "
                "the image was not hashed or passed to Binwalk."
            ),
        ))
    if not sbom_too_large:
        rule_definition_by_id = {rule.id: rule for rule in enabled_rules}
        for rule_id, rule in rule_definition_by_id.items():
            if rule_id in rule_timeouts:
                status = "partial"
                detail = rule_timeouts[rule_id]
            elif rule_id in rule_incomplete:
                status = "partial"
                detail = rule_incomplete[rule_id]
            elif rule_id in rule_errors:
                status = "failed"
                detail = rule_errors[rule_id]
            elif rule_runs[rule_id]:
                status = "partial" if limits_reached or skipped else "completed"
                detail = f"Evaluated {rule_runs[rule_id]} selected input(s)."
                if rule_prefilter_skips[rule_id]:
                    detail += (
                        f" The conservative prefilter excluded {rule_prefilter_skips[rule_id]} "
                        "inputs without the rule's required markers."
                    )
                if status == "partial":
                    detail += " Other selected inputs were skipped or limited."
            else:
                status = "skipped"
                detail = (
                    "No selected input matched this rule's supported input scope."
                    if rule_prefilter_skips[rule_id]
                    else "No selected input was passed to this rule."
                )
            analyzer_status = (*analyzer_status, AnalyzerStatus(
                name=f"native-rule:{rule_id}",
                status=status,
                version=rule.version,
                detail=detail,
                findings=rule_finding_counts[rule_id],
            ))
    if dependency_status is not None:
        analyzer_status = (*analyzer_status, dependency_status)
    if hardening_status is not None:
        analyzer_status = (*analyzer_status, hardening_status)
    if build_dir is not None:
        platform_rule_ids = {"FUSE006", "FUSE007"} if profile == "esp-idf" else set()
        platform_rules_incomplete = any(
            rule_id in rule_timeouts or rule_id in rule_incomplete or rule_id in rule_errors
            for rule_id in platform_rule_ids
        )
        platform_status = (
            "completed"
            if generated_config_sources and not context_warnings and not platform_rules_incomplete
            else "partial"
        )
        analyzer_status = (*analyzer_status, AnalyzerStatus(
            name="platform-build-context",
            status=platform_status,
            detail=(
                f"Inspected the selected {profile} build context without invoking its build system."
                if platform_status == "completed"
                else "; ".join(context_warnings)
                or f"No recognized generated configuration was found in {project_context.build_dir}."
            ),
            findings=platform_findings,
        ))
    target_kind = (
        "firmware-image"
        if firmware_image
        else "sbom"
        if sbom_input
        else "directory"
        if requested.is_dir()
        else "source-file"
        if profile_info.supports(requested)
        else "unsupported-file"
    )
    return ScanResult(
        target=shareable_target,
        target_kind=target_kind,
        profile=profile_info.name,
        started_at=started_at,
        completed_at=_timestamp(),
        input_manifest_sha256=manifest.hexdigest(),
        files_discovered=files_discovered,
        files_selected=len(candidates),
        files_filtered=files_discovered - len(candidates),
        files_scanned=files_scanned,
        files_skipped_by_reason=dict(sorted(skipped.items())),
        rules_available=available,
        rules_enabled=tuple(rule.id for rule in enabled_rules),
        analyzers=analyzer_status,
        findings=tuple(findings),
        unsupported_file_types=unsupported_file_types,
        hardware_inventory=HardwareInventory(
            scope="directory" if requested.is_dir() else "single-file",
            artifacts=tuple(hardware_items),
            complete=discovery_complete,
        ),
        project_context=project_context,
        platformio_inventory=platformio_inventory,
        compilation_database=compilation_database,
        hardware_bom=hardware_bom_inventory,
        source_bytes_read=files_scanned_bytes,
        discovery_complete=discovery_complete,
        limits_reached=tuple(sorted(limits_reached)),
    )
