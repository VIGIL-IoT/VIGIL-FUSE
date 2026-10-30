from __future__ import annotations

import tomllib
from dataclasses import dataclass
from pathlib import Path

from .profiles import PROFILES
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
from .target_labels import validate_target_label

DEFAULT_MAX_FILE_BYTES = 2 * 1024 * 1024
MAX_CONFIGURABLE_FILE_BYTES = 100 * 1024 * 1024


@dataclass(frozen=True)
class ScanConfig:
    profile: str = "generic"
    target_label: str | None = None
    include: tuple[str, ...] = ()
    exclude: tuple[str, ...] = ()
    disabled_rules: tuple[str, ...] = ()
    max_file_bytes: int = DEFAULT_MAX_FILE_BYTES
    max_discovered_paths: int = DEFAULT_MAX_DISCOVERED_PATHS
    max_discovered_directories: int = DEFAULT_MAX_DISCOVERED_DIRECTORIES
    max_source_bytes: int = DEFAULT_MAX_SOURCE_BYTES
    max_scan_seconds: int = DEFAULT_MAX_SCAN_SECONDS
    max_firmware_bytes: int = DEFAULT_MAX_FIRMWARE_BYTES
    output_dir: str | None = None
    sbom: bool = False
    vulnerabilities: bool = False
    firmware: bool = False
    offline_vulnerabilities: bool = False
    git_history: bool = False


def _string_list(value: object, key: str) -> tuple[str, ...]:
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise ValueError(f"Config '{key}' must be an array of strings")
    return tuple(value)


def load_config(path: str | Path) -> ScanConfig:
    config_path = Path(path).expanduser()
    try:
        data = tomllib.loads(config_path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise FileNotFoundError(f"Config file does not exist: {config_path}") from None
    except tomllib.TOMLDecodeError as error:
        raise ValueError(f"Invalid TOML config '{config_path}': {error}") from error

    unknown_sections = set(data) - {"scan", "rules", "report", "analysis"}
    if unknown_sections:
        raise ValueError(f"Unknown config sections: {', '.join(sorted(unknown_sections))}")
    scan_data = data.get("scan", {})
    rules_data = data.get("rules", {})
    report_data = data.get("report", {})
    analysis_data = data.get("analysis", {})
    for section_name, section in (
        ("scan", scan_data),
        ("rules", rules_data),
        ("report", report_data),
        ("analysis", analysis_data),
    ):
        if not isinstance(section, dict):
            raise ValueError(f"Config section [{section_name}] must be a table")
    unknown_scan = set(scan_data) - {
        "profile",
        "target_label",
        "include",
        "exclude",
        "max_file_bytes",
        "max_discovered_paths",
        "max_discovered_directories",
        "max_source_bytes",
        "max_scan_seconds",
        "max_firmware_bytes",
    }
    unknown_rules = set(rules_data) - {"disabled"}
    unknown_report = set(report_data) - {"output_dir"}
    unknown_analysis = set(analysis_data) - {
        "sbom",
        "vulnerabilities",
        "firmware",
        "offline_vulnerabilities",
        "git_history",
    }
    if unknown_scan or unknown_rules or unknown_report or unknown_analysis:
        unknown = sorted(unknown_scan | unknown_rules | unknown_report | unknown_analysis)
        raise ValueError(f"Unknown config keys: {', '.join(unknown)}")

    profile = scan_data.get("profile", "generic")
    if not isinstance(profile, str) or profile not in PROFILES:
        raise ValueError(f"Config profile must be one of: {', '.join(PROFILES)}")
    target_label = scan_data.get("target_label")
    if target_label is not None:
        target_label = validate_target_label(target_label)
    max_file_bytes = scan_data.get("max_file_bytes", DEFAULT_MAX_FILE_BYTES)
    if not isinstance(max_file_bytes, int) or isinstance(max_file_bytes, bool):
        raise ValueError("Config 'scan.max_file_bytes' must be an integer")
    if not 1 <= max_file_bytes <= MAX_CONFIGURABLE_FILE_BYTES:
        raise ValueError(
            f"Config 'scan.max_file_bytes' must be between 1 and {MAX_CONFIGURABLE_FILE_BYTES}"
        )
    source_limits = {
        "max_discovered_paths": (DEFAULT_MAX_DISCOVERED_PATHS, MAX_CONFIGURABLE_DISCOVERED_PATHS),
        "max_discovered_directories": (
            DEFAULT_MAX_DISCOVERED_DIRECTORIES,
            MAX_CONFIGURABLE_DISCOVERED_DIRECTORIES,
        ),
        "max_source_bytes": (DEFAULT_MAX_SOURCE_BYTES, MAX_CONFIGURABLE_SOURCE_BYTES),
        "max_scan_seconds": (DEFAULT_MAX_SCAN_SECONDS, MAX_CONFIGURABLE_SCAN_SECONDS),
    }
    configured_source_limits: dict[str, int] = {}
    for key, (default, maximum) in source_limits.items():
        value = scan_data.get(key, default)
        if not isinstance(value, int) or isinstance(value, bool):
            raise ValueError(f"Config 'scan.{key}' must be an integer")
        if not 1 <= value <= maximum:
            raise ValueError(f"Config 'scan.{key}' must be between 1 and {maximum}")
        configured_source_limits[key] = value
    max_firmware_bytes = scan_data.get("max_firmware_bytes", DEFAULT_MAX_FIRMWARE_BYTES)
    if not isinstance(max_firmware_bytes, int) or isinstance(max_firmware_bytes, bool):
        raise ValueError("Config 'scan.max_firmware_bytes' must be an integer")
    if not 1 <= max_firmware_bytes <= MAX_CONFIGURABLE_FIRMWARE_BYTES:
        raise ValueError(
            "Config 'scan.max_firmware_bytes' must be between 1 and "
            f"{MAX_CONFIGURABLE_FIRMWARE_BYTES}"
        )
    output_dir = report_data.get("output_dir")
    if output_dir is not None and not isinstance(output_dir, str):
        raise ValueError("Config 'report.output_dir' must be a string")

    analysis_options: dict[str, bool] = {}
    for key in ("sbom", "vulnerabilities", "firmware", "offline_vulnerabilities", "git_history"):
        value = analysis_data.get(key, False)
        if not isinstance(value, bool):
            raise ValueError(f"Config 'analysis.{key}' must be true or false")
        analysis_options[key] = value
    if analysis_options["offline_vulnerabilities"] and not analysis_options["vulnerabilities"]:
        raise ValueError(
            "Config 'analysis.offline_vulnerabilities' requires analysis.vulnerabilities = true"
        )

    return ScanConfig(
        profile=profile,
        target_label=target_label,
        include=_string_list(scan_data.get("include", []), "scan.include"),
        exclude=_string_list(scan_data.get("exclude", []), "scan.exclude"),
        disabled_rules=_string_list(rules_data.get("disabled", []), "rules.disabled"),
        max_file_bytes=max_file_bytes,
        **configured_source_limits,
        max_firmware_bytes=max_firmware_bytes,
        output_dir=output_dir,
        **analysis_options,
    )
