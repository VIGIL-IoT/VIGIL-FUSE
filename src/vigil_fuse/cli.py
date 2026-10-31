from __future__ import annotations

import argparse
import hashlib
import json
import platform
import shutil
import subprocess
import sys
from dataclasses import replace
from pathlib import Path
from typing import Literal, TextIO, TypedDict

from . import __version__
from .analyzers import (
    generate_sbom,
    identify_firmware,
    inspect_tools,
    scan_git_history,
    scan_vulnerabilities,
)
from .baseline import create_baseline, diff_baseline, suppress_finding, unsuppress_finding
from .build_context import inspect_compilation_database, inspect_platformio
from .config import ScanConfig, load_config
from .esp_idf_lock import lock_parser_available
from .hardware_bom import hardware_bom_document
from .model import AnalysisArtifact, AnalyzerStatus, ScanResult
from .platform_context import detect_project_frameworks, resolve_build_dir
from .product_context import import_vex, inspect_provenance, validate_package_purl
from .profiles import PROFILES, get_profile
from .reporting import to_json, to_text
from .rule_execution import (
    DEFAULT_RULE_TIMEOUT_SECONDS,
    MAX_RULE_TIMEOUT_SECONDS,
    MIN_RULE_TIMEOUT_SECONDS,
    validate_rule_timeout,
)
from .sarif import to_sarif
from .scanner import (
    DiscoveryPreview,
    preview_discovery,
    scan,
)
from .support import CapabilitySummary, capability_for_plan, support_matrix
from .input_types import MAX_SBOM_DETECTION_BYTES, is_sbom_candidate, is_sbom_file
from .text_safety import safe_terminal_text
from .limits import (
    MAX_CONFIGURABLE_DISCOVERED_DIRECTORIES,
    MAX_CONFIGURABLE_DISCOVERED_PATHS,
    MAX_CONFIGURABLE_FIRMWARE_BYTES,
    MAX_CONFIGURABLE_SCAN_SECONDS,
    MAX_CONFIGURABLE_SOURCE_BYTES,
)
from .terminal import show_banner
from .target_labels import report_target_label
from .zephyr_hardening import resolve_hardening_report_path

_SEVERITY_ORDER = {"unknown": -1, "info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
_PlanStageStatus = Literal["planned", "skipped", "unavailable", "unsupported", "partial"]


class _FrameworkHint(TypedDict):
    name: str
    evidence: list[str]


class _PlanStage(TypedDict):
    name: str
    requested: bool
    status: _PlanStageStatus
    reason: str


class _ScanPlan(TypedDict):
    target: str
    target_kind: str
    profile: str
    selected_build_dir: str | None
    selected_zephyr_hardening_report: str | None
    detected_frameworks: list[_FrameworkHint]
    framework_hints_are_advisory: bool
    build_context: dict[str, object]
    discovery_preview: DiscoveryPreview | None
    support: CapabilitySummary
    stages: list[_PlanStage]
    reports_directory: str | None
    report_file: str | None
    network: str
    resource_limits: dict[str, int | float]
    executed: bool


def _safe_print(
    *values: object,
    sep: str = " ",
    end: str = "\n",
    file: TextIO | None = None,
    flush: bool = False,
) -> None:
    rendered = sep.join(safe_terminal_text(str(value)) for value in values)
    print(rendered, end=end, file=file, flush=flush)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="vigil-fuse",
        description="FUSE, the Firmware & Unified Security Engine. A VIGIL Project.",
    )
    parser.add_argument("--version", action="version", version=f"FUSE {__version__}")
    commands = parser.add_subparsers(dest="command")
    commands.add_parser("doctor", help="show runtime and optional analyzer availability")
    baseline_parser = commands.add_parser(
        "baseline", help="compare findings and manage reasoned suppressions"
    )
    baseline_commands = baseline_parser.add_subparsers(dest="baseline_action", required=True)
    baseline_create = baseline_commands.add_parser(
        "create", help="save findings from a complete scan as a baseline"
    )
    baseline_create.add_argument("report", type=Path, help="FUSE findings.json report")
    baseline_create.add_argument(
        "--output",
        type=Path,
        default=Path(".fuse-results/baseline.json"),
        help="baseline JSON path",
    )
    baseline_diff = baseline_commands.add_parser(
        "diff", help="compare a scan report with a saved baseline"
    )
    baseline_diff.add_argument("report", type=Path, help="current FUSE findings.json report")
    baseline_diff.add_argument("--baseline", type=Path, required=True, help="baseline JSON path")
    baseline_diff.add_argument("--suppressions", type=Path, help="reasoned suppression JSON path")
    baseline_diff.add_argument(
        "--format", choices=("text", "json"), default="text", help="diff output format"
    )
    baseline_diff.add_argument(
        "--fail-on-new",
        choices=("none", "info", "low", "medium", "high", "critical"),
        default="none",
        help="exit 1 for an unsuppressed new finding at or above this severity",
    )
    baseline_suppress = baseline_commands.add_parser(
        "suppress", help="record a reasoned, optionally expiring suppression"
    )
    baseline_suppress.add_argument(
        "report", type=Path, help="FUSE findings.json containing the finding"
    )
    baseline_suppress.add_argument(
        "--finding", required=True, help="finding fingerprint from the report"
    )
    baseline_suppress.add_argument(
        "--reason", required=True, help="why this finding is accepted for now"
    )
    baseline_suppress.add_argument("--owner", help="person or team responsible for review")
    baseline_suppress.add_argument("--expires", help="optional expiry date in YYYY-MM-DD format")
    baseline_suppress.add_argument(
        "--output",
        type=Path,
        default=Path(".fuse-results/suppressions.json"),
        help="suppression JSON path",
    )
    baseline_unsuppress = baseline_commands.add_parser(
        "unsuppress", help="remove a suppression using the current finding report"
    )
    baseline_unsuppress.add_argument(
        "report", type=Path, help="FUSE findings.json containing the finding"
    )
    baseline_unsuppress.add_argument(
        "--finding", required=True, help="finding fingerprint from the report"
    )
    baseline_unsuppress.add_argument(
        "--output",
        type=Path,
        default=Path(".fuse-results/suppressions.json"),
        help="suppression JSON path",
    )
    scan_parser = commands.add_parser(
        "scan", help="analyze a project, SBOM, or supported firmware input"
    )
    scan_parser.add_argument(
        "target", nargs="?", default=".", help="project directory, file, SBOM, or firmware image"
    )
    scan_parser.add_argument("--config", type=Path, help="load scan options from a TOML file")
    scan_parser.add_argument("--profile", choices=tuple(PROFILES), help="input discovery profile")
    scan_parser.add_argument(
        "--target-label",
        help="shareable report and baseline identity, such as organization/repository; local paths stay private",
    )
    scan_parser.add_argument(
        "--build-dir",
        type=Path,
        help="inspect a selected ESP-IDF or Zephyr build directory inside the target; no build is run",
    )
    scan_parser.add_argument(
        "--platformio-config",
        type=Path,
        help="inspect a PlatformIO INI file inside the target; no PlatformIO command is run",
    )
    scan_parser.add_argument(
        "--platformio-env",
        action="append",
        default=[],
        help="select a declared PlatformIO environment for the report matrix (repeatable; no build is run)",
    )
    scan_parser.add_argument(
        "--compile-commands",
        type=Path,
        help="index a compile_commands.json inside the target; commands are never executed",
    )
    scan_parser.add_argument(
        "--hardware-bom",
        type=Path,
        help="import an explicit hardware BOM CSV or TSV and emit a CycloneDX HBOM",
    )
    scan_parser.add_argument(
        "--hardware-netlist",
        type=Path,
        help="inspect one KiCad XML netlist for debug-interface candidates; no PCB exposure is asserted",
    )
    scan_parser.add_argument(
        "--vex",
        type=Path,
        help="import reviewed CycloneDX VEX context for exact package and advisory matches",
    )
    scan_parser.add_argument(
        "--product-purl",
        help="product package URL required to bind an imported VEX document to this scan",
    )
    scan_parser.add_argument(
        "--provenance",
        type=Path,
        help="compare an in-toto/SLSA statement subject digest with a --firmware image",
    )
    scan_parser.add_argument(
        "--zephyr-hardening-report",
        type=Path,
        help=(
            "import Zephyr hardenconfig JSON from the selected --build-dir; "
            "FUSE does not run west or the build"
        ),
    )
    scan_parser.add_argument(
        "--include", action="append", default=[], help="include relative path glob (repeatable)"
    )
    scan_parser.add_argument(
        "--exclude", action="append", default=[], help="exclude relative path glob (repeatable)"
    )
    scan_parser.add_argument(
        "--disable-rule", action="append", default=[], help="disable a rule ID (repeatable)"
    )
    scan_parser.add_argument(
        "--max-file-bytes", type=int, help="maximum bytes read from one source file"
    )
    scan_parser.add_argument(
        "--max-firmware-bytes",
        type=int,
        help="maximum bytes accepted for a firmware image (default 536870912; maximum 2147483648)",
    )
    scan_parser.add_argument(
        "--max-discovered-paths",
        type=int,
        help=f"maximum filesystem paths visited (default 100000; maximum {MAX_CONFIGURABLE_DISCOVERED_PATHS})",
    )
    scan_parser.add_argument(
        "--max-discovered-directories",
        type=int,
        help=f"maximum directories visited (default 20000; maximum {MAX_CONFIGURABLE_DISCOVERED_DIRECTORIES})",
    )
    scan_parser.add_argument(
        "--max-source-bytes",
        type=int,
        help=f"maximum aggregate source bytes read (default 536870912; maximum {MAX_CONFIGURABLE_SOURCE_BYTES})",
    )
    scan_parser.add_argument(
        "--max-scan-seconds",
        type=int,
        help=f"maximum native scan time in seconds (default 600; maximum {MAX_CONFIGURABLE_SCAN_SECONDS})",
    )
    scan_parser.add_argument(
        "--rule-timeout",
        type=float,
        default=DEFAULT_RULE_TIMEOUT_SECONDS,
        help=(
            f"maximum time per native rule and input in seconds "
            f"({MIN_RULE_TIMEOUT_SECONDS:g} to {MAX_RULE_TIMEOUT_SECONDS:g})"
        ),
    )
    scan_parser.add_argument(
        "--sbom",
        action=argparse.BooleanOptionalAction,
        default=None,
        help="generate a CycloneDX SBOM with optional Syft",
    )
    scan_parser.add_argument(
        "--vulnerabilities",
        action=argparse.BooleanOptionalAction,
        default=None,
        help="match dependencies against OSV advisories with optional tools",
    )
    scan_parser.add_argument(
        "--firmware",
        action=argparse.BooleanOptionalAction,
        default=None,
        help="identify signatures in a firmware image with Binwalk; no extraction",
    )
    scan_parser.add_argument(
        "--git-history",
        action=argparse.BooleanOptionalAction,
        default=None,
        help="scan commits reachable from HEAD for historical secret patterns with optional Gitleaks",
    )
    scan_parser.add_argument(
        "--offline-vulnerabilities",
        action=argparse.BooleanOptionalAction,
        default=None,
        help="use OSV-Scanner's local vulnerability database",
    )
    scan_parser.add_argument(
        "--no-network",
        action="store_true",
        help="require OSV-Scanner's strict offline mode when checking vulnerabilities",
    )
    scan_parser.add_argument(
        "--plan", action="store_true", help="show selected analysis stages without running scanners"
    )
    scan_parser.add_argument(
        "--format",
        choices=("text", "json", "sarif"),
        default="text",
        help="stdout or single-file report format",
    )
    outputs = scan_parser.add_mutually_exclusive_group()
    outputs.add_argument("--output", type=Path, help="write one report to this file")
    outputs.add_argument(
        "--output-dir",
        type=Path,
        help="write JSON, text, SARIF, and requested analyzer artifacts into this directory",
    )
    scan_parser.add_argument(
        "--fail-on",
        choices=("none", "info", "low", "medium", "high", "critical"),
        default="none",
        help="exit 1 when a finding at or above this severity is present",
    )
    return parser


def _resolve_output_dir(
    cli_output: Path | None,
    config: ScanConfig,
    config_path: Path | None,
) -> Path | None:
    if cli_output is not None:
        return cli_output.expanduser()
    if config.output_dir is None:
        return None
    configured = Path(config.output_dir).expanduser()
    if configured.is_absolute() or config_path is None:
        return configured
    return config_path.expanduser().parent / configured


def _default_output_dir(target: Path) -> Path:
    if target.is_dir():
        base = target
    elif target.is_file():
        base = target.parent
    else:
        base = Path.cwd()
    return base / ".fuse-results"


def _exclude_output_directory(
    target: str, output_dir: Path | None, excludes: tuple[str, ...]
) -> tuple[str, ...]:
    if output_dir is None:
        return excludes
    target_path = Path(target).expanduser()
    if not target_path.is_dir():
        return excludes
    target_abs = target_path.resolve()
    output_abs = output_dir.resolve()
    try:
        relative = output_abs.relative_to(target_abs)
    except ValueError:
        return excludes
    if relative == Path("."):
        raise ValueError("--output-dir cannot be the same directory as the scan target")
    return (*excludes, relative.as_posix().rstrip("/") + "/**")


def _write_reports(result: ScanResult, output_dir: Path) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    reports = {
        "findings.json": to_json(result),
        "findings.txt": to_text(result),
        "findings.sarif": to_sarif(result),
    }
    for name, content in reports.items():
        path = output_dir / name
        if path.is_symlink():
            raise OSError(f"Refusing to write report through symbolic link: {name}")
        if path.exists() and not path.is_file():
            raise OSError(f"Report output path is not a regular file: {name}")
        path.write_text(content, encoding="utf-8")


def _doctor() -> int:
    _safe_print(f"FUSE {__version__}")
    _safe_print(f"Python: {platform.python_version()} ({sys.executable})")
    _safe_print(f"Platform: {platform.system()} {platform.release()} ({platform.machine()})")
    _safe_print("Optional analyzers:")
    for name, executable, version in inspect_tools():
        if executable is None:
            _safe_print(f"  {name}: not installed")
        else:
            detail = version or "version unavailable"
            _safe_print(f"  {name}: {detail} [{executable}]")
    _safe_print(
        "ESP-IDF lockfile parser: "
        + (
            "available (PyYAML)"
            if lock_parser_available()
            else "not installed; use vigil-fuse[esp-idf]"
        )
    )
    _safe_print("Core scanner: available")
    _safe_print(
        "Native rule execution: isolated subprocess, "
        f"{DEFAULT_RULE_TIMEOUT_SECONDS:g} seconds per rule and input"
    )
    _safe_print("Support matrix:")
    for capability in support_matrix()["capabilities"]:
        _safe_print(f"  {capability['id']}: {capability['label']} - {capability['scope']}")
    return 0


def _scan_plan(
    *,
    target: Path,
    profile: str,
    target_label: str | None,
    build_dir: Path | None,
    zephyr_hardening_report: Path | None,
    platformio_config: Path | None,
    platformio_environments: tuple[str, ...],
    compile_commands: Path | None,
    hardware_bom: Path | None,
    hardware_netlist: Path | None,
    vex: Path | None,
    provenance: Path | None,
    sbom: bool,
    vulnerabilities: bool,
    firmware: bool,
    max_firmware_bytes: int,
    max_discovered_paths: int,
    max_discovered_directories: int,
    max_source_bytes: int,
    max_scan_seconds: int,
    git_history: bool,
    offline_vulnerabilities: bool,
    no_network: bool,
    output_dir: Path,
    output_file: Path | None,
    sbom_input: bool,
    output_format: str,
    include: tuple[str, ...],
    exclude: tuple[str, ...],
    rule_timeout_seconds: float,
) -> int:
    validate_rule_timeout(rule_timeout_seconds)
    for name, value, maximum in (
        ("--max-discovered-paths", max_discovered_paths, MAX_CONFIGURABLE_DISCOVERED_PATHS),
        (
            "--max-discovered-directories",
            max_discovered_directories,
            MAX_CONFIGURABLE_DISCOVERED_DIRECTORIES,
        ),
        ("--max-source-bytes", max_source_bytes, MAX_CONFIGURABLE_SOURCE_BYTES),
        ("--max-scan-seconds", max_scan_seconds, MAX_CONFIGURABLE_SCAN_SECONDS),
    ):
        if not 1 <= value <= maximum:
            raise ValueError(f"{name} must be between 1 and {maximum}")
    if not target.exists() or (not target.is_file() and not target.is_dir()):
        raise ValueError(f"Target does not exist or is not a regular file/directory: {target}")
    if target.is_symlink():
        raise ValueError(
            "Symbolic-link targets are not followed; pass the resolved file or directory explicitly"
        )
    shareable_target = report_target_label(target, target_label)
    selected_build_dir = None
    if build_dir is not None:
        if profile not in {"esp-idf", "zephyr"}:
            raise ValueError("--build-dir requires the esp-idf or zephyr profile")
        if not target.is_dir():
            raise ValueError("--build-dir requires a project directory target")
        _, selected_build_dir = resolve_build_dir(target, build_dir)
    selected_hardening_report = None
    if zephyr_hardening_report is not None:
        if profile != "zephyr":
            raise ValueError("--zephyr-hardening-report requires the zephyr profile")
        if build_dir is None:
            raise ValueError("--zephyr-hardening-report requires --build-dir")
        _, selected_hardening_report = resolve_hardening_report_path(
            target, build_dir, zephyr_hardening_report
        )
    platformio_inventory = inspect_platformio(
        target,
        selected_environments=platformio_environments,
        config_path=platformio_config,
    )
    compilation_database = inspect_compilation_database(
        target,
        database_path=compile_commands,
    )
    kind = (
        "sbom"
        if sbom_input
        else "firmware-image"
        if firmware
        else "directory"
        if target.is_dir()
        else "file"
    )
    plan_preview_seconds = min(15, max_scan_seconds)
    sbom_too_large = sbom_input and target.stat().st_size > MAX_SBOM_DETECTION_BYTES
    firmware_too_large = (
        firmware and target.is_file() and target.stat().st_size > max_firmware_bytes
    )
    framework_hints: list[_FrameworkHint] = [
        {"name": name, "evidence": list(evidence)}
        for name, evidence in detect_project_frameworks(target)
    ]
    discovery_preview: DiscoveryPreview | None = None
    if not sbom_input and not firmware:
        discovery_preview = preview_discovery(
            target,
            profile,
            include,
            exclude,
            budget_seconds=plan_preview_seconds,
            max_discovered_paths=max_discovered_paths,
            max_discovered_directories=max_discovered_directories,
        )
    available = {
        name.casefold(): executable is not None
        for name, executable, _ in (
            ("Syft", shutil.which("syft"), None),
            ("OSV-Scanner", shutil.which("osv-scanner"), None),
            ("Binwalk", shutil.which("binwalk"), None),
            ("Gitleaks", shutil.which("gitleaks"), None),
        )
    }
    native_supported = (
        bool(discovery_preview["files_selected"])
        or not bool(discovery_preview["discovery_complete"])
        if discovery_preview is not None
        else not sbom_input and not firmware and get_profile(profile).supports(target)
    )
    stages: list[_PlanStage] = [
        {
            "name": "fuse-native",
            "requested": True,
            "status": "planned" if native_supported else "skipped",
            "reason": (
                "discovery preview was incomplete; matching source files may remain"
                if discovery_preview is not None
                and not discovery_preview["files_selected"]
                and not discovery_preview["discovery_complete"]
                else "selected source/configuration files"
                if native_supported
                else "no files match the active source profile and path filters"
                if discovery_preview is not None
                else "SBOM and firmware inputs use specialized stages"
                if sbom_input or firmware
                else "no native profile selects this file type"
            ),
        },
        {
            "name": "hardware-inventory",
            "requested": True,
            "status": "planned" if kind != "sbom" else "skipped",
            "reason": "filename-based inventory of recognized hardware artifacts",
        },
    ]
    if kind == "directory":
        netlist_count = (
            discovery_preview.get("hardware_category_counts", {}).get("netlist", 0)
            if discovery_preview is not None
            else 0
        )
        netlist_stage_requested = hardware_netlist is not None or bool(netlist_count)
        stages.extend(
            (
                {
                    "name": "firmware-candidate-inventory",
                    "requested": True,
                    "status": "planned",
                    "reason": "records candidate filenames, extensions, and sizes without reading binary contents",
                },
                {
                    "name": "github-actions-static",
                    "requested": True,
                    "status": "planned"
                    if (target / ".github" / "workflows").is_dir()
                    else "skipped",
                    "reason": "checks exact write-all permissions, mutable non-SHA action refs, and explicit pull_request_target checkout of pull request head code without executing workflows",
                },
                {
                    "name": "kicad-netlist-static",
                    "requested": netlist_stage_requested,
                    "status": "planned" if netlist_stage_requested else "skipped",
                    "reason": (
                        "inspects a selected KiCad XML netlist for debug-labeled nets connected to connector candidates"
                        if hardware_netlist is not None
                        else "auto-selects one detected electronic netlist"
                        if netlist_count == 1
                        else "select a netlist with --hardware-netlist because multiple design variants were detected"
                        if netlist_count > 1
                        else "no electronic netlist was detected"
                    ),
                },
            )
        )
    if build_dir is not None:
        stages.append(
            {
                "name": "platform-build-context",
                "requested": True,
                "status": "planned",
                "reason": (
                    f"inspect selected {profile} build output without invoking its build system"
                ),
            }
        )
        if profile == "zephyr":
            stages.append(
                {
                    "name": "zephyr-hardenconfig",
                    "requested": zephyr_hardening_report is not None,
                    "status": "planned" if zephyr_hardening_report is not None else "skipped",
                    "reason": (
                        "imports the selected JSON emitted by Zephyr hardenconfig; no Zephyr command is run"
                        if zephyr_hardening_report is not None
                        else "optional; export JSON with HARDENCONFIG_JSON and pass --zephyr-hardening-report"
                    ),
                }
            )
    stages.append(
        {
            "name": "platformio-environment-matrix",
            "requested": True,
            "status": "planned" if platformio_inventory.status != "not-detected" else "skipped",
            "reason": (
                f"indexes {len(platformio_inventory.environments)} declared environment(s) without invoking PlatformIO"
                if platformio_inventory.status != "not-detected"
                else "no platformio.ini was detected"
            ),
        }
    )
    stages.append(
        {
            "name": "compilation-database-index",
            "requested": compile_commands is not None
            or compilation_database.status != "not-detected",
            "status": "planned" if compilation_database.status != "not-detected" else "skipped",
            "reason": (
                "indexes translation-unit and compiler metadata; compiler commands are never executed"
                if compilation_database.status != "not-detected"
                else "no compile_commands.json was detected or selected"
            ),
        }
    )
    stages.append(
        {
            "name": "hardware-bom-import",
            "requested": hardware_bom is not None,
            "status": "planned" if hardware_bom is not None else "skipped",
            "reason": (
                "imports a selected CSV or TSV into a CycloneDX hardware bill of materials"
                if hardware_bom is not None
                else "optional; select a BOM with --hardware-bom"
            ),
        }
    )
    stages.append(
        {
            "name": "cyclonedx-vex-context",
            "requested": vex is not None,
            "status": "planned" if vex is not None else "skipped",
            "reason": (
                "imports exact product, package PURL, and advisory matches as review metadata"
                if vex is not None
                else "optional; pass --vex together with --product-purl"
            ),
        }
    )
    stages.append(
        {
            "name": "slsa-subject-digest-check",
            "requested": provenance is not None,
            "status": "planned" if provenance is not None else "skipped",
            "reason": (
                "compares a supplied statement subject digest with the selected firmware image; no signature trust is asserted"
                if provenance is not None
                else "optional; pass --provenance with --firmware"
            ),
        }
    )
    if profile == "esp-idf":
        lockfile = target / "dependencies.lock" if target.is_dir() else None
        lock_exists = bool(lockfile and (lockfile.exists() or lockfile.is_symlink()))
        lock_is_link = bool(lockfile and lockfile.is_symlink())
        stages.append(
            {
                "name": "esp-idf-dependencies",
                "requested": True,
                "status": (
                    "skipped"
                    if not lock_exists
                    else "partial"
                    if lock_is_link
                    else "planned"
                    if lock_parser_available()
                    else "unavailable"
                ),
                "reason": (
                    "no project dependencies.lock was detected"
                    if not lock_exists
                    else "symbolic-link lockfiles are not followed"
                    if lock_is_link
                    else "optional parser is available; resolved metadata will be inventoried without running the component manager"
                    if lock_parser_available()
                    else "install the optional PyYAML parser with vigil-fuse[esp-idf]"
                ),
            }
        )
    if sbom_too_large:
        stages.append(
            {
                "name": "sbom-input",
                "requested": True,
                "status": "unsupported",
                "reason": "SBOM exceeds the 50 MiB parse and hash limit",
            }
        )
    if sbom or vulnerabilities:
        stages.append(
            {
                "name": "syft",
                "requested": bool(sbom or vulnerabilities) and not sbom_input,
                "status": "skipped"
                if sbom_input
                else "planned"
                if available["syft"]
                else "unavailable",
                "reason": "supplied SBOM is too large to process"
                if sbom_too_large
                else "local component inventory; not needed for a supplied SBOM"
                if sbom_input
                else "optional local component inventory",
            }
        )
    if vulnerabilities:
        stages.append(
            {
                "name": "osv-scanner",
                "requested": True,
                "status": "skipped"
                if sbom_too_large
                else "planned"
                if available["osv-scanner"]
                else "unavailable",
                "reason": "input SBOM exceeds 50 MiB and will not be parsed"
                if sbom_too_large
                else "strict offline mode"
                if no_network
                else "offline database mode"
                if offline_vulnerabilities
                else "network lookup may occur",
            }
        )
    if firmware:
        stages.append(
            {
                "name": "firmware-input",
                "requested": True,
                "status": "unsupported" if firmware_too_large else "planned",
                "reason": (
                    f"image is {target.stat().st_size} bytes, above the configured {max_firmware_bytes}-byte limit; it will not be hashed"
                    if firmware_too_large
                    else f"input size is capped at {max_firmware_bytes} bytes before hashing"
                ),
            }
        )
        stages.append(
            {
                "name": "binwalk",
                "requested": True,
                "status": "skipped"
                if firmware_too_large
                else "planned"
                if available["binwalk"]
                else "unavailable",
                "reason": "firmware input exceeded its size limit"
                if firmware_too_large
                else "signature identification only; extraction is not run",
            }
        )
    if git_history:
        repository_root = False
        git_available = shutil.which("git") is not None
        if target.is_dir():
            git = shutil.which("git")
            if git is not None:
                try:
                    root_result = subprocess.run(
                        [git, "rev-parse", "--show-toplevel"],
                        cwd=target,
                        capture_output=True,
                        text=True,
                        timeout=5,
                        check=False,
                    )
                    repository_root = (
                        root_result.returncode == 0
                        and Path(root_result.stdout.strip()).resolve() == target.resolve()
                    )
                except (OSError, subprocess.TimeoutExpired):
                    repository_root = False
        stages.append(
            {
                "name": "gitleaks-history",
                "requested": True,
                "status": (
                    "planned"
                    if available["gitleaks"] and git_available and repository_root
                    else "unavailable"
                    if not available["gitleaks"]
                    else "unavailable"
                    if not git_available
                    else "skipped"
                ),
                "reason": (
                    "install Gitleaks to run the requested history scan"
                    if not available["gitleaks"]
                    else "install Git to inspect repository history"
                    if not git_available
                    else "select the repository-root directory to scan Git history"
                    if not repository_root
                    else "redacted scan of commits reachable from HEAD; shallow histories are marked partial"
                ),
            }
        )

    plan: _ScanPlan = {
        "target": shareable_target,
        "target_kind": kind,
        "profile": profile,
        "selected_build_dir": selected_build_dir,
        "selected_zephyr_hardening_report": selected_hardening_report,
        "detected_frameworks": framework_hints,
        "framework_hints_are_advisory": True,
        "build_context": {
            "platformio": {
                "status": platformio_inventory.status,
                "path": platformio_inventory.path,
                "default_environments": list(platformio_inventory.default_environments),
                "selected_environments": list(platformio_inventory.selected_environments),
                "environment_count": len(platformio_inventory.environments),
            },
            "compilation_database": {
                "status": compilation_database.status,
                "path": compilation_database.path,
                "entry_count": compilation_database.entry_count,
                "unique_translation_units": compilation_database.unique_translation_units,
                "compiler_families": compilation_database.compiler_families,
            },
        },
        "discovery_preview": discovery_preview,
        "support": capability_for_plan(
            profile,
            sbom_input=sbom_input,
            firmware=firmware,
            oversized_sbom=sbom_too_large,
            oversized_firmware=firmware_too_large,
            unsupported_input=(
                not target.is_dir()
                and not sbom_input
                and not firmware
                and not get_profile(profile).supports(target)
            ),
        ),
        "stages": stages,
        "reports_directory": str(output_dir) if output_file is None else None,
        "report_file": str(output_file) if output_file is not None else None,
        "network": "blocked for vulnerability lookup"
        if no_network
        else "offline vulnerability database"
        if offline_vulnerabilities
        else "OSV network lookup may occur"
        if vulnerabilities
        else "no networked stage requested",
        "resource_limits": {
            "discovered_paths": max_discovered_paths,
            "discovered_directories": max_discovered_directories,
            "source_bytes": max_source_bytes,
            "firmware_image_bytes": max_firmware_bytes,
            "elapsed_seconds": max_scan_seconds,
            "native_rule_seconds_per_input": rule_timeout_seconds,
            "plan_preview_seconds": plan_preview_seconds,
        },
        "executed": False,
    }
    if output_format == "json":
        _safe_print(json.dumps(plan, indent=2, ensure_ascii=True))
    elif output_format == "sarif":
        raise ValueError("--format sarif is not available with --plan; use text or json")
    else:
        _safe_print(f"FUSE scan plan for {plan['target']} ({kind}, profile: {profile})")
        _safe_print("No analyzer ran; this is a bounded path and metadata preview.")
        _safe_print(
            "Framework hints: "
            + (
                ", ".join(
                    f"{item['name']} ({'; '.join(item['evidence'])})" for item in framework_hints
                )
                if framework_hints
                else "none detected"
            )
        )
        if platformio_inventory.status != "not-detected":
            _safe_print(
                f"PlatformIO environments: {len(platformio_inventory.environments)} found; "
                f"selected: {', '.join(platformio_inventory.selected_environments) or 'none'}"
            )
            _safe_print("  PlatformIO commands will not run.")
        if compilation_database.status != "not-detected":
            _safe_print(
                f"Compilation database: {compilation_database.unique_translation_units} unique "
                f"translation unit(s); commands will not run."
            )
        _safe_print(f"Selected profile controls analyzer routing: {profile}")
        if discovery_preview is not None:
            _safe_print(
                "Discovery preview: "
                f"{discovery_preview['files_discovered']} supported, "
                f"{discovery_preview['files_selected']} selected, "
                f"{discovery_preview['files_filtered']} path-filtered; "
                f"complete: {'yes' if discovery_preview['discovery_complete'] else 'no'}"
            )
            unsupported = discovery_preview["unsupported_file_types"]
            if unsupported:
                _safe_print(
                    "File types not selected by this source profile: "
                    + ", ".join(f"{kind}={count}" for kind, count in unsupported.items())
                )
            samples = discovery_preview["selected_files_sample"]
            if samples:
                _safe_print("Selected files (first 100):")
                for path in samples:
                    _safe_print(f"  {path}")
                if discovery_preview["selected_files_omitted"]:
                    _safe_print(f"  ... {discovery_preview['selected_files_omitted']} more")
            if discovery_preview["hardware_artifact_count"]:
                _safe_print(
                    f"Hardware artifacts detected by filename: {discovery_preview['hardware_artifact_count']}"
                )
                for category, count in discovery_preview["hardware_category_counts"].items():
                    _safe_print(f"  {category}: {count}")
        _safe_print(
            f"Support: {plan['support']['label']} / {plan['support']['status']} "
            f"({plan['support']['capability_id']})"
        )
        for stage in stages:
            suffix = f" ({stage['reason']})" if stage.get("reason") else ""
            _safe_print(f"  {stage['name']}: {stage['status']}{suffix}")
        _safe_print(
            f"Reports directory: {output_dir}"
            if output_file is None
            else f"Report file: {output_file}"
        )
        if selected_build_dir is not None:
            _safe_print(f"Selected build directory: {selected_build_dir}")
        if selected_hardening_report is not None:
            _safe_print(f"Selected Zephyr hardening report: {selected_hardening_report}")
        _safe_print(f"Network: {plan['network']}")
        _safe_print(
            "Resource caps: "
            f"{max_discovered_paths} paths, {max_discovered_directories} directories, "
            f"{max_source_bytes // (1024 * 1024)} MiB of source, "
            f"{max_firmware_bytes // (1024 * 1024)} MiB per firmware image, "
            f"{rule_timeout_seconds:g} seconds per rule/input, {max_scan_seconds} seconds total"
        )
    return 0


def _analyze_with_optional_tools(
    result: ScanResult,
    target: Path,
    output_dir: Path,
    *,
    sbom: bool,
    vulnerabilities: bool,
    firmware: bool,
    offline_vulnerabilities: bool,
    git_history: bool = False,
    no_network: bool = False,
    sbom_input: bool = False,
) -> ScanResult:
    analyzers = list(result.analyzers)
    findings = list(result.findings)
    artifacts = list(result.artifacts)
    sbom_path: Path | None = None
    sbom_too_large = sbom_input and target.stat().st_size > MAX_SBOM_DETECTION_BYTES

    if sbom_input:
        if sbom_too_large:
            if sbom or vulnerabilities:
                analyzers.append(
                    AnalyzerStatus(
                        "syft",
                        "skipped",
                        detail="The supplied SBOM exceeds the 50 MiB limit and will not be parsed or regenerated.",
                    )
                )
            if vulnerabilities:
                analyzers.append(
                    AnalyzerStatus(
                        "osv-scanner",
                        "skipped",
                        detail="The supplied SBOM exceeds the 50 MiB input limit; advisory matching was not run.",
                    )
                )
        else:
            sbom_path = target
        if (sbom or vulnerabilities) and not sbom_too_large:
            analyzers.append(
                AnalyzerStatus(
                    "syft",
                    "skipped",
                    detail="The input is already an SBOM; FUSE uses it directly rather than regenerating it.",
                )
            )
    elif sbom or vulnerabilities:
        syft_result = generate_sbom(target, output_dir)
        analyzers.append(syft_result.status)
        findings.extend(syft_result.findings)
        artifacts.extend(syft_result.artifacts)
        if syft_result.status.status == "completed":
            sbom_path = output_dir / "components.cdx.json"

    if vulnerabilities:
        if sbom_too_large:
            osv_result = None
        elif firmware and sbom_path is None:
            osv_result = None
            analyzers.append(
                AnalyzerStatus(
                    "osv-scanner",
                    "skipped",
                    detail="A firmware-image SBOM is required; Syft did not produce one.",
                )
            )
        else:
            osv_result = scan_vulnerabilities(
                target,
                output_dir,
                sbom_path=sbom_path,
                offline=offline_vulnerabilities,
                no_network=no_network,
            )
        if osv_result is not None:
            analyzers.append(osv_result.status)
            findings.extend(osv_result.findings)
            artifacts.extend(osv_result.artifacts)

    if firmware:
        firmware_input = next(
            (item for item in analyzers if item.name == "firmware-input"),
            None,
        )
        if firmware_input is not None:
            analyzers.append(
                AnalyzerStatus(
                    "binwalk",
                    "skipped",
                    detail="Firmware input exceeded its configured size limit; signature identification was not run.",
                )
            )
        else:
            binwalk_result = identify_firmware(target, output_dir)
            analyzers.append(binwalk_result.status)
            findings.extend(binwalk_result.findings)
            artifacts.extend(binwalk_result.artifacts)

    if git_history:
        history_result = scan_git_history(target, output_dir)
        analyzers.append(history_result.status)
        findings.extend(history_result.findings)
        artifacts.extend(history_result.artifacts)

    findings.sort(key=lambda item: (item.file.casefold(), item.start_line or 0, item.rule_id))
    return replace(
        result,
        analyzers=tuple(analyzers),
        findings=tuple(findings),
        artifacts=tuple(artifacts),
    )


def main(argv: list[str] | None = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    show_banner()
    if args.command is None:
        parser.print_help()
        return 0
    if args.command == "doctor":
        return _doctor()
    if args.command == "baseline":
        try:
            if args.baseline_action == "create":
                return create_baseline(args.report, args.output)
            if args.baseline_action == "suppress":
                return suppress_finding(
                    args.report,
                    args.finding,
                    args.reason,
                    args.owner,
                    args.expires,
                    args.output,
                )
            if args.baseline_action == "unsuppress":
                return unsuppress_finding(args.report, args.finding, args.output)
            return diff_baseline(
                args.report,
                args.baseline,
                args.suppressions,
                args.format,
                args.fail_on_new,
            )
        except (OSError, ValueError) as error:
            _safe_print(f"vigil-fuse: {error}", file=sys.stderr)
            return 2
    try:
        config_path = args.config.expanduser() if args.config else None
        config = load_config(config_path) if config_path else ScanConfig()
        profile = args.profile or config.profile
        target_label = args.target_label if args.target_label is not None else config.target_label
        include = (*config.include, *args.include)
        exclude = (*config.exclude, *args.exclude)
        disabled_rules = (*config.disabled_rules, *args.disable_rule)
        sbom = config.sbom if args.sbom is None else args.sbom
        vulnerabilities = (
            config.vulnerabilities if args.vulnerabilities is None else args.vulnerabilities
        )
        firmware = config.firmware if args.firmware is None else args.firmware
        git_history = config.git_history if args.git_history is None else args.git_history
        offline_vulnerabilities = (
            config.offline_vulnerabilities
            if args.offline_vulnerabilities is None
            else args.offline_vulnerabilities
        )
        if offline_vulnerabilities and not vulnerabilities:
            raise ValueError("--offline-vulnerabilities requires --vulnerabilities")
        analyzer_target = Path(args.target).expanduser()
        if analyzer_target.is_symlink():
            raise ValueError(
                "Symbolic-link targets are not followed; pass the resolved file or directory explicitly"
            )
        if firmware and not analyzer_target.is_file():
            raise ValueError("--firmware requires a single firmware image file")
        sbom_candidate = analyzer_target.is_file() and is_sbom_candidate(analyzer_target)
        sbom_input = analyzer_target.is_file() and (
            (sbom_candidate and analyzer_target.stat().st_size > MAX_SBOM_DETECTION_BYTES)
            or is_sbom_file(analyzer_target)
        )
        if firmware and sbom_input:
            raise ValueError("The target is recognized as an SBOM, not a firmware image")
        if args.vex and not args.product_purl:
            raise ValueError(
                "--vex requires --product-purl so FUSE can bind the review to the intended product"
            )
        if args.product_purl:
            validate_package_purl(args.product_purl)
        if args.vex and not vulnerabilities:
            raise ValueError(
                "--vex requires --vulnerabilities so review records can match advisory findings"
            )
        if args.provenance and not firmware:
            raise ValueError("--provenance requires --firmware")
        if args.hardware_bom and not analyzer_target.is_dir():
            raise ValueError("--hardware-bom requires a project directory target")
        if args.hardware_netlist and not analyzer_target.is_dir():
            raise ValueError("--hardware-netlist requires a project directory target")
        if (
            args.platformio_config is not None
            or args.platformio_env
            or args.compile_commands is not None
            or args.hardware_bom is not None
            or args.hardware_netlist is not None
        ) and not analyzer_target.is_dir():
            raise ValueError(
                "PlatformIO, compilation database, and hardware BOM options require a project directory target"
            )
        max_file_bytes = (
            args.max_file_bytes if args.max_file_bytes is not None else config.max_file_bytes
        )
        max_firmware_bytes = (
            args.max_firmware_bytes
            if args.max_firmware_bytes is not None
            else config.max_firmware_bytes
        )
        max_discovered_paths = (
            args.max_discovered_paths
            if args.max_discovered_paths is not None
            else config.max_discovered_paths
        )
        max_discovered_directories = (
            args.max_discovered_directories
            if args.max_discovered_directories is not None
            else config.max_discovered_directories
        )
        max_source_bytes = (
            args.max_source_bytes if args.max_source_bytes is not None else config.max_source_bytes
        )
        max_scan_seconds = (
            args.max_scan_seconds if args.max_scan_seconds is not None else config.max_scan_seconds
        )
        if not 1 <= max_firmware_bytes <= MAX_CONFIGURABLE_FIRMWARE_BYTES:
            raise ValueError(
                f"--max-firmware-bytes must be between 1 and {MAX_CONFIGURABLE_FIRMWARE_BYTES}"
            )
        for name, value, maximum in (
            ("--max-discovered-paths", max_discovered_paths, MAX_CONFIGURABLE_DISCOVERED_PATHS),
            (
                "--max-discovered-directories",
                max_discovered_directories,
                MAX_CONFIGURABLE_DISCOVERED_DIRECTORIES,
            ),
            ("--max-source-bytes", max_source_bytes, MAX_CONFIGURABLE_SOURCE_BYTES),
            ("--max-scan-seconds", max_scan_seconds, MAX_CONFIGURABLE_SCAN_SECONDS),
        ):
            if not 1 <= value <= maximum:
                raise ValueError(f"{name} must be between 1 and {maximum}")
        output_dir = (
            None
            if args.output is not None
            else _resolve_output_dir(args.output_dir, config, config_path)
        )
        if args.output is None and output_dir is None:
            output_dir = _default_output_dir(analyzer_target)
        if output_dir is not None and output_dir.is_symlink():
            raise ValueError("Report output directory must not be a symbolic link")
        optional_analysis = sbom or vulnerabilities or firmware or git_history
        if optional_analysis and args.output is not None:
            raise ValueError("Use --output-dir when enabling external analyzers")
        if args.hardware_bom and args.output is not None:
            raise ValueError("Use --output-dir when exporting a CycloneDX hardware BOM")
        if args.output is not None and output_dir is not None:
            raise ValueError("Use either --output or --output-dir, not both")
        exclude = _exclude_output_directory(args.target, output_dir, exclude)

        if args.plan:
            return _scan_plan(
                target=analyzer_target,
                profile=profile,
                target_label=target_label,
                build_dir=args.build_dir,
                zephyr_hardening_report=args.zephyr_hardening_report,
                platformio_config=args.platformio_config,
                platformio_environments=tuple(args.platformio_env),
                compile_commands=args.compile_commands,
                hardware_bom=args.hardware_bom,
                hardware_netlist=args.hardware_netlist,
                vex=args.vex,
                provenance=args.provenance,
                sbom=sbom,
                vulnerabilities=vulnerabilities,
                firmware=firmware,
                max_firmware_bytes=max_firmware_bytes,
                max_discovered_paths=max_discovered_paths,
                max_discovered_directories=max_discovered_directories,
                max_source_bytes=max_source_bytes,
                max_scan_seconds=max_scan_seconds,
                git_history=git_history,
                offline_vulnerabilities=offline_vulnerabilities,
                no_network=args.no_network,
                output_dir=output_dir or Path(".fuse-results"),
                output_file=args.output,
                sbom_input=sbom_input,
                output_format=args.format,
                include=include,
                exclude=exclude,
                rule_timeout_seconds=args.rule_timeout,
            )

        result = scan(
            args.target,
            profile=profile,
            target_label=target_label,
            include=include,
            exclude=exclude,
            disabled_rules=disabled_rules,
            max_file_bytes=max_file_bytes,
            max_firmware_bytes=max_firmware_bytes,
            max_discovered_paths=max_discovered_paths,
            max_discovered_directories=max_discovered_directories,
            max_source_bytes=max_source_bytes,
            max_scan_seconds=max_scan_seconds,
            rule_timeout_seconds=args.rule_timeout,
            firmware_image=firmware,
            sbom_input=sbom_input,
            build_dir=args.build_dir,
            zephyr_hardening_report=args.zephyr_hardening_report,
            platformio_config=args.platformio_config,
            platformio_environments=tuple(args.platformio_env),
            compile_commands=args.compile_commands,
            hardware_bom=args.hardware_bom,
            hardware_netlist=args.hardware_netlist,
        )
        network_policy = (
            "no-network"
            if args.no_network
            else "offline-vulnerabilities"
            if offline_vulnerabilities
            else "network-allowed"
            if vulnerabilities
            else "not-requested"
        )
        result = replace(result, network_policy=network_policy)
        if optional_analysis and output_dir is not None:
            output_dir.mkdir(parents=True, exist_ok=True)
            result = _analyze_with_optional_tools(
                result,
                analyzer_target,
                output_dir,
                sbom=sbom,
                vulnerabilities=vulnerabilities,
                firmware=firmware,
                git_history=git_history,
                offline_vulnerabilities=offline_vulnerabilities,
                no_network=args.no_network,
                sbom_input=sbom_input,
            )
        if args.product_purl:
            result = replace(result, product_purl=args.product_purl)
        if args.vex:
            vex_root = analyzer_target if analyzer_target.is_dir() else analyzer_target.parent
            findings, vex_import = import_vex(
                vex_root,
                args.vex,
                product_purl=args.product_purl,
                findings=result.findings,
            )
            result = replace(result, findings=findings, vex_import=vex_import)
        if args.provenance:
            provenance = inspect_provenance(
                analyzer_target.parent,
                args.provenance,
                firmware_path=analyzer_target,
                max_firmware_bytes=max_firmware_bytes,
            )
            result = replace(result, provenance=provenance)
        if result.hardware_bom.status in {"imported", "partial"}:
            if output_dir is None:
                raise ValueError("A CycloneDX hardware BOM needs a report output directory")
            output_dir.mkdir(parents=True, exist_ok=True)
            bom_path = output_dir / "hardware-bom.cdx.json"
            if bom_path.is_symlink():
                raise ValueError(
                    "Refusing to write the CycloneDX hardware BOM through a symbolic link"
                )
            bom_content = hardware_bom_document(result.hardware_bom, product_name=result.target)
            bom_path.write_bytes(bom_content.encode("utf-8"))
            bom_digest = hashlib.sha256(bom_path.read_bytes()).hexdigest()
            result = replace(
                result,
                artifacts=(
                    *result.artifacts,
                    AnalysisArtifact(
                        path=bom_path.relative_to(output_dir).as_posix(),
                        media_type="application/vnd.cyclonedx+json",
                        sha256=bom_digest,
                    ),
                ),
            )
        if output_dir is not None:
            _write_reports(result, output_dir)
            _safe_print(f"Reports written to {output_dir}", file=sys.stderr)
            if args.output_dir is None and config.output_dir is None:
                sys.stdout.write(
                    to_json(result)
                    if args.format == "json"
                    else to_sarif(result)
                    if args.format == "sarif"
                    else to_text(result)
                )
        elif args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            if args.output.is_symlink():
                raise ValueError("Refusing to write report through symbolic link")
            report = (
                to_json(result)
                if args.format == "json"
                else to_sarif(result)
                if args.format == "sarif"
                else to_text(result)
            )
            args.output.write_text(report, encoding="utf-8")
            _safe_print(f"Report written to {args.output}", file=sys.stderr)
        else:
            sys.stdout.write(
                to_json(result)
                if args.format == "json"
                else to_sarif(result)
                if args.format == "sarif"
                else to_text(result)
            )
    except (OSError, ValueError) as error:
        _safe_print(f"vigil-fuse: {error}", file=sys.stderr)
        return 2

    required_analyzers = {
        "syft": sbom and not sbom_input,
        "osv-scanner": vulnerabilities,
        "binwalk": firmware,
        "gitleaks-history": git_history,
    }
    if any(
        analyzer.status in {"partial", "unavailable", "skipped", "failed"}
        for analyzer in result.analyzers
        if required_analyzers.get(analyzer.name, False)
    ):
        return 2
    if any(
        analyzer.name == "fuse-native" and analyzer.status == "partial"
        for analyzer in result.analyzers
    ):
        return 2
    if any(
        analyzer.name == "platform-build-context" and analyzer.status != "completed"
        for analyzer in result.analyzers
    ):
        return 2
    if any(
        analyzer.name == "esp-idf-dependencies" and analyzer.status != "completed"
        for analyzer in result.analyzers
    ):
        return 2
    if any(
        analyzer.name == "zephyr-hardenconfig" and analyzer.status != "completed"
        for analyzer in result.analyzers
    ):
        return 2
    if result.platformio_inventory.status in {"partial", "invalid"}:
        return 2
    if result.compilation_database.status in {"partial", "invalid"}:
        return 2
    if result.hardware_bom.status in {"partial", "invalid"}:
        return 2
    if result.vex_import.status in {"partial", "invalid"}:
        return 2
    if result.provenance.status not in {"not-requested", "subject-match"}:
        return 2
    if result.firmware_candidates.status == "partial":
        return 2
    if result.github_actions.status == "partial":
        return 2
    if result.netlist_inventory.status in {"partial", "invalid"}:
        return 2

    if not result.analysis_performed:
        return 2

    if args.fail_on != "none":
        threshold = _SEVERITY_ORDER[args.fail_on]
        if any(_SEVERITY_ORDER[item.severity] >= threshold for item in result.findings):
            return 1
    return 0
