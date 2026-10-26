from __future__ import annotations

import argparse
import sys
from dataclasses import replace
from pathlib import Path

from . import __version__
from .analyzers import generate_sbom, identify_firmware, scan_vulnerabilities
from .config import ScanConfig, load_config
from .model import AnalyzerStatus
from .profiles import PROFILES
from .reporting import to_json, to_text
from .sarif import to_sarif
from .scanner import scan
from .input_types import is_sbom_file

_SEVERITY_ORDER = {"unknown": -1, "info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="vigil-fuse",
        description="FUSE - Firmware & Unified Security Engine, a VIGIL-IoT project.",
    )
    parser.add_argument("--version", action="version", version=f"FUSE {__version__}")
    commands = parser.add_subparsers(dest="command", required=True)
    scan_parser = commands.add_parser("scan", help="analyze a project, SBOM, or supported firmware input")
    scan_parser.add_argument("target", nargs="?", default=".", help="project directory, file, SBOM, or firmware image")
    scan_parser.add_argument("--config", type=Path, help="load scan options from a TOML file")
    scan_parser.add_argument("--profile", choices=tuple(PROFILES), help="input discovery profile")
    scan_parser.add_argument("--include", action="append", default=[], help="include relative path glob (repeatable)")
    scan_parser.add_argument("--exclude", action="append", default=[], help="exclude relative path glob (repeatable)")
    scan_parser.add_argument("--disable-rule", action="append", default=[], help="disable a rule ID (repeatable)")
    scan_parser.add_argument("--max-file-bytes", type=int, help="maximum bytes read from one source file")
    scan_parser.add_argument("--sbom", action=argparse.BooleanOptionalAction, default=None,
                             help="generate a CycloneDX SBOM with optional Syft")
    scan_parser.add_argument("--vulnerabilities", action=argparse.BooleanOptionalAction, default=None,
                             help="match dependencies against OSV advisories with optional tools")
    scan_parser.add_argument("--firmware", action=argparse.BooleanOptionalAction, default=None,
                             help="identify signatures in a firmware image with Binwalk; no extraction")
    scan_parser.add_argument("--offline-vulnerabilities", action=argparse.BooleanOptionalAction, default=None,
                             help="use OSV-Scanner's local vulnerability database")
    scan_parser.add_argument(
        "--format", choices=("text", "json", "sarif"), default="text",
        help="stdout or single-file report format",
    )
    outputs = scan_parser.add_mutually_exclusive_group()
    outputs.add_argument("--output", type=Path, help="write one report to this file")
    outputs.add_argument(
        "--output-dir", type=Path,
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


def _exclude_output_directory(target: str, output_dir: Path | None, excludes: tuple[str, ...]) -> tuple[str, ...]:
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


def _write_reports(result, output_dir: Path) -> None:
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


def _analyze_with_optional_tools(result, target: Path, output_dir: Path, *, sbom: bool,
                                 vulnerabilities: bool, firmware: bool,
                                 offline_vulnerabilities: bool, sbom_input: bool = False):
    analyzers = list(result.analyzers)
    findings = list(result.findings)
    artifacts = list(result.artifacts)
    sbom_path: Path | None = None

    if sbom_input:
        sbom_path = target
        if sbom or vulnerabilities:
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
        if firmware and sbom_path is None:
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
            )
        if osv_result is not None:
            analyzers.append(osv_result.status)
            findings.extend(osv_result.findings)
            artifacts.extend(osv_result.artifacts)

    if firmware:
        binwalk_result = identify_firmware(target, output_dir)
        analyzers.append(binwalk_result.status)
        findings.extend(binwalk_result.findings)
        artifacts.extend(binwalk_result.artifacts)

    findings.sort(key=lambda item: (item.file.casefold(), item.start_line or 0, item.rule_id))
    return replace(
        result,
        analyzers=tuple(analyzers),
        findings=tuple(findings),
        artifacts=tuple(artifacts),
    )


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        config_path = args.config.expanduser() if args.config else None
        config = load_config(config_path) if config_path else ScanConfig()
        profile = args.profile or config.profile
        include = (*config.include, *args.include)
        exclude = (*config.exclude, *args.exclude)
        disabled_rules = (*config.disabled_rules, *args.disable_rule)
        sbom = config.sbom if args.sbom is None else args.sbom
        vulnerabilities = config.vulnerabilities if args.vulnerabilities is None else args.vulnerabilities
        firmware = config.firmware if args.firmware is None else args.firmware
        offline_vulnerabilities = (
            config.offline_vulnerabilities
            if args.offline_vulnerabilities is None
            else args.offline_vulnerabilities
        )
        if offline_vulnerabilities and not vulnerabilities:
            raise ValueError("--offline-vulnerabilities requires --vulnerabilities")
        if firmware and not Path(args.target).expanduser().is_file():
            raise ValueError("--firmware requires a single firmware image file")
        analyzer_target = Path(args.target).expanduser()
        sbom_input = analyzer_target.is_file() and is_sbom_file(analyzer_target)
        if firmware and sbom_input:
            raise ValueError("The target is recognized as an SBOM, not a firmware image")
        max_file_bytes = (
            args.max_file_bytes
            if args.max_file_bytes is not None
            else config.max_file_bytes
        )
        output_dir = (
            None
            if args.output is not None
            else _resolve_output_dir(args.output_dir, config, config_path)
        )
        if output_dir is not None and output_dir.is_symlink():
            raise ValueError("Report output directory must not be a symbolic link")
        optional_analysis = sbom or vulnerabilities or firmware
        if optional_analysis and output_dir is None:
            if args.output is not None:
                raise ValueError("Use --output-dir when enabling external analyzers")
            output_dir = Path(".fuse-results")
        if args.output is not None and output_dir is not None:
            raise ValueError("Use either --output or --output-dir, not both")
        exclude = _exclude_output_directory(args.target, output_dir, exclude)

        result = scan(
            args.target,
            profile=profile,
            include=include,
            exclude=exclude,
            disabled_rules=disabled_rules,
            max_file_bytes=max_file_bytes,
            firmware_image=firmware,
            sbom_input=sbom_input,
        )
        if optional_analysis and output_dir is not None:
            output_dir.mkdir(parents=True, exist_ok=True)
            result = _analyze_with_optional_tools(
                result,
                analyzer_target,
                output_dir,
                sbom=sbom,
                vulnerabilities=vulnerabilities,
                firmware=firmware,
                offline_vulnerabilities=offline_vulnerabilities,
                sbom_input=sbom_input,
            )
        if output_dir is not None:
            _write_reports(result, output_dir)
            print(f"Reports written to {output_dir}", file=sys.stderr)
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
            print(f"Report written to {args.output}", file=sys.stderr)
        else:
            sys.stdout.write(
                to_json(result)
                if args.format == "json"
                else to_sarif(result)
                if args.format == "sarif"
                else to_text(result)
            )
    except (OSError, ValueError) as error:
        print(f"vigil-fuse: {error}", file=sys.stderr)
        return 2

    required_analyzers = {
        "syft": sbom,
        "osv-scanner": vulnerabilities,
        "binwalk": firmware,
    }
    if any(
        analyzer.status in {"unavailable", "failed"}
        for analyzer in result.analyzers
        if required_analyzers.get(analyzer.name, False)
    ):
        return 2

    if args.fail_on != "none":
        threshold = _SEVERITY_ORDER[args.fail_on]
        if any(_SEVERITY_ORDER[item.severity] >= threshold for item in result.findings):
            return 1
    return 0
