"""Measure repeatable FUSE CLI scans over a pinned local repository cohort."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import math
import os
import platform
import statistics
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_MANIFEST = ROOT / "reports" / "repository-scans" / "fresh-validation-next" / "manifest.json"
DEFAULT_CHECKOUTS = ROOT.parent / "fuse-scan-targets-fresh-validation-next"
SOURCE_ROOT = ROOT / "src"
RUN_TIMEOUT_SECONDS = 900


class RepositoryBenchmarkError(RuntimeError):
    """Raised when a pinned scan cannot produce comparable measurements."""


def _git(repository: Path, *arguments: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(repository), *arguments],
        check=True,
        capture_output=True,
        text=True,
        encoding="utf-8",
    )
    return result.stdout.strip()


def _fuse_revision() -> dict[str, Any]:
    try:
        revision = _git(ROOT, "rev-parse", "HEAD")
        dirty = bool(_git(ROOT, "status", "--porcelain", "--untracked-files=all"))
    except (OSError, subprocess.CalledProcessError):
        revision = None
        dirty = None
    return {"commit": revision, "working_tree_dirty": dirty}


def _median_absolute_deviation(values: list[float]) -> float:
    center = statistics.median(values)
    return statistics.median(abs(value - center) for value in values)


def summarize_samples(
    samples: list[float], *, files_scanned: int, source_bytes_read: int
) -> dict[str, Any]:
    if not samples or any(not math.isfinite(value) or value <= 0 for value in samples):
        raise ValueError("samples must contain positive finite durations")
    if files_scanned < 0 or source_bytes_read < 0:
        raise ValueError("scan counts cannot be negative")
    median_seconds = statistics.median(samples)
    return {
        "wall_time_seconds": {
            "samples": [round(value, 6) for value in samples],
            "median": round(median_seconds, 6),
            "minimum": round(min(samples), 6),
            "maximum": round(max(samples), 6),
            "median_absolute_deviation": round(_median_absolute_deviation(samples), 6),
        },
        "files_per_second_at_median": (
            round(files_scanned / median_seconds, 3) if files_scanned else None
        ),
        "mebibytes_per_second_at_median": (
            round(source_bytes_read / (1024 * 1024) / median_seconds, 6)
            if source_bytes_read
            else None
        ),
    }


def _scan_command(
    checkout: Path,
    profile: str,
    scan: dict[str, Any],
    output: Path,
) -> list[str]:
    command = [
        sys.executable,
        "-m",
        "vigil_fuse",
        "scan",
        str(checkout),
        "--profile",
        profile,
        "--target-label",
        str(scan.get("target_label", "pinned-cohort/unknown")),
    ]
    for include in scan.get("includes", ()):
        if not isinstance(include, str):
            raise RepositoryBenchmarkError("manifest include patterns must be strings")
        command.extend(("--include", include))
    command.extend(
        (
            "--no-network",
            "--no-sbom",
            "--no-vulnerabilities",
            "--no-firmware",
            "--no-git-history",
            "--output-dir",
            str(output),
        )
    )
    return command


def _run_once(
    command: list[str], *, timeout_seconds: int, environment: dict[str, str]
) -> tuple[float, dict[str, Any], int]:
    started = time.perf_counter()
    try:
        completed = subprocess.run(
            command,
            cwd=ROOT,
            env=environment,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=False,
            timeout=timeout_seconds,
        )
    except subprocess.TimeoutExpired as error:
        raise RepositoryBenchmarkError(
            f"FUSE scan exceeded the {timeout_seconds}-second timeout"
        ) from error
    elapsed = time.perf_counter() - started
    if completed.returncode not in {0, 2}:
        raise RepositoryBenchmarkError(
            f"FUSE exited with status {completed.returncode}: {completed.stderr[-1000:]}"
        )
    report_path = Path(command[-1]) / "findings.json"
    if not report_path.is_file():
        raise RepositoryBenchmarkError("FUSE did not write a JSON report")
    try:
        report = json.loads(report_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise RepositoryBenchmarkError("FUSE wrote an unreadable JSON report") from error
    if not isinstance(report, dict):
        raise RepositoryBenchmarkError("FUSE report must be a JSON object")
    summary = report.get("summary")
    coverage = report.get("coverage")
    if not isinstance(summary, dict) or not isinstance(coverage, dict):
        raise RepositoryBenchmarkError("FUSE report lacks summary or coverage data")
    if summary.get("analysis_performed") is not True:
        raise RepositoryBenchmarkError("FUSE did not perform analysis")
    return elapsed, report, completed.returncode


def _summary_signature(report: dict[str, Any]) -> tuple[Any, ...]:
    summary = report["summary"]
    coverage = report["coverage"]
    native_analysis_status, skipped_by_reason = _coverage_details(coverage)
    return (
        summary.get("files_discovered"),
        summary.get("files_selected"),
        summary.get("files_scanned"),
        summary.get("source_bytes_read"),
        summary.get("files_skipped"),
        summary.get("finding_count"),
        coverage.get("discovery_complete"),
        native_analysis_status,
        tuple(sorted(skipped_by_reason.items())),
    )


def _coverage_details(coverage: dict[str, Any]) -> tuple[str, dict[str, int]]:
    raw_skipped_by_reason = coverage.get("files_skipped_by_reason", {})
    if not isinstance(raw_skipped_by_reason, dict):
        raise RepositoryBenchmarkError("FUSE report has invalid skipped-file reason counts")
    skipped_by_reason: dict[str, int] = {}
    for reason, count in raw_skipped_by_reason.items():
        if (
            not isinstance(reason, str)
            or not isinstance(count, int)
            or isinstance(count, bool)
            or count < 0
        ):
            raise RepositoryBenchmarkError("FUSE report has invalid skipped-file reason counts")
        skipped_by_reason[reason] = count
    analyzers = coverage.get("analyzers")
    if not isinstance(analyzers, list):
        raise RepositoryBenchmarkError("FUSE report lacks analyzer coverage")
    native = next(
        (
            analyzer
            for analyzer in analyzers
            if isinstance(analyzer, dict) and analyzer.get("name") == "fuse-native"
        ),
        None,
    )
    native_status = native.get("status") if isinstance(native, dict) else None
    if not isinstance(native_status, str):
        raise RepositoryBenchmarkError("FUSE report lacks native analysis status")
    return native_status, skipped_by_reason


def _scope_measurement(
    repository: dict[str, Any],
    checkout: Path,
    scan: dict[str, Any],
    *,
    warmups: int,
    repetitions: int,
    timeout_seconds: int,
    environment: dict[str, str],
    temporary_root: Path,
) -> dict[str, Any]:
    timings: list[float] = []
    warmup_timings: list[float] = []
    reports: list[dict[str, Any]] = []
    return_codes: list[int] = []
    scan_id = scan["id"]
    for index in range(warmups + repetitions):
        output = temporary_root / repository["id"] / scan_id / f"run-{index:02d}"
        command = _scan_command(checkout, repository["profile"], scan, output)
        elapsed, report, return_code = _run_once(
            command, timeout_seconds=timeout_seconds, environment=environment
        )
        if index < warmups:
            warmup_timings.append(elapsed)
            continue
        timings.append(elapsed)
        reports.append(report)
        return_codes.append(return_code)

    signatures = {_summary_signature(report) for report in reports}
    if len(signatures) != 1:
        raise RepositoryBenchmarkError(
            f"scan counts or coverage changed between repetitions for {scan_id}"
        )
    if len(set(return_codes)) != 1:
        raise RepositoryBenchmarkError(
            f"scan exit status changed between repetitions for {scan_id}"
        )
    report = reports[-1]
    summary = report["summary"]
    coverage = report["coverage"]
    native_analysis_status, skipped_by_reason = _coverage_details(coverage)
    files_scanned = summary["files_scanned"]
    source_bytes = summary["source_bytes_read"]
    measured = summarize_samples(
        timings, files_scanned=files_scanned, source_bytes_read=source_bytes
    )
    return {
        "repository_id": repository["id"],
        "repository": repository["name"],
        "repository_commit": repository["commit"],
        "scan_id": scan_id,
        "scope": scan.get("scope", "unspecified"),
        "profile": repository["profile"],
        "include_patterns": scan.get("includes", []),
        "files_discovered": summary["files_discovered"],
        "files_selected": summary["files_selected"],
        "files_scanned": files_scanned,
        "source_bytes_read": source_bytes,
        "files_skipped": summary["files_skipped"],
        "files_skipped_by_reason": skipped_by_reason,
        "finding_count": summary["finding_count"],
        "discovery_complete": coverage.get("discovery_complete"),
        "native_analysis_status": native_analysis_status,
        "scan_return_code": return_codes[0],
        "warmup_count": warmups,
        "warmup_seconds": [round(value, 6) for value in warmup_timings],
        "repetition_count": repetitions,
        **measured,
    }


def run_benchmark(
    *,
    manifest_path: Path = DEFAULT_MANIFEST,
    checkouts_root: Path = DEFAULT_CHECKOUTS,
    warmups: int = 1,
    repetitions: int = 3,
    timeout_seconds: int = RUN_TIMEOUT_SECONDS,
) -> dict[str, Any]:
    if not 0 <= warmups <= 10:
        raise ValueError("warmups must be between 0 and 10")
    if not 1 <= repetitions <= 20:
        raise ValueError("repetitions must be between 1 and 20")
    if not 1 <= timeout_seconds <= 3600:
        raise ValueError("timeout must be between 1 and 3600 seconds")
    manifest_path = manifest_path.resolve()
    checkouts_root = checkouts_root.resolve()
    manifest_bytes = manifest_path.read_bytes()
    manifest = json.loads(manifest_bytes)
    repositories = manifest.get("repositories") if isinstance(manifest, dict) else None
    if not isinstance(repositories, list) or not repositories:
        raise RepositoryBenchmarkError("manifest must contain a non-empty repositories list")

    environment = os.environ.copy()
    existing_pythonpath = environment.get("PYTHONPATH")
    environment["PYTHONPATH"] = os.pathsep.join(
        item for item in (str(SOURCE_ROOT), existing_pythonpath) if item
    )
    measurements: list[dict[str, Any]] = []
    with tempfile.TemporaryDirectory(prefix="fuse-repository-benchmark-") as temporary:
        temporary_root = Path(temporary)
        for repository in repositories:
            if not isinstance(repository, dict):
                raise RepositoryBenchmarkError("manifest repository entries must be objects")
            repository_id = repository.get("id")
            if (
                not isinstance(repository_id, str)
                or not repository_id
                or Path(repository_id).is_absolute()
            ):
                raise RepositoryBenchmarkError("repository IDs must be non-empty relative names")
            checkout = (checkouts_root / repository_id).resolve()
            if not checkout.is_relative_to(checkouts_root) or not checkout.is_dir():
                raise RepositoryBenchmarkError(f"missing or unsafe checkout for {repository_id}")
            actual_commit = _git(checkout, "rev-parse", "HEAD")
            if actual_commit.lower() != str(repository.get("commit", "")).lower():
                raise RepositoryBenchmarkError(f"pinned commit mismatch for {repository_id}")
            if _git(checkout, "status", "--porcelain", "--untracked-files=all"):
                raise RepositoryBenchmarkError(f"checkout is dirty: {repository_id}")
            scans = repository.get("scans")
            profile = repository.get("profile")
            if not isinstance(profile, str) or not isinstance(scans, list) or not scans:
                raise RepositoryBenchmarkError(f"invalid profile or scan list for {repository_id}")
            for scan in scans:
                if not isinstance(scan, dict) or not isinstance(scan.get("id"), str):
                    raise RepositoryBenchmarkError(f"invalid scan entry for {repository_id}")
                if Path(scan["id"]).is_absolute() or ".." in Path(scan["id"]).parts:
                    raise RepositoryBenchmarkError("scan IDs must not escape the temporary output")
                measurements.append(
                    _scope_measurement(
                        repository,
                        checkout,
                        scan,
                        warmups=warmups,
                        repetitions=repetitions,
                        timeout_seconds=timeout_seconds,
                        environment=environment,
                        temporary_root=temporary_root,
                    )
                )

    try:
        from vigil_fuse import __version__
    except ImportError as error:
        raise RepositoryBenchmarkError("install FUSE or set PYTHONPATH to src") from error
    return {
        "schema_version": "1.0",
        "benchmark": "fuse-pinned-repository-scan",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "tool": {"name": "FUSE", "version": __version__},
        "source_revision": _fuse_revision(),
        "environment": {
            "python_version": platform.python_version(),
            "operating_system": platform.system(),
            "os_release": platform.release(),
            "machine": platform.machine(),
            "logical_cpu_count": os.cpu_count(),
        },
        "cohort": {
            "scan_date": manifest.get("scan_date"),
            "repository_count": len(repositories),
            "manifest_sha256": hashlib.sha256(manifest_bytes).hexdigest(),
            "repository_commits": {
                item["id"]: item["commit"]
                for item in repositories
                if isinstance(item, dict) and "id" in item and "commit" in item
            },
        },
        "configuration": {
            "warmups": warmups,
            "repetitions": repetitions,
            "timeout_seconds": timeout_seconds,
            "network_enabled": False,
            "optional_analyzers_enabled": False,
            "native_rules_enabled": True,
        },
        "scopes": measurements,
        "scope_limitations": [
            "Measurements describe only the pinned repository scopes in the input manifest.",
            "Wall time includes starting a fresh Python CLI process and writing temporary reports.",
            f"Measurements use a single {platform.system()} host; this is not a controlled cross-platform comparison.",
            "Optional networked and external analyzers were disabled for every run.",
            "Files skipped or partial coverage remain visible and are not treated as complete scans.",
            "Finding counts are scan observations, not a measure of detection accuracy.",
            "Memory, CPU utilization, build time, device runtime, and firmware behavior were not measured.",
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--checkouts", type=Path, default=DEFAULT_CHECKOUTS)
    parser.add_argument("--warmups", type=int, default=1)
    parser.add_argument("--repetitions", type=int, default=3)
    parser.add_argument("--timeout-seconds", type=int, default=RUN_TIMEOUT_SECONDS)
    parser.add_argument("--output", type=Path, help="write JSON results to this path")
    args = parser.parse_args()
    try:
        result = run_benchmark(
            manifest_path=args.manifest,
            checkouts_root=args.checkouts,
            warmups=args.warmups,
            repetitions=args.repetitions,
            timeout_seconds=args.timeout_seconds,
        )
    except (OSError, ValueError, KeyError, json.JSONDecodeError, RepositoryBenchmarkError) as error:
        print(f"repository benchmark failed: {error}", file=sys.stderr)
        return 2
    rendered = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.output:
        output = args.output.expanduser()
        if not output.is_absolute():
            output = ROOT / output
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(rendered, encoding="utf-8")
        print(f"Measured {len(result['scopes'])} pinned repository scopes on {platform.system()}.")
        for scope in result["scopes"]:
            times = scope["wall_time_seconds"]
            print(
                f"{scope['repository_id']}/{scope['scan_id']}: "
                f"{scope['files_scanned']} files, median {times['median']:.3f}s, "
                f"{scope['finding_count']} signals, discovery_complete={scope['discovery_complete']}"
            )
        print(f"JSON report written to {output}")
    else:
        print(rendered, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
