#!/usr/bin/env python3
"""Measure FUSE scan time and sampled process-tree RSS on a synthetic C project."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
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
SOURCE_ROOT = ROOT / "src"
sys.path.insert(0, str(SOURCE_ROOT))

from vigil_fuse import __version__  # noqa: E402


class BenchmarkError(RuntimeError):
    """Raised when a benchmark run cannot produce complete, comparable evidence."""


@dataclass(frozen=True)
class Workload:
    file_count: int
    source_bytes: int
    sha256: str


@dataclass(frozen=True)
class ScanObservation:
    wall_time_seconds: float
    sampled_process_tree_rss_bytes: int
    rss_sample_count: int
    inaccessible_process_samples: int
    files_scanned: int
    source_bytes_read: int
    finding_count: int
    completed_native_rules: tuple[str, ...]


def create_synthetic_project(root: Path, file_count: int) -> Workload:
    """Create deterministic, comment-only prefilter probes and benign C source files."""
    if not 1 <= file_count <= 10_000:
        raise ValueError("file_count must be between 1 and 10000")

    root.mkdir(parents=True, exist_ok=False)
    digest = hashlib.sha256()
    source_bytes = 0

    for index in range(file_count):
        probe = ""
        if index == 0:
            probe_parts = (
                "pass" + 'word = "placeholder"',
                "m" + "qtt://sensor.example.invalid",
                "h" + "ttp://controller.example.invalid",
                "verify" + "=false",
                "-----BEGIN " + "PRIVATE KEY-----",
            )
            probe = "/* " + "; ".join(probe_parts) + " */\n"

        source = (
            probe
            + "#include <stdint.h>\n"
            + f"uint32_t sample_{index:06d}(void) {{\n"
            + f"    return {index % 1024}u;\n"
            + "}\n"
        )
        relative_path = f"module_{index:06d}.c"
        content = source.encode("utf-8")
        (root / relative_path).write_bytes(content)
        source_bytes += len(content)
        digest.update(relative_path.encode("utf-8") + b"\0" + content + b"\0")

    return Workload(file_count=file_count, source_bytes=source_bytes, sha256=digest.hexdigest())


def _sample_process_tree_rss(pid: int, psutil: Any) -> tuple[int, int]:
    """Return summed RSS and the number of inaccessible process samples."""
    try:
        root_process = psutil.Process(pid)
        processes = [root_process, *root_process.children(recursive=True)]
    except psutil.NoSuchProcess:
        return 0, 0
    except psutil.AccessDenied:
        return 0, 1

    total_rss = 0
    inaccessible = 0
    for process in processes:
        try:
            total_rss += process.memory_info().rss
        except (psutil.NoSuchProcess, psutil.ZombieProcess):
            continue
        except psutil.AccessDenied:
            inaccessible += 1
    return total_rss, inaccessible


def _terminate_process_tree(pid: int, process: subprocess.Popen[str], psutil: Any) -> None:
    try:
        root_process = psutil.Process(pid)
        children = root_process.children(recursive=True)
        for child in reversed(children):
            try:
                child.terminate()
            except psutil.NoSuchProcess:
                pass
        try:
            root_process.terminate()
        except psutil.NoSuchProcess:
            pass
        _, alive = psutil.wait_procs([*children, root_process], timeout=2)
        for remaining in alive:
            try:
                remaining.kill()
            except psutil.NoSuchProcess:
                pass
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        process.kill()


def _run_scan(
    target: Path,
    report_path: Path,
    expected_workload: Workload,
    sample_interval_seconds: float,
    timeout_seconds: int,
    psutil: Any,
) -> ScanObservation:
    command = [
        sys.executable,
        "-m",
        "vigil_fuse",
        "scan",
        str(target),
        "--profile",
        "generic",
        "--target-label",
        "benchmark/synthetic",
        "--no-network",
        "--no-sbom",
        "--no-vulnerabilities",
        "--no-firmware",
        "--no-git-history",
        "--format",
        "json",
        "--output",
        str(report_path),
    ]
    child_environment = os.environ.copy()
    existing_pythonpath = child_environment.get("PYTHONPATH")
    child_environment["PYTHONPATH"] = os.pathsep.join(
        part for part in (str(SOURCE_ROOT), existing_pythonpath) if part
    )

    started = time.perf_counter()
    process = subprocess.Popen(
        command,
        cwd=ROOT,
        env=child_environment,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    deadline = started + timeout_seconds
    peak_rss = 0
    sample_count = 0
    inaccessible_samples = 0

    while process.poll() is None:
        rss_bytes, inaccessible = _sample_process_tree_rss(process.pid, psutil)
        if rss_bytes:
            sample_count += 1
            peak_rss = max(peak_rss, rss_bytes)
        inaccessible_samples += inaccessible
        if time.perf_counter() >= deadline:
            _terminate_process_tree(process.pid, process, psutil)
            stdout, stderr = process.communicate()
            raise BenchmarkError(
                f"FUSE scan exceeded {timeout_seconds} seconds; "
                f"stdout={stdout[-500:]!r}, stderr={stderr[-500:]!r}"
            )
        time.sleep(sample_interval_seconds)

    stdout, stderr = process.communicate()
    elapsed = time.perf_counter() - started
    if process.returncode != 0:
        raise BenchmarkError(
            f"FUSE exited with status {process.returncode}; stderr={stderr[-1000:]!r}"
        )
    if not report_path.is_file():
        raise BenchmarkError("FUSE completed without writing its JSON report")

    report = json.loads(report_path.read_text(encoding="utf-8"))
    summary = report.get("summary")
    coverage = report.get("coverage")
    tool = report.get("tool")
    if (
        not isinstance(summary, dict)
        or not isinstance(coverage, dict)
        or not isinstance(tool, dict)
    ):
        raise BenchmarkError("FUSE report is missing summary, coverage, or tool metadata")
    if tool.get("version") != __version__:
        raise BenchmarkError("the benchmark runner and scanned FUSE versions do not match")
    if (
        summary.get("analysis_performed") is not True
        or coverage.get("discovery_complete") is not True
    ):
        raise BenchmarkError("FUSE did not complete analysis and discovery")
    if summary.get("files_scanned") != expected_workload.file_count:
        raise BenchmarkError("FUSE scanned a different number of files than the workload contains")
    if summary.get("source_bytes_read") != expected_workload.source_bytes:
        raise BenchmarkError(
            "FUSE read a different number of source bytes than the workload contains"
        )
    if summary.get("finding_count") != 0:
        raise BenchmarkError("the benign synthetic workload produced unexpected findings")

    completed_native_rules = tuple(
        sorted(
            item["name"]
            for item in coverage.get("analyzers", [])
            if isinstance(item, dict)
            and isinstance(item.get("name"), str)
            and item["name"].startswith("native-rule:")
            and item.get("status") == "completed"
        )
    )
    return ScanObservation(
        wall_time_seconds=elapsed,
        sampled_process_tree_rss_bytes=peak_rss,
        rss_sample_count=sample_count,
        inaccessible_process_samples=inaccessible_samples,
        files_scanned=summary["files_scanned"],
        source_bytes_read=summary["source_bytes_read"],
        finding_count=summary["finding_count"],
        completed_native_rules=completed_native_rules,
    )


def _git_revision() -> tuple[str | None, bool | None]:
    try:
        revision = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=ROOT,
            check=True,
            capture_output=True,
            text=True,
            encoding="utf-8",
        ).stdout.strip()
        status = subprocess.run(
            ["git", "status", "--porcelain"],
            cwd=ROOT,
            check=True,
            capture_output=True,
            text=True,
            encoding="utf-8",
        ).stdout
    except (OSError, subprocess.CalledProcessError):
        return None, None
    return revision, bool(status.strip())


def _median_absolute_deviation(values: list[float]) -> float:
    center = statistics.median(values)
    return statistics.median(abs(value - center) for value in values)


def run_benchmark(
    *,
    file_count: int = 128,
    warmups: int = 1,
    repetitions: int = 5,
    sample_interval_ms: int = 10,
    timeout_seconds: int = 120,
) -> dict[str, Any]:
    if not 0 <= warmups <= 10:
        raise ValueError("warmups must be between 0 and 10")
    if not 1 <= repetitions <= 30:
        raise ValueError("repetitions must be between 1 and 30")
    if not 1 <= sample_interval_ms <= 1000:
        raise ValueError("sample_interval_ms must be between 1 and 1000")
    if not 1 <= timeout_seconds <= 1800:
        raise ValueError("timeout_seconds must be between 1 and 1800")

    try:
        import psutil
    except ImportError as error:
        raise BenchmarkError(
            "psutil is required for process-tree RSS sampling; install with "
            '`python -m pip install -e ".[dev]"`.'
        ) from error

    revision, dirty = _git_revision()
    with tempfile.TemporaryDirectory(prefix="fuse-benchmark-") as temporary:
        workspace = Path(temporary)
        target = workspace / "synthetic-embedded-project"
        report_path = workspace / "scan-report.json"
        workload = create_synthetic_project(target, file_count)
        observations: list[ScanObservation] = []

        for index in range(warmups + repetitions):
            observation = _run_scan(
                target,
                report_path,
                workload,
                sample_interval_seconds=sample_interval_ms / 1000,
                timeout_seconds=timeout_seconds,
                psutil=psutil,
            )
            if index >= warmups:
                observations.append(observation)

    durations = [item.wall_time_seconds for item in observations]
    rss_samples = [item.sampled_process_tree_rss_bytes for item in observations]
    median_duration = statistics.median(durations)
    processor = platform.processor().strip() or None
    try:
        total_memory_bytes = psutil.virtual_memory().total
    except psutil.Error:
        total_memory_bytes = None

    return {
        "schema_version": "1.0",
        "benchmark": "fuse-synthetic-project-scan",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "tool": {"name": "FUSE", "version": __version__},
        "source_revision": {"commit": revision, "working_tree_dirty": dirty},
        "environment": {
            "python_version": platform.python_version(),
            "operating_system": platform.system(),
            "os_release": platform.release(),
            "os_version": platform.version(),
            "machine": platform.machine(),
            "processor": processor,
            "psutil_version": psutil.__version__,
            "logical_cpu_count": psutil.cpu_count(logical=True),
            "total_memory_bytes": total_memory_bytes,
        },
        "input": {
            "profile": "generic",
            "description": (
                "Deterministically generated C source files. The first file contains "
                "comment-only prefilter probes and should produce no findings."
            ),
            "files": workload.file_count,
            "source_bytes": workload.source_bytes,
            "sha256": workload.sha256,
        },
        "configuration": {
            "warmups": warmups,
            "repetitions": repetitions,
            "sample_interval_ms": sample_interval_ms,
            "timeout_seconds": timeout_seconds,
            "scanner_options": [
                "--profile generic",
                "--target-label benchmark/synthetic",
                "--no-network",
                "--no-sbom",
                "--no-vulnerabilities",
                "--no-firmware",
                "--no-git-history",
                "--format json",
                "--output <temporary-report-path>",
            ],
            "network_enabled": False,
            "external_analyzers_enabled": False,
            "native_rules_enabled": True,
        },
        "measurements": {
            "wall_time_seconds": {
                "samples": [round(value, 6) for value in durations],
                "median": round(median_duration, 6),
                "minimum": round(min(durations), 6),
                "maximum": round(max(durations), 6),
                "median_absolute_deviation": round(_median_absolute_deviation(durations), 6),
            },
            "files_scanned": observations[-1].files_scanned,
            "source_bytes_read": observations[-1].source_bytes_read,
            "finding_count": observations[-1].finding_count,
            "completed_native_rules": list(observations[-1].completed_native_rules),
            "files_per_second_at_median": round(
                observations[-1].files_scanned / median_duration, 3
            ),
            "mebibytes_per_second_at_median": round(
                observations[-1].source_bytes_read / (1024 * 1024) / median_duration, 6
            ),
            "sampled_process_tree_rss_bytes": {
                "samples": rss_samples,
                "median": round(statistics.median(rss_samples)),
                "maximum": max(rss_samples),
                "process_samples_per_run": [item.rss_sample_count for item in observations],
                "inaccessible_process_samples": sum(
                    item.inaccessible_process_samples for item in observations
                ),
                "sampling_complete": all(
                    item.rss_sample_count > 0 and item.inaccessible_process_samples == 0
                    for item in observations
                ),
            },
        },
        "scope_limitations": [
            "The input is synthetic and does not represent a typical embedded repository.",
            "Wall time includes a fresh Python CLI process for each scan.",
            "Process-tree RSS is the sum of sampled per-process RSS values; shared pages can be counted more than once.",
            "RSS sampling can miss short peaks and does not include filesystem cache or other system memory.",
            "This benchmark is descriptive and does not define a performance pass threshold.",
        ],
    }


def _render_text(result: dict[str, Any]) -> str:
    measurements = result["measurements"]
    timings = measurements["wall_time_seconds"]
    memory = measurements["sampled_process_tree_rss_bytes"]
    lines = [
        "FUSE synthetic project scan benchmark",
        f"Input: {measurements['files_scanned']} source files, "
        f"{measurements['source_bytes_read']} source bytes, {measurements['finding_count']} findings",
        f"Wall time: median {timings['median']:.6f}s, "
        f"range {timings['minimum']:.6f}s to {timings['maximum']:.6f}s",
        f"Throughput: {measurements['files_per_second_at_median']:.3f} files/s, "
        f"{measurements['mebibytes_per_second_at_median']:.6f} MiB/s",
        f"Maximum sampled process-tree RSS: {memory['maximum']} bytes",
        "Synthetic benchmark only. Results depend on the recorded environment.",
    ]
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--files", type=int, default=128, help="number of generated C source files")
    parser.add_argument("--warmups", type=int, default=1, help="scans discarded before measurement")
    parser.add_argument("--repetitions", type=int, default=5, help="measured scan count")
    parser.add_argument(
        "--sample-interval-ms", type=int, default=10, help="process RSS sampling interval"
    )
    parser.add_argument("--timeout-seconds", type=int, default=120, help="per-scan timeout")
    parser.add_argument("--output", type=Path, help="write machine-readable JSON to this path")
    args = parser.parse_args(argv)

    try:
        result = run_benchmark(
            file_count=args.files,
            warmups=args.warmups,
            repetitions=args.repetitions,
            sample_interval_ms=args.sample_interval_ms,
            timeout_seconds=args.timeout_seconds,
        )
    except (BenchmarkError, OSError, ValueError, json.JSONDecodeError) as error:
        print(f"scan benchmark failed: {error}", file=sys.stderr)
        return 2

    rendered_json = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.output is not None:
        output_path = args.output.expanduser()
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(rendered_json, encoding="utf-8")
        print(_render_text(result))
        print(f"JSON report written to {output_path}")
    else:
        print(rendered_json)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
