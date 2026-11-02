"""Measure one controlled Ghidra adapter run without adding a timing gate."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import subprocess
import sys
import tempfile
import threading
import time
from typing import Any
from unittest.mock import patch

import psutil

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "src"))

from scripts.benchmark_process import sample_process_tree_rss  # noqa: E402
from vigil_fuse import ghidra_analyzer  # noqa: E402
from vigil_fuse.analyzer_runtime import _run  # noqa: E402

SAMPLE_INTERVAL_SECONDS = 0.02


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path, help="one controlled ELF, PE, or Mach-O sample")
    parser.add_argument("--ghidra-install-dir", type=Path, required=True)
    parser.add_argument("--timeout-seconds", type=int, default=300)
    parser.add_argument("--output", type=Path, help="write the JSON record to this path")
    return parser.parse_args()


def _cold_start_probe(probe: ghidra_analyzer.GhidraProbe) -> float:
    if probe.install_dir is None or probe.java_executable is None:
        raise RuntimeError("Validated Ghidra installation details are missing.")
    utility_jar = probe.install_dir / "Ghidra" / "Framework" / "Utility" / "lib" / "Utility.jar"
    with tempfile.TemporaryDirectory(prefix="fuse-ghidra-startup-") as temporary:
        command = [
            str(probe.java_executable),
            "-Xmx2G",
            "-Djava.awt.headless=true",
            "-Djava.system.class.loader=ghidra.GhidraClassLoader",
            f"-Dghidra.install.dir={str(probe.install_dir).replace(chr(92), '/')}",
            "-cp",
            str(utility_jar).replace("\\", "/"),
            "ghidra.Ghidra",
            "ghidra.app.util.headless.AnalyzeHeadless",
            "-help",
        ]
        started = time.perf_counter()
        result = _run(
            command,
            timeout=120,
            cwd=Path(temporary),
            output_limit_bytes=1024 * 1024,
            environment_exclude=getattr(ghidra_analyzer, "_JAVA_ENVIRONMENT_OVERRIDES"),
        )
        elapsed = time.perf_counter() - started
    output = result.stdout + "\n" + result.stderr
    if "Headless Analyzer Usage" not in output:
        raise RuntimeError("Ghidra Headless Analyzer did not complete its startup probe.")
    return elapsed


def _sample_until_stopped(
    stop: threading.Event,
    samples: list[tuple[int, int]],
) -> None:
    while not stop.is_set():
        samples.append(sample_process_tree_rss(os.getpid(), psutil))
        stop.wait(SAMPLE_INTERVAL_SECONDS)


def _source_revision() -> dict[str, str | bool | None]:
    repository_root = Path(__file__).resolve().parents[1]
    try:
        revision = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=repository_root,
            check=True,
            capture_output=True,
            text=True,
            timeout=5,
        ).stdout.strip()
        status = subprocess.run(
            ["git", "status", "--porcelain"],
            cwd=repository_root,
            check=True,
            capture_output=True,
            text=True,
            timeout=5,
        ).stdout
    except (OSError, subprocess.SubprocessError):
        return {"commit": None, "working_tree_dirty": None}
    if len(revision) not in {40, 64} or any(
        character not in "0123456789abcdef" for character in revision
    ):
        return {"commit": None, "working_tree_dirty": bool(status)}
    return {"commit": revision, "working_tree_dirty": bool(status)}


def main() -> int:
    args = _arguments()
    if args.binary.is_symlink() or not args.binary.is_file():
        raise SystemExit("binary must be a regular file and must not be a symbolic link")
    probe_started = time.perf_counter()
    probe = ghidra_analyzer.inspect_ghidra(args.ghidra_install_dir)
    discovery_seconds = time.perf_counter() - probe_started
    if probe.status != "available":
        raise SystemExit(f"Ghidra is not available: {probe.detail}")

    cold_start_seconds = _cold_start_probe(probe)
    samples: list[tuple[int, int]] = []
    stop = threading.Event()
    sampler = threading.Thread(
        target=_sample_until_stopped,
        args=(stop, samples),
        daemon=True,
    )
    headless_wall_seconds: float | None = None
    original_run = _run

    def timed_run(command: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        nonlocal headless_wall_seconds
        if len(command) > 1 and command[1] == "-version":
            return original_run(command, **kwargs)
        started = time.perf_counter()
        completed = original_run(command, **kwargs)
        headless_wall_seconds = time.perf_counter() - started
        return completed

    with tempfile.TemporaryDirectory(prefix="fuse-ghidra-benchmark-") as temporary:
        output_dir = Path(temporary) / "output"
        sampler.start()
        adapter_started = time.perf_counter()
        try:
            with patch.object(ghidra_analyzer, "_run", side_effect=timed_run):
                result = ghidra_analyzer.analyze_ghidra(
                    args.binary,
                    output_dir,
                    configured_install_dir=args.ghidra_install_dir,
                    timeout_seconds=args.timeout_seconds,
                )
        finally:
            adapter_wall_seconds = time.perf_counter() - adapter_started
            stop.set()
            sampler.join(timeout=2)

        artifact_path = output_dir / "ghidra-analysis.json"
        artifact_bytes = artifact_path.stat().st_size if artifact_path.is_file() else None
        try:
            input_size = args.binary.stat().st_size
            if input_size > ghidra_analyzer.GHIDRA_MAXIMUM_INPUT_BYTES:
                raise SystemExit("sample input exceeds the Ghidra input limit")
            digest = hashlib.sha256()
            with args.binary.open("rb") as stream:
                while block := stream.read(1024 * 1024):
                    digest.update(block)
            input_digest = digest.hexdigest()
        except OSError as error:
            raise SystemExit(
                f"could not describe the sample input: {type(error).__name__}"
            ) from error

        peak_rss = max((sample[0] for sample in samples), default=0)
        inaccessible = sum(sample[1] for sample in samples)
        payload = {
            "schema_version": "1.0",
            "benchmark": "fuse-ghidra-controlled-input",
            "generated_at_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "source_revision": _source_revision(),
            "method": "single controlled input; a fresh headless JVM process per measured run",
            "environment": {
                "os": platform.system(),
                "os_release": platform.release(),
                "architecture": platform.machine(),
                "python": platform.python_version(),
                "ghidra": probe.version,
                "java": probe.java_version,
            },
            "input": {
                "kind": "controlled local executable",
                "format": (
                    detected.format
                    if (detected := ghidra_analyzer.detect_binary_input(args.binary))
                    else "raw"
                ),
                "byte_size": input_size,
                "sha256": input_digest,
            },
            "measurements": {
                "cold_headless_startup_seconds": round(cold_start_seconds, 6),
                "ghidra_discovery_seconds": round(discovery_seconds, 6),
                "headless_process_wall_seconds": (
                    round(headless_wall_seconds, 6) if headless_wall_seconds is not None else None
                ),
                "adapter_wall_seconds": round(adapter_wall_seconds, 6),
                "sample_interval_seconds": SAMPLE_INTERVAL_SECONDS,
                "sampled_process_tree_peak_rss_bytes": peak_rss,
                "sampled_process_tree_inaccessible_samples": inaccessible,
                "sampled_process_tree_sample_count": len(samples),
                "artifact_bytes": artifact_bytes,
            },
            "result": {
                "status": result.status.status,
                "finding_count": len(result.findings),
                "rule_ids": sorted({item.rule_id for item in result.findings}),
            },
            "measurement_notes": [
                "The cold startup probe launches Ghidra Headless Analyzer with -help and records its class-loading and usage response.",
                "The headless process wall time includes import, automatic analysis, trusted script export, and Java shutdown. Ghidra does not expose a stable internal analysis timer through this adapter.",
                "Adapter wall time includes installation discovery, input staging and hashing, headless execution, validation, normalization, and artifact writing.",
                "Sampled RSS sums the benchmark Python process and visible descendants. It can miss short peaks and may double-count shared pages.",
                "This is one controlled sample on one environment. It has no performance threshold and does not change default FUSE scan timing claims.",
            ],
        }

    text = json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    if args.output:
        destination = args.output.expanduser()
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(text, encoding="utf-8")
    else:
        sys.stdout.write(text)
    return 0 if result.status.status == "completed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
