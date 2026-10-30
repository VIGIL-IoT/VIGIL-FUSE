"""Run a local positive and clean-control check for FUSE's Binwalk adapter."""

from __future__ import annotations

import argparse
import gzip
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
RUN_TIMEOUT_SECONDS = 240
SIGNATURE_MARKER = "gzip"


def run(
    command: list[str],
    *,
    cwd: Path | None = None,
    env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        cwd=cwd,
        env=env,
        capture_output=True,
        check=False,
        text=True,
        timeout=RUN_TIMEOUT_SECONDS,
    )


def analyzer_status(report: dict[str, Any]) -> dict[str, Any]:
    coverage = report.get("coverage")
    analyzers = coverage.get("analyzers", []) if isinstance(coverage, dict) else []
    if not isinstance(analyzers, list):
        raise RuntimeError("FUSE report did not contain analyzer coverage records.")
    status = next(
        (item for item in analyzers if isinstance(item, dict) and item.get("name") == "binwalk"),
        None,
    )
    if not isinstance(status, dict):
        raise RuntimeError("FUSE report did not contain Binwalk coverage status.")
    return status


def scan_case(
    *,
    label: str,
    positive: bool,
    expected_version: str | None,
    root: Path,
    env: dict[str, str],
) -> str:
    target = root / f"{label}-firmware.bin"
    output = root / f"{label}-reports"
    payload = b"FUSE synthetic gzip signature fixture"
    data = gzip.compress(payload, mtime=0) if positive else payload
    target.write_bytes(data)

    result = run(
        [
            sys.executable,
            "-m",
            "vigil_fuse",
            "scan",
            str(target),
            "--firmware",
            "--no-sbom",
            "--no-vulnerabilities",
            "--format",
            "json",
            "--output-dir",
            str(output),
        ],
        cwd=target.parent,
        env=env,
    )
    if result.returncode != 0:
        raise RuntimeError(f"FUSE {label} scan failed with exit status {result.returncode}.")

    report_path = output / "findings.json"
    identification_path = output / "firmware-identification.txt"
    if not report_path.is_file() or not identification_path.is_file():
        raise RuntimeError(f"FUSE {label} scan did not produce expected firmware reports.")
    try:
        report = json.loads(report_path.read_text(encoding="utf-8"))
        identification = identification_path.read_text(encoding="utf-8")
    except (OSError, json.JSONDecodeError) as error:
        raise RuntimeError(f"FUSE {label} scan produced unreadable reports.") from error
    if not isinstance(report, dict):
        raise RuntimeError(f"FUSE {label} scan produced an unexpected JSON structure.")

    status = analyzer_status(report)
    if status.get("status") != "completed":
        raise RuntimeError(f"FUSE {label} scan did not complete Binwalk identification.")
    version = status.get("version")
    if not isinstance(version, str) or not version:
        raise RuntimeError(f"FUSE {label} scan did not record the Binwalk version.")
    if expected_version and expected_version not in version:
        raise RuntimeError("FUSE reported a Binwalk version different from the expected value.")

    marker_found = SIGNATURE_MARKER in identification.casefold()
    if marker_found != positive:
        expectation = "present" if positive else "absent"
        raise RuntimeError(
            f"The gzip signature marker was expected to be {expectation} in {label} output."
        )
    extraction_path = root / f"_{target.name}.extracted"
    if extraction_path.exists():
        raise RuntimeError(
            "Binwalk created an extraction directory during identification-only scanning."
        )
    return version


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--expected-version", help="require this Binwalk version substring")
    args = parser.parse_args()
    if shutil.which("binwalk") is None:
        parser.error("Binwalk must be available on PATH")

    env = os.environ.copy()
    source_path = str(ROOT / "src")
    env["PYTHONPATH"] = os.pathsep.join(
        part for part in (source_path, env.get("PYTHONPATH", "")) if part
    )

    with tempfile.TemporaryDirectory(prefix="fuse-binwalk-adapter-e2e-") as temporary:
        root = Path(temporary)
        positive_version = scan_case(
            label="positive",
            positive=True,
            expected_version=args.expected_version,
            root=root,
            env=env,
        )
        clean_version = scan_case(
            label="clean",
            positive=False,
            expected_version=args.expected_version,
            root=root,
            env=env,
        )

    if positive_version != clean_version:
        raise RuntimeError("FUSE reported inconsistent Binwalk versions across the two controls.")
    print(
        f"Binwalk adapter smoke check passed: {positive_version}; "
        "gzip positive detected, clean control clear, no extraction."
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, RuntimeError, subprocess.TimeoutExpired) as error:
        raise SystemExit(f"Binwalk adapter smoke check failed: {error}") from error
