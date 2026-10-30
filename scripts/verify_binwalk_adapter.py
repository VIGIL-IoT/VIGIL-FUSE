"""Run a local positive and clean-control check for FUSE's Binwalk adapter."""

from __future__ import annotations

import argparse
import gzip
import json
import lzma
import os
import shutil
import struct
import subprocess
import sys
import tempfile
import zlib
from dataclasses import dataclass
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
RUN_TIMEOUT_SECONDS = 240
FIRMWARE_PREFIX = b"FUSE synthetic container\x00"
PAYLOAD = b"FUSE synthetic firmware signature fixture"


@dataclass(frozen=True)
class SignatureCase:
    label: str
    data: bytes
    marker: str
    detected: bool


def _make_uimage(payload: bytes) -> bytes:
    """Build a minimal CRC-valid U-Boot legacy image without executing it."""
    name = b"FUSE synthetic image".ljust(32, b"\x00")
    header = bytearray(
        struct.pack(
            ">7I4B32s",
            0x27051956,
            0,
            0,
            len(payload),
            0x80000000,
            0x80000000,
            zlib.crc32(payload),
            5,
            2,
            2,
            0,
            name,
        )
    )
    struct.pack_into(">I", header, 4, zlib.crc32(header))
    return bytes(header) + payload


def signature_cases() -> tuple[SignatureCase, ...]:
    """Return deterministic positive, clean, and malformed firmware controls."""
    xz_data = lzma.compress(PAYLOAD, format=lzma.FORMAT_XZ)
    invalid_uimage = struct.pack(">I", 0x27051956) + bytes(60) + PAYLOAD
    return (
        SignatureCase(
            "gzip-positive",
            FIRMWARE_PREFIX + gzip.compress(PAYLOAD, mtime=0),
            "gzip",
            True,
        ),
        SignatureCase(
            "xz-positive",
            FIRMWARE_PREFIX + xz_data,
            "xz compressed data",
            True,
        ),
        SignatureCase(
            "uimage-positive",
            FIRMWARE_PREFIX + _make_uimage(PAYLOAD),
            "uimage firmware image",
            True,
        ),
        SignatureCase("clean", PAYLOAD, "no known signature", False),
        SignatureCase(
            "invalid-uimage-control",
            FIRMWARE_PREFIX + invalid_uimage,
            "uimage firmware image",
            False,
        ),
    )


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


def configure_binwalk_environment(
    executable: Path | None,
    env: dict[str, str],
) -> Path | None:
    """Make an explicitly supplied Binwalk executable discoverable by FUSE."""
    if executable is None:
        discovered = shutil.which("binwalk", path=env.get("PATH"))
        return Path(discovered) if discovered else None

    resolved = executable.expanduser().resolve()
    if not resolved.is_file():
        raise FileNotFoundError("The supplied Binwalk executable does not exist.")
    env["PATH"] = os.pathsep.join(
        part for part in (str(resolved.parent), env.get("PATH", "")) if part
    )
    return resolved


def scan_case(
    case: SignatureCase,
    *,
    expected_version: str | None,
    root: Path,
    env: dict[str, str],
) -> str:
    target = root / f"{case.label}-firmware.bin"
    output = root / f"{case.label}-reports"
    target.write_bytes(case.data)

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
        raise RuntimeError(f"FUSE {case.label} scan failed with exit status {result.returncode}.")

    report_path = output / "findings.json"
    identification_path = output / "firmware-identification.txt"
    if not report_path.is_file() or not identification_path.is_file():
        raise RuntimeError(f"FUSE {case.label} scan did not produce expected firmware reports.")
    try:
        report = json.loads(report_path.read_text(encoding="utf-8"))
        identification = identification_path.read_text(encoding="utf-8")
    except (OSError, json.JSONDecodeError) as error:
        raise RuntimeError(f"FUSE {case.label} scan produced unreadable reports.") from error
    if not isinstance(report, dict):
        raise RuntimeError(f"FUSE {case.label} scan produced an unexpected JSON structure.")

    status = analyzer_status(report)
    if status.get("status") != "completed":
        raise RuntimeError(f"FUSE {case.label} scan did not complete Binwalk identification.")
    version = status.get("version")
    if not isinstance(version, str) or not version:
        raise RuntimeError(f"FUSE {case.label} scan did not record the Binwalk version.")
    if expected_version and expected_version not in version:
        raise RuntimeError("FUSE reported a Binwalk version different from the expected value.")

    marker_found = case.marker in identification.casefold()
    if marker_found != case.detected:
        expectation = "present" if case.detected else "absent"
        raise RuntimeError(
            f"The {case.marker} signature marker was expected to be {expectation} "
            f"in {case.label} output."
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
    parser.add_argument(
        "--binwalk-executable",
        type=Path,
        help="use this Binwalk executable and add its directory to the scan PATH",
    )
    args = parser.parse_args()
    env = os.environ.copy()
    try:
        executable = configure_binwalk_environment(args.binwalk_executable, env)
    except FileNotFoundError as error:
        parser.error(str(error))
    if executable is None:
        parser.error("Binwalk must be available on PATH")

    source_path = str(ROOT / "src")
    env["PYTHONPATH"] = os.pathsep.join(
        part for part in (source_path, env.get("PYTHONPATH", "")) if part
    )

    with tempfile.TemporaryDirectory(prefix="fuse-binwalk-adapter-e2e-") as temporary:
        root = Path(temporary)
        versions = [
            scan_case(
                case,
                expected_version=args.expected_version,
                root=root,
                env=env,
            )
            for case in signature_cases()
        ]

    if len(set(versions)) != 1:
        raise RuntimeError(
            "FUSE reported inconsistent Binwalk versions across the fixture controls."
        )
    print(
        f"Binwalk adapter smoke check passed: {versions[0]}; "
        "gzip, XZ, and U-Boot uImage signatures detected; clean and invalid-uImage "
        "controls clear; no extraction."
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, RuntimeError, subprocess.TimeoutExpired) as error:
        raise SystemExit(f"Binwalk adapter smoke check failed: {error}") from error
