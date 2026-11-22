"""Bounded subprocess boundary and report helpers for the desktop interface."""

from __future__ import annotations

import json
import os
import shutil
import signal
import subprocess
import sys
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Any

PROFILES = frozenset({"generic", "esp-idf", "zephyr", "embedded-linux", "rtl"})
REPORT_FILES = (
    "findings.json",
    "findings.txt",
    "findings.sarif",
    "provenance.json",
    "fuse-citation.txt",
    "fuse-report.pdf",
)
MAX_REPORT_BYTES = 50 * 1024 * 1024


@dataclass(frozen=True)
class ScanOptions:
    target: Path
    profile: str = "generic"
    network: bool = False
    dependencies: bool = False

    def arguments(self) -> list[str]:
        try:
            target = self.target.expanduser().resolve(strict=True)
        except OSError as error:
            raise ValueError("Select an existing project directory") from error
        if not target.is_dir():
            raise ValueError("Select a project directory")
        if self.profile not in PROFILES:
            raise ValueError("Unknown scan profile")
        args = [
            str(target),
            "--profile",
            self.profile,
            "--no-firmware",
            "--no-ghidra",
            "--no-git-history",
        ]
        args += (
            ["--sbom", "--vulnerabilities"]
            if self.dependencies
            else ["--no-sbom", "--no-vulnerabilities"]
        )
        if not self.network:
            args.append("--no-network")
        return args


@dataclass(frozen=True)
class CommandResult:
    returncode: int
    stdout: str
    stderr: str
    cancelled: bool


class Runner:
    """Run only the installed FUSE module, outside the target checkout."""

    def __init__(self, workdir: Path) -> None:
        self.workdir = workdir
        self._process: subprocess.Popen[str] | None = None
        self._lock = threading.Lock()
        self._cancelled = False

    def prepare(self) -> None:
        with self._lock:
            self._cancelled = False

    def run(self, args: list[str]) -> CommandResult:
        env = os.environ.copy()
        # Anchor package resolution to this FUSE installation, not the target directory.
        env["PYTHONPATH"] = str(Path(__file__).resolve().parents[2])
        env["PYTHONNOUSERSITE"] = "1"
        kwargs: dict[str, Any] = {}
        if os.name == "nt":
            kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP
        else:
            kwargs["start_new_session"] = True
        with self._lock:
            if self._cancelled:
                return CommandResult(-1, "", "Cancelled before launch.", True)
            self._process = subprocess.Popen(
                [sys.executable, "-m", "vigil_fuse", *args],
                cwd=self.workdir,
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding="utf-8",
                errors="replace",
                **kwargs,
            )
            process = self._process
        try:
            stdout, stderr = process.communicate(timeout=1800)
        except subprocess.TimeoutExpired:
            self.cancel()
            stdout, stderr = process.communicate()
            stderr += "\nFUSE exceeded the desktop process time limit."
        finally:
            with self._lock:
                self._process = None
                cancelled = self._cancelled
        return CommandResult(process.returncode, stdout, stderr, cancelled)

    def cancel(self) -> bool:
        with self._lock:
            process = self._process
            self._cancelled = True
            if process is None or process.poll() is not None:
                return True
            if os.name == "nt":
                subprocess.run(
                    ["taskkill", "/PID", str(process.pid), "/T", "/F"],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    check=False,
                )
            else:
                try:
                    os.kill(-process.pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass
            return True


def load_report(path: Path) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_REPORT_BYTES:
        raise ValueError("Report must be a regular JSON file no larger than 50 MiB")
    data = json.loads(path.read_text(encoding="utf-8"))
    if (
        not isinstance(data, dict)
        or not isinstance(data.get("findings"), list)
        or not isinstance(data.get("coverage"), dict)
    ):
        raise ValueError("Not a supported FUSE findings report")
    return data


def filter_findings(
    findings: list[dict[str, Any]], text: str, field: str, value: str
) -> list[dict[str, Any]]:
    needle = text.casefold().strip()
    result = []
    for finding in findings:
        location = finding.get("location") or {}
        searchable = " ".join(
            str(finding.get(key, "")) for key in ("rule_id", "title", "analyzer", "category")
        )
        searchable += " " + str(location.get("file", ""))
        selected = str(finding.get(field, "unknown")).casefold()
        if (not needle or needle in searchable.casefold()) and (
            value == "all" or selected == value.casefold()
        ):
            result.append(finding)
    return result


def paginate_findings(
    findings: list[dict[str, Any]], page: int, page_size: int = 250
) -> tuple[list[dict[str, Any]], int, int]:
    if page_size < 1:
        raise ValueError("Page size must be positive")
    max_page = max(0, (len(findings) - 1) // page_size)
    current_page = min(max(0, page), max_page)
    start = current_page * page_size
    return findings[start : start + page_size], current_page, max_page


def export_reports(source: Path, destination: Path) -> list[Path]:
    if not destination.is_dir():
        raise ValueError("Select an existing export directory")
    files = [source / name for name in REPORT_FILES if (source / name).is_file()]
    if any(item.is_symlink() for item in files):
        raise ValueError("Refusing to export a symbolic-link report")
    if any(item.stat().st_size > MAX_REPORT_BYTES for item in files):
        raise ValueError("A report exceeds the 50 MiB export limit")
    if not files:
        raise ValueError("There are no reports to export")
    if any(
        (destination / item.name).exists() or (destination / item.name).is_symlink()
        for item in files
    ):
        raise FileExistsError(
            "Export destination already contains a report; choose an empty directory"
        )
    for item in files:
        shutil.copyfile(item, destination / item.name)
    return [destination / item.name for item in files]


def prepare_export_metadata(output: Path, report: dict[str, Any]) -> None:
    provenance = report.get("provenance")
    if isinstance(provenance, dict):
        (output / "provenance.json").write_text(
            json.dumps(provenance, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
        )
    tool = report.get("tool")
    version = tool.get("version", "unknown") if isinstance(tool, dict) else "unknown"
    (output / "fuse-citation.txt").write_text(
        f"FUSE: Firmware & Unified Security Engine, version {version}.\n"
        "https://github.com/VIGIL-IoT/VIGIL-FUSE\n"
        "For authorship and revision details, see the repository CITATION.cff.\n",
        encoding="utf-8",
    )
