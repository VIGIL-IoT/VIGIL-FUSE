from __future__ import annotations

import ctypes
import hashlib
import os
import signal
import shutil
import subprocess
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import IO

from .model import AnalysisArtifact, AnalyzerStatus, Finding

ANALYZER_TIMEOUT_SECONDS = 180
TOOL_VERSION_TIMEOUT_SECONDS = 5
MAX_ANALYZER_OUTPUT_BYTES = 10 * 1024 * 1024
MAX_SBOM_BYTES = 50 * 1024 * 1024
MAX_BINWALK_REPORT_BYTES = 1024 * 1024


@dataclass(frozen=True)
class AdapterResult:
    status: AnalyzerStatus
    findings: tuple[Finding, ...] = ()
    artifacts: tuple[AnalysisArtifact, ...] = ()


def inspect_tools() -> tuple[tuple[str, str | None, str | None], ...]:
    """Return optional tool availability, executable path, and version for doctor."""
    tools = []
    for name, executable_name in (
        ("Syft", "syft"),
        ("OSV-Scanner", "osv-scanner"),
        ("Binwalk", "binwalk"),
        ("Gitleaks", "gitleaks"),
    ):
        executable = shutil.which(executable_name)
        version = _tool_version(executable) if executable else None
        tools.append((name, executable, version))
    return tuple(tools)


class AnalyzerOutputLimitError(RuntimeError):
    """Raised when a child process exceeds FUSE's combined diagnostic limit."""


def _windows_system_directory() -> Path | None:
    """Resolve the actual Windows system directory without consulting PATH."""
    if os.name != "nt":
        return None
    try:
        win_dll = getattr(ctypes, "WinDLL")
        kernel32 = win_dll("kernel32", use_last_error=True)
        get_system_directory = kernel32.GetSystemDirectoryW
        get_system_directory.argtypes = [ctypes.POINTER(ctypes.c_wchar), ctypes.c_uint]
        get_system_directory.restype = ctypes.c_uint
        buffer = ctypes.create_unicode_buffer(32768)
        length = get_system_directory(buffer, len(buffer))
    except (AttributeError, OSError, TypeError, ctypes.ArgumentError):
        return None
    if length == 0 or length >= len(buffer):
        return None
    return Path(buffer.value)


def _terminate_process_tree(process: subprocess.Popen[bytes]) -> None:
    """Best-effort termination of an analyzer and descendants it started."""
    if os.name == "nt":
        system_directory = _windows_system_directory()
        taskkill = system_directory / "taskkill.exe" if system_directory is not None else None
        if taskkill is not None and taskkill.is_file():
            try:
                completed = subprocess.run(
                    [str(taskkill), "/PID", str(process.pid), "/T", "/F"],
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=5,
                    check=False,
                    creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
                )
            except (OSError, subprocess.TimeoutExpired):
                pass
            else:
                if completed.returncode == 0:
                    return
        try:
            process.kill()
        except OSError:
            pass
        return

    kill_process_group = getattr(os, "killpg", None)
    kill_signal = getattr(signal, "SIGKILL", None)
    if kill_process_group is not None and kill_signal is not None:
        try:
            kill_process_group(process.pid, kill_signal)
            return
        except OSError:
            pass
    try:
        process.kill()
    except OSError:
        pass


def _artifact(path: Path, media_type: str, output_dir: Path) -> AnalysisArtifact:
    data = path.read_bytes()
    return AnalysisArtifact(
        path=path.relative_to(output_dir).as_posix(),
        media_type=media_type,
        sha256=hashlib.sha256(data).hexdigest(),
    )


def _artifact_destination(output_dir: Path, filename: str) -> Path:
    path = output_dir / filename
    if path.is_symlink():
        raise OSError(f"Refusing to write analyzer output through symbolic link: {path.name}")
    if path.exists() and not path.is_file():
        raise OSError(f"Analyzer output path is not a regular file: {path.name}")
    return path


def _run(
    command: list[str], *, timeout: int = ANALYZER_TIMEOUT_SECONDS, cwd: Path | None = None
) -> subprocess.CompletedProcess[str]:
    if os.name == "nt":
        process = subprocess.Popen(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=cwd,
        )
    else:
        process = subprocess.Popen(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=cwd,
            start_new_session=True,
        )
    captured = {"stdout": bytearray(), "stderr": bytearray()}
    total = 0
    lock = threading.Lock()
    exceeded = threading.Event()

    def drain(name: str, stream: IO[bytes]) -> None:
        nonlocal total
        while True:
            chunk = stream.read(64 * 1024)
            if not chunk:
                return
            terminate_tree = False
            with lock:
                remaining = max(0, MAX_ANALYZER_OUTPUT_BYTES - total)
                keep = min(len(chunk), remaining)
                captured[name].extend(chunk[:keep])
                total += len(chunk)
                if len(chunk) > remaining and not exceeded.is_set():
                    exceeded.set()
                    terminate_tree = True
            if terminate_tree:
                _terminate_process_tree(process)

    assert process.stdout is not None and process.stderr is not None
    readers = [
        threading.Thread(target=drain, args=("stdout", process.stdout), daemon=True),
        threading.Thread(target=drain, args=("stderr", process.stderr), daemon=True),
    ]
    for reader in readers:
        reader.start()
    try:
        returncode = process.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        _terminate_process_tree(process)
        process.wait()
        for reader in readers:
            reader.join()
        process.stdout.close()
        process.stderr.close()
        raise
    for reader in readers:
        reader.join()
    process.stdout.close()
    process.stderr.close()
    if exceeded.is_set():
        raise AnalyzerOutputLimitError("Analyzer output exceeded the configured limit")
    return subprocess.CompletedProcess(
        command,
        returncode,
        stdout=bytes(captured["stdout"]).decode("utf-8", errors="replace"),
        stderr=bytes(captured["stderr"]).decode("utf-8", errors="replace"),
    )


def _tool_version(executable: str) -> str | None:
    try:
        completed = _run([executable, "--version"], timeout=TOOL_VERSION_TIMEOUT_SECONDS)
    except (OSError, subprocess.TimeoutExpired, AnalyzerOutputLimitError):
        return None
    if completed.returncode != 0:
        return None
    lines = (completed.stdout or completed.stderr).strip().splitlines()
    return lines[0][:120] if lines else None


def _output_exclude_pattern(target: Path, output_dir: Path) -> str | None:
    if not target.is_dir():
        return None
    try:
        relative = output_dir.resolve().relative_to(target.resolve())
    except ValueError:
        return None
    if relative == Path("."):
        return None
    return relative.as_posix().rstrip("/") + "/**"
