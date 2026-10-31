from __future__ import annotations

import ctypes
import hashlib
import os
import re
import signal
import shutil
import select
import subprocess
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import IO, Any
from ctypes import wintypes

from .model import AnalysisArtifact, AnalyzerStatus, Finding

ANALYZER_TIMEOUT_SECONDS = 180
TOOL_VERSION_TIMEOUT_SECONDS = 5
MAX_ANALYZER_OUTPUT_BYTES = 10 * 1024 * 1024
MAX_SBOM_BYTES = 50 * 1024 * 1024
MAX_BINWALK_REPORT_BYTES = 1024 * 1024
_SENSITIVE_ENVIRONMENT_NAME = re.compile(
    r"(?:^|_)(?:ACCESS[_-]?KEY(?:_ID)?|API[_-]?KEY|AUTH(?:ORIZATION)?|BEARER|"
    r"CREDENTIALS?|KUBECONFIG|NETRC|PASS(?:WORD|WD)?|PRIVATE[_-]?KEY|SECRET|TOKEN)(?:_|$)",
    re.IGNORECASE,
)
_ANALYZER_ENV_ALLOWLIST = "FUSE_ANALYZER_ENV_ALLOWLIST"
_WINDOWS_JOB_OBJECT_EXTENDED_LIMIT_INFORMATION = 9
_WINDOWS_JOB_OBJECT_LIMIT_KILL_ON_CLOSE = 0x00002000
_WINDOWS_THREAD_SNAPSHOT_FLAG = 0x00000004
_WINDOWS_THREAD_SUSPEND_RESUME = 0x0002
_WINDOWS_RESUME_THREAD_FAILED = 0xFFFFFFFF


class _WindowsBasicLimitInformation(ctypes.Structure):
    _fields_ = [
        ("PerProcessUserTimeLimit", ctypes.c_longlong),
        ("PerJobUserTimeLimit", ctypes.c_longlong),
        ("LimitFlags", wintypes.DWORD),
        ("MinimumWorkingSetSize", ctypes.c_size_t),
        ("MaximumWorkingSetSize", ctypes.c_size_t),
        ("ActiveProcessLimit", wintypes.DWORD),
        ("Affinity", ctypes.c_size_t),
        ("PriorityClass", wintypes.DWORD),
        ("SchedulingClass", wintypes.DWORD),
    ]


class _WindowsIoCounters(ctypes.Structure):
    _fields_ = [
        ("ReadOperationCount", ctypes.c_ulonglong),
        ("WriteOperationCount", ctypes.c_ulonglong),
        ("OtherOperationCount", ctypes.c_ulonglong),
        ("ReadTransferCount", ctypes.c_ulonglong),
        ("WriteTransferCount", ctypes.c_ulonglong),
        ("OtherTransferCount", ctypes.c_ulonglong),
    ]


class _WindowsExtendedLimitInformation(ctypes.Structure):
    _fields_ = [
        ("BasicLimitInformation", _WindowsBasicLimitInformation),
        ("IoInfo", _WindowsIoCounters),
        ("ProcessMemoryLimit", ctypes.c_size_t),
        ("JobMemoryLimit", ctypes.c_size_t),
        ("PeakProcessMemoryUsed", ctypes.c_size_t),
        ("PeakJobMemoryUsed", ctypes.c_size_t),
    ]


class _WindowsThreadEntry32(ctypes.Structure):
    _fields_ = [
        ("dwSize", wintypes.DWORD),
        ("cntUsage", wintypes.DWORD),
        ("th32ThreadID", wintypes.DWORD),
        ("th32OwnerProcessID", wintypes.DWORD),
        ("tpBasePri", wintypes.LONG),
        ("tpDeltaPri", wintypes.LONG),
        ("dwFlags", wintypes.DWORD),
    ]


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


def _analyzer_environment(command: list[str]) -> dict[str, str]:
    """Drop common credential-named variables from optional analyzer children.

    Trusted tools can receive exact variables listed as tool-name:VARIABLE
    pairs in FUSE_ANALYZER_ENV_ALLOWLIST, separated by commas. The allowlist
    setting itself is never forwarded. This is defense in depth, not isolation.
    """
    tool_name = Path(command[0]).stem.casefold() if command else ""
    allowlist: set[str] = set()
    for entry in os.environ.get(_ANALYZER_ENV_ALLOWLIST, "").split(","):
        tool, separator, variable = entry.strip().partition(":")
        if separator and tool.casefold() == tool_name and variable.strip():
            allowlist.add(variable.strip().casefold())
    return {
        name: value
        for name, value in os.environ.items()
        if name.casefold() != _ANALYZER_ENV_ALLOWLIST.casefold()
        and (not _SENSITIVE_ENVIRONMENT_NAME.search(name) or name.casefold() in allowlist)
    }


def _windows_kernel32() -> Any:
    win_dll = getattr(ctypes, "WinDLL", None)
    if win_dll is None:
        raise OSError("Windows process containment APIs are unavailable")
    kernel32 = win_dll("kernel32", use_last_error=True)
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL
    return kernel32


def _create_windows_job() -> int:
    """Create a kill-on-close job for one optional analyzer process tree."""
    kernel32 = _windows_kernel32()
    create_job = kernel32.CreateJobObjectW
    create_job.argtypes = [ctypes.c_void_p, wintypes.LPCWSTR]
    create_job.restype = wintypes.HANDLE
    job_handle = create_job(None, None)
    if not job_handle:
        raise OSError(ctypes.get_last_error(), "Could not create analyzer job object")

    limits = _WindowsExtendedLimitInformation()
    limits.BasicLimitInformation.LimitFlags = _WINDOWS_JOB_OBJECT_LIMIT_KILL_ON_CLOSE
    set_information = kernel32.SetInformationJobObject
    set_information.argtypes = [
        wintypes.HANDLE,
        ctypes.c_int,
        ctypes.c_void_p,
        wintypes.DWORD,
    ]
    set_information.restype = wintypes.BOOL
    if not set_information(
        job_handle,
        _WINDOWS_JOB_OBJECT_EXTENDED_LIMIT_INFORMATION,
        ctypes.byref(limits),
        ctypes.sizeof(limits),
    ):
        error = ctypes.get_last_error()
        kernel32.CloseHandle(job_handle)
        raise OSError(error, "Could not configure analyzer job object")
    return int(job_handle)


def _resume_suspended_windows_process(process: subprocess.Popen[bytes]) -> None:
    """Resume the suspended process's initial thread after assigning its job."""
    kernel32 = _windows_kernel32()
    kernel32.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
    kernel32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
    snapshot = kernel32.CreateToolhelp32Snapshot(_WINDOWS_THREAD_SNAPSHOT_FLAG, 0)
    invalid_handle = ctypes.c_void_p(-1).value
    if not snapshot or snapshot == invalid_handle:
        raise OSError(ctypes.get_last_error(), "Could not inspect analyzer process threads")

    try:
        entry = _WindowsThreadEntry32()
        entry.dwSize = ctypes.sizeof(entry)
        thread32_first = kernel32.Thread32First
        thread32_first.argtypes = [wintypes.HANDLE, ctypes.POINTER(_WindowsThreadEntry32)]
        thread32_first.restype = wintypes.BOOL
        thread32_next = kernel32.Thread32Next
        thread32_next.argtypes = [wintypes.HANDLE, ctypes.POINTER(_WindowsThreadEntry32)]
        thread32_next.restype = wintypes.BOOL
        open_thread = kernel32.OpenThread
        open_thread.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        open_thread.restype = wintypes.HANDLE
        resume_thread = kernel32.ResumeThread
        resume_thread.argtypes = [wintypes.HANDLE]
        resume_thread.restype = wintypes.DWORD

        has_entry = thread32_first(snapshot, ctypes.byref(entry))
        while has_entry:
            if entry.th32OwnerProcessID == process.pid:
                thread_handle = open_thread(
                    _WINDOWS_THREAD_SUSPEND_RESUME, False, entry.th32ThreadID
                )
                if not thread_handle:
                    raise OSError(ctypes.get_last_error(), "Could not open analyzer start thread")
                try:
                    if resume_thread(thread_handle) == _WINDOWS_RESUME_THREAD_FAILED:
                        raise OSError(ctypes.get_last_error(), "Could not resume analyzer process")
                    return
                finally:
                    kernel32.CloseHandle(thread_handle)
            has_entry = thread32_next(snapshot, ctypes.byref(entry))
        raise OSError("Could not find the suspended analyzer start thread")
    finally:
        kernel32.CloseHandle(snapshot)


def _assign_windows_job(process: subprocess.Popen[bytes], job_handle: int) -> None:
    """Assign a suspended analyzer before it can create descendant processes."""
    kernel32 = _windows_kernel32()
    assign = kernel32.AssignProcessToJobObject
    assign.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
    assign.restype = wintypes.BOOL
    process_handle = getattr(process, "_handle", None)
    if process_handle is None or not assign(job_handle, int(process_handle)):
        raise OSError(ctypes.get_last_error(), "Could not assign analyzer to its job object")
    _resume_suspended_windows_process(process)


def _close_windows_job(job_handle: int) -> None:
    kernel32 = _windows_kernel32()
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL
    kernel32.CloseHandle(job_handle)


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


def _terminate_process_tree(
    process: subprocess.Popen[bytes], job_handle: int | None = None
) -> None:
    """Best-effort termination of an analyzer and descendants it started."""
    if os.name == "nt":
        if job_handle is not None:
            kernel32 = _windows_kernel32()
            terminate_job = kernel32.TerminateJobObject
            terminate_job.argtypes = [wintypes.HANDLE, wintypes.UINT]
            terminate_job.restype = wintypes.BOOL
            if terminate_job(job_handle, 1):
                return
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
    environment = _analyzer_environment(command)
    job_handle: int | None = None
    if os.name == "nt":
        job_handle = _create_windows_job()
        process: subprocess.Popen[bytes] | None = None
        try:
            process = subprocess.Popen(
                command,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                cwd=cwd,
                env=environment,
                creationflags=getattr(subprocess, "CREATE_SUSPENDED", 0x00000004),
            )
            _assign_windows_job(process, job_handle)
        except BaseException:
            if process is not None:
                try:
                    process.kill()
                    process.wait(timeout=5)
                except (OSError, subprocess.TimeoutExpired):
                    pass
            _close_windows_job(job_handle)
            raise
        assert process is not None
    else:
        process = subprocess.Popen(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=cwd,
            env=environment,
            start_new_session=True,
        )
    deadline = time.monotonic() + timeout
    captured = {"stdout": bytearray(), "stderr": bytearray()}
    total = 0
    lock = threading.Lock()
    exceeded = threading.Event()
    drain_timed_out = threading.Event()

    def drain(name: str, stream: IO[bytes]) -> None:
        nonlocal total
        if os.name != "nt":
            descriptor = stream.fileno()
            set_blocking = getattr(os, "set_blocking", None)
            if set_blocking is None:
                raise OSError("Nonblocking pipe reads are unavailable")
            set_blocking(descriptor, False)
        while True:
            if os.name != "nt":
                remaining_time = deadline - time.monotonic()
                if remaining_time <= 0:
                    drain_timed_out.set()
                    return
                try:
                    chunk = os.read(descriptor, 64 * 1024)
                except BlockingIOError:
                    select.select([descriptor], [], [], min(0.05, remaining_time))
                    continue
            else:
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
                _terminate_process_tree(process, job_handle)

    assert process.stdout is not None and process.stderr is not None
    readers = [
        threading.Thread(target=drain, args=("stdout", process.stdout), daemon=True),
        threading.Thread(target=drain, args=("stderr", process.stderr), daemon=True),
    ]
    for reader in readers:
        reader.start()
    timed_out = False
    try:
        returncode = process.wait(timeout=max(0, deadline - time.monotonic()))
    except subprocess.TimeoutExpired:
        timed_out = True
        _terminate_process_tree(process, job_handle)
        process.wait()
        returncode = process.returncode if process.returncode is not None else -1

    if job_handle is not None:
        _close_windows_job(job_handle)
        job_handle = None
    elif any(reader.is_alive() for reader in readers):
        _terminate_process_tree(process)

    for reader in readers:
        reader.join(timeout=max(0, deadline - time.monotonic()))
    if any(reader.is_alive() for reader in readers):
        timed_out = True
        _terminate_process_tree(process, job_handle)
        for reader in readers:
            reader.join(timeout=0.25)
    if not any(reader.is_alive() for reader in readers):
        process.stdout.close()
        process.stderr.close()
    if exceeded.is_set():
        raise AnalyzerOutputLimitError("Analyzer output exceeded the configured limit")
    if timed_out or drain_timed_out.is_set():
        raise subprocess.TimeoutExpired(command, timeout)
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
