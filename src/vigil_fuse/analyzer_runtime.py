from __future__ import annotations

import ctypes
import hashlib
import json
import os
import re
import signal
import shutil
import select
import subprocess
import tempfile
import threading
import time
import uuid
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
from pathlib import Path
from typing import IO, Any, Iterator, Sequence
from ctypes import wintypes

from .analyzer_sandbox import (
    SUPPORTED_ANALYZERS,
    AnalyzerSandbox,
    build_create_command,
    container_user,
    report_mask_destination,
)
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
_ACTIVE_ANALYZER_SANDBOX: ContextVar[tuple[AnalyzerSandbox, tuple[Path, ...]] | None] = ContextVar(
    "vigil_fuse_analyzer_sandbox", default=None
)


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


@contextmanager
def analyzer_sandbox_context(
    sandbox: AnalyzerSandbox,
    *,
    target: Path,
) -> Iterator[None]:
    """Scope Docker isolation to optional third-party analyzer invocations."""
    token = _ACTIVE_ANALYZER_SANDBOX.set(
        (
            AnalyzerSandbox(
                runtime=sandbox.runtime,
                images=sandbox.images,
                target=target.resolve(),
                output_dir=sandbox.output_dir,
                allow_osv_network=sandbox.allow_osv_network,
            ),
            (),
        )
    )
    try:
        yield
    finally:
        _ACTIVE_ANALYZER_SANDBOX.reset(token)


def resolve_analyzer_executable(
    name: str,
    *,
    host_lookup: Any | None = None,
) -> str | None:
    """Resolve a host tool or an explicitly configured local image tool."""
    active = _ACTIVE_ANALYZER_SANDBOX.get()
    if active is None:
        return (host_lookup or shutil.which)(name)
    sandbox, _ = active
    if name not in SUPPORTED_ANALYZERS or sandbox.runtime is None:
        return None
    image = sandbox.image_for(name)
    if image is None:
        return None
    try:
        inspected = subprocess.run(
            [
                sandbox.runtime,
                "image",
                "inspect",
                "--format",
                "{{.Id}}|{{json .Config.Entrypoint}}",
                image,
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            text=True,
            stderr=subprocess.DEVNULL,
            check=False,
            timeout=10,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if inspected.returncode != 0:
        return None
    _, separator, entrypoint_json = inspected.stdout.strip().partition("|")
    if not separator:
        return None
    try:
        entrypoint = json.loads(entrypoint_json)
    except json.JSONDecodeError:
        return None
    if isinstance(entrypoint, list) and entrypoint and isinstance(entrypoint[0], str):
        executable = entrypoint[0]
        if Path(executable).name.casefold() in {name.casefold(), f"{name.casefold()}.exe"}:
            return executable
    return name


def analyzer_sandbox_active() -> bool:
    """Return whether optional analyzer calls are scoped to Docker mode."""
    return _ACTIVE_ANALYZER_SANDBOX.get() is not None


def analyzer_unavailable_detail(name: str, host_detail: str) -> str:
    active = _ACTIVE_ANALYZER_SANDBOX.get()
    if active is None:
        return host_detail
    sandbox, _ = active
    return f"Docker sandbox unavailable for {name}: {sandbox.unavailable_reason(name)}"


def analyzer_execution_detail(name: str) -> str | None:
    active = _ACTIVE_ANALYZER_SANDBOX.get()
    if active is None:
        return None
    sandbox, _ = active
    network = (
        "bridge network explicitly enabled"
        if name == "osv-scanner" and sandbox.allow_osv_network
        else "network disabled"
    )
    return (
        f"Docker sandbox: image {sandbox.image_for(name)}, read-only input and root filesystem, "
        f"non-root UID, no Linux capabilities, {network}; limits 1 CPU, 1 GiB memory, "
        "64 processes, 64 MiB temporary storage; report directories are not bind-mounted, and nested report paths are masked."
    )


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


def _isolated_analyzer_environment(command: list[str], root: Path) -> dict[str, str]:
    """Use per-run user, config, cache, and temporary directories for a tool."""
    home = root / "home"
    directories = {
        "HOME": home,
        "USERPROFILE": home,
        "APPDATA": root / "appdata",
        "LOCALAPPDATA": root / "local-appdata",
        "XDG_CONFIG_HOME": root / "config",
        "XDG_CACHE_HOME": root / "cache",
        "XDG_DATA_HOME": root / "data",
        "TMPDIR": root / "tmp",
        "TEMP": root / "tmp",
        "TMP": root / "tmp",
    }
    for directory in set(directories.values()):
        directory.mkdir(parents=True, exist_ok=True)
    environment = _analyzer_environment(command)
    environment.update({name: str(directory) for name, directory in directories.items()})
    if os.name == "nt":
        home_drive, home_path = os.path.splitdrive(str(home))
        environment["HOMEDRIVE"] = home_drive
        environment["HOMEPATH"] = home_path
    return environment


def _windows_kernel32() -> Any:
    win_dll = getattr(ctypes, "WinDLL", None)
    if win_dll is None:
        raise OSError("Windows process containment APIs are unavailable")
    kernel32 = win_dll("kernel32", use_last_error=True)
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL
    return kernel32


def _windows_last_error() -> int:
    """Return ctypes' saved Windows error code when running on Windows."""
    get_last_error: Any = getattr(ctypes, "get_last_error", None)
    return int(get_last_error()) if callable(get_last_error) else 0


def _create_windows_job() -> int:
    """Create a kill-on-close job for one optional analyzer process tree."""
    kernel32 = _windows_kernel32()
    create_job = kernel32.CreateJobObjectW
    create_job.argtypes = [ctypes.c_void_p, wintypes.LPCWSTR]
    create_job.restype = wintypes.HANDLE
    job_handle = create_job(None, None)
    if not job_handle:
        raise OSError(_windows_last_error(), "Could not create analyzer job object")

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
        error = _windows_last_error()
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
        raise OSError(_windows_last_error(), "Could not inspect analyzer process threads")

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
                    raise OSError(_windows_last_error(), "Could not open analyzer start thread")
                try:
                    if resume_thread(thread_handle) == _WINDOWS_RESUME_THREAD_FAILED:
                        raise OSError(_windows_last_error(), "Could not resume analyzer process")
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
        raise OSError(_windows_last_error(), "Could not assign analyzer to its job object")
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
    command: list[str],
    *,
    timeout: int = ANALYZER_TIMEOUT_SECONDS,
    cwd: Path | None = None,
    readonly_mounts: Sequence[Path] = (),
    output_limit_bytes: int = MAX_ANALYZER_OUTPUT_BYTES,
) -> subprocess.CompletedProcess[str]:
    """Run an optional tool with isolated user paths or an explicit Docker sandbox.

    Host mode limits the child process and its default user paths. Docker mode
    adds read-only input, no-network execution by default, and resource limits.
    """
    with tempfile.TemporaryDirectory(
        prefix="vigil-fuse-analyzer-", ignore_cleanup_errors=True
    ) as temporary:
        root = Path(temporary)
        environment = _isolated_analyzer_environment(command, root)
        active = _ACTIVE_ANALYZER_SANDBOX.get()
        if active is not None:
            sandbox, context_mounts = active
            return _run_in_docker(
                command,
                sandbox=sandbox,
                environment=environment,
                timeout=timeout,
                temporary_root=root,
                readonly_mounts=(*context_mounts, *readonly_mounts),
                output_limit_bytes=output_limit_bytes,
            )
        return _run_with_environment(
            command,
            environment=environment,
            timeout=timeout,
            cwd=cwd if cwd is not None else root,
            output_limit_bytes=output_limit_bytes,
        )


def _run_in_docker(
    command: list[str],
    *,
    sandbox: AnalyzerSandbox,
    environment: dict[str, str],
    timeout: int,
    temporary_root: Path,
    readonly_mounts: Sequence[Path],
    output_limit_bytes: int = MAX_ANALYZER_OUTPUT_BYTES,
) -> subprocess.CompletedProcess[str]:
    if not command:
        raise OSError("Docker sandbox received an empty analyzer command")
    analyzer = Path(command[0]).stem.casefold()
    if analyzer not in SUPPORTED_ANALYZERS:
        raise OSError("Docker sandbox does not support this analyzer command")
    if resolve_analyzer_executable(analyzer) is None:
        raise OSError(sandbox.unavailable_reason(analyzer))
    if not _docker_rootless_limits_supported(sandbox, environment, temporary_root):
        raise OSError(
            "Docker rootless mode requires cgroup v2 with the systemd cgroup driver "
            "for analyzer resource limits"
        )

    container_name = f"vigil-fuse-analyzer-{uuid.uuid4().hex}"
    create_command = build_create_command(
        sandbox,
        analyzer=analyzer,
        command=command,
        container_name=container_name,
        extra_readonly_mounts=readonly_mounts,
    )
    container_created = False
    try:
        create_result = subprocess.run(
            create_command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            env=environment,
            cwd=temporary_root,
            check=False,
            timeout=20,
        )
        if create_result.returncode != 0:
            raise OSError("Docker could not create the isolated analyzer container")
        container_created = True
        if not _container_configuration_isolated(
            sandbox, analyzer, container_name, readonly_mounts
        ):
            raise OSError("Docker did not apply all required analyzer isolation settings")
        completed = _run_with_environment(
            [sandbox.runtime or "docker", "start", "--attach", container_name],
            environment=environment,
            timeout=timeout,
            cwd=temporary_root,
            output_limit_bytes=output_limit_bytes,
        )
        return subprocess.CompletedProcess(
            command,
            completed.returncode,
            stdout=completed.stdout,
            stderr=completed.stderr,
        )
    finally:
        if sandbox.runtime is not None:
            try:
                cleanup = subprocess.run(
                    [sandbox.runtime, "rm", "--force", container_name],
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    env=environment,
                    cwd=temporary_root,
                    check=False,
                    timeout=15,
                )
                if container_created and cleanup.returncode != 0:
                    raise OSError("Docker did not remove the analyzer sandbox container")
            except (OSError, subprocess.TimeoutExpired):
                if container_created:
                    raise OSError("Docker could not clean up the analyzer sandbox container")


def _docker_rootless_limits_supported(
    sandbox: AnalyzerSandbox,
    environment: dict[str, str],
    temporary_root: Path,
) -> bool:
    if sandbox.runtime is None:
        return False
    try:
        result = subprocess.run(
            [
                sandbox.runtime,
                "info",
                "--format",
                "{{json .SecurityOptions}}|{{.CgroupVersion}}|{{.CgroupDriver}}",
            ],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            env=environment,
            cwd=temporary_root,
            check=False,
            timeout=10,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    if result.returncode != 0:
        return False
    try:
        security_json, cgroup_version, cgroup_driver = result.stdout.strip().split("|", 2)
        security_options = json.loads(security_json)
    except (ValueError, json.JSONDecodeError):
        return False
    if not isinstance(security_options, list):
        return False
    rootless = any("rootless" in str(option).casefold() for option in security_options)
    return not rootless or (cgroup_version == "2" and cgroup_driver == "systemd")


def _container_configuration_isolated(
    sandbox: AnalyzerSandbox,
    analyzer: str,
    container_name: str,
    readonly_mounts: Sequence[Path],
) -> bool:
    if sandbox.runtime is None:
        return False
    try:
        inspected = subprocess.run(
            [sandbox.runtime, "inspect", "--format", "{{json .}}", container_name],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            check=False,
            timeout=10,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    if inspected.returncode != 0:
        return False
    try:
        details = json.loads(inspected.stdout)
    except (json.JSONDecodeError, TypeError):
        return False
    if not isinstance(details, dict):
        return False
    host = details.get("HostConfig", {})
    config = details.get("Config", {})
    if not isinstance(host, dict) or not isinstance(config, dict):
        return False
    expected_network = (
        "bridge" if analyzer == "osv-scanner" and sandbox.allow_osv_network else "none"
    )
    security_options = host.get("SecurityOpt") or []
    capabilities = {str(value).upper() for value in (host.get("CapDrop") or [])}
    pid_mode = host.get("PidMode")
    expected_tmpfs = {"/tmp": "rw,noexec,nosuid,nodev,size=64m,mode=1777"}
    try:
        report_mask = report_mask_destination(sandbox)
    except ValueError:
        return False
    if report_mask is not None:
        expected_tmpfs[report_mask] = "rw,noexec,nosuid,nodev,size=64m,mode=1777"
    if not isinstance(security_options, list) or not isinstance(host.get("Tmpfs"), dict):
        return False
    try:
        expected_user = container_user()
    except ValueError:
        return False
    if not (
        host.get("NetworkMode") == expected_network
        and host.get("ReadonlyRootfs") is True
        and "ALL" in capabilities
        and any(str(value).casefold() == "no-new-privileges=true" for value in security_options)
        and not any("seccomp=unconfined" in str(value).casefold() for value in security_options)
        and host.get("PidsLimit") == 64
        and host.get("Memory") == 1024 * 1024 * 1024
        and host.get("MemorySwap") == 1024 * 1024 * 1024
        and host.get("NanoCpus") == 1_000_000_000
        and config.get("User") == expected_user
        and host.get("Privileged") is False
        and isinstance(pid_mode, str)
        and pid_mode in {"", "private"}
        and host.get("IpcMode") == "private"
        and host.get("CgroupnsMode") == "private"
        and not host.get("Devices")
        and not host.get("DeviceRequests")
        and host.get("Tmpfs") == expected_tmpfs
    ):
        return False

    expected_mounts: dict[str, bool] = {}
    if sandbox.target is not None:
        expected_mounts["/fuse/input"] = False
    expected_mounts.update(
        {f"/fuse/readonly-{index}": False for index, _ in enumerate(readonly_mounts)}
    )
    raw_mounts = details.get("Mounts")
    if not isinstance(raw_mounts, list):
        return False
    if any(
        not isinstance(mount, dict)
        or not isinstance(mount.get("Destination"), str)
        or not isinstance(mount.get("RW"), bool)
        for mount in raw_mounts
    ):
        return False
    actual_mounts = {mount.get("Destination"): mount.get("RW") for mount in raw_mounts}
    return len(actual_mounts) == len(raw_mounts) == len(expected_mounts) and (
        actual_mounts == expected_mounts
    )


def _run_with_environment(
    command: list[str],
    *,
    environment: dict[str, str],
    timeout: int = ANALYZER_TIMEOUT_SECONDS,
    cwd: Path | None = None,
    output_limit_bytes: int = MAX_ANALYZER_OUTPUT_BYTES,
) -> subprocess.CompletedProcess[str]:
    if output_limit_bytes < 1:
        raise ValueError("Analyzer output limit must be positive")
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
                remaining = max(0, output_limit_bytes - total)
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
