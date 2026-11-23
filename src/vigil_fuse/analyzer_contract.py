"""Common opt-in execution contract for passive evidence producers."""

from __future__ import annotations

from dataclasses import dataclass, replace
from pathlib import Path
import shutil
import subprocess
import uuid

from .analyzer_runtime import AnalyzerOutputLimitError, _run
from .analyzer_sandbox import container_user, validate_image_reference
from .evidence_graph import text


@dataclass(frozen=True)
class SandboxPolicy:
    network: str = "none"
    filesystem: str = "read-only-input"
    devices: tuple[str, ...] = ()
    cpu: int = 1
    memory_mb: int = 2048
    pids: int = 64
    timeout: int = 300
    stdout_limit: int = 8 * 1024 * 1024
    stderr_limit: int = 1024 * 1024
    artifact_size: int = 8 * 1024 * 1024
    temporary_mb: int = 1024
    working_directory: str = "/work"
    environment: tuple[str, ...] = ("HOME=/work", "TMPDIR=/work")

    def validate(self) -> None:
        if (
            self.network != "none"
            or self.filesystem != "read-only-input"
            or self.devices
            or self.working_directory != "/work"
            or self.environment != ("HOME=/work", "TMPDIR=/work")
        ):
            raise ValueError("Unsupported sandbox policy")
        for value, maximum in (
            (self.cpu, 4),
            (self.memory_mb, 8192),
            (self.pids, 256),
            (self.timeout, 3600),
            (self.stdout_limit, 16 * 1024 * 1024),
            (self.stderr_limit, 2 * 1024 * 1024),
            (self.artifact_size, 16 * 1024 * 1024),
            (self.temporary_mb, 4096),
        ):
            if type(value) is not int or not 1 <= value <= maximum:
                raise ValueError("Invalid sandbox budget")


@dataclass(frozen=True)
class AnalyzerRequest:
    tool: str
    tool_version: str
    image: str
    command: tuple[str, ...]
    inputs: tuple[Path, ...]
    authorized: bool = False


@dataclass(frozen=True)
class AnalyzerResult:
    tool: str
    tool_version: str
    tool_digest: str
    status: str
    stdout: str = ""
    limitations: tuple[str, ...] = ()


def container_command(
    request: AnalyzerRequest, policy: SandboxPolicy, name: str, runtime: str
) -> list[str]:
    policy.validate()
    if request.authorized is not True:
        raise ValueError("Explicit analyzer execution authorization required")
    text(request.tool)
    text(request.tool_version)
    image = validate_image_reference(request.image)
    if not request.command or len(request.command) > 32 or request.command[0].startswith("-"):
        raise ValueError("Invalid analyzer command")
    if any(
        not isinstance(arg, str) or len(arg) > 32768 or "\x00" in arg for arg in request.command
    ):
        raise ValueError("Invalid analyzer argument")
    if len(request.inputs) > 8:
        raise ValueError("Too many analyzer mounts")
    command = [
        runtime,
        "run",
        "--rm",
        "--pull=never",
        "--name",
        name,
        "--network=none",
        "--read-only",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges=true",
        "--ipc=private",
        "--cgroupns=private",
        "--user",
        container_user(),
        f"--cpus={policy.cpu}",
        f"--memory={policy.memory_mb}m",
        f"--memory-swap={policy.memory_mb}m",
        f"--pids-limit={policy.pids}",
        "--ulimit",
        "core=0",
        "--workdir=/work",
        "--tmpfs",
        f"/work:rw,nosuid,nodev,noexec,size={policy.temporary_mb}m,mode=1777",
    ]
    for variable in policy.environment:
        command.extend(("--env", variable))
    for index, source in enumerate(request.inputs):
        if source.is_symlink() or not source.exists() or "," in str(source.resolve()):
            raise ValueError("Invalid analyzer input mount")
        command.extend(
            ("--mount", f"type=bind,source={source.resolve()},target=/input{index},readonly")
        )
    command.extend(("--entrypoint", request.command[0], image, *request.command[1:]))
    return command


def run_analyzer(
    request: AnalyzerRequest, policy: SandboxPolicy = SandboxPolicy()
) -> AnalyzerResult:
    """No host fallback, image pulling, writable host mounts, or target execution."""
    runtime = shutil.which("docker")
    name = "fuse-evidence-" + uuid.uuid4().hex
    command = container_command(request, policy, name, runtime or "docker")
    base = (request.tool, request.tool_version, request.image)
    if runtime is None:
        return AnalyzerResult(
            *base, status="unavailable", limitations=("Docker unavailable; no host fallback.",)
        )
    try:
        result = _run(
            command,
            timeout=policy.timeout,
            output_limit_bytes=policy.stdout_limit + policy.stderr_limit,
        )
        if result.returncode != 0:
            outcome = AnalyzerResult(
                *base,
                status="failed",
                limitations=(
                    "Analyzer failed; diagnostics omitted to protect sensitive material.",
                ),
            )
        elif (
            len(result.stdout.encode()) > min(policy.stdout_limit, policy.artifact_size)
            or len(result.stderr.encode()) > policy.stderr_limit
        ):
            outcome = AnalyzerResult(
                *base, status="failed", limitations=("Analyzer output exceeded budget.",)
            )
        else:
            outcome = AnalyzerResult(*base, status="completed", stdout=result.stdout)
    except subprocess.TimeoutExpired:
        outcome = AnalyzerResult(*base, status="timeout", limitations=("Analyzer timeout.",))
    except (OSError, AnalyzerOutputLimitError):
        outcome = AnalyzerResult(
            *base,
            status="failed",
            limitations=("Analyzer unavailable or output budget exceeded.",),
        )
    # Killing a Docker client alone does not guarantee container teardown.
    try:
        cleanup = subprocess.run(
            [runtime, "rm", "--force", name],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=10,
            check=False,
        )
        if cleanup.returncode != 0 and outcome.status in {"failed", "timeout"}:
            outcome = replace(
                outcome,
                limitations=(*outcome.limitations, "Container cleanup could not be verified."),
            )
    except (OSError, subprocess.TimeoutExpired):
        outcome = replace(
            outcome,
            status="failed",
            stdout="",
            limitations=(
                *outcome.limitations,
                "Container cleanup failed; inspect the Docker runtime.",
            ),
        )
    return outcome
