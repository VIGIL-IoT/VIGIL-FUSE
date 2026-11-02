from __future__ import annotations

import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping, Sequence

SUPPORTED_ANALYZERS = frozenset({"syft", "osv-scanner", "binwalk", "gitleaks"})
_DIGEST_REFERENCE = re.compile(r"(?:^|@)sha256:([0-9a-f]{64})$")


@dataclass(frozen=True)
class AnalyzerSandbox:
    """Explicit Docker isolation settings for optional third-party analyzers."""

    runtime: str | None
    images: Mapping[str, str]
    target: Path | None = None
    output_dir: Path | None = None
    allow_osv_network: bool = False

    def image_for(self, analyzer: str) -> str | None:
        return self.images.get(analyzer)

    def unavailable_reason(self, analyzer: str) -> str:
        if self.runtime is None:
            return "Docker is unavailable; no host analyzer fallback was attempted."
        if analyzer not in self.images:
            return (
                f"No digest-pinned Docker image was configured for {analyzer}; "
                "no host analyzer fallback was attempted."
            )
        return f"The configured Docker image for {analyzer} is not available locally."


def validate_image_reference(reference: str) -> str:
    """Accept an immutable registry digest or a local content-addressed image ID."""
    candidate = reference.strip()
    if (
        not candidate
        or candidate.startswith("-")
        or any(character.isspace() or ord(character) < 32 for character in candidate)
        or _DIGEST_REFERENCE.search(candidate) is None
    ):
        raise ValueError(
            "Sandbox images must use an immutable @sha256 digest or a local sha256 image ID"
        )
    return candidate


def container_user() -> str:
    """Use a non-root identity that can read mounted inputs."""
    get_uid = getattr(os, "geteuid", None)
    get_gid = getattr(os, "getegid", None)
    if callable(get_uid) and callable(get_gid):
        uid = int(get_uid())
        gid = int(get_gid())
        if uid == 0:
            raise ValueError("Docker analyzer sandbox refuses to run from a root host account")
        return f"{uid}:{gid}"
    return "65532:65532"


def parse_image_assignments(values: Sequence[str]) -> dict[str, str]:
    images: dict[str, str] = {}
    for value in values:
        analyzer, separator, reference = value.partition("=")
        analyzer = analyzer.strip().casefold()
        if not separator or analyzer not in SUPPORTED_ANALYZERS:
            expected = ", ".join(sorted(SUPPORTED_ANALYZERS))
            raise ValueError(f"Sandbox image must use TOOL=IMAGE with TOOL one of: {expected}")
        if analyzer in images:
            raise ValueError(f"Sandbox image for {analyzer} was specified more than once")
        images[analyzer] = validate_image_reference(reference)
    return images


def _container_path(path: Path, root: Path, destination: str) -> str | None:
    try:
        relative = path.resolve().relative_to(root.resolve())
    except (OSError, ValueError):
        return None
    suffix = relative.as_posix()
    return destination if suffix == "." else f"{destination}/{suffix}"


def report_mask_destination(sandbox: AnalyzerSandbox) -> str | None:
    """Return a bounded tmpfs overlay that hides reports nested in the input tree."""
    if sandbox.target is None or sandbox.output_dir is None or not sandbox.target.is_dir():
        return None
    try:
        relative = sandbox.output_dir.resolve().relative_to(sandbox.target.resolve())
    except (OSError, ValueError):
        return None
    if relative == Path("."):
        raise ValueError("Docker analyzer mode cannot use the target root as its report directory")
    relative_posix = relative.as_posix()
    if ":" in relative_posix or "," in relative_posix:
        raise ValueError("Docker report paths cannot contain colon or comma characters")
    return f"/fuse/input/{relative_posix}"


def map_argument(
    argument: str,
    *,
    sandbox: AnalyzerSandbox,
    extra_readonly_mounts: Sequence[Path] = (),
) -> str:
    """Translate mounted host paths to fixed container paths, rejecting escapes."""
    prefix = ""
    candidate = argument
    for marker in ("dir:", "file:", "cyclonedx-json="):
        if argument.startswith(marker):
            prefix = marker
            candidate = argument[len(marker) :]
            break
    else:
        if "=" in argument:
            key, value = argument.split("=", 1)
            if value and Path(value).is_absolute():
                prefix, candidate = f"{key}=", value

    path = Path(candidate)
    if not path.is_absolute():
        return argument

    roots: list[tuple[Path, str]] = [
        (root, f"/fuse/readonly-{index}") for index, root in enumerate(extra_readonly_mounts)
    ]
    if sandbox.target is not None:
        roots.append((sandbox.target, "/fuse/input"))
    for root, destination in roots:
        mapped = _container_path(path, root, destination)
        if mapped is not None:
            return f"{prefix}{mapped}"
    raise ValueError("Sandbox analyzer argument refers to a host path outside mounted inputs")


def build_create_command(
    sandbox: AnalyzerSandbox,
    *,
    analyzer: str,
    command: Sequence[str],
    container_name: str,
    extra_readonly_mounts: Sequence[Path] = (),
) -> list[str]:
    """Build a fail-closed Docker create command with bounded, read-only inputs."""
    if sandbox.runtime is None:
        raise FileNotFoundError("Docker is not available")
    image = sandbox.image_for(analyzer)
    if image is None:
        raise ValueError(f"No sandbox image was configured for {analyzer}")
    validate_image_reference(image)
    if not command or Path(command[0]).stem.casefold() != analyzer:
        raise ValueError(f"Sandbox command does not match configured analyzer {analyzer}")

    network = "bridge" if analyzer == "osv-scanner" and sandbox.allow_osv_network else "none"
    result = [
        sandbox.runtime,
        "create",
        "--pull=never",
        "--name",
        container_name,
        "--network",
        network,
        "--ipc=private",
        "--cgroupns=private",
        "--read-only",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges=true",
        "--pids-limit=64",
        "--memory=1g",
        "--memory-swap=1g",
        "--cpus=1",
        f"--user={container_user()}",
        "--tmpfs",
        "/tmp:rw,noexec,nosuid,nodev,size=64m,mode=1777",
        "--env",
        "HOME=/tmp",
        "--env",
        "TMPDIR=/tmp",
        "--env",
        "GIT_CONFIG_COUNT=1",
        "--env",
        "GIT_CONFIG_KEY_0=safe.directory",
        "--env",
        "GIT_CONFIG_VALUE_0=/fuse/input",
    ]
    if analyzer == "syft":
        result.extend(("--env", "SYFT_CHECK_FOR_APP_UPDATE=false"))
    if sandbox.target is not None:
        result.extend(
            (
                "--mount",
                _mount_argument(sandbox.target, "/fuse/input", readonly=True),
            )
        )
    for index, root in enumerate(extra_readonly_mounts):
        result.extend(
            (
                "--mount",
                _mount_argument(root, f"/fuse/readonly-{index}", readonly=True),
            )
        )
    report_mask = report_mask_destination(sandbox)
    if report_mask is not None:
        result.extend(
            (
                "--tmpfs",
                f"{report_mask}:rw,noexec,nosuid,nodev,size=64m,mode=1777",
            )
        )

    working_directory = "/tmp"
    if sandbox.target is not None and sandbox.target.is_dir():
        working_directory = "/fuse/input"
    result.extend(("--workdir", working_directory, "--entrypoint", command[0], image))
    result.extend(
        map_argument(argument, sandbox=sandbox, extra_readonly_mounts=extra_readonly_mounts)
        for argument in command[1:]
    )
    return result


def _mount_argument(source: Path, destination: str, *, readonly: bool) -> str:
    resolved = source.resolve()
    if not resolved.exists():
        raise FileNotFoundError(f"Sandbox mount source does not exist: {resolved.name}")
    source_value = str(resolved)
    if "," in source_value:
        raise ValueError("Sandbox mount paths cannot contain commas")
    suffix = ",readonly" if readonly else ""
    return f"type=bind,source={source_value},target={destination}{suffix}"
