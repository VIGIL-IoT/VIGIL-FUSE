from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

from .analyzer_runtime import (
    MAX_BINWALK_REPORT_BYTES,
    AdapterResult,
    AnalyzerOutputLimitError,
    _artifact,
    _artifact_destination,
    _run,
    _tool_version,
    TOOL_VERSION_TIMEOUT_SECONDS,
)
from .model import AnalyzerStatus


def _binwalk_version(executable: str) -> str | None:
    version = _tool_version(executable)
    if version is not None:
        return version
    try:
        completed = _run(
            [executable, "--help"],
            timeout=TOOL_VERSION_TIMEOUT_SECONDS,
        )
    except (OSError, subprocess.TimeoutExpired, AnalyzerOutputLimitError):
        return None
    if completed.returncode != 0:
        return None
    output = completed.stdout or completed.stderr
    for line in output.splitlines():
        value = line.strip()
        if re.match(r"(?i)^binwalk\s+v?\d", value):
            return value[:120]
    return None


def identify_firmware(target: Path, output_dir: Path) -> AdapterResult:
    """Run Binwalk signature identification only. No extraction option is invoked."""
    executable = shutil.which("binwalk")
    if executable is None:
        return AdapterResult(
            AnalyzerStatus(
                "binwalk",
                "unavailable",
                detail="Install Binwalk and rerun with --firmware; extraction is not performed.",
            )
        )
    version = _binwalk_version(executable)
    try:
        completed = _run([executable, str(target.resolve())])
    except subprocess.TimeoutExpired:
        return AdapterResult(
            AnalyzerStatus(
                "binwalk", "failed", version=version, detail="Timed out after 180 seconds."
            )
        )
    except OSError as error:
        return AdapterResult(
            AnalyzerStatus(
                "binwalk",
                "failed",
                version=version,
                detail=f"Could not start Binwalk ({type(error).__name__}).",
            )
        )
    except AnalyzerOutputLimitError:
        return AdapterResult(
            AnalyzerStatus(
                "binwalk",
                "failed",
                version=version,
                detail="Binwalk diagnostics exceeded 10 MiB limit.",
            )
        )

    output_dir.mkdir(parents=True, exist_ok=True)
    try:
        report_path = _artifact_destination(output_dir, "firmware-identification.txt")
    except OSError as error:
        return AdapterResult(
            AnalyzerStatus("binwalk", "failed", version=version, detail=str(error))
        )
    content = (completed.stdout + ("\n" + completed.stderr if completed.stderr else "")).strip()
    if not content:
        content = "Binwalk produced no signature output."
    content_bytes = content.encode("utf-8")
    output_truncated = len(content_bytes) > MAX_BINWALK_REPORT_BYTES
    report_path.write_bytes(content_bytes[:MAX_BINWALK_REPORT_BYTES])
    status = (
        "failed" if completed.returncode != 0 else "partial" if output_truncated else "completed"
    )
    detail = (
        f"Binwalk exited with code {completed.returncode}."
        if completed.returncode != 0
        else "Signature identification only; no extraction or firmware execution was attempted. "
        "A successful signature scan is not a complete firmware security assessment."
    )
    if output_truncated:
        detail += f" The saved signature report was truncated at the {MAX_BINWALK_REPORT_BYTES}-byte limit."
    try:
        artifact = _artifact(report_path, "text/plain", output_dir)
    except OSError as error:
        return AdapterResult(AnalyzerStatus("binwalk", "failed", detail=str(error)))
    return AdapterResult(
        AnalyzerStatus("binwalk", status, version=version, detail=detail),  # type: ignore[arg-type]
        artifacts=(artifact,),
    )
