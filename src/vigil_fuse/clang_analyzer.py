"""Opt-in compiler observations. Native evidence never assigns security verdicts."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import subprocess
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from .analyzer_runtime import _run
from .execution_contract import _object, decode_message
from .model import AnalyzerStatus

MAX_BYTES = 1024 * 1024
MEMORY_APIS = frozenset(
    {
        "strcpy",
        "strcat",
        "sprintf",
        "vsprintf",
        "gets",
        "scanf",
        "fscanf",
        "sscanf",
        "memcpy",
        "memmove",
    }
)
SECURITY_APIS = frozenset(
    {
        "esp_tls_conn_new",
        "esp_tls_conn_http_new",
        "esp_http_client_init",
        "esp_mqtt_client_init",
        "esp_https_ota",
        "esp_ota_begin",
        "esp_ota_end",
        "esp_secure_boot_verify_signature",
        "mbedtls_ssl_conf_authmode",
        "mbedtls_ssl_set_hostname",
        "mbedtls_ssl_get_verify_result",
        "mbedtls_pk_parse_key",
        "esp_console_init",
    }
)


@dataclass(frozen=True)
class SemanticResult:
    status: AnalyzerStatus
    evidence: dict[str, Any] | None = None
    coverage: tuple[dict[str, str], ...] = ()
    sensitive_calls: tuple[dict[str, Any], ...] = ()


def sensitive_calls(document: dict[str, Any]) -> tuple[dict[str, Any], ...]:
    """Select exact direct API calls, without interpreting safety or flow."""
    calls = []
    for observation in document["observations"]:
        name = observation["name"]
        if observation["kind"] != "call" or name not in MEMORY_APIS | SECURITY_APIS:
            continue
        arguments = observation["arguments"]
        calls.append(
            {
                **observation,
                "api_family": "memory" if name in MEMORY_APIS else "embedded-security",
                "argument_count": len(arguments),
                "destination_expression": _destination(name, arguments),
                "size_expression": arguments[2]["expression"]
                if name in {"memcpy", "memmove"} and len(arguments) >= 3
                else None,
            }
        )
    return tuple(calls)


def _destination(name: str, arguments: list[dict[str, Any]]) -> str | None:
    index = 1 if name == "scanf" else 2 if name in {"sscanf", "fscanf"} else 0
    if name in MEMORY_APIS and len(arguments) > index:
        return str(arguments[index]["expression"])
    return None


def _text(value: object, maximum: int = 256) -> str:
    if not isinstance(value, str) or len(value) > maximum or "\x00" in value:
        raise ValueError("Invalid semantic text")
    return value


def _number(value: object, maximum: int = 10_000_000, minimum: int = 1) -> None:
    if type(value) is not int or not minimum <= value <= maximum:
        raise ValueError("Invalid semantic number")


def _version(value: object) -> str:
    text = _text(value)
    if not re.fullmatch(r"[0-9]+\.[0-9]+(?:\.[0-9]+)?[-+ .a-zA-Z0-9()]*", text):
        raise ValueError("Invalid Clang version")
    return text


def _path(value: object, root: Path) -> str:
    name = _text(value, 1024)
    if not name or "\\" in name or Path(name).is_absolute() or ".." in Path(name).parts:
        raise ValueError("Invalid semantic path")
    resolved = (root / name).resolve(strict=True)
    if not resolved.is_relative_to(root) or not resolved.is_file():
        raise ValueError("Semantic path escapes root")
    return name


def validate_evidence(value: object, root: Path, selected: set[str]) -> dict[str, Any]:
    """Validate every field, including paths and correspondence to selected TUs."""
    document = _object(
        value,
        {
            "schema_version",
            "tool",
            "clang_version",
            "status",
            "translation_units",
            "observations",
            "diagnostic_count",
            "limitations",
        },
    )
    if document["schema_version"] != "1.0" or document["tool"] != "fuse-clang-analyzer":
        raise ValueError("Unsupported semantic producer")
    _version(document["clang_version"])
    if document["status"] not in ("completed", "partial"):
        raise ValueError("Invalid semantic status")
    _number(document["diagnostic_count"], 64, 0)
    units = document["translation_units"]
    if not isinstance(units, list) or not 1 <= len(units) <= 32:
        raise ValueError("Invalid translation units")
    reported = set()
    for item in units:
        unit = _object(item, {"file", "parsed"})
        reported.add(_path(unit["file"], root))
        if type(unit["parsed"]) is not bool:
            raise ValueError("Invalid parse state")
    if reported != selected:
        raise ValueError("Translation units do not match selected build")
    observations = document["observations"]
    if not isinstance(observations, list) or len(observations) > 1024:
        raise ValueError("Invalid observations")
    for item in observations:
        observation = _object(
            item,
            {
                "kind",
                "name",
                "file",
                "line",
                "column",
                "spelling_file",
                "spelling_line",
                "function",
                "definition",
                "arguments",
            },
        )
        if observation["kind"] not in ("call", "function"):
            raise ValueError("Invalid observation kind")
        if _path(observation["file"], root) not in selected:
            raise ValueError("Observation outside selected translation units")
        _path(observation["spelling_file"], root)
        for field in ("line", "column", "spelling_line"):
            _number(observation[field])
        for field in ("name", "function"):
            _text(observation[field])
        if type(observation["definition"]) is not bool:
            raise ValueError("Invalid definition state")
        arguments = observation["arguments"]
        if not isinstance(arguments, list) or len(arguments) > 32:
            raise ValueError("Invalid arguments")
        if observation["kind"] == "function" and arguments:
            raise ValueError("Function record cannot contain call arguments")
        for item in arguments:
            argument = _object(item, {"expression", "literal", "integer_constant"})
            _text(argument["expression"])
            if any(type(argument[key]) is not bool for key in ("literal", "integer_constant")):
                raise ValueError("Invalid constant information")
    limits = document["limitations"]
    if not isinstance(limits, list) or len(limits) > 16:
        raise ValueError("Invalid limitations")
    for limit in limits:
        _text(limit, 512)
    if document["status"] == "completed" and (
        document["diagnostic_count"] or any(not unit["parsed"] for unit in units)
    ):
        raise ValueError("Completed evidence contradicts parse state")
    return document


def inspect_clang(executable: str | None = None) -> tuple[str | None, AnalyzerStatus]:
    path = shutil.which(executable or "fuse-clang-analyzer")
    if path is None:
        return None, AnalyzerStatus(
            "Clang semantic analyzer", "unavailable", detail="not installed"
        )
    try:
        result = _run([path, "--version"], timeout=5, output_limit_bytes=4096)
        probe = _object(
            decode_message(result.stdout.encode()),
            {
                "tool",
                "schema_version",
                "clang_version",
                "compile_commands",
            },
        )
        version = _version(probe["clang_version"])
        if (
            result.returncode
            or probe["tool"] != "fuse-clang-analyzer"
            or probe["schema_version"] != "1.0"
            or probe["compile_commands"] is not True
            or not version
        ):
            raise ValueError("Unsupported semantic probe")
        return path, AnalyzerStatus(
            "Clang semantic analyzer", "completed", version, "compile_commands support: available"
        )
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError):
        return None, AnalyzerStatus(
            "Clang semantic analyzer", "incompatible", detail="probe failed"
        )


def analyze(
    root: Path,
    compilation_database: Path,
    *,
    executable: str | None = None,
    present_sources: tuple[Path, ...] = (),
) -> SemanticResult:
    path, status = inspect_clang(executable)
    if path is None:
        return SemanticResult(status)
    try:
        root = root.resolve(strict=True)
        database = compilation_database.resolve(strict=True)
        if not database.is_relative_to(root):
            raise ValueError("Compilation database must be inside selected root")
        payload = _read_input(database)
        entries = decode_message(payload)
        if not isinstance(entries, list) or not 1 <= len(entries) <= 32:
            raise ValueError("Expected 1..32 compilation entries")
        inputs = {database}
        selected = set()
        for entry in entries:
            if not isinstance(entry, dict):
                raise ValueError("Invalid compilation entry")
            directory = root / _text(entry.get("directory"), 1024)
            source_name = _text(entry.get("file"), 1024)
            arguments = entry.get("arguments")
            if (
                not isinstance(arguments, list)
                or not 1 <= len(arguments) <= 128
                or any(
                    not isinstance(arg, str) or len(arg) > 1024 or "\x00" in arg
                    for arg in arguments
                )
            ):
                raise ValueError("Invalid bounded arguments array")
            source = (directory / source_name).resolve(strict=True)
            if not source.is_relative_to(root) or source.stat().st_size > MAX_BYTES:
                raise ValueError("Source outside input bounds")
            if source.suffix.lower() not in {".c", ".cc", ".cpp", ".cxx"}:
                raise ValueError("Expected a C or C++ translation unit")
            selected.add(source.relative_to(root).as_posix())
            inputs.add(source)
        if len(present_sources) > 32:
            raise ValueError("Too many presence-only sources")
        present = {
            _path(file.resolve(strict=True).relative_to(root).as_posix(), root)
            for file in present_sources
        }
        digests = {file: _digest(file) for file in inputs}
        result = _run(
            [path, str(root), str(database)],
            timeout=65,
            cwd=root,
            output_limit_bytes=MAX_BYTES,
            environment_exclude=(
                "CCC_OVERRIDE_OPTIONS",
                "CPATH",
                "C_INCLUDE_PATH",
                "CPLUS_INCLUDE_PATH",
                "OBJC_INCLUDE_PATH",
                "SDKROOT",
                "CL",
                "_CL_",
                "INCLUDE",
                "EXTERNAL_INCLUDE",
            ),
        )
        if result.returncode:
            return SemanticResult(
                AnalyzerStatus(
                    status.name, "failed", status.version, "Native parser rejected input or failed"
                )
            )
        evidence = validate_evidence(decode_message(result.stdout.encode()), root, selected)
        if evidence["clang_version"] != status.version:
            raise ValueError("Analyzer version changed after probe")
        if any(_digest(file) != digest for file, digest in digests.items()):
            raise ValueError("Input changed during analysis")
        coverage = tuple(
            {"file": unit["file"], "state": "BUILD_INCLUDED" if unit["parsed"] else "UNKNOWN"}
            for unit in evidence["translation_units"]
        )
        coverage += tuple({"file": name, "state": "PRESENT"} for name in sorted(present - selected))
        return SemanticResult(
            AnalyzerStatus(
                status.name,
                evidence["status"],
                status.version,
                "Compiler observations only; no security verdict",
            ),
            evidence,
            coverage,
            sensitive_calls(evidence),
        )
    except subprocess.TimeoutExpired:
        return SemanticResult(AnalyzerStatus(status.name, "timeout", status.version))
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError):
        return SemanticResult(
            AnalyzerStatus(
                status.name,
                "failed",
                status.version,
                "Invalid, oversized or changed semantic input/output",
            )
        )


def _digest(file: Path) -> str:
    return hashlib.sha256(_read_input(file)).hexdigest()


def _read_input(file: Path) -> bytes:
    with file.open("rb") as stream:
        data = stream.read(MAX_BYTES + 1)
    if len(data) > MAX_BYTES:
        raise ValueError("Input exceeds byte limit")
    return data


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", type=Path)
    parser.add_argument("compilation_database", type=Path)
    parser.add_argument("--executable")
    parser.add_argument("--present-source", action="append", type=Path, default=[])
    args = parser.parse_args()
    result = analyze(
        args.root,
        args.compilation_database,
        executable=args.executable,
        present_sources=tuple(args.present_source),
    )
    print(json.dumps(asdict(result), sort_keys=True))
    return 0 if result.evidence is not None else 1


if __name__ == "__main__":
    raise SystemExit(main())
