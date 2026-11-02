from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import tempfile
from dataclasses import dataclass
from importlib.resources import as_file, files
from pathlib import Path
from typing import Callable, Literal, Mapping
from urllib.parse import urlsplit, urlunsplit

from .analyzer_runtime import (
    MAX_ANALYZER_OUTPUT_BYTES,
    AdapterResult,
    AnalyzerOutputLimitError,
    _artifact,
    _artifact_destination,
    _run,
    analyzer_sandbox_active,
)
from .model import AnalyzerStatus, Finding
from .text_safety import safe_terminal_text

GHIDRA_SUPPORTED_VERSION = "12.2"
GHIDRA_MINIMUM_JAVA = 25
GHIDRA_DEFAULT_TIMEOUT_SECONDS = 300
GHIDRA_MINIMUM_TIMEOUT_SECONDS = 15
GHIDRA_MAXIMUM_TIMEOUT_SECONDS = 3600
GHIDRA_MAXIMUM_INPUT_BYTES = 128 * 1024 * 1024
GHIDRA_MAXIMUM_ARTIFACT_BYTES = 8 * 1024 * 1024
GHIDRA_MAXIMUM_DIAGNOSTIC_BYTES = MAX_ANALYZER_OUTPUT_BYTES
_JAVA_ENVIRONMENT_OVERRIDES = (
    "JAVA_TOOL_OPTIONS",
    "JDK_JAVA_OPTIONS",
    "_JAVA_OPTIONS",
    "JAVA_OPTS",
    "CLASSPATH",
    "GHIDRA_INSTALL_DIR",
    "GHIDRA_MAXMEM",
    "GHIDRA_HEADLESS_MAXMEM",
    "GHIDRA_JAVA_OPTIONS",
    "GHIDRA_HEADLESS_JAVA_OPTIONS",
    "GHIDRA_LAUNCH_PROPERTIES",
)
_JAVA_VERSION_PATTERN = re.compile(r'(?i)(?:java|openjdk) version\s+"?(\d+)(?:\.(\d+))?')
_RAW_LANGUAGE_PATTERN = re.compile(r"^[A-Za-z0-9_.:-]{1,128}$")
_COMPILER_SPEC_PATTERN = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")
_BASE_ADDRESS_PATTERN = re.compile(r"^(?:0[xX][0-9a-fA-F]{1,16}|[0-9]{1,20})$")
_SECRET_TEXT_PATTERN = re.compile(
    r"(?i)(password|passwd|api[_-]?key|access[_-]?token|secret|authorization|private[_-]?key)\s*[:=]"
)
_JWT_PATTERN = re.compile(r"\b[A-Za-z0-9_-]{15,}\.[A-Za-z0-9_-]{15,}\.[A-Za-z0-9_-]{10,}\b")
_ENDPOINT_PATTERN = re.compile(r"(?i)^(https?|mqtts?)://")


@dataclass(frozen=True)
class GhidraProbe:
    status: Literal["available", "unavailable", "incompatible", "unsupported"]
    install_dir: Path | None = None
    version: str | None = None
    launcher: Path | None = None
    java_executable: Path | None = None
    java_version: str | None = None
    detail: str = ""


@dataclass(frozen=True)
class BinaryInput:
    format: str
    raw: bool


def inspect_ghidra(
    configured_install_dir: str | Path | None = None,
    *,
    environ: Mapping[str, str] | None = None,
    which: Callable[[str], str | None] = shutil.which,
) -> GhidraProbe:
    """Validate one explicitly selected or safely discovered Ghidra installation."""
    environment = os.environ if environ is None else environ
    selected_path: str | Path | None = configured_install_dir
    if selected_path is None or not str(selected_path).strip():
        selected_path = environment.get("GHIDRA_INSTALL_DIR")

    launcher_from_path: Path | None = None
    if selected_path is None or not str(selected_path).strip():
        launcher_name = "analyzeHeadless.bat" if os.name == "nt" else "analyzeHeadless"
        launcher_text = which(launcher_name)
        if launcher_text is None:
            return GhidraProbe(
                status="unavailable",
                detail="Ghidra is not installed or GHIDRA_INSTALL_DIR is not configured.",
            )
        launcher_from_path = Path(launcher_text).expanduser().resolve()
        install_dir = launcher_from_path.parent.parent
    else:
        install_dir = Path(selected_path).expanduser()
        try:
            install_dir = install_dir.resolve(strict=True)
        except (OSError, RuntimeError):
            return GhidraProbe(
                status="unavailable",
                detail="The configured Ghidra installation directory does not exist.",
            )

    if not install_dir.is_dir():
        return GhidraProbe(
            status="unavailable",
            install_dir=install_dir,
            detail="The configured Ghidra installation path is not a directory.",
        )
    properties_path = install_dir / "Ghidra" / "application.properties"
    try:
        if properties_path.stat().st_size > 256 * 1024:
            raise ValueError("properties file exceeds 256 KiB")
        properties = _read_properties(properties_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, ValueError):
        return GhidraProbe(
            status="unsupported",
            install_dir=install_dir,
            detail="The selected directory is not a validated Ghidra installation.",
        )

    version = properties.get("application.version")
    if version is None:
        return GhidraProbe(
            status="unsupported",
            install_dir=install_dir,
            detail="Ghidra version metadata is missing from application.properties.",
        )
    if version != GHIDRA_SUPPORTED_VERSION:
        return GhidraProbe(
            status="incompatible",
            install_dir=install_dir,
            version=version,
            detail=(
                f"FUSE currently validates Ghidra {GHIDRA_SUPPORTED_VERSION}; "
                f"the detected version is {version}."
            ),
        )

    launcher = launcher_from_path or _headless_launcher(install_dir)
    if launcher is None or not launcher.is_file():
        return GhidraProbe(
            status="unavailable",
            install_dir=install_dir,
            version=version,
            detail="Ghidra is present but its Headless Analyzer launcher is missing.",
        )
    if not _headless_launcher_supported_by_host(launcher):
        return GhidraProbe(
            status="unsupported",
            install_dir=install_dir,
            version=version,
            launcher=launcher,
            detail="The Ghidra installation has no Headless Analyzer launcher for this host.",
        )

    java_executable = _find_java(environment, which)
    if java_executable is None:
        return GhidraProbe(
            status="unavailable",
            install_dir=install_dir,
            version=version,
            launcher=launcher,
            detail=f"Ghidra {version} is installed, but a Java {GHIDRA_MINIMUM_JAVA}+ JDK was not found.",
        )
    try:
        java_result = _run(
            [str(java_executable), "-version"],
            timeout=5,
            output_limit_bytes=16 * 1024,
            environment_exclude=_JAVA_ENVIRONMENT_OVERRIDES,
        )
    except (OSError, subprocess.TimeoutExpired, AnalyzerOutputLimitError):
        return GhidraProbe(
            status="unavailable",
            install_dir=install_dir,
            version=version,
            launcher=launcher,
            java_executable=java_executable,
            detail="Java was found but its version could not be read.",
        )
    java_output = java_result.stdout + "\n" + java_result.stderr
    java_version = _parse_java_version(java_output)
    if java_result.returncode != 0 or java_version is None:
        return GhidraProbe(
            status="unavailable",
            install_dir=install_dir,
            version=version,
            launcher=launcher,
            java_executable=java_executable,
            detail="Java was found but did not report a recognized version.",
        )
    minimum_version = _positive_int(properties.get("application.java.min"))
    maximum_version = _positive_int(properties.get("application.java.max"))
    if minimum_version is None:
        return GhidraProbe(
            status="unsupported",
            install_dir=install_dir,
            version=version,
            launcher=launcher,
            java_executable=java_executable,
            java_version=java_version,
            detail="Ghidra Java compatibility metadata is missing or invalid.",
        )
    java_major = int(java_version.split(".", maxsplit=1)[0])
    if java_major < minimum_version or (maximum_version and java_major > maximum_version):
        requirement = (
            f"Java {minimum_version}+"
            if maximum_version is None
            else f"Java {minimum_version} through {maximum_version}"
        )
        return GhidraProbe(
            status="incompatible",
            install_dir=install_dir,
            version=version,
            launcher=launcher,
            java_executable=java_executable,
            java_version=java_version,
            detail=f"Ghidra {version} requires {requirement}; Java {java_version} was detected.",
        )
    return GhidraProbe(
        status="available",
        install_dir=install_dir,
        version=version,
        launcher=launcher,
        java_executable=java_executable,
        java_version=java_version,
        detail=f"Ghidra {version} Headless Analyzer and Java {java_version} are available.",
    )


def _read_properties(content: str) -> dict[str, str]:
    values: dict[str, str] = {}
    for line in content.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith(("#", "!")):
            continue
        key, separator, value = stripped.partition("=")
        if separator:
            values[key.strip()] = value.strip()
    return values


def _positive_int(value: str | None) -> int | None:
    if value is None or not value.isdecimal():
        return None
    parsed = int(value)
    return parsed if parsed > 0 else None


def _parse_java_version(output: str) -> str | None:
    match = _JAVA_VERSION_PATTERN.search(output)
    if match is None:
        return None
    major = int(match.group(1))
    minor = match.group(2)
    if major == 1 and minor is not None:
        return f"{int(minor)}"
    return f"{major}"


def _find_java(environ: Mapping[str, str], which: Callable[[str], str | None]) -> Path | None:
    java = which("java")
    if java:
        return Path(java).expanduser().resolve()
    java_home = environ.get("JAVA_HOME")
    if java_home:
        executable = (
            Path(java_home).expanduser() / "bin" / ("java.exe" if os.name == "nt" else "java")
        )
        if executable.is_file():
            return executable.resolve()
    return None


def _headless_launcher(install_dir: Path) -> Path | None:
    names = ("analyzeHeadless.bat", "analyzeHeadless")
    for name in names:
        path = install_dir / "support" / name
        if path.is_file():
            return path
    return None


def _headless_launcher_supported_by_host(launcher: Path) -> bool:
    expected = "analyzeheadless.bat" if os.name == "nt" else "analyzeheadless"
    return launcher.name.casefold() == expected


def detect_binary_input(path: Path) -> BinaryInput | None:
    """Recognize self-describing executable formats without trusting file extensions."""
    try:
        size = path.stat().st_size
        with path.open("rb") as stream:
            header = stream.read(64)
            if header.startswith(b"\x7fELF"):
                return BinaryInput("ELF", raw=False)
            if len(header) >= 2 and header[:2] == b"MZ" and size >= 0x40:
                offset = int.from_bytes(header[0x3C:0x40], "little")
                if offset <= size - 4:
                    stream.seek(offset)
                    if stream.read(4) == b"PE\0\0":
                        return BinaryInput("PE", raw=False)
            if header[:4] in {
                b"\xfe\xed\xfa\xce",
                b"\xce\xfa\xed\xfe",
                b"\xfe\xed\xfa\xcf",
                b"\xcf\xfa\xed\xfe",
                b"\xca\xfe\xba\xbe",
                b"\xbe\xba\xfe\xca",
                b"\xca\xfe\xba\xbf",
                b"\xbf\xba\xfe\xca",
            }:
                return BinaryInput("Mach-O", raw=False)
    except OSError:
        return None
    return None


def _normalize_raw_options(
    binary_input: BinaryInput | None,
    *,
    language: str | None,
    base_address: str | None,
    compiler_spec: str | None,
) -> tuple[str | None, str | None, str | None, str | None]:
    if binary_input is not None:
        if language is not None or base_address is not None or compiler_spec is not None:
            return (
                None,
                None,
                None,
                "Raw-language and base-address options only apply to raw binary input.",
            )
        return binary_input.format, None, None, None
    if language is None or base_address is None:
        return (
            None,
            None,
            None,
            (
                "Input is not a recognized ELF, PE, or Mach-O executable. For raw firmware, "
                "supply both --ghidra-language and --ghidra-base-address."
            ),
        )
    if not _RAW_LANGUAGE_PATTERN.fullmatch(language):
        return None, None, None, "The Ghidra language ID contains unsupported characters."
    if not _BASE_ADDRESS_PATTERN.fullmatch(base_address):
        return None, None, None, "The Ghidra base address must be hexadecimal or decimal."
    base_value = int(base_address, 16 if base_address.lower().startswith("0x") else 10)
    if base_value > 0xFFFFFFFFFFFFFFFF:
        return None, None, None, "The Ghidra base address exceeds the supported 64-bit range."
    if compiler_spec is not None and not _COMPILER_SPEC_PATTERN.fullmatch(compiler_spec):
        return (
            None,
            None,
            None,
            "The Ghidra compiler specification contains unsupported characters.",
        )
    return "raw", language, f"0x{base_value:x}", None


def _copy_and_hash_input(source: Path, destination: Path) -> tuple[str, int]:
    if source.is_symlink():
        raise ValueError("Symbolic-link firmware inputs are not followed.")
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    if hasattr(os, "O_BINARY"):
        flags |= os.O_BINARY
    descriptor = os.open(source, flags)
    digest = hashlib.sha256()
    byte_count = 0
    try:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise ValueError("Ghidra accepts one regular firmware or executable file.")
        with os.fdopen(descriptor, "rb", closefd=False) as source_stream:
            with destination.open("xb") as destination_stream:
                while block := source_stream.read(1024 * 1024):
                    byte_count += len(block)
                    if byte_count > GHIDRA_MAXIMUM_INPUT_BYTES:
                        raise ValueError(
                            f"Input exceeds the {GHIDRA_MAXIMUM_INPUT_BYTES}-byte Ghidra limit."
                        )
                    digest.update(block)
                    destination_stream.write(block)
    finally:
        os.close(descriptor)
    return digest.hexdigest(), byte_count


def _java_argument_file_line(value: str) -> str:
    escaped = value.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


def _normalized_json_value(value: object, key: str = "") -> object:
    if isinstance(value, dict):
        return {str(name): _normalized_json_value(item, str(name)) for name, item in value.items()}
    if isinstance(value, list):
        values = [_normalized_json_value(item, key) for item in value]
        if key == "records":
            values.sort(key=lambda item: json.dumps(item, sort_keys=True, ensure_ascii=False))
        return values
    if isinstance(value, str) and key in {"name", "function", "symbol", "value"}:
        return _redact_binary_string(value)
    return value


def _redact_binary_string(value: str) -> str:
    cleaned = safe_terminal_text(value).replace("\x00", " ").replace("\r", " ").replace("\n", " ")
    if (
        "-----BEGIN " in cleaned
        or _SECRET_TEXT_PATTERN.search(cleaned)
        or _JWT_PATTERN.search(cleaned)
    ):
        return "[redacted]"
    if _ENDPOINT_PATTERN.match(cleaned):
        try:
            parsed = urlsplit(cleaned)
            if parsed.scheme and parsed.hostname:
                hostname = parsed.hostname
                if ":" in hostname and not hostname.startswith("["):
                    hostname = f"[{hostname}]"
                port = f":{parsed.port}" if parsed.port is not None else ""
                return urlunsplit((parsed.scheme.casefold(), f"{hostname}{port}", "", "", ""))
        except ValueError:
            pass
    return cleaned[:256]


def _validate_result_document(
    document: object, digest: str, input_format: str
) -> dict[str, object]:
    if not isinstance(document, dict):
        raise ValueError("Ghidra result must be a JSON object.")
    if document.get("schema_version") != "1.0":
        raise ValueError("Unsupported Ghidra result schema version.")
    input_info = document.get("input")
    if not isinstance(input_info, dict) or input_info.get("sha256") != digest:
        raise ValueError("Ghidra result input digest does not match the staged input.")
    if input_info.get("format") != input_format:
        raise ValueError("Ghidra result format does not match the selected input loader.")
    if (
        set(input_info) != {"sha256", "format", "byte_size"}
        or not isinstance(input_info.get("byte_size"), int)
        or isinstance(input_info.get("byte_size"), bool)
        or not 0 <= input_info["byte_size"] <= GHIDRA_MAXIMUM_INPUT_BYTES
        or not isinstance(input_info.get("format"), str)
        or len(input_info["format"]) > 32
    ):
        raise ValueError("Ghidra input metadata does not match the artifact schema.")
    tool = document.get("tool")
    if (
        not isinstance(tool, dict)
        or set(tool) != {"name", "version"}
        or tool.get("name") != "Ghidra"
        or not isinstance(tool.get("version"), str)
        or not tool["version"]
        or len(tool["version"]) > 64
    ):
        raise ValueError("Ghidra result tool identity is missing.")
    analysis = document.get("analysis")
    analysis_fields = {
        "status",
        "timeout_occurred",
        "loader",
        "processor",
        "language_id",
        "compiler_spec",
        "endianness",
        "pointer_size_bytes",
        "image_base",
        "entry_points",
        "warnings",
        "errors",
    }
    if (
        not isinstance(analysis, dict)
        or set(analysis) != analysis_fields
        or analysis.get("status") not in {"completed", "partial"}
        or not isinstance(analysis.get("timeout_occurred"), bool)
        or analysis.get("endianness") not in {"little", "big"}
        or not isinstance(analysis.get("pointer_size_bytes"), int)
        or isinstance(analysis.get("pointer_size_bytes"), bool)
        or not 1 <= analysis["pointer_size_bytes"] <= 16
    ):
        raise ValueError("Ghidra analysis status is invalid.")
    for field_name, maximum in (
        ("loader", 128),
        ("processor", 128),
        ("language_id", 128),
        ("compiler_spec", 128),
        ("image_base", 128),
    ):
        if not isinstance(analysis.get(field_name), str) or len(analysis[field_name]) > maximum:
            raise ValueError(f"Ghidra analysis field {field_name} is invalid.")
    for field_name, maximum_items, maximum_chars in (
        ("entry_points", 1024, 128),
        ("warnings", 64, 512),
        ("errors", 64, 512),
    ):
        values = analysis.get(field_name)
        if (
            not isinstance(values, list)
            or len(values) > maximum_items
            or any(not isinstance(value, str) or len(value) > maximum_chars for value in values)
        ):
            raise ValueError(f"Ghidra analysis list {field_name} is invalid.")
    required_bounded = (
        "memory_blocks",
        "functions",
        "symbols",
        "imports",
        "exports",
        "strings",
        "cross_references",
        "api_references",
    )
    for name in required_bounded:
        group = document.get(name)
        if not isinstance(group, dict):
            raise ValueError(f"Ghidra result is missing the {name} inventory.")
        records = group.get("records")
        observed = group.get("observed")
        reported = group.get("reported")
        if (
            not isinstance(records, list)
            or not isinstance(observed, int)
            or isinstance(observed, bool)
            or not isinstance(reported, int)
            or isinstance(reported, bool)
            or reported != len(records)
            or observed < reported
            or not isinstance(group.get("truncated"), bool)
            or not isinstance(group.get("observed_is_lower_bound"), bool)
        ):
            raise ValueError(f"Ghidra result has invalid bounds for {name}.")
        if any(not isinstance(record, dict) for record in records):
            raise ValueError(f"Ghidra result contains a malformed {name} record.")
    record_fields: dict[str, dict[str, type | tuple[type, ...]]] = {
        "memory_blocks": {
            "name": str,
            "start": str,
            "end": str,
            "byte_size": int,
            "initialized": bool,
            "read": bool,
            "write": bool,
            "execute": bool,
        },
        "functions": {"name": str, "entry_address": str, "external": bool, "thunk": bool},
        "symbols": {
            "name": str,
            "address": str,
            "type": str,
            "external": bool,
            "entry_point": bool,
        },
        "imports": {
            "name": str,
            "address": str,
            "type": str,
            "external": bool,
            "entry_point": bool,
        },
        "exports": {
            "name": str,
            "address": str,
            "type": str,
            "external": bool,
            "entry_point": bool,
        },
        "strings": {"address": str, "value": str, "redacted": bool},
        "cross_references": {
            "string_address": str,
            "from_address": str,
            "function": str,
            "function_entry_address": str,
            "reference_type": str,
        },
        "api_references": {
            "symbol": str,
            "address": str,
            "function": str,
            "function_entry_address": str,
        },
    }
    string_limits = {
        "name": 128,
        "start": 128,
        "end": 128,
        "entry_address": 128,
        "address": 128,
        "type": 64,
        "value": 256,
        "string_address": 128,
        "from_address": 128,
        "function": 128,
        "function_entry_address": 128,
        "reference_type": 64,
        "symbol": 128,
    }
    for name, fields in record_fields.items():
        group = document[name]
        assert isinstance(group, dict)
        records_value = group["records"]
        assert isinstance(records_value, list)
        expected_fields = set(fields)
        for record in records_value:
            assert isinstance(record, dict)
            if set(record) != expected_fields:
                raise ValueError(f"Ghidra {name} record has unknown or missing fields.")
            for field_name, expected_type in fields.items():
                value = record[field_name]
                if not isinstance(value, expected_type) or (
                    expected_type is int and isinstance(value, bool)
                ):
                    raise ValueError(f"Ghidra {name}.{field_name} has an invalid value type.")
                if isinstance(value, str) and len(value) > string_limits[field_name]:
                    raise ValueError(f"Ghidra {name}.{field_name} exceeds its text limit.")
                if field_name == "byte_size" and isinstance(value, int) and value < 0:
                    raise ValueError("Ghidra memory block size cannot be negative.")
    limits = document.get("limits")
    truncation = document.get("truncation")
    if not isinstance(limits, dict) or not isinstance(truncation, dict):
        raise ValueError("Ghidra result limits or truncation metadata are missing.")
    limit_keys = {
        "max_functions",
        "max_symbols",
        "max_imports",
        "max_exports",
        "max_strings",
        "max_string_scan_items",
        "max_cross_references",
        "max_api_references",
        "max_memory_blocks",
        "max_name_chars",
        "max_string_chars",
        "max_output_bytes",
    }
    if set(limits) != limit_keys or any(
        not isinstance(value, int) or isinstance(value, bool) or value <= 0
        for value in limits.values()
    ):
        raise ValueError("Ghidra result limit values are invalid.")
    truncation_keys = set(required_bounded)
    if set(truncation) != truncation_keys or any(
        not isinstance(value, bool) for value in truncation.values()
    ):
        raise ValueError("Ghidra result truncation values are invalid.")
    if any(
        truncation[name] != document[name]["truncated"]
        for name in truncation_keys
        if isinstance(document[name], dict)
    ):
        raise ValueError("Ghidra result truncation summary does not match its inventories.")
    return document


def _findings_from_document(
    document: dict[str, object],
    *,
    input_path: Path,
    input_digest: str,
) -> tuple[Finding, ...]:
    strings = document.get("strings")
    references = document.get("cross_references")
    if not isinstance(strings, dict) or not isinstance(references, dict):
        return ()
    string_records = strings.get("records")
    reference_records = references.get("records")
    if not isinstance(string_records, list) or not isinstance(reference_records, list):
        return ()
    strings_by_address = {
        record.get("address"): record.get("value")
        for record in string_records
        if isinstance(record, dict)
        and isinstance(record.get("address"), str)
        and isinstance(record.get("value"), str)
    }
    findings: list[Finding] = []
    seen: set[tuple[str, str, str]] = set()
    for reference in reference_records:
        if not isinstance(reference, dict):
            continue
        address = reference.get("string_address")
        function = reference.get("function")
        from_address = reference.get("from_address")
        value = strings_by_address.get(address)
        if (
            not isinstance(address, str)
            or not isinstance(function, str)
            or not isinstance(from_address, str)
            or not isinstance(value, str)
        ):
            continue
        endpoint = value
        scheme = urlsplit(endpoint).scheme.casefold()
        if scheme not in {"http", "mqtt"}:
            continue
        rule_id = "FUSE-BIN-001" if scheme == "http" else "FUSE-BIN-002"
        marker = (rule_id, address, function)
        if marker in seen:
            continue
        seen.add(marker)
        short_digest = hashlib.sha256(
            f"{input_digest}\0{rule_id}\0{address}\0{function}".encode("utf-8")
        ).hexdigest()
        title = (
            "Referenced plaintext HTTP endpoint in executable"
            if scheme == "http"
            else "Referenced plaintext MQTT endpoint in executable"
        )
        findings.append(
            Finding(
                id=f"{rule_id}:{short_digest[:12]}",
                fingerprint=short_digest,
                rule_id=rule_id,
                rule_version="1.0.0",
                analyzer="ghidra",
                title=title,
                severity="low",
                confidence="high",
                category="insecure-communication",
                file=safe_terminal_text(input_path.name)[:160],
                start_line=None,
                end_line=None,
                evidence=(
                    f"Static reference from {function} at {from_address} to {scheme} endpoint "
                    f"{endpoint} at {address}. URL path, credentials, query, and fragment are omitted."
                ),
                explanation=(
                    "Ghidra identified a code cross-reference from a function to a plaintext "
                    "network endpoint string. Static reference evidence does not prove that the "
                    "function executes, the endpoint is reachable, or traffic uses this value."
                ),
                potential_impact=(
                    "If the referenced endpoint is used for device communication, data or control "
                    "traffic may be observable or modifiable on the network path."
                ),
                remediation=(
                    "Confirm the endpoint's runtime use and replace plaintext transport with a "
                    "supported authenticated TLS transport. Verify certificate and hostname checks "
                    "in the target implementation."
                ),
                applicability="candidate",
                validation_method="static",
                validation_status="not-validated",
            )
        )
    findings.sort(key=lambda item: (item.rule_id, item.file.casefold(), item.evidence))
    return tuple(findings)


def _java_command_arguments(
    probe: GhidraProbe,
    *,
    workspace: Path,
    staged_input: Path,
    script_path: Path,
    raw_output: Path,
    digest: str,
    input_format: str,
    input_size: int,
    timeout_seconds: int,
    language: str | None,
    base_address: str | None,
    compiler_spec: str | None,
) -> list[str]:
    if probe.install_dir is None or probe.java_executable is None:
        raise ValueError("Validated Ghidra installation details are missing.")
    install_dir = probe.install_dir
    utility_jar = install_dir / "Ghidra" / "Framework" / "Utility" / "lib" / "Utility.jar"
    if not utility_jar.is_file():
        raise ValueError("The Ghidra bootstrap library is missing from the selected installation.")
    if ";" in str(install_dir) or ";" in str(script_path.parent):
        raise ValueError("Ghidra installation and script paths cannot contain semicolons.")

    headless = [
        str(workspace).replace("\\", "/"),
        "fuse-analysis",
        "-import",
        str(staged_input).replace("\\", "/"),
        "-readOnly",
        "-deleteProject",
        "-analysisTimeoutPerFile",
        str(max(1, timeout_seconds - 10)),
        "-max-cpu",
        "1",
        "-scriptPath",
        str(script_path.parent).replace("\\", "/"),
        "-postScript",
        script_path.name,
        str(raw_output).replace("\\", "/"),
        digest,
        input_format,
        str(input_size),
    ]
    if input_format == "raw":
        assert language is not None and base_address is not None
        headless.extend(
            [
                "-loader",
                "BinaryLoader",
                "-loader-baseAddr",
                base_address,
                "-processor",
                language,
            ]
        )
        if compiler_spec is not None:
            headless.extend(["-cspec", compiler_spec])

    return [
        "-Xmx2G",
        "-XX:ParallelGCThreads=2",
        "-XX:CICompilerCount=2",
        "-Djava.awt.headless=true",
        "-Djava.system.class.loader=ghidra.GhidraClassLoader",
        f"-Dghidra.install.dir={str(install_dir).replace(chr(92), '/')}",
        "-cp",
        str(utility_jar).replace("\\", "/"),
        "ghidra.Ghidra",
        "ghidra.app.util.headless.AnalyzeHeadless",
        *headless,
    ]


def analyze_ghidra(
    input_path: Path,
    output_dir: Path,
    *,
    configured_install_dir: str | Path | None = None,
    timeout_seconds: int = GHIDRA_DEFAULT_TIMEOUT_SECONDS,
    language: str | None = None,
    base_address: str | None = None,
    compiler_spec: str | None = None,
) -> AdapterResult:
    """Analyze one executable using FUSE's trusted Ghidra script and bounded process runner."""
    if analyzer_sandbox_active():
        return AdapterResult(
            AnalyzerStatus(
                "ghidra",
                "unsupported",
                detail="Docker analyzer mode does not support Ghidra; no host fallback was attempted.",
            )
        )
    if not GHIDRA_MINIMUM_TIMEOUT_SECONDS <= timeout_seconds <= GHIDRA_MAXIMUM_TIMEOUT_SECONDS:
        return AdapterResult(
            AnalyzerStatus(
                "ghidra",
                "failed",
                detail=(
                    f"Ghidra timeout must be between {GHIDRA_MINIMUM_TIMEOUT_SECONDS} and "
                    f"{GHIDRA_MAXIMUM_TIMEOUT_SECONDS} seconds."
                ),
            )
        )
    probe = inspect_ghidra(configured_install_dir)
    if probe.status != "available":
        mapped_status: Literal["unavailable", "incompatible", "unsupported"] = probe.status
        return AdapterResult(
            AnalyzerStatus("ghidra", mapped_status, version=probe.version, detail=probe.detail)
        )
    if input_path.is_symlink() or not input_path.is_file():
        return AdapterResult(
            AnalyzerStatus(
                "ghidra",
                "unsupported",
                version=probe.version,
                detail="Ghidra accepts one regular firmware or executable file.",
            )
        )
    try:
        size = input_path.stat().st_size
    except OSError:
        return AdapterResult(
            AnalyzerStatus(
                "ghidra",
                "failed",
                version=probe.version,
                detail="Could not read the selected firmware input metadata.",
            )
        )
    if size > GHIDRA_MAXIMUM_INPUT_BYTES:
        return AdapterResult(
            AnalyzerStatus(
                "ghidra",
                "unsupported",
                version=probe.version,
                detail=f"Input exceeds the {GHIDRA_MAXIMUM_INPUT_BYTES}-byte Ghidra limit.",
            )
        )
    binary_input = detect_binary_input(input_path)
    input_format, language, base_address, raw_error = _normalize_raw_options(
        binary_input,
        language=language,
        base_address=base_address,
        compiler_spec=compiler_spec,
    )
    if raw_error is not None or input_format is None:
        return AdapterResult(
            AnalyzerStatus(
                "ghidra",
                "unsupported",
                version=probe.version,
                detail=raw_error or "Input format is not supported.",
            )
        )

    try:
        with tempfile.TemporaryDirectory(prefix="vigil-fuse-ghidra-") as temporary:
            workspace = Path(temporary)
            staged_input = workspace / "input.bin"
            raw_output = workspace / "ghidra-raw.json"
            project_dir = workspace / "project"
            project_dir.mkdir()
            try:
                digest, byte_size = _copy_and_hash_input(input_path, staged_input)
            except (OSError, ValueError) as error:
                return AdapterResult(
                    AnalyzerStatus(
                        "ghidra",
                        "unsupported",
                        version=probe.version,
                        detail=str(error)[:320],
                    )
                )

            resource = files("vigil_fuse").joinpath("resources", "ghidra", "FuseExport.java")
            with as_file(resource) as script_path:
                arguments = _java_command_arguments(
                    probe,
                    workspace=project_dir,
                    staged_input=staged_input,
                    script_path=script_path,
                    raw_output=raw_output,
                    digest=digest,
                    input_format=input_format,
                    input_size=byte_size,
                    timeout_seconds=timeout_seconds,
                    language=language,
                    base_address=base_address,
                    compiler_spec=compiler_spec,
                )
                argument_file = workspace / "java.args"
                argument_file.write_text(
                    "\n".join(_java_argument_file_line(argument) for argument in arguments) + "\n",
                    encoding="utf-8",
                )
                command = [str(probe.java_executable), f"@{argument_file}"]
                completed = _run(
                    command,
                    timeout=timeout_seconds,
                    cwd=workspace,
                    output_limit_bytes=GHIDRA_MAXIMUM_DIAGNOSTIC_BYTES,
                    environment_exclude=_JAVA_ENVIRONMENT_OVERRIDES,
                )
            if not raw_output.is_file():
                return AdapterResult(
                    AnalyzerStatus(
                        "ghidra",
                        "failed",
                        version=probe.version,
                        detail=(
                            f"Ghidra exited with code {completed.returncode} without producing "
                            "the structured FUSE result."
                        ),
                    )
                )
            if raw_output.stat().st_size > GHIDRA_MAXIMUM_ARTIFACT_BYTES:
                return AdapterResult(
                    AnalyzerStatus(
                        "ghidra",
                        "failed",
                        version=probe.version,
                        detail="Ghidra result exceeded the 8 MiB artifact limit.",
                    )
                )
            try:
                document = _validate_result_document(
                    json.loads(raw_output.read_text(encoding="utf-8")), digest, input_format
                )
            except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as error:
                return AdapterResult(
                    AnalyzerStatus(
                        "ghidra",
                        "failed",
                        version=probe.version,
                        detail=f"Ghidra result was malformed or invalid ({type(error).__name__}).",
                    )
                )
            normalized = _normalized_json_value(document)
            if not isinstance(normalized, dict):
                raise ValueError("Normalized Ghidra result must remain a JSON object.")
            normalized_text = (
                json.dumps(normalized, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
            )
            if len(normalized_text.encode("utf-8")) > GHIDRA_MAXIMUM_ARTIFACT_BYTES:
                return AdapterResult(
                    AnalyzerStatus(
                        "ghidra",
                        "failed",
                        version=probe.version,
                        detail="Normalized Ghidra artifact exceeded the 8 MiB output limit.",
                    )
                )
            if output_dir.is_symlink():
                raise OSError("Refusing to write Ghidra output through a symbolic-link directory.")
            if output_dir.exists() and not output_dir.is_dir():
                raise OSError("Ghidra output path is not a directory.")
            output_dir.mkdir(parents=True, exist_ok=True)
            artifact_path = _artifact_destination(output_dir, "ghidra-analysis.json")
            artifact_path.write_text(normalized_text, encoding="utf-8")
            artifact = _artifact(
                artifact_path,
                "application/vnd.vigil-fuse.ghidra-analysis+json",
                output_dir,
            )
            findings = _findings_from_document(
                normalized,
                input_path=input_path,
                input_digest=digest,
            )
            analysis = normalized.get("analysis")
            timed_out = isinstance(analysis, dict) and analysis.get("timeout_occurred") is True
            if completed.returncode != 0:
                status: Literal["completed", "partial", "failed"] = "failed"
                detail = f"Ghidra Headless Analyzer exited with code {completed.returncode}."
            elif timed_out or (isinstance(analysis, dict) and analysis.get("status") == "partial"):
                status = "partial"
                detail = "Ghidra completed with an analysis timeout or reported truncation; review artifact limits."
            else:
                status = "completed"
                detail = "Ghidra Headless Analyzer completed bounded static analysis; no target code was executed."
            return AdapterResult(
                AnalyzerStatus(
                    "ghidra",
                    status,
                    version=probe.version,
                    detail=detail,
                    findings=len(findings),
                ),
                findings=findings,
                artifacts=(artifact,),
            )
    except subprocess.TimeoutExpired:
        return AdapterResult(
            AnalyzerStatus(
                "ghidra",
                "timeout",
                version=probe.version,
                detail=f"Ghidra exceeded the {timeout_seconds}-second wall-time limit; its process tree was terminated.",
            )
        )
    except AnalyzerOutputLimitError:
        return AdapterResult(
            AnalyzerStatus(
                "ghidra",
                "failed",
                version=probe.version,
                detail="Ghidra diagnostics exceeded the 10 MiB process-output limit.",
            )
        )
    except (OSError, ValueError, RuntimeError) as error:
        return AdapterResult(
            AnalyzerStatus(
                "ghidra",
                "failed",
                version=probe.version,
                detail=f"Ghidra could not complete analysis ({type(error).__name__}).",
            )
        )
