"""Passive runtime evidence adapters. These APIs never execute a target program."""

from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import re
from typing import Any, Callable

from .evidence_graph import EvidenceGraph, identity, object_fields, relative_path, text
from .firmware_rootfs import digest

TOOLS = {
    "ASan": "AddressSanitizer",
    "MSan": "MemorySanitizer",
    "TSan": "ThreadSanitizer",
    "LSan": "LeakSanitizer",
    "UBSan": "UndefinedBehaviorSanitizer",
}
MAX_LOG = 4 * 1024 * 1024


@dataclass(frozen=True)
class RuntimeObservation:
    tool: str
    tool_version: str
    artifact: dict[str, str]
    process: dict[str, Any]
    stack_trace: list[dict[str, Any]]
    source_location: dict[str, Any] | None
    error_class: str
    reproducer_reference: str | None
    validation_state: str = "runtime-observed"


def _location(value: str, source_root: str) -> dict[str, Any] | None:
    match = re.fullmatch(r"(.+?):([0-9]+)(?::([0-9]+))?", value.strip())
    if not match:
        return None
    path = match[1].replace("\\", "/")
    root = source_root.replace("\\", "/").rstrip("/")
    if root and path.startswith(root + "/"):
        path = path[len(root) + 1 :]
    try:
        path = relative_path(path)
    except ValueError:
        return None
    line, column = int(match[2]), int(match[3] or 1)
    if not 1 <= line <= 100000000 or not 1 <= column <= 1000000:
        raise ValueError("Invalid runtime location")
    return {"file": path, "line": line, "column": column}


def validate_observation(value: object) -> dict[str, Any]:
    row = object_fields(value, set(RuntimeObservation.__dataclass_fields__))
    for key in ("tool", "tool_version", "error_class"):
        text(row[key])
    object_fields(row["artifact"], {"sha256", "reference"})
    digest(row["artifact"]["sha256"])
    text(row["artifact"]["reference"])
    object_fields(row["process"], {"pid", "binary_sha256"})
    digest(row["process"]["binary_sha256"])
    pid = row["process"]["pid"]
    if pid is not None and (type(pid) is not int or not 1 <= pid <= 4294967295):
        raise ValueError("Invalid runtime process")
    if row["validation_state"] != "runtime-observed":
        raise ValueError("Runtime evidence cannot claim deployed exploitability")
    if row["reproducer_reference"] is not None:
        text(row["reproducer_reference"])
    stack = row["stack_trace"]
    if not isinstance(stack, list) or len(stack) > 64:
        raise ValueError("Runtime stack limit")
    for frame in stack:
        object_fields(frame, {"function", "location"})
        text(frame["function"])
    for location in [row["source_location"], *(f["location"] for f in stack)]:
        if location is None:
            continue
        object_fields(location, {"file", "line", "column"})
        relative_path(location["file"])
        if any(
            type(location[k]) is not int or not 1 <= location[k] <= 100000000
            for k in ("line", "column")
        ):
            raise ValueError("Invalid runtime source location")
    return row


def parse_sanitizer(payload: bytes, metadata: dict[str, Any]) -> dict[str, Any]:
    """Read symbolized Clang sanitizer diagnostics; discard messages and target output."""
    object_fields(
        metadata,
        {
            "tool",
            "tool_version",
            "binary_sha256",
            "artifact_reference",
            "source_root",
            "reproducer_reference",
        },
    )
    tool = metadata["tool"]
    if tool not in TOOLS or len(payload) > MAX_LOG:
        raise ValueError("Unsupported sanitizer or oversized log")
    for key in ("tool_version", "artifact_reference", "source_root"):
        if metadata[key] != "" or key != "source_root":
            text(metadata[key])
    digest(metadata["binary_sha256"])
    artifact = {
        "sha256": hashlib.sha256(payload).hexdigest(),
        "reference": metadata["artifact_reference"],
    }
    observations: list[dict[str, Any]] = []
    current: dict[str, Any] | None = None
    truncated = False
    for line in payload.decode("utf-8", errors="replace").splitlines():
        if len(line) > 16384:
            raise ValueError("Runtime diagnostic line limit")
        header = re.search(r"(?:ERROR|WARNING): " + TOOLS[tool] + r": ([A-Za-z0-9_-]+)", line)
        location = None
        error = header[1] if header else None
        if header and tool == "TSan" and "data race" in line:
            error = "data-race"
        if header and tool == "LSan":
            error = "memory-leak"
        if tool == "UBSan" and ": runtime error: " in line:
            prefix, message = line.split(": runtime error: ", 1)
            location = _location(prefix, metadata["source_root"])
            error = next(
                (
                    name
                    for pattern, name in (
                        ("signed integer overflow", "signed-integer-overflow"),
                        ("unsigned integer overflow", "unsigned-integer-overflow"),
                        ("out of bounds", "out-of-bounds"),
                        ("null pointer", "null-pointer"),
                        ("misaligned address", "misaligned-address"),
                        ("division by zero", "division-by-zero"),
                        ("shift exponent", "invalid-shift"),
                    )
                    if pattern in message
                ),
                "undefined-behavior",
            )
        if error:
            if len(observations) >= 256:
                raise ValueError("Runtime observation limit")
            pid_match = re.search(r"==([0-9]+)==|\(pid=([0-9]+)\)", line)
            pid = int(pid_match[1] or pid_match[2]) if pid_match else None
            current = asdict(
                RuntimeObservation(
                    tool,
                    metadata["tool_version"],
                    artifact,
                    {"pid": pid, "binary_sha256": metadata["binary_sha256"]},
                    [],
                    location,
                    error,
                    metadata["reproducer_reference"],
                )
            )
            observations.append(current)
            continue
        if current is None or not line.lstrip().startswith("#"):
            continue
        if len(current["stack_trace"]) >= 64:
            truncated = True
            continue
        frame = re.search(
            r"#\d+\s+(?:0x[0-9a-fA-F]+\s+)?(?:in\s+)?(.+?)\s+(\S+:\d+(?::\d+)?)\s*$", line
        )
        if frame:
            function = frame[1].split("(", 1)[0].strip()
            if not re.fullmatch(r"[A-Za-z_$~][A-Za-z0-9_$~:<>., *]*", function):
                function = "unknown"
            location = _location(frame[2], metadata["source_root"])
            current["stack_trace"].append({"function": function, "location": location})
            if current["source_location"] is None:
                current["source_location"] = location
    unique = {identity("runtime", validate_observation(row)): row for row in observations}
    return {
        "schema_version": "1.0",
        "status": "partial" if truncated or not unique else "completed",
        "observations": [unique[key] for key in sorted(unique)],
        "limitations": [
            "Logs are external assertions; artifact and build identity require independent verification.",
            "A runtime error does not establish deployed exploitability or physical accessibility.",
            "Unmapped paths, unsymbolized frames, program output, addresses and diagnostic values are omitted.",
        ],
    }


RuntimeAdapter = Callable[[bytes, dict[str, Any]], dict[str, Any]]


def ingest_runtime(
    payload: bytes, metadata: dict[str, Any], *, adapter: RuntimeAdapter = parse_sanitizer
) -> dict[str, Any]:
    """Adapter boundary reusable by future passive crash/proof importers."""
    if len(payload) > MAX_LOG:
        raise ValueError("Runtime artifact limit")
    result = adapter(payload, metadata)
    object_fields(result, {"schema_version", "status", "observations", "limitations"})
    from .evidence_graph import strings

    if result["schema_version"] != "1.0" or result["status"] not in {
        "completed",
        "partial",
        "unsupported",
        "unavailable",
        "failed",
        "timeout",
    }:
        raise ValueError("Invalid runtime adapter envelope")
    strings(result["limitations"])
    if not isinstance(result["observations"], list) or len(result["observations"]) > 256:
        raise ValueError("Runtime observation limit")
    for row in result["observations"]:
        validate_observation(row)
    return result


def add_runtime(
    graph: EvidenceGraph, document: dict[str, Any], links: list[dict[str, Any]] | None = None
) -> list[str]:
    document = ingest_runtime(b"", {}, adapter=lambda _payload, _metadata: document)
    ids = []
    for row in document["observations"]:
        run = graph.run(
            row["tool"],
            document["status"],
            version=row["tool_version"],
            artifact=row["artifact"]["sha256"],
        )
        node = graph.node("RuntimeObservation", identity("runtime", row), observation=row)
        binary = graph.node("Binary", row["process"]["binary_sha256"])
        graph.edge(
            node,
            binary,
            "derived_from",
            producer=run,
            method="runtime-log-import",
            evidence_refs=[row["artifact"]["reference"]],
            assertion="ASSERTED",
            limitations=document["limitations"],
        )
        ids.append(node)
    if links is not None and (not isinstance(links, list) or len(links) > 1000):
        raise ValueError("Runtime link limit")
    for link in links or []:
        object_fields(link, {"observation", "target", "artifact", "method"})
        if (
            link["observation"] not in ids
            or link["target"] not in graph.nodes
            or graph.nodes[link["target"]]["type"] not in {"Finding", "Function", "CallPath"}
        ):
            raise ValueError("Dangling runtime support")
        text(link["artifact"])
        text(link["method"])
        observation = graph.nodes[link["observation"]]["attributes"]["observation"]
        run = graph.run("runtime-correlation", "completed", artifact=link["artifact"])
        graph.edge(
            link["observation"],
            link["target"],
            "supports",
            producer=run,
            method=link["method"],
            evidence_refs=[link["artifact"], observation["artifact"]["reference"]],
            assertion="ASSERTED",
            limitations=[
                "Explicit reviewer correspondence; static finding verdict is unchanged.",
                "Supports a test observation, not deployed exploitability.",
            ],
        )
    return ids
