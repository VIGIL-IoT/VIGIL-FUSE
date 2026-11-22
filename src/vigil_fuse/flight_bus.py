"""Bounded extraction of cFE software-bus call evidence from C source."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import re
from typing import Mapping

from .c_source import mask_c
from .json_limits import bounded_json

MAX_BUS_FILES = 512
MAX_BUS_FILE_BYTES = 2 * 1024 * 1024
MAX_BUS_TOTAL_BYTES = 10 * 1024 * 1024
MAX_BUS_CALLS = 10_000
MAX_BUS_ARGUMENT_CHARS = 4096
MAX_BUS_CALL_DEPTH = 64
MAX_BUS_GRAPH_EDGES = 20_000
MAX_BUS_GRAPH_NODES = 30_000
MAX_BUS_GRAPH_JSON_BYTES = 4 * 1024 * 1024
_CALL = re.compile(
    r"\b(CFE_SB_CreatePipe|CFE_SB_SubscribeEx|CFE_SB_Subscribe|"
    r"CFE_SB_TransmitMsg|CFE_SB_TransmitBuffer|CFE_MSG_SetMsgId)\s*\("
)
_MESSAGE_EXPRESSION = re.compile(
    r"[A-Za-z_]\w*|0[xX][0-9A-Fa-f]+|\d+|CFE_SB_ValueToMsgId\(\s*[A-Za-z_]\w*\s*\)"
)
_OBJECT_TARGET = r"&?\s*[A-Za-z_]\w*(?:(?:\.|->)[A-Za-z_]\w*)*"
_OBJECT_EXPRESSION = re.compile(rf"(?:CFE_MSG_PTR\(\s*{_OBJECT_TARGET}\s*\)|{_OBJECT_TARGET})")


@dataclass(frozen=True)
class BusCall:
    file: str
    line: int
    api: str
    arguments: tuple[str, ...]


@dataclass(frozen=True)
class BusCalls:
    status: str
    calls: tuple[BusCall, ...]
    limitations: tuple[str, ...]


@dataclass(frozen=True)
class BusNode:
    id: str
    kind: str
    label: str


@dataclass(frozen=True)
class BusEdge:
    source: str
    relation: str
    target: str
    file: str
    line: int
    api: str


@dataclass(frozen=True)
class BusObservation:
    rule_id: str
    severity: str
    confidence: str
    applicability: str
    validation_status: str
    pipe_id: str
    message_id: str
    pipe: str
    message_expression: str
    count: int
    evidence: tuple[str, ...]


@dataclass(frozen=True)
class BusComponent:
    name: str
    criticality: str | None
    trust: str | None


@dataclass(frozen=True)
class BusPolicyObservation:
    rule_id: str
    severity: str
    confidence: str
    applicability: str
    validation_status: str
    application: str
    message_expression: str
    evidence: str


@dataclass(frozen=True)
class BusGraph:
    status: str
    nodes: tuple[BusNode, ...]
    edges: tuple[BusEdge, ...]
    limitations: tuple[str, ...]
    observations: tuple[BusObservation, ...] = ()
    policy_source: str | None = None
    policy_sha256: str | None = None
    components: tuple[BusComponent, ...] = ()
    policy_observations: tuple[BusPolicyObservation, ...] = ()

    def to_json(self) -> str:
        return bounded_json(self, MAX_BUS_GRAPH_JSON_BYTES, indent=2)


def extract_bus_calls(files: Mapping[str, bytes]) -> BusCalls:
    """Extract literal call expressions; no C preprocessing or target execution occurs."""
    limitations = {
        "C preprocessing, data flow, application ownership, and runtime routing are not resolved.",
        "Recognized expressions may include declarations or inactive code.",
    }
    if len(files) > MAX_BUS_FILES:
        return BusCalls("partial", (), ("Software-bus file limit exceeded.",))
    if sum(map(len, files.values())) > MAX_BUS_TOTAL_BYTES:
        return BusCalls("partial", (), ("Software-bus total byte limit exceeded.",))
    calls: list[BusCall] = []
    for name, data in sorted(files.items()):
        if len(data) > MAX_BUS_FILE_BYTES:
            limitations.add("At least one source file exceeded the byte limit.")
            continue
        try:
            text = data.decode("utf-8-sig")
        except UnicodeDecodeError:
            limitations.add("At least one source file is not UTF-8.")
            continue
        masked, complete = mask_c(text)
        if not complete:
            limitations.add("At least one source file has an unterminated comment or string.")
        previous = 0
        line = 1
        for match in _CALL.finditer(masked):
            line += text.count("\n", previous, match.start())
            previous = match.start()
            if len(calls) >= MAX_BUS_CALLS:
                limitations.add("Software-bus call limit reached.")
                return BusCalls("partial", tuple(calls), tuple(sorted(limitations)))
            start = match.end()
            index = start
            depth = 1
            parts: list[str] = []
            part_start = start
            while index < len(masked) and index - start <= MAX_BUS_ARGUMENT_CHARS:
                char = masked[index]
                if char == "(":
                    depth += 1
                    if depth > MAX_BUS_CALL_DEPTH:
                        break
                elif char == ")":
                    depth -= 1
                    if depth == 0:
                        parts.append(text[part_start:index].strip())
                        break
                elif char == "," and depth == 1:
                    parts.append(text[part_start:index].strip())
                    part_start = index + 1
                index += 1
            if depth != 0:
                limitations.add("At least one call was malformed or exceeded a parsing limit.")
                continue
            calls.append(BusCall(name, line, match.group(1), tuple(parts)))
    # shortcut: C preprocessing and control flow are unresolved, upgrade before complete graphs.
    return BusCalls("partial", tuple(calls), tuple(sorted(limitations)))


def build_bus_graph(extraction: BusCalls, applications: Mapping[str, str]) -> BusGraph:
    """Build symbolic relationships only for files assigned to an application by the caller."""
    nodes: dict[str, BusNode] = {}
    edges: list[BusEdge] = []
    limitations = set(extraction.limitations)
    limitations.add(
        "Application ownership is supplied by the caller and not independently verified."
    )
    limitations.add("Message expressions are symbolic; matching names do not prove matching IDs.")
    limitations.add("Transmit message IDs and execution order are not resolved by data flow.")

    def node(kind: str, label: str, scope: str = "") -> str:
        digest = hashlib.sha256(f"{kind}\0{scope}\0{label}".encode("utf-8")).hexdigest()
        identifier = f"{kind}:{digest}"
        nodes.setdefault(identifier, BusNode(identifier, kind, label))
        return identifier

    if len(extraction.calls) > MAX_BUS_CALLS:
        limitations.add("Software-bus call limit reached; remaining calls were omitted.")
    for call in extraction.calls[:MAX_BUS_CALLS]:
        application = applications.get(call.file)
        if not application or len(application) > 512 or "\0" in application:
            limitations.add("Calls in files without an application assignment were omitted.")
            continue
        if any(len(argument) > MAX_BUS_ARGUMENT_CHARS for argument in call.arguments):
            limitations.add("An oversized call argument was omitted.")
            continue
        if len(nodes) + 3 > MAX_BUS_GRAPH_NODES or len(edges) + 2 > MAX_BUS_GRAPH_EDGES:
            limitations.add("Software-bus graph limit reached; remaining calls were omitted.")
            break
        app = node("flight_application", application)
        args = call.arguments
        if (
            call.api == "CFE_SB_CreatePipe"
            and args
            and re.fullmatch(r"&\s*[A-Za-z_]\w*(?:(?:\.|->)[A-Za-z_]\w*)*", args[0])
        ):
            pipe = node("software_bus_pipe", re.sub(r"\s+", "", args[0])[1:], application)
            edges.append(BusEdge(app, "creates", pipe, call.file, call.line, call.api))
        elif call.api in {"CFE_SB_Subscribe", "CFE_SB_SubscribeEx"} and len(args) >= 2:
            expression, pipe_expression = args[:2]
            if not re.fullmatch(r"[A-Za-z_]\w*(?:(?:\.|->)[A-Za-z_]\w*)*", pipe_expression):
                limitations.add("At least one pipe expression could not be resolved symbolically.")
                continue
            if not _MESSAGE_EXPRESSION.fullmatch(expression):
                limitations.add(
                    "At least one message expression could not be resolved symbolically."
                )
                continue
            pipe = node("software_bus_pipe", pipe_expression, application)
            message = node("message_expression", re.sub(r"\s+", "", expression))
            edges.append(BusEdge(pipe, "subscribes_to", message, call.file, call.line, call.api))
            edges.append(BusEdge(app, "subscribes_to", message, call.file, call.line, call.api))
        elif call.api in {"CFE_SB_TransmitMsg", "CFE_SB_TransmitBuffer"} and args and args[0]:
            expression = (
                re.sub(r"\s+", "", args[0]) if _OBJECT_EXPRESSION.fullmatch(args[0]) else args[0]
            )
            message = node("message_object_expression", expression, application)
            edges.append(BusEdge(app, "transmits", message, call.file, call.line, call.api))
        elif call.api == "CFE_MSG_SetMsgId" and len(args) >= 2:
            if not _OBJECT_EXPRESSION.fullmatch(args[0]) or not _MESSAGE_EXPRESSION.fullmatch(
                args[1]
            ):
                limitations.add(
                    "At least one SetMsgId expression could not be resolved symbolically."
                )
                continue
            message_object = node(
                "message_object_expression", re.sub(r"\s+", "", args[0]), application
            )
            message = node("message_expression", re.sub(r"\s+", "", args[1]))
            edges.append(
                BusEdge(message_object, "sets_message_id", message, call.file, call.line, call.api)
            )
        else:
            limitations.add("At least one recognized call did not produce a graph edge.")
    subscriptions: dict[tuple[str, str], list[BusEdge]] = {}
    for edge in edges:
        if edge.relation == "subscribes_to" and nodes[edge.source].kind == "software_bus_pipe":
            subscriptions.setdefault((edge.source, edge.target), []).append(edge)
    observations = tuple(
        BusObservation(
            "FUSE-FSW-001",
            "unknown",
            "low",
            "candidate",
            "not-validated",
            pipe,
            message,
            nodes[pipe].label,
            nodes[message].label,
            len(occurrences),
            tuple(f"{edge.file}:{edge.line}: {edge.api}" for edge in occurrences[:10]),
        )
        for (pipe, message), occurrences in sorted(subscriptions.items())
        if len(occurrences) > 1
    )
    return BusGraph(
        "partial",
        tuple(sorted(nodes.values(), key=lambda item: item.id)),
        tuple(
            sorted(
                edges,
                key=lambda edge: (
                    edge.file,
                    edge.line,
                    edge.api,
                    edge.source,
                    edge.relation,
                    edge.target,
                ),
            )
        ),
        tuple(sorted(limitations)),
        observations,
    )
