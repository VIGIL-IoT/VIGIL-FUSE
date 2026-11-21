from __future__ import annotations

from bisect import bisect_right
from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import re

from .build_context import _read_bounded, _select_project_file
from .model import Finding, SourceFile

MAX_FLIGHT_BUS_POLICY_BYTES = 1024 * 1024
MAX_FLIGHT_BUS_SOURCE_BYTES = 10 * 1024 * 1024
MAX_FLIGHT_BUS_SOURCE_FILES = 2000
MAX_FLIGHT_BUS_FINDINGS = 500
_IDENTIFIER = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,127}$")
_MESSAGE_ID = re.compile(r"^(?:0x[0-9a-f]{1,8}|[0-9]{1,10}|[a-z_][a-z0-9_]{0,127})$", re.IGNORECASE)
_DEFINE = re.compile(r"^\s*#\s*define\s+([A-Za-z_]\w*)\s+\(?\s*(0x[0-9a-fA-F]+|[0-9]+)\b", re.MULTILINE)
_CALL_TOKEN = r"(?:CFE_SB_ValueToMsgId\s*\(\s*)?([A-Za-z_]\w*|0x[0-9a-fA-F]+|[0-9]+)\s*\)?"
_SUBSCRIBE = re.compile(r"\bCFE_SB_Subscribe(?:Ex|Local)?\s*\(\s*" + _CALL_TOKEN + r"\s*,\s*([A-Za-z_]\w*)", re.MULTILINE)
_CREATE_PIPE = re.compile(r"\bCFE_SB_CreatePipe\s*\(\s*&?\s*([A-Za-z_]\w*)", re.MULTILINE)
_INITIALIZE = re.compile(r"\bCFE_(?:SB_InitMsg|MSG_Init)\s*\(\s*&?\s*([A-Za-z_]\w*)\s*,\s*" + _CALL_TOKEN, re.MULTILINE)
_TRANSMIT = re.compile(r"\bCFE_SB_Transmit(?:Msg|Buffer)\s*\(\s*&?\s*([A-Za-z_]\w*)", re.MULTILINE)


@dataclass(frozen=True)
class FlightBusPolicy:
    applications: dict[str, str]
    command_message_ids: frozenset[str]
    message_origin_validation: dict[str, str]


@dataclass(frozen=True)
class FlightBusPublisher:
    application: str
    message_id: str
    source: str
    line: int
    api: str


@dataclass(frozen=True)
class FlightBusSubscriber:
    application: str
    message_id: str
    pipe: str
    source: str
    line: int
    pipe_creation_observed: bool
    api: str


@dataclass(frozen=True)
class FlightBusAnalysis:
    status: str
    edge_count: int
    findings: tuple[Finding, ...]
    limitations: tuple[str, ...]
    operator_validated_edges: int = 0


def _canonical_message_id(value: str, macros: dict[str, str | None]) -> str:
    token = value.strip()
    if token.casefold().startswith("0x") or token.isdecimal():
        return f"0x{int(token, 0 if token.casefold().startswith('0x') else 10):x}"
    canonical = macros.get(token.casefold())
    return canonical if canonical else token.casefold()


def parse_flight_bus_policy(data: bytes) -> FlightBusPolicy:
    if len(data) > MAX_FLIGHT_BUS_POLICY_BYTES:
        raise ValueError("cFS mission policy exceeds the 1 MiB limit")
    try:
        document = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("cFS mission policy is not valid UTF-8 JSON") from error
    if not isinstance(document, dict) or document.get("version") != 1:
        raise ValueError("cFS mission policy needs version 1")
    raw_applications = document.get("applications")
    if not isinstance(raw_applications, dict) or len(raw_applications) > 500:
        raise ValueError("cFS mission policy needs at most 500 declared applications")
    applications: dict[str, str] = {}
    for application, value in raw_applications.items():
        if not isinstance(application, str) or not _IDENTIFIER.fullmatch(application):
            raise ValueError("cFS mission-policy application names must be C-style identifiers")
        if not isinstance(value, dict) or value.get("trust_zone") not in {
            "lower_trust", "trusted", "flight_critical", "unknown"
        }:
            raise ValueError(f"Application {application} needs a supported trust_zone declaration")
        applications[application.casefold()] = value["trust_zone"]
    raw_commands = document.get("command_message_ids", [])
    if not isinstance(raw_commands, list) or len(raw_commands) > 4096:
        raise ValueError("command_message_ids must be an array of at most 4096 values")
    if any(not isinstance(item, str) or not _MESSAGE_ID.fullmatch(item) for item in raw_commands):
        raise ValueError("cFS message IDs must be hexadecimal, decimal, or C-style identifiers")
    raw_validation = document.get("message_origin_validation", {})
    if not isinstance(raw_validation, dict) or len(raw_validation) > 4096:
        raise ValueError("message_origin_validation must be an object of at most 4096 entries")
    validation: dict[str, str] = {}
    for message_id, state in raw_validation.items():
        if not isinstance(message_id, str) or not _MESSAGE_ID.fullmatch(message_id):
            raise ValueError("cFS validation message IDs must be hexadecimal, decimal, or identifiers")
        if state not in {"present", "absent", "unknown"}:
            raise ValueError("message-origin validation values must be present, absent, or unknown")
        validation[message_id.casefold()] = state
    return FlightBusPolicy(
        applications=applications,
        command_message_ids=frozenset(item.casefold() for item in raw_commands),
        message_origin_validation=validation,
    )


def load_flight_bus_policy(root: Path, supplied: str | Path) -> tuple[FlightBusPolicy, str, str]:
    path, display = _select_project_file(root, supplied, "--flight-bus-policy")
    data = _read_bounded(path, MAX_FLIGHT_BUS_POLICY_BYTES, "cFS mission policy")
    return parse_flight_bus_policy(data), display, hashlib.sha256(data).hexdigest()


def _mask_comments_and_strings(text: str) -> str:
    masked = list(text)
    state = "code"
    quote = ""
    escaped = False
    index = 0
    while index < len(text):
        char = text[index]
        next_char = text[index + 1] if index + 1 < len(text) else ""
        if state == "code":
            if char == "/" and next_char == "/":
                state = "line-comment"
                masked[index] = masked[index + 1] = " "
                index += 2
                continue
            if char == "/" and next_char == "*":
                state = "block-comment"
                masked[index] = masked[index + 1] = " "
                index += 2
                continue
            if char in {"\"", "'"}:
                state = "quoted"
                quote = char
                masked[index] = " "
        elif state == "line-comment":
            if char == "\n":
                state = "code"
            else:
                masked[index] = " "
        elif state == "block-comment":
            if char == "*" and next_char == "/":
                masked[index] = masked[index + 1] = " "
                state = "code"
                index += 2
                continue
            if char != "\n":
                masked[index] = " "
        elif state == "quoted":
            if char != "\n":
                masked[index] = " "
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                state = "code"
        index += 1
    return "".join(masked)


def _line_starts(text: str) -> list[int]:
    return [0, *(index + 1 for index, char in enumerate(text) if char == "\n")]


def _line_number(starts: list[int], offset: int) -> int:
    return bisect_right(starts, offset)


def analyze_flight_bus(
    sources: tuple[SourceFile, ...],
    policy: FlightBusPolicy | None,
    *,
    source_limit_reached: bool = False,
) -> FlightBusAnalysis:
    selected = tuple(
        source
        for source in sources
        if Path(source.path).suffix.casefold() in {".c", ".h", ".cc", ".cpp", ".hpp"}
    )
    if len(selected) > MAX_FLIGHT_BUS_SOURCE_FILES or sum(item.byte_size for item in selected) > MAX_FLIGHT_BUS_SOURCE_BYTES:
        source_limit_reached = True
        size = 0
        bounded: list[SourceFile] = []
        for source in selected:
            if len(bounded) >= MAX_FLIGHT_BUS_SOURCE_FILES or size + source.byte_size > MAX_FLIGHT_BUS_SOURCE_BYTES:
                break
            bounded.append(source)
            size += source.byte_size
        selected = tuple(bounded)

    masked_sources = {source.path: _mask_comments_and_strings(source.text) for source in selected}
    macros: dict[str, str | None] = {}
    for text in masked_sources.values():
        for name, raw_value in _DEFINE.findall(text):
            canonical = _canonical_message_id(raw_value, {})
            macro_key = name.casefold()
            if macro_key in macros and macros[macro_key] != canonical:
                macros[macro_key] = None
            else:
                macros[macro_key] = canonical

    publishers: list[FlightBusPublisher] = []
    subscribers: list[FlightBusSubscriber] = []
    for source in selected:
        text = masked_sources[source.path]
        starts = _line_starts(text)
        application = Path(source.path).stem
        initialized: dict[str, str] = {}
        created_pipes = {match.group(1) for match in _CREATE_PIPE.finditer(text)}
        for match in _INITIALIZE.finditer(text):
            initialized[match.group(1)] = _canonical_message_id(match.group(2), macros)
        for match in _TRANSMIT.finditer(text):
            message_id = initialized.get(match.group(1))
            if message_id:
                publishers.append(
                    FlightBusPublisher(
                        application=application,
                        message_id=message_id,
                        source=source.path,
                        line=_line_number(starts, match.start()),
                        api=(
                            "CFE_SB_TransmitBuffer"
                            if "TransmitBuffer" in match.group(0)
                            else "CFE_SB_TransmitMsg"
                        ),
                    )
                )
        for match in _SUBSCRIBE.finditer(text):
            subscribers.append(
                FlightBusSubscriber(
                    application=application,
                    message_id=_canonical_message_id(match.group(1), macros),
                    pipe=match.group(2),
                    source=source.path,
                    line=_line_number(starts, match.start()),
                    pipe_creation_observed=match.group(2) in created_pipes,
                    api=(
                        "CFE_SB_SubscribeEx"
                        if "SubscribeEx" in match.group(0)
                        else "CFE_SB_SubscribeLocal"
                        if "SubscribeLocal" in match.group(0)
                        else "CFE_SB_Subscribe"
                    ),
                )
            )

    publishers.sort(key=lambda item: (item.message_id, item.application.casefold(), item.source, item.line))
    subscribers.sort(key=lambda item: (item.message_id, item.application.casefold(), item.source, item.line))
    edges = [
        (publisher, subscriber)
        for publisher in publishers
        for subscriber in subscribers
        if publisher.message_id == subscriber.message_id
        and publisher.application.casefold() != subscriber.application.casefold()
    ]
    limitations: list[str] = [
        "Only direct message initialization, transmission, and subscription calls are correlated; helper wrappers, generated routing, and conditional compilation need review."
    ]
    if policy is None:
        limitations.append("No operator mission policy was supplied; application names do not establish trust zones.")
    if source_limit_reached:
        limitations.append("cFS source analysis reached the bounded file or byte limit.")
    findings: list[Finding] = []
    operator_validated_edges = 0
    if policy is not None:
        command_ids = {
            _canonical_message_id(message_id, macros) for message_id in policy.command_message_ids
        }
        validation = {
            _canonical_message_id(message_id, macros): state
            for message_id, state in policy.message_origin_validation.items()
        }
        for publisher, subscriber in edges:
            trust = policy.applications.get(publisher.application.casefold(), "unknown")
            criticality = policy.applications.get(subscriber.application.casefold(), "unknown")
            if (
                trust != "lower_trust"
                or criticality != "flight_critical"
                or publisher.message_id not in command_ids
            ):
                continue
            if validation.get(publisher.message_id) == "present":
                operator_validated_edges += 1
                continue
            evidence = (
                f"{publisher.application} calls {publisher.api} for message "
                f"{publisher.message_id} at {publisher.source}:{publisher.line}; "
                f"{subscriber.application} calls {subscriber.api} on pipe {subscriber.pipe} "
                f"at {subscriber.source}:{subscriber.line}; "
                f"pipe creation observed in that source: "
                f"{'yes' if subscriber.pipe_creation_observed else 'no'}; "
                "Both trust-zone labels are operator-declared."
            )
            fingerprint = hashlib.sha256(
                f"FUSE-FSW-001\0{evidence}".encode("utf-8")
            ).hexdigest()
            findings.append(
                Finding(
                    id=f"FUSE-FSW-001:{fingerprint[:20]}",
                    fingerprint=fingerprint,
                    rule_id="FUSE-FSW-001",
                    rule_version="1.0.0",
                    analyzer="cfs-software-bus-static",
                    title="Potential command-origin trust-boundary exposure",
                    severity="unknown",
                    confidence="medium",
                    category="flight-software-security",
                    file=publisher.source,
                    start_line=publisher.line,
                    end_line=publisher.line,
                    evidence=evidence,
                    explanation=(
                        "Static cFS API evidence supports a message path from an operator-declared lower-trust "
                        "publisher to an operator-declared flight-critical subscriber. Authentication coverage "
                        "is unknown or operator-declared absent; this does not establish command spoofing or "
                        "deployed-system reachability."
                    ),
                    potential_impact="If the mission classifications and runtime route are correct and message origin is not validated, a command trust boundary may need review.",
                    remediation="Review message-origin authentication and authorization at this trust boundary against the exact cFS version and mission build.",
                    references=("https://ntrs.nasa.gov/api/citations/20210022378/downloads/NASA%20TM%2020205000691%20REV%202%20Final.pdf",),
                    applicability="candidate",
                    validation_method="operator-guided",
                    validation_status="not-validated",
                )
            )
            if len(findings) >= MAX_FLIGHT_BUS_FINDINGS:
                limitations.append(f"cFS candidate findings were capped at {MAX_FLIGHT_BUS_FINDINGS}.")
                break
    status = "partial" if limitations else "completed"
    return FlightBusAnalysis(
        status=status,
        edge_count=len(edges),
        findings=tuple(findings),
        limitations=tuple(limitations),
        operator_validated_edges=operator_validated_edges,
    )
