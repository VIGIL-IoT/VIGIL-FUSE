"""Explicit project policy for symbolic flight-bus review."""

from __future__ import annotations

from dataclasses import dataclass, replace
import hashlib
import tomllib

from .flight_bus import BusComponent, BusGraph, BusPolicyObservation

MAX_POLICY_BYTES = 256 * 1024
MAX_POLICY_ENTRIES = 2048
MAX_POLICY_MEMBERS = 10_000
MAX_POLICY_TEXT = 512
MAX_POLICY_RELATION_CHECKS = 20_000


@dataclass(frozen=True)
class BusPolicy:
    source: str
    sha256: str
    components: tuple[BusComponent, ...]
    subscribers: tuple[tuple[str, tuple[str, ...]], ...]
    publishers: tuple[tuple[str, tuple[str, ...]], ...]


def _name(value: object) -> str:
    if not isinstance(value, str) or not value or len(value) > MAX_POLICY_TEXT or "\0" in value:
        raise ValueError("Invalid flight policy name or value")
    return value


def parse_bus_policy(data: bytes, source: str) -> BusPolicy:
    """Parse a bounded TOML policy; only explicitly configured boundaries are checked."""
    if len(data) > MAX_POLICY_BYTES:
        raise ValueError("Flight policy byte limit exceeded")
    _name(source)
    try:
        document = tomllib.loads(data.decode("utf-8-sig"))
    except (UnicodeError, tomllib.TOMLDecodeError, RecursionError) as error:
        raise ValueError("Invalid UTF-8 TOML flight policy") from error
    if set(document) != {"flight_software"} or not isinstance(document["flight_software"], dict):
        raise ValueError("Flight policy requires a [flight_software] table")
    section = document["flight_software"]
    if set(section) - {"components", "messages"}:
        raise ValueError("Unknown flight policy section")
    components = section.get("components", {})
    messages = section.get("messages", {})
    if not isinstance(components, dict) or not isinstance(messages, dict):
        raise ValueError("Flight components and messages must be tables")
    if len(components) + len(messages) > MAX_POLICY_ENTRIES:
        raise ValueError("Flight policy entry limit exceeded")
    component_items: list[BusComponent] = []
    for raw_name, item in sorted(components.items()):
        name = _name(raw_name)
        if not isinstance(item, dict) or set(item) - {"criticality", "trust"}:
            raise ValueError("Invalid flight component policy")
        criticality = _name(item["criticality"]) if "criticality" in item else None
        trust = _name(item["trust"]) if "trust" in item else None
        component_items.append(BusComponent(name, criticality, trust))
    subscribers: list[tuple[str, tuple[str, ...]]] = []
    publishers: list[tuple[str, tuple[str, ...]]] = []
    members = 0
    for raw_expression, item in sorted(messages.items()):
        expression = _name(raw_expression)
        if (
            not isinstance(item, dict)
            or not item
            or set(item) - {"allowed_subscribers", "allowed_publishers"}
        ):
            raise ValueError("Each message policy requires allowed subscribers or publishers")
        for key, destination in (
            ("allowed_subscribers", subscribers),
            ("allowed_publishers", publishers),
        ):
            if key not in item:
                continue
            allowed = item[key]
            if not isinstance(allowed, list):
                raise ValueError(f"{key} must be an array")
            members += len(allowed)
            if members > MAX_POLICY_MEMBERS:
                raise ValueError("Flight policy member limit exceeded")
            names = tuple(sorted(_name(value) for value in allowed))
            if len(set(names)) != len(names):
                raise ValueError(f"Duplicate member in {key}")
            destination.append((expression, names))
    return BusPolicy(
        source,
        hashlib.sha256(data).hexdigest(),
        tuple(component_items),
        tuple(subscribers),
        tuple(publishers),
    )


def apply_bus_policy(graph: BusGraph, policy: BusPolicy) -> BusGraph:
    """Record exact symbolic subscription mismatches as unvalidated review candidates."""
    allowed = dict(policy.subscribers)
    allowed_publishers = dict(policy.publishers)
    nodes = {node.id: node for node in graph.nodes}
    observations: list[BusPolicyObservation] = []
    for edge in graph.edges:
        source, target = nodes[edge.source], nodes[edge.target]
        if (
            edge.relation != "subscribes_to"
            or source.kind != "flight_application"
            or target.kind != "message_expression"
            or target.label not in allowed
        ):
            continue
        if source.label not in allowed[target.label]:
            observations.append(
                BusPolicyObservation(
                    "FUSE-FSW-002",
                    "unknown",
                    "low",
                    "candidate",
                    "not-validated",
                    source.label,
                    target.label,
                    f"{edge.file}:{edge.line}: {edge.api}; application absent from configured allowlist",
                )
            )
    limitations = set(graph.limitations)
    limitations.add(
        "Policy checks are exact symbolic comparisons, not verified runtime access control."
    )
    assignments: dict[str, dict[str, str]] = {}
    for edge in graph.edges:
        if edge.relation == "sets_message_id" and nodes[edge.target].label in allowed_publishers:
            assignments.setdefault(edge.source, {}).setdefault(
                nodes[edge.target].label, f"{edge.file}:{edge.line}: {edge.api}"
            )
    checks = 0
    for edge in graph.edges:
        if edge.relation != "transmits" or nodes[edge.source].kind != "flight_application":
            continue
        for message, assignment in assignments.get(edge.target, {}).items():
            checks += 1
            if checks > MAX_POLICY_RELATION_CHECKS:
                break
            if nodes[edge.source].label not in allowed_publishers[message]:
                observations.append(
                    BusPolicyObservation(
                        "FUSE-FSW-003",
                        "unknown",
                        "low",
                        "candidate",
                        "not-validated",
                        nodes[edge.source].label,
                        message,
                        f"{assignment}; {edge.file}:{edge.line}: {edge.api}; "
                        "application absent from configured publisher allowlist",
                    )
                )
        if checks > MAX_POLICY_RELATION_CHECKS:
            limitations.add(
                "Publisher relationship check limit reached; further checks were omitted."
            )
            break
    if allowed_publishers:
        limitations.add(
            "Publisher candidates use symbolic object associations without data-flow validation."
        )
    return replace(
        graph,
        policy_source=policy.source,
        policy_sha256=policy.sha256,
        components=policy.components,
        policy_observations=tuple(observations),
        limitations=tuple(sorted(limitations)),
    )
