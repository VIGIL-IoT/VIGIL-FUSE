"""Deterministic, conservative cross-layer candidates from explicit evidence bindings."""

from __future__ import annotations

from collections import defaultdict
from typing import Any

from .evidence_graph import ASSERTIONS, EvidenceGraph, identity, object_fields, strings, text

LAYERS = frozenset(
    "source build dependency binary firmware device_configuration hardware rtl deployment".split()
)
# Each tuple is mandatory. No count of weaker or repeated signals substitutes for it.
RULES: dict[str, dict[str, Any]] = {
    "debug-uart-exposure": {
        "feature": "uart",
        "requires": [
            ("source", "debug-enabled"),
            ("device_configuration", "pins-configured"),
            ("firmware", "debug-feature-present"),
            ("hardware", "interface-connected"),
        ],
        "unknown": [
            "connector population",
            "enclosure accessibility",
            "authentication",
            "runtime activation",
        ],
    },
    "external-flash-exposure": {
        "feature": "external-flash",
        "requires": [
            ("hardware", "flash-connected"),
            ("firmware", "flash-driver-present"),
            ("deployment", "flash-interface-routed"),
        ],
        "unknown": ["physical accessibility", "readout protection", "device population"],
    },
    "firmware-update-path": {
        "feature": "firmware-update",
        "requires": [
            ("source", "update-handler"),
            ("binary", "update-function-present"),
            ("firmware", "update-service-present"),
        ],
        "unknown": ["network exposure", "authentication", "image acceptance", "runtime execution"],
    },
    "bootloader-validation-weakness": {
        "feature": "bootloader",
        "requires": [
            ("source", "validation-disabled"),
            ("build", "bootloader-included"),
            ("firmware", "bootloader-present"),
        ],
        "unknown": ["fused boot policy", "runtime configuration", "image authenticity enforcement"],
    },
    "dependency-binary-presence": {
        "feature": None,
        "requires": [
            ("dependency", "advisory-symbol-declared"),
            ("build", "package-included"),
            ("binary", "symbol-present"),
        ],
        "unknown": ["function reachability", "runtime execution", "deployment exposure"],
    },
    "source-configuration-firmware-feature": {
        "feature": None,
        "requires": [
            ("source", "feature-enabled"),
            ("build", "feature-included"),
            ("firmware", "feature-present"),
        ],
        "unknown": ["runtime activation", "deployment configuration"],
    },
    "hardware-debug-path": {
        "feature": "debug",
        "requires": [
            ("rtl", "debug-port-enabled"),
            ("hardware", "debug-connector-connected"),
            ("device_configuration", "debug-pins-configured"),
        ],
        "unknown": [
            "manufactured connectivity",
            "physical accessibility",
            "debug authentication",
            "lifecycle fuse policy",
        ],
    },
}
FACT_FIELDS = {
    "subject",
    "feature",
    "layer",
    "predicate",
    "assertion",
    "evidence_nodes",
    "evidence_edges",
    "limitations",
}


def _fact(graph: EvidenceGraph, value: object) -> dict[str, Any]:
    row = object_fields(value, FACT_FIELDS)
    text(row["feature"])
    text(row["predicate"])
    if (
        row["subject"] not in graph.nodes
        or row["layer"] not in LAYERS
        or row["assertion"] not in ASSERTIONS
    ):
        raise ValueError("Invalid cross-layer fact binding")
    nodes, edges = strings(row["evidence_nodes"]), strings(row["evidence_edges"])
    strings(row["limitations"])
    if (
        not nodes
        or not edges
        or any(node not in graph.nodes for node in nodes)
        or any(edge not in graph.edges for edge in edges)
    ):
        raise ValueError("Dangling cross-layer evidence")
    if any(
        not {graph.edges[e]["source"], graph.edges[e]["target"]}.intersection(nodes) for e in edges
    ):
        raise ValueError("Cross-layer edge does not reference supporting nodes")
    if row["assertion"] == "OBSERVED" and any(
        graph.edges[e]["assertion"] != "OBSERVED" for e in edges
    ):
        raise ValueError("Asserted or unknown evidence cannot become observed")
    return row


def import_facts(graph: EvidenceGraph, document: dict[str, Any]) -> list[str]:
    """Bind producer/reviewer-normalized facts to existing nodes, never infer by names."""
    object_fields(document, {"schema_version", "producer", "tool_version", "artifact", "facts"})
    if (
        document["schema_version"] != "1.0"
        or not isinstance(document["facts"], list)
        or len(document["facts"]) > 1000
    ):
        raise ValueError("Invalid cross-layer envelope")
    rows = [_fact(graph, row) for row in document["facts"]]
    run = graph.run(
        document["producer"],
        "completed",
        version=document["tool_version"],
        artifact=document["artifact"],
    )
    result = []
    for row in rows:
        node = graph.node("Configuration", ["cross-layer-fact", row], correlation_fact=row)
        result.append(node)
        refs = sorted(
            {
                document["artifact"],
                *(ref for e in row["evidence_edges"] for ref in graph.edges[e]["evidence_refs"]),
            }
        )
        for support in sorted(set(row["evidence_nodes"])):
            graph.edge(
                node,
                support,
                "derived_from",
                producer=run,
                method="explicit-cross-layer-binding",
                evidence_refs=refs,
                assertion=row["assertion"],
                limitations=row["limitations"],
            )
    return result


def _references(graph: EvidenceGraph, rows: list[tuple[str, dict[str, Any]]]) -> set[str]:
    return {
        ref
        for _, row in rows
        for edge in row["evidence_edges"]
        for ref in graph.edges[edge]["evidence_refs"]
    }


def _independent(groups: list[set[str]]) -> bool:
    """Require a distinct underlying artifact reference for each mandatory layer."""
    matched: dict[str, int] = {}

    def assign(index: int, seen: set[str]) -> bool:
        for ref in sorted(groups[index]):
            if ref in seen:
                continue
            seen.add(ref)
            if ref not in matched or assign(matched[ref], seen):
                matched[ref] = index
                return True
        return False

    return all(assign(index, set()) for index in range(len(groups)))


def correlate(graph: EvidenceGraph) -> dict[str, Any]:
    facts: dict[tuple[str, str], list[tuple[str, dict[str, Any]]]] = defaultdict(list)
    for node in sorted(graph.nodes.values(), key=lambda n: n["id"]):
        if "correlation_fact" in node["attributes"]:
            row = _fact(graph, node["attributes"]["correlation_fact"])
            facts[row["subject"], row["feature"]].append((node["id"], row))
    candidates, blocked, unknown = [], [], []
    negated = {
        (e["source"], e["target"], e["relation"])
        for e in graph.edges.values()
        if e["assertion"] == "NEGATED"
    }
    contradicted_nodes = {
        node
        for edge in graph.edges.values()
        if edge["relation"] == "contradicts" and edge["assertion"] in {"OBSERVED", "ASSERTED"}
        for node in (edge["source"], edge["target"])
    }
    for (subject, feature), rows in sorted(facts.items()):
        for rule_id, rule in sorted(RULES.items()):
            if rule["feature"] is not None and rule["feature"] != feature:
                continue
            relevant = [
                (node, row)
                for node, row in rows
                if (row["layer"], row["predicate"]) in rule["requires"]
            ]
            if not relevant:
                continue
            groups = [
                [
                    pair
                    for pair in relevant
                    if (pair[1]["layer"], pair[1]["predicate"]) == requirement
                    and pair[1]["assertion"] in {"OBSERVED", "ASSERTED"}
                    and all(
                        graph.edges[e]["assertion"] in {"OBSERVED", "ASSERTED"}
                        for e in pair[1]["evidence_edges"]
                    )
                ]
                for requirement in rule["requires"]
            ]
            positive = [pair for group in groups for pair in group]
            conflicts = [
                node
                for node, row in relevant
                if row["assertion"] == "NEGATED"
                or bool(contradicted_nodes.intersection([node, *row["evidence_nodes"]]))
                or any(
                    (graph.edges[e]["source"], graph.edges[e]["target"], graph.edges[e]["relation"])
                    in negated
                    or graph.edges[e]["assertion"] == "NEGATED"
                    or graph.edges[e]["relation"] == "contradicts"
                    for e in row["evidence_edges"]
                )
            ]
            record = {
                "rule": rule_id,
                "subject": subject,
                "feature": feature,
                "fact_nodes": sorted(node for node, _ in relevant),
            }
            if conflicts:
                blocked.append(
                    {
                        **record,
                        "reason": "contradictory evidence",
                        "contradictions": sorted(conflicts),
                    }
                )
                continue
            if not all(groups) or not _independent([_references(graph, group) for group in groups]):
                unknown.append(
                    {**record, "reason": "missing mandatory layer or distinct artifact support"}
                )
                continue
            supporting_nodes = sorted(
                {node for node, _ in positive}
                | {n for _, row in positive for n in row["evidence_nodes"]}
            )
            supporting_edges = sorted({e for _, row in positive for e in row["evidence_edges"]})
            limitations = sorted(
                {item for _, row in positive for item in row["limitations"]}
                | {item for edge in supporting_edges for item in graph.edges[edge]["limitations"]}
            )
            candidate = {
                **record,
                "classification": "cross-layer candidate",
                "assertion": "INFERRED",
                "severity": None,
                "confidence": None,
                "supporting_nodes": supporting_nodes,
                "supporting_edges": supporting_edges,
                "observed": sorted(
                    node for node, row in positive if row["assertion"] == "OBSERVED"
                ),
                "asserted": sorted(
                    node for node, row in positive if row["assertion"] == "ASSERTED"
                ),
                "inferred": "Possible " + rule_id.replace("-", " "),
                "unknown": rule["unknown"],
                "evidence_refs": sorted(_references(graph, positive)),
                "limitations": limitations,
            }
            candidate["id"] = identity("correlation", [graph.target_identity, candidate])
            candidates.append(candidate)
    return {
        "schema_version": "1.0",
        "candidates": candidates,
        "blocked": blocked,
        "unknown": unknown,
        "limitations": [
            "Explicit subject/feature bindings are producer or reviewer assertions, not automatic identity proof.",
            "Distinct artifact references are required; they do not attest producer independence.",
            "Correlation never upgrades existing severity, confidence, applicability or validation.",
        ],
    }


def materialize_correlations(graph: EvidenceGraph, report: dict[str, Any]) -> None:
    run = graph.run(
        "cross-layer-correlation",
        "completed",
        version="1.0",
        artifact=identity("correlation-report", report),
    )
    for candidate in report["candidates"]:
        finding = graph.node("Finding", candidate["id"], correlation=candidate)
        for node in candidate["supporting_nodes"]:
            graph.edge(
                node,
                finding,
                "supports",
                producer=run,
                method=candidate["rule"],
                evidence_refs=candidate["evidence_refs"],
                assertion="INFERRED",
                limitations=[*candidate["limitations"], *candidate["unknown"]],
            )
