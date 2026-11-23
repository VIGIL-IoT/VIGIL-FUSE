"""Deterministic attack path candidates, with explicit weakest-edge semantics."""

from __future__ import annotations

from typing import Any

from .evidence_graph import EvidenceGraph, identity, object_fields, strings, text
from .graph_query import paths
from .runtime_evidence import validate_observation

RELATIONS = frozenset(
    {
        "calls",
        "may_call",
        "flows_to",
        "contains",
        "includes",
        "connected_to",
        "configured_by",
        "corresponds_to",
    }
)
RANK = {"UNKNOWN": 0, "INFERRED": 1, "ASSERTED": 2, "OBSERVED": 3, "VALIDATED": 4}


def _validations(graph: EvidenceGraph, values: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    if not isinstance(values, list) or len(values) > 1000:
        raise ValueError("Attack-path validation limit")
    result = {}
    for value in values:
        row = object_fields(
            value, {"edge", "observation", "support_edge", "review_artifact", "scope"}
        )
        text(row["review_artifact"])
        if (
            row["scope"] != "test-execution"
            or row["edge"] not in graph.edges
            or row["support_edge"] not in graph.edges
            or row["observation"] not in graph.nodes
        ):
            raise ValueError("Invalid validation binding")
        observation, support = graph.nodes[row["observation"]], graph.edges[row["support_edge"]]
        if observation["type"] != "RuntimeObservation":
            raise ValueError("Validation needs a runtime observation")
        validate_observation(observation["attributes"].get("observation"))
        target = graph.nodes[support["target"]]
        if any(
            (
                edge["relation"] == "contradicts"
                and edge["assertion"] in {"OBSERVED", "ASSERTED"}
                and {edge["source"], edge["target"]}.intersection({observation["id"], target["id"]})
            )
            or (
                edge["assertion"] == "NEGATED"
                and all(edge[key] == support[key] for key in ("source", "target", "relation"))
            )
            for edge in graph.edges.values()
        ):
            raise ValueError("Contradicted runtime validation")
        if target["type"] == "CallPath":
            strings(target["attributes"].get("edge_ids"))
        if (
            support["source"] != row["observation"]
            or support["relation"] != "supports"
            or support["assertion"] not in {"OBSERVED", "ASSERTED"}
            or row["review_artifact"] not in support["evidence_refs"]
            or target["type"] != "CallPath"
            or row["edge"] not in target["attributes"].get("edge_ids", [])
            or graph.edges[row["edge"]]["assertion"] not in {"OBSERVED", "ASSERTED"}
        ):
            raise ValueError("Validation must reference an explicitly reviewed exact call path")
        if row["edge"] in result:
            raise ValueError("Duplicate edge validation")
        result[row["edge"]] = row
    return result


def attack_paths(
    graph: EvidenceGraph,
    starts: list[str],
    goals: list[str],
    *,
    relations: frozenset[str] = RELATIONS,
    max_depth: int = 32,
    max_paths: int = 64,
    max_visits: int = 50000,
    validations: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    validated = _validations(graph, validations if validations is not None else [])
    blocked_nodes = {
        node
        for e in graph.edges.values()
        if e["relation"] == "contradicts" and e["assertion"] in {"OBSERVED", "ASSERTED"}
        for node in (e["source"], e["target"])
    }
    guarded_artifacts = {
        e["source"]
        for e in graph.edges.values()
        if e["relation"] == "sanitized_by" and e["assertion"] in {"OBSERVED", "ASSERTED"}
    }
    excluded = {
        e["id"]
        for e in graph.edges.values()
        if e["source"] in blocked_nodes
        or e["target"] in blocked_nodes
        or guarded_artifacts.intersection(e["evidence_refs"])
    }
    if {"contradicts", "sanitized_by"}.intersection(relations):
        raise ValueError("Contradictions and sanitizer annotations are not attack transitions")
    query = paths(
        graph,
        starts,
        goals,
        relations=relations,
        assertions=frozenset({"OBSERVED", "ASSERTED", "INFERRED", "UNKNOWN"}),
        excluded_edges=frozenset(excluded),
        max_depth=max_depth,
        max_paths=max_paths,
        max_visits=max_visits,
    )
    candidates = []
    for edge_ids in query["paths"]:
        if not edge_ids:
            continue
        rows, assumptions = [], []
        for edge_id in edge_ids:
            edge = graph.edges[edge_id]
            state = "VALIDATED" if edge_id in validated else edge["assertion"]
            row = {**edge, "display_state": state, "validation": validated.get(edge_id)}
            rows.append(row)
            if state != "VALIDATED" or edge["confidence"] is None:
                assumptions.append(
                    {
                        "edge": edge_id,
                        "assertion": state,
                        "reason": "Unvalidated transition or unknown confidence.",
                        "limitations": edge["limitations"],
                    }
                )
        weakest = min(
            rows,
            key=lambda e: (
                RANK[e["display_state"]],
                -1 if e["confidence"] is None else e["confidence"],
                e["id"],
            ),
        )
        confidence = (
            None
            if any(e["confidence"] is None or e["display_state"] == "UNKNOWN" for e in rows)
            else min(e["confidence"] for e in rows)
        )
        candidate = {
            "classification": "attack path candidate",
            "nodes": [rows[0]["source"], *(e["target"] for e in rows)],
            "edges": rows,
            "path_confidence": confidence,
            "confidence_method": "Minimum supplied edge confidence, not a joint exploit probability; null if any confidence or transition is unknown.",
            "weakest_edge": weakest["id"],
            "weakest_state": weakest["display_state"],
            "unvalidated_assumptions": assumptions,
            "evidence_refs": sorted(
                {
                    ref
                    for e in rows
                    for ref in [
                        *e["evidence_refs"],
                        *([e["validation"]["review_artifact"]] if e["validation"] else []),
                    ]
                }
            ),
            "limitations": sorted(
                {item for e in rows for item in e["limitations"]}
                | {
                    "Runtime validation applies only to the explicitly reviewed test execution.",
                    "Deployment, privileged execution and physical accessibility require separate evidence.",
                }
            ),
        }
        candidate["id"] = identity("attack-path", [graph.target_identity, candidate])
        candidates.append(candidate)
    return {
        "schema_version": "1.0",
        "target_identity": graph.target_identity,
        "candidates": candidates,
        "truncated": query["truncated"],
        "visits": query["visits"],
        "excluded_edges": sorted(excluded),
        "limitations": [
            "No candidate is not evidence of safety or absence.",
            "Contradicted nodes and analyzer-reported sanitizer/barrier paths are excluded conservatively; exclusion does not prove a barrier effective.",
            "No AI-generated chains or automatic exploitability verdicts.",
        ],
    }


def to_text(report: dict[str, Any]) -> str:
    lines = [
        "FUSE attack path candidates",
        "Target: " + report["target_identity"],
        "Truncated: " + str(report["truncated"]),
    ]
    for candidate in report["candidates"]:
        lines.extend(
            [
                "",
                candidate["id"] + ": attack path candidate",
                "Path confidence: " + str(candidate["path_confidence"]),
                "Weakest edge: "
                + candidate["weakest_edge"]
                + " ("
                + candidate["weakest_state"]
                + ")",
            ]
        )
        for edge in candidate["edges"]:
            lines.append(
                f"{edge['source']} -> {edge['relation']} [{edge['display_state']}] -> {edge['target']}"
            )
        lines.append("Unvalidated assumptions: " + str(len(candidate["unvalidated_assumptions"])))
        lines.extend(
            "Assumption: " + assumption["edge"] + ": " + assumption["reason"]
            for assumption in candidate["unvalidated_assumptions"]
        )
        lines.extend("Evidence: " + ref for ref in candidate["evidence_refs"])
        lines.extend("Limitation: " + item for item in candidate["limitations"])
    lines.extend("Limitation: " + item for item in report["limitations"])
    return "\n".join(lines) + "\n"
