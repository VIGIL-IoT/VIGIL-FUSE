"""Bounded deterministic graph traversal. No path is not evidence of absence."""

from __future__ import annotations

from typing import Any

from .evidence_graph import EvidenceGraph


def paths(
    graph: EvidenceGraph,
    starts: list[str],
    goals: list[str],
    *,
    relations: frozenset[str] = frozenset({"calls"}),
    max_depth: int = 32,
    max_paths: int = 64,
    max_visits: int = 50000,
) -> dict[str, Any]:
    if not 1 <= max_depth <= 64 or not 1 <= max_paths <= 256 or not 1 <= max_visits <= 100000:
        raise ValueError("Invalid graph query budget")
    if any(n not in graph.nodes for n in [*starts, *goals]):
        raise ValueError("Unknown graph query endpoint")
    adjacency: dict[str, list[dict[str, Any]]] = {}
    negated = {
        (e["source"], e["target"], e["relation"])
        for e in graph.edges.values()
        if e["assertion"] == "NEGATED"
    }
    for edge in sorted(graph.edges.values(), key=lambda e: e["id"]):
        if (
            edge["relation"] in relations
            and edge["assertion"] in {"OBSERVED", "ASSERTED"}
            and (edge["source"], edge["target"], edge["relation"]) not in negated
        ):
            adjacency.setdefault(edge["source"], []).append(edge)
    results: list[list[str]] = []
    truncated = False
    visits = 0
    stack: list[tuple[str, list[str], list[str]]] = [
        (node, [node], []) for node in reversed(sorted(set(starts)))
    ]
    while stack:
        node, nodes, edges = stack.pop()
        visits += 1
        if visits > max_visits:
            truncated = True
            break
        if node in goals:
            results.append(edges)
            if len(results) >= max_paths:
                truncated = bool(stack)
                break
            continue
        outgoing = adjacency.get(node, [])
        if len(edges) >= max_depth:
            truncated |= bool(outgoing)
            continue
        for edge in reversed(outgoing):
            if edge["target"] not in nodes:
                stack.append((edge["target"], [*nodes, edge["target"]], [*edges, edge["id"]]))
    return {"paths": results, "truncated": truncated, "visits": visits}
