"""Create a deterministic structural graph from passive RepoDNA results."""

from __future__ import annotations

from typing import TypedDict

from .repo_dna import RepoDNA


class ComponentNode(TypedDict):
    id: str
    type: str
    path: str


class ComponentEdge(TypedDict):
    source: str
    relation: str
    target: str


class ComponentGraph(TypedDict):
    schema_version: str
    nodes: list[ComponentNode]
    edges: list[ComponentEdge]
    complete: bool


def build_component_graph(dna: RepoDNA) -> ComponentGraph:
    """Represent discovered component containment, without inferring dependencies."""
    nodes: list[ComponentNode] = [{"id": "repository", "type": "repository", "path": "."}]
    edges: list[ComponentEdge] = []
    for path in sorted(set(dna["components"])):
        node_id = f"component:{path}"
        nodes.append({"id": node_id, "type": "component", "path": path})
        edges.append({"source": "repository", "relation": "contains", "target": node_id})
    return {"schema_version": "0.1", "nodes": nodes, "edges": edges, "complete": dna["complete"]}
