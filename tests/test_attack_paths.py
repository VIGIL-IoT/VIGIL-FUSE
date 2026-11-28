from __future__ import annotations

import json
from pathlib import Path
import sys

import pytest

from vigil_fuse.attack_paths import attack_paths, to_text
from vigil_fuse.deep_evidence import main
from vigil_fuse.evidence_graph import EvidenceGraph
from vigil_fuse.graph_query import paths
from vigil_fuse.runtime_evidence import add_runtime, ingest_runtime
from test_runtime_evidence import LOGS, metadata
from test_semantic_flow import sarif


def chain() -> tuple[EvidenceGraph, list[str], list[str]]:
    graph = EvidenceGraph("product")
    run = graph.run("reviewed-analysis", "completed", artifact="artifact:flow")
    nodes = [
        graph.node("Function", name)
        for name in ("endpoint", "input", "parser", "shell", "privileged-component")
    ]
    edges = []
    for index, (a, b) in enumerate(zip(nodes, nodes[1:])):
        edges.append(
            graph.edge(
                a,
                b,
                "flows_to",
                producer=run,
                method="producer-contract",
                evidence_refs=["artifact:flow"],
                assertion="UNKNOWN" if index == 3 else "OBSERVED",
                confidence=None if index == 3 else 0.8,
                limitations=["Path feasibility unknown."],
            )
        )
    return graph, nodes, edges


def test_unknown_weakest_edge_is_preserved_and_json_text_deterministic() -> None:
    graph, nodes, edges = chain()
    report = attack_paths(graph, [nodes[0]], [nodes[-1]])
    candidate = report["candidates"][0]
    assert candidate["weakest_edge"] == edges[-1] and candidate["weakest_state"] == "UNKNOWN"
    assert candidate["path_confidence"] is None
    assert candidate["edges"][-1]["display_state"] == "UNKNOWN"
    assert (
        candidate["classification"] == "attack path candidate"
        and candidate["unvalidated_assumptions"]
    )
    assert "[UNKNOWN]" in to_text(report) and "artifact:flow" in to_text(report)
    assert attack_paths(EvidenceGraph.from_dict(graph.to_dict()), [nodes[0]], [nodes[-1]]) == report
    assert paths(graph, [nodes[0]], [nodes[-1]], relations=frozenset({"flows_to"}))["paths"] == []


def test_inferred_edges_cycles_limits_and_absent_path_do_not_claim_safety() -> None:
    graph, nodes, edges = chain()
    run = graph.edges[edges[0]]["producer"]
    graph.edge(
        nodes[2],
        nodes[0],
        "calls",
        producer=run,
        method="cycle",
        evidence_refs=["artifact:cycle"],
        assertion="INFERRED",
        confidence=0.2,
    )
    assert len(attack_paths(graph, [nodes[0]], [nodes[-1]])["candidates"]) == 1
    limited = attack_paths(graph, [nodes[0]], [nodes[-1]], max_depth=2)
    assert limited["truncated"] and not limited["candidates"]
    assert attack_paths(graph, [nodes[0]], [nodes[-1]], max_visits=1)["truncated"]
    reverse = attack_paths(graph, [nodes[-1]], [nodes[0]])
    assert reverse["candidates"] == [] and "absence" in reverse["limitations"][0]
    for budget in (0, 65, True):
        with pytest.raises(ValueError):
            attack_paths(graph, [nodes[0]], [nodes[-1]], max_depth=budget)
    with pytest.raises(ValueError):
        attack_paths(graph, ["missing"], [nodes[-1]])


def test_negation_and_explicit_contradiction_exclude_paths() -> None:
    graph, nodes, edges = chain()
    edge = graph.edges[edges[0]]
    graph.edge(
        edge["source"],
        edge["target"],
        edge["relation"],
        producer=edge["producer"],
        method="negative-review",
        evidence_refs=["review:negative"],
        assertion="NEGATED",
    )
    assert attack_paths(graph, [nodes[0]], [nodes[-1]])["candidates"] == []
    graph, nodes, edges = chain()
    review = graph.node("EvidenceArtifact", "review")
    graph.edge(
        review,
        nodes[2],
        "contradicts",
        producer=graph.edges[edges[0]]["producer"],
        method="review",
        evidence_refs=["review:contradiction"],
    )
    report = attack_paths(graph, [nodes[0]], [nodes[-1]])
    assert not report["candidates"] and report["excluded_edges"]


def test_semantic_sanitizer_or_barrier_is_not_silently_bypassed() -> None:
    from vigil_fuse.semantic_flow import add_flows, normalize_sarif

    graph = EvidenceGraph("semantic-product")
    evidence = normalize_sarif(sarif(), "python")
    add_flows(graph, evidence)
    source = next(
        n["id"]
        for n in graph.nodes.values()
        if n["type"] == "Function" and n["identity"][-1] == "handler"
    )
    sink = next(
        n["id"]
        for n in graph.nodes.values()
        if n["type"] == "Function" and n["identity"][-1] == "execute"
    )
    report = attack_paths(graph, [source], [sink])
    assert not report["candidates"] and report["excluded_edges"]


def test_validated_requires_reviewed_runtime_support_for_exact_edge() -> None:
    graph, nodes, edges = chain()
    observation = add_runtime(graph, ingest_runtime(LOGS["ASan"].encode(), metadata()))[0]
    call_path = graph.node("CallPath", "reviewed-test-path", edge_ids=[edges[0]])
    run = graph.run("runtime-review", "completed", artifact="review:test")
    support = graph.edge(
        observation,
        call_path,
        "supports",
        producer=run,
        method="reviewed-test-trace",
        evidence_refs=["review:test"],
        assertion="ASSERTED",
    )
    validation = {
        "edge": edges[0],
        "observation": observation,
        "support_edge": support,
        "review_artifact": "review:test",
        "scope": "test-execution",
    }
    report = attack_paths(graph, [nodes[0]], [nodes[-1]], validations=[validation])
    candidate = report["candidates"][0]
    assert candidate["edges"][0]["display_state"] == "VALIDATED"
    assert candidate["edges"][0]["assertion"] == "OBSERVED"
    assert candidate["weakest_state"] == "UNKNOWN" and "review:test" in candidate["evidence_refs"]
    validation["edge"] = edges[-1]
    with pytest.raises(ValueError):
        attack_paths(graph, [nodes[0]], [nodes[-1]], validations=[validation])
    validation["edge"] = edges[0]
    validation["scope"] = "deployed-exploitability"
    with pytest.raises(ValueError):
        attack_paths(graph, [nodes[0]], [nodes[-1]], validations=[validation])


def test_known_confidence_uses_minimum_and_cli_text(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    graph, nodes, _edges = chain()
    report = attack_paths(graph, [nodes[0]], [nodes[-2]])
    assert report["candidates"][0]["path_confidence"] == 0.8
    graph_path, request, output = (
        tmp_path / name for name in ("graph.json", "query.json", "paths.txt")
    )
    graph_path.write_text(json.dumps(graph.to_dict()))
    request.write_text(json.dumps({"starts": [nodes[0]], "goals": [nodes[-1]]}))
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "deep-evidence",
            "attack-paths",
            str(graph_path),
            str(request),
            "--format",
            "text",
            "--output",
            str(output),
        ],
    )
    assert main() == 0 and "Weakest edge:" in output.read_text()


def test_indirect_asserted_alternative_and_result_limit() -> None:
    graph, nodes, edges = chain()
    alternative = graph.node("Function", "indirect-candidate")
    run = graph.edges[edges[0]]["producer"]
    graph.edge(
        nodes[0],
        alternative,
        "may_call",
        producer=run,
        method="indirect-target",
        evidence_refs=["artifact:indirect"],
        assertion="INFERRED",
        confidence=0.3,
    )
    graph.edge(
        alternative,
        nodes[-1],
        "flows_to",
        producer=run,
        method="producer-assertion",
        evidence_refs=["artifact:alternative"],
        assertion="ASSERTED",
        confidence=0.6,
    )
    report = attack_paths(graph, [nodes[0]], [nodes[-1]])
    assert len(report["candidates"]) == 2
    indirect = next(c for c in report["candidates"] if c["weakest_state"] == "INFERRED")
    assert indirect["path_confidence"] == 0.3
    assert {e["display_state"] for e in indirect["edges"]} == {"INFERRED", "ASSERTED"}
    assert attack_paths(graph, [nodes[0]], [nodes[-1]], max_paths=1)["truncated"]
