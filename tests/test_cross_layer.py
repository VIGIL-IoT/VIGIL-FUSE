from __future__ import annotations

import copy

import pytest

from vigil_fuse.cross_layer import RULES, correlate, import_facts, materialize_correlations
from vigil_fuse.evidence_graph import EvidenceGraph


def scenario(
    rule_id: str = "debug-uart-exposure", shared_artifact: bool = False
) -> tuple[EvidenceGraph, dict]:
    graph = EvidenceGraph("product")
    subject = graph.node("Component", "device-A")
    rule = RULES[rule_id]
    rows = []
    types = {
        "source": "File",
        "build": "BuildTarget",
        "dependency": "Package",
        "binary": "Function",
        "firmware": "FirmwareImage",
        "device_configuration": "Configuration",
        "hardware": "Net",
        "rtl": "File",
        "deployment": "Interface",
    }
    for layer, predicate in rule["requires"]:
        run = graph.run("producer-" + layer, "completed", artifact="artifact:" + layer)
        support = graph.node(types[layer], [layer, predicate])
        edge = graph.edge(
            subject,
            support,
            "contains",
            producer=run,
            method="fixture-producer-contract",
            evidence_refs=["artifact:shared" if shared_artifact else "artifact:" + layer],
        )
        rows.append(
            {
                "subject": subject,
                "feature": rule["feature"] or "feature-A",
                "layer": layer,
                "predicate": predicate,
                "assertion": "OBSERVED",
                "evidence_nodes": [support],
                "evidence_edges": [edge],
                "limitations": ["Fixture validates correlation behavior, not accuracy."],
            }
        )
    return graph, {
        "schema_version": "1.0",
        "producer": "reviewed-bindings",
        "tool_version": "fixture",
        "artifact": "artifact:identity-mappings",
        "facts": rows,
    }


@pytest.mark.parametrize("rule", RULES)
def test_each_rule_requires_specific_independent_layers(rule: str) -> None:
    graph, document = scenario(rule)
    incomplete = copy.deepcopy(document)
    incomplete["facts"].pop()
    import_facts(graph, incomplete)
    assert correlate(graph)["candidates"] == []
    import_facts(graph, document)
    report = correlate(graph)
    candidate = next(row for row in report["candidates"] if row["rule"] == rule)
    assert candidate["severity"] is None and candidate["confidence"] is None
    assert candidate["assertion"] == "INFERRED" and candidate["unknown"]
    assert set(candidate["supporting_edges"]) == {r["evidence_edges"][0] for r in document["facts"]}
    assert set(candidate["observed"]) == set(candidate["fact_nodes"])
    assert correlate(EvidenceGraph.from_dict(graph.to_dict())) == report


def test_duplicates_and_shared_underlying_artifact_cannot_meet_independence_threshold() -> None:
    graph, doc = scenario(shared_artifact=True)
    doc["facts"] *= 2
    import_facts(graph, doc)
    assert correlate(graph)["candidates"] == []
    graph, doc = scenario()
    doc["facts"] = [doc["facts"][0]] * 20
    import_facts(graph, doc)
    assert correlate(graph)["candidates"] == []


def test_unknown_and_negated_evidence_and_cross_product_binding() -> None:
    graph, doc = scenario()
    unknown = copy.deepcopy(doc)
    unknown["facts"][0]["assertion"] = "UNKNOWN"
    import_facts(graph, unknown)
    assert correlate(graph)["candidates"] == []
    other = graph.node("Component", "device-B")
    doc["facts"][0]["subject"] = other
    import_facts(graph, doc)
    assert correlate(graph)["candidates"] == []
    graph, doc = scenario()
    import_facts(graph, doc)
    negative = copy.deepcopy(doc)
    negative["facts"] = negative["facts"][:1]
    negative["facts"][0]["assertion"] = "NEGATED"
    import_facts(graph, negative)
    report = correlate(graph)
    assert report["candidates"] == [] and report["blocked"][0]["contradictions"]


def test_graph_edge_contradiction_blocks_candidate_and_unknown_source_is_not_promoted() -> None:
    graph, doc = scenario()
    original = graph.edges[doc["facts"][0]["evidence_edges"][0]]
    graph.edge(
        original["source"],
        original["target"],
        original["relation"],
        producer=original["producer"],
        method="independent-negative-review",
        evidence_refs=["review:exclusion"],
        assertion="NEGATED",
    )
    import_facts(graph, doc)
    assert correlate(graph)["candidates"] == [] and correlate(graph)["blocked"]
    graph, doc = scenario()
    original = graph.edges[doc["facts"][0]["evidence_edges"][0]]
    uncertain = graph.edge(
        original["source"],
        original["target"],
        original["relation"],
        producer=original["producer"],
        method="uncertain",
        evidence_refs=["artifact:uncertain"],
        assertion="UNKNOWN",
    )
    doc["facts"][0]["evidence_edges"] = [uncertain]
    with pytest.raises(ValueError):
        import_facts(graph, doc)
    doc["facts"][0]["assertion"] = "ASSERTED"
    import_facts(graph, doc)
    assert correlate(graph)["candidates"] == []


@pytest.mark.parametrize("mode", ["node", "edge", "layer", "field", "subject"])
def test_malformed_bindings_rejected(mode: str) -> None:
    graph, doc = scenario()
    row = doc["facts"][0]
    if mode == "node":
        row["evidence_nodes"] = ["missing"]
    if mode == "edge":
        row["evidence_edges"] = ["missing"]
    if mode == "layer":
        row["layer"] = "imagined"
    if mode == "field":
        row["severity"] = "critical"
    if mode == "subject":
        row["subject"] = "missing"
    with pytest.raises(ValueError):
        import_facts(graph, doc)


def test_materialization_preserves_original_findings_and_lists_all_support() -> None:
    graph, doc = scenario()
    finding = graph.node(
        "Finding", "existing", severity="low", applicability="unknown", validation="unverified"
    )
    before = copy.deepcopy(graph.nodes[finding])
    import_facts(graph, doc)
    report = correlate(graph)
    materialize_correlations(graph, report)
    first = graph.to_dict()
    materialize_correlations(graph, report)
    assert graph.to_dict() == first and graph.nodes[finding] == before
    candidate = report["candidates"][0]
    inferred = [e for e in graph.edges.values() if e["method"] == candidate["rule"]]
    assert {e["source"] for e in inferred} == set(candidate["supporting_nodes"])
    assert all(e["assertion"] == "INFERRED" for e in inferred)


def test_explicit_graph_contradiction_of_support_blocks_candidate() -> None:
    graph, doc = scenario()
    import_facts(graph, doc)
    review = graph.node("EvidenceArtifact", "review:contradiction")
    run = graph.run("review", "completed", artifact="review:contradiction")
    graph.edge(
        review,
        doc["facts"][0]["evidence_nodes"][0],
        "contradicts",
        producer=run,
        method="review",
        evidence_refs=["review:contradiction"],
        assertion="ASSERTED",
    )
    assert not correlate(graph)["candidates"] and correlate(graph)["blocked"]
