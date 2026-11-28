from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from vigil_fuse import evidence_graph as eg
from vigil_fuse.reporting import to_json
from vigil_fuse.scanner import scan


def graph() -> eg.EvidenceGraph:
    result = eg.EvidenceGraph("project:fixture")
    run = result.run("fixture", "partial")
    a = result.node("Function", ["fixture", "entry"])
    b = result.node("Function", ["fixture", "sink"])
    result.edge(
        a,
        b,
        "may_call",
        producer=run,
        method="fixture",
        evidence_refs=["fixture:1"],
        assertion="UNKNOWN",
        limitations=["Runtime unknown"],
    )
    return result


def test_deterministic_roundtrip_dedup_and_contradictions() -> None:
    g = graph()
    assert g.to_dict() == graph().to_dict()
    assert eg.EvidenceGraph.from_dict(json.loads(json.dumps(g.to_dict()))).to_dict() == g.to_dict()
    edge = next(iter(g.edges.values()))
    args = {k: v for k, v in edge.items() if k != "id"}
    g.edge(**args)
    assert len(g.edges) == 1
    args["assertion"] = "NEGATED"
    g.edge(**args)
    assert len(g.edges) == 2
    assert edge["confidence"] is None
    assert eg.identity("File", ["a.c", "a" * 64]) != eg.identity("File", ["a.c", "b" * 64])


@pytest.mark.parametrize(
    "change",
    [
        "version",
        "extra",
        "dangling",
        "identity",
        "duplicate",
        "coverage",
        "producer",
        "confidence",
        "assertion",
    ],
)
def test_malformed_graph_rejected(change: str) -> None:
    row = copy.deepcopy(graph().to_dict())
    if change == "version":
        row["schema_version"] = "999"
    if change == "extra":
        row["surprise"] = True
    if change == "dangling":
        row["edges"][0]["source"] = "missing"
    if change == "identity":
        row["nodes"][0]["identity"] = "wrong"
    if change == "duplicate":
        row["nodes"].append(row["nodes"][0])
    if change == "coverage":
        row["coverage"] = {}
    if change == "producer":
        row["edges"][0]["producer"] = "missing"
    if change == "confidence":
        row["edges"][0]["confidence"] = float("nan")
    if change == "assertion":
        row["edges"][0]["assertion"] = "VALIDATED"
    with pytest.raises(ValueError):
        eg.EvidenceGraph.from_dict(row)


def test_limits_and_conflicts(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    g = graph()
    monkeypatch.setattr(eg, "MAX_NODES", len(g.nodes))
    with pytest.raises(ValueError):
        g.node("File", "extra")
    with pytest.raises(ValueError):
        g.node("Function", ["fixture", "entry"], different=True)
    monkeypatch.setattr(eg, "MAX_EDGES", 0)
    e = next(iter(g.edges.values()))
    with pytest.raises(ValueError):
        g.edge(
            e["source"],
            e["target"],
            "calls",
            producer=e["producer"],
            method="test",
            evidence_refs=["ref"],
        )
    for payload in ('{"a":1,"a":2}', '{"a":NaN}', "[" * 2000, "x" * 50):
        path = tmp_path / "invalid.json"
        path.write_text(payload)
        with pytest.raises(ValueError):
            eg.read_json(path, 100)


def test_report_backward_compatibility_schema_and_integration(tmp_path: Path) -> None:
    (tmp_path / "main.c").write_text("int main(void) { return 0; }\n")
    result = scan(tmp_path)
    baseline = to_json(result)
    report = json.loads(to_json(result, include_evidence_graph=True))
    assert "evidence_graph" not in json.loads(baseline)
    assert report["findings"] == json.loads(baseline)["findings"]
    assert to_json(result) == baseline
    g = eg.EvidenceGraph.from_dict(report["evidence_graph"])
    eg.import_sbom(
        g,
        {
            "bomFormat": "CycloneDX",
            "components": [
                {"purl": "pkg:pypi/demo@1", "version": "1", "bom-ref": "a"},
                {"purl": "pkg:pypi/other@2", "version": "2", "bom-ref": "b"},
            ],
            "dependencies": [{"ref": "a", "dependsOn": ["b"]}],
        },
    )
    eg.import_build(
        g,
        {
            "target": "product",
            "translation_units": [{"path": "main.c", "sha256": "a" * 64, "included": True}],
            "artifact": "build:1",
        },
    )
    firmware = g.node("FirmwareImage", "c" * 64)
    binary = g.node("Binary", "d" * 64)
    run = g.run("firmware-fixture", "completed")
    g.edge(
        firmware,
        binary,
        "contains",
        producer=run,
        method="fixture",
        evidence_refs=["fixture:firmware"],
    )
    from vigil_fuse.hardware_netlist import NetlistTopology, NetlistNet, NetlistEndpoint

    eg.import_netlist(
        g,
        NetlistTopology(
            status="completed",
            sha256="e" * 64,
            components=("J1",),
            nets=(NetlistNet("UART_TX", (NetlistEndpoint("J1", "1", True),)),),
        ),
    )
    eg.import_policy(g, {"policy": "review", "evidence_nodes": [binary], "artifact": "policy:1"})
    assert {
        "Package",
        "TranslationUnit",
        "FirmwareImage",
        "Binary",
        "HardwareComponent",
        "Net",
        "Pin",
        "Policy",
    } <= {n["type"] for n in g.nodes.values()}
    schemas = Path(__file__).parents[1] / "src/vigil_fuse/schemas"
    Draft202012Validator(
        json.loads((schemas / "evidence-graph-1.0.schema.json").read_text())
    ).validate(g.to_dict())
    Draft202012Validator(
        json.loads((schemas / "fuse-report-1.14.schema.json").read_text())
    ).validate(report)


def test_existing_kicad_parser_status_is_normalized() -> None:
    from vigil_fuse.hardware_netlist import read_netlist_topology

    root = Path(__file__).parent / "fixtures/hardware"
    g = eg.EvidenceGraph("kicad-fixture")
    eg.import_netlist(g, read_netlist_topology(root, "debug-interface.net"))
    assert "completed" in g.coverage.values()
    assert any(e["relation"] == "connected_to" for e in g.edges.values())
    failed = eg.EvidenceGraph("invalid-kicad")
    eg.import_netlist(failed, read_netlist_topology(root, "missing.net"))
    assert list(failed.coverage.values()) == ["failed"]
