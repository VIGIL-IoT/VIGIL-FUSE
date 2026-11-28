"""Contract integration, not independent accuracy or a physical/runtime experiment."""

from __future__ import annotations

import copy
import hashlib
import json
from importlib.resources import files
from pathlib import Path

from jsonschema import Draft202012Validator

from vigil_fuse.attack_paths import attack_paths
from vigil_fuse.binary_intelligence import import_call_graph, import_correspondence
from vigil_fuse.cross_layer import correlate, import_facts, materialize_correlations
from vigil_fuse.dependency_reachability import assess_dependency, import_advisory_symbols
from vigil_fuse.evidence_graph import (
    EvidenceGraph,
    graph_from_report,
    import_build,
    import_netlist,
    import_policy,
    import_sbom,
)
from vigil_fuse.firmware_rootfs import add_rootfs
from vigil_fuse.hardware_netlist import read_netlist_topology
from vigil_fuse.reporting import to_json
from vigil_fuse.runtime_evidence import add_runtime, ingest_runtime
from vigil_fuse.scanner import scan
from vigil_fuse.semantic_flow import add_flows, normalize_sarif
from test_firmware_rootfs import safe_root
from test_runtime_evidence import LOGS, metadata
from test_semantic_flow import sarif


def test_project_to_graph_flow_reachability_runtime_correlation_paths_policy(
    tmp_path: Path,
) -> None:
    project = tmp_path / "project"
    project.mkdir()
    (project / "server.py").write_text('password = "integration_secret_value"\n')
    (project / "debug.sv").write_text(
        "module debug_top(input wire debug_en, output wire debug_out); assign debug_out = debug_en; endmodule\n"
    )
    scan_result = scan(project)
    baseline = to_json(scan_result)
    report = json.loads(baseline)
    graph = graph_from_report(report)
    original = {n: copy.deepcopy(row) for n, row in graph.nodes.items() if row["type"] == "Finding"}
    assert original and graph.target_identity
    assert any(
        n["type"] == "BuildTarget" and n["identity"][0] == "rtl-candidate"
        for n in graph.nodes.values()
    )
    import_build(
        graph,
        {
            "target": "device",
            "translation_units": [
                {
                    "path": "server.py",
                    "sha256": hashlib.sha256((project / "server.py").read_bytes()).hexdigest(),
                    "included": True,
                }
            ],
            "artifact": "fixture:build-metadata",
        },
    )
    import_sbom(
        graph,
        {"bomFormat": "CycloneDX", "components": [{"purl": "pkg:pypi/demo@1", "version": "1"}]},
    )
    package = graph.node("Package", ["pkg:pypi/demo@1", "1"])
    build = graph.node("BuildTarget", "device")
    advisory = graph.node("Advisory", "fixture:advisory")
    root = tmp_path / "rootfs"
    root.mkdir()
    rootfs = safe_root(root)
    add_rootfs(graph, rootfs)
    binary_digest = rootfs["binaries"][0]["sha256"]
    binary = graph.node("Binary", binary_digest)
    import_call_graph(
        graph,
        {
            "schema_version": "fuse-ghidra-calls-1.0",
            "producer": "Ghidra",
            "sha256": binary_digest,
            "functions": [
                {"name": "api", "address": "1000"},
                {"name": "foo_parse", "address": "2000"},
            ],
            "calls": [{"caller": "1000", "callee": "2000", "site": "1010", "indirect": False}],
            "truncated": False,
        },
    )
    entry, sink = [
        graph.node("Function", ["ghidra", binary_digest, address, name])
        for address, name in (("1000", "api"), ("2000", "foo_parse"))
    ]
    producer = graph.run(
        "integration-build-review", "completed", artifact="fixture:build-membership"
    )
    for a, b, relation in ((build, package, "includes"), (package, binary, "contains")):
        graph.edge(
            a,
            b,
            relation,
            producer=producer,
            method="fixture-exact-build-binding",
            evidence_refs=["fixture:build-membership"],
            assertion="ASSERTED",
        )
    symbols = import_advisory_symbols(
        graph,
        {
            "package": package,
            "advisory": advisory,
            "artifact": "fixture:advisory-symbols",
            "symbols": [{"namespace": "Ghidra", "name": "foo_parse", "node": sink}],
        },
    )
    reachability = assess_dependency(
        graph,
        {
            "package": package,
            "advisory": advisory,
            "symbols": symbols,
            "build_target": build,
            "entry_points": [entry],
        },
    )
    assert reachability["symbols"][0]["symbol_reachable"] == "YES"
    assert reachability["runtime_reachability"] == "UNKNOWN"
    sarif_document = sarif()
    sarif_document["runs"][0]["results"][0]["codeFlows"][0]["threadFlows"][0]["locations"][2][
        "kinds"
    ] = []
    add_flows(graph, normalize_sarif(sarif_document, "python"))
    source = graph.node("Function", ["CodeQL", "server.py", "handler"])
    import_correspondence(
        graph,
        {
            "source": source,
            "binary": entry,
            "method": "fixture-debug-info-binding",
            "artifact": "fixture:debug-info",
        },
    )
    netlist = Path(__file__).parent / "fixtures/hardware/debug-interface.net"
    import_netlist(graph, read_netlist_topology(netlist.parent, netlist.name))
    hardware_edge = next(e for e in graph.edges.values() if e["relation"] == "connected_to")
    source_edge = next(e for e in graph.edges.values() if e["relation"] == "flows_to")
    firmware_edge = next(
        e
        for e in graph.edges.values()
        if graph.nodes[e["source"]]["type"] == "Filesystem" and e["target"] == binary
    )
    config = graph.node("Configuration", "fixture:uart-pin-config")
    config_run = graph.run("device-tree-fixture", "completed", artifact="fixture:device-tree")
    config_edge = graph.edge(
        config,
        entry,
        "configured_by",
        producer=config_run,
        method="fixture-config",
        evidence_refs=["fixture:device-tree"],
        assertion="ASSERTED",
    )
    subject = graph.node("FirmwareImage", rootfs["firmware_sha256"])
    facts = []
    for layer, predicate, evidence_edge in (
        ("source", "debug-enabled", source_edge["id"]),
        ("device_configuration", "pins-configured", config_edge),
        ("firmware", "debug-feature-present", firmware_edge["id"]),
        ("hardware", "interface-connected", hardware_edge["id"]),
    ):
        edge = graph.edges[evidence_edge]
        facts.append(
            {
                "subject": subject,
                "feature": "uart",
                "layer": layer,
                "predicate": predicate,
                "assertion": "ASSERTED",
                "evidence_nodes": [edge["target"]],
                "evidence_edges": [evidence_edge],
                "limitations": ["Explicit fixture correspondence; not a physical experiment."],
            }
        )
    import_facts(
        graph,
        {
            "schema_version": "1.0",
            "producer": "integration-review",
            "tool_version": "fixture",
            "artifact": "fixture:cross-layer-bindings",
            "facts": facts,
        },
    )
    correlations = correlate(graph)
    assert correlations["candidates"][0]["assertion"] == "INFERRED"
    materialize_correlations(graph, correlations)
    runtime_metadata = metadata()
    runtime_metadata["binary_sha256"] = binary_digest
    observation = add_runtime(graph, ingest_runtime(LOGS["ASan"].encode(), runtime_metadata))[0]
    binary_call = next(
        e
        for e in graph.edges.values()
        if e["source"] == entry and e["target"] == sink and e["relation"] == "calls"
    )
    call_path = graph.node("CallPath", "fixture:reviewed-test-path", edge_ids=[binary_call["id"]])
    review = graph.run("integration-runtime-review", "completed", artifact="fixture:runtime-review")
    support = graph.edge(
        observation,
        call_path,
        "supports",
        producer=review,
        method="fixture-reviewed-runtime-correspondence",
        evidence_refs=["fixture:runtime-review"],
        assertion="ASSERTED",
    )
    privileged = graph.node("Component", "privileged-execution")
    graph.edge(
        sink,
        privileged,
        "flows_to",
        producer=review,
        method="exposure-unknown",
        evidence_refs=["fixture:exposure-gap"],
        assertion="UNKNOWN",
    )
    attacks = attack_paths(
        graph,
        [entry],
        [privileged],
        validations=[
            {
                "edge": binary_call["id"],
                "observation": observation,
                "support_edge": support,
                "review_artifact": "fixture:runtime-review",
                "scope": "test-execution",
            }
        ],
    )
    assert attacks["candidates"][0]["weakest_state"] == "UNKNOWN"
    assert {e["display_state"] for e in attacks["candidates"][0]["edges"]} == {
        "VALIDATED",
        "UNKNOWN",
    }
    import_policy(
        graph,
        {
            "policy": "review-runtime-and-physical-gaps",
            "evidence_nodes": [observation, call_path],
            "artifact": "fixture:policy-review",
        },
    )
    restored = EvidenceGraph.from_dict(graph.to_dict())
    assert restored.to_dict() == graph.to_dict()
    assert all(graph.nodes[n] == row for n, row in original.items())
    assert to_json(scan_result) == baseline
    report.update(evidence_graph=graph.to_dict())
    schema = json.loads(
        files("vigil_fuse").joinpath("schemas/fuse-report-1.15.schema.json").read_text()
    )
    Draft202012Validator(schema).validate(report)
    assert "integration_secret_value" not in json.dumps(report)
