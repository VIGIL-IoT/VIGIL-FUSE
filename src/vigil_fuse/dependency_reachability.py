"""Evidence-specific dependency assessments, independent of static finding verdicts."""

from __future__ import annotations

from typing import Any

from .evidence_graph import EvidenceGraph, object_fields, strings, text
from .graph_query import paths


def require_node(graph: EvidenceGraph, node: str, kinds: set[str]) -> None:
    if node not in graph.nodes or graph.nodes[node]["type"] not in kinds:
        raise ValueError("Missing or mismatched reachability node")


def import_calls(graph: EvidenceGraph, document: dict[str, Any]) -> None:
    object_fields(document, {"engine", "version", "artifact", "status", "calls"})
    if document["engine"] not in {"CodeQL", "Joern", "Ghidra", "Clang"}:
        raise ValueError("Unsupported call evidence producer")
    if not isinstance(document["calls"], list) or len(document["calls"]) > 10000:
        raise ValueError("Call evidence limit exceeded")
    run = graph.run(
        document["engine"],
        document["status"],
        version=document["version"],
        artifact=document["artifact"],
    )
    if document["status"] not in {"completed", "partial"} and document["calls"]:
        raise ValueError("Unavailable producer cannot emit calls")
    for call in document["calls"]:
        object_fields(call, {"caller", "callee", "direct", "evidence_refs"})
        require_node(graph, call["caller"], {"Function"})
        require_node(graph, call["callee"], {"Function", "Symbol"})
        if type(call["direct"]) is not bool:
            raise ValueError("Call resolution must be explicit")
        graph.edge(
            call["caller"],
            call["callee"],
            "calls" if call["direct"] else "may_call",
            producer=run,
            method="external-call-evidence",
            evidence_refs=strings(call["evidence_refs"]),
            assertion="ASSERTED",
            limitations=["Static call evidence does not establish runtime execution."],
        )


def import_advisory_symbols(graph: EvidenceGraph, document: dict[str, Any]) -> list[str]:
    object_fields(document, {"advisory", "package", "symbols", "artifact"})
    require_node(graph, document["advisory"], {"Advisory"})
    require_node(graph, document["package"], {"Package"})
    if not isinstance(document["symbols"], list) or len(document["symbols"]) > 1000:
        raise ValueError("Advisory symbol limit exceeded")
    run = graph.run("function-advisory", "completed", artifact=text(document["artifact"]))
    result = []
    for symbol in document["symbols"]:
        object_fields(symbol, {"namespace", "name", "node"})
        key = [
            document["package"],
            document["advisory"],
            text(symbol["namespace"]),
            text(symbol["name"]),
        ]
        vulnerable = graph.node("VulnerableSymbol", key)
        result.append(vulnerable)
        for a, b in ((document["advisory"], vulnerable), (vulnerable, document["package"])):
            graph.edge(
                a,
                b,
                "supports",
                producer=run,
                method="advisory-symbol-metadata",
                evidence_refs=[document["artifact"]],
                assertion="ASSERTED",
            )
        if symbol["node"] is not None:
            require_node(graph, symbol["node"], {"Function", "Symbol"})
            graph.edge(
                vulnerable,
                symbol["node"],
                "corresponds_to",
                producer=run,
                method="explicit-symbol-match",
                evidence_refs=[document["artifact"]],
                assertion="ASSERTED",
                limitations=[
                    "Identity correspondence is supplied by the producer; name similarity alone is insufficient."
                ],
            )
    return result


def _state(edges: list[dict[str, Any]]) -> str:
    positive = any(e["assertion"] in {"OBSERVED", "ASSERTED"} for e in edges)
    negative = any(e["assertion"] == "NEGATED" for e in edges)
    return (
        "CONTRADICTORY"
        if positive and negative
        else "YES"
        if positive
        else "NO"
        if negative
        else "UNKNOWN"
    )


def assess_dependency(graph: EvidenceGraph, request: dict[str, Any]) -> dict[str, Any]:
    object_fields(request, {"package", "advisory", "symbols", "build_target", "entry_points"})
    package, advisory, build = request["package"], request["advisory"], request["build_target"]
    require_node(graph, package, {"Package"})
    require_node(graph, advisory, {"Advisory"})
    if build is not None:
        require_node(graph, build, {"BuildTarget"})
    symbols, entries = strings(request["symbols"]), strings(request["entry_points"])
    for entry_node in entries:
        require_node(graph, entry_node, {"Function"})
    edges = sorted(graph.edges.values(), key=lambda e: e["id"])
    build_edges = [
        e
        for e in edges
        if e["source"] == build
        and e["target"] == package
        and e["relation"] in {"includes", "depends_on"}
    ]
    included = _state(build_edges)
    evidence_refs: set[str] = {e["id"] for e in build_edges}
    assessments = []
    for symbol in sorted(set(symbols)):
        require_node(graph, symbol, {"VulnerableSymbol"})
        key = graph.nodes[symbol]["identity"]
        if not isinstance(key, list) or key[:2] != [package, advisory]:
            raise ValueError("Advisory symbol belongs to a different package/version")
        matches = [
            e
            for e in edges
            if e["source"] == symbol
            and e["relation"] == "corresponds_to"
            and e["assertion"] in {"OBSERVED", "ASSERTED"}
        ]
        nodes = [e["target"] for e in matches]
        # Package membership must be explicit, including a package -> binary -> symbol chain.
        members = paths(graph, [package], nodes, relations=frozenset({"contains", "includes"}))
        present = "YES" if members["paths"] else "UNKNOWN"
        references = [
            e
            for e in edges
            if e["target"] in nodes and e["relation"] in {"calls", "may_call", "references"}
        ]
        calls = paths(graph, entries, nodes)
        reachable = (
            "YES"
            if calls["paths"] and present == "YES" and included == "YES"
            else "NO"
            if included == "NO"
            else "UNKNOWN"
        )
        evidence_refs.update(e["id"] for e in matches + references)
        for path in members["paths"] + calls["paths"]:
            evidence_refs.update(path)
        assessments.append(
            {
                "symbol": symbol,
                "symbol_present": present,
                "symbol_referenced": _state(references),
                "symbol_reachable": reachable,
                "call_paths": calls["paths"],
                "coverage_limited": members["truncated"] or calls["truncated"],
                "runtime_reachability": "UNKNOWN",
            }
        )
    vex = []
    for node in graph.nodes.values():
        finding = node["attributes"].get("finding")
        if (
            node["type"] != "Finding"
            or not isinstance(finding, dict)
            or not finding.get("component")
        ):
            continue
        if not any(
            e["source"] == node["id"]
            and e["target"] == advisory
            and e["relation"] == "derived_from"
            for e in edges
        ):
            continue
        component = finding["component"]
        if graph.nodes[package]["identity"] == [
            component.get("purl") or [component["ecosystem"], component["name"]],
            component["version"],
        ] and finding.get("vex_review"):
            vex.append({"finding": node["id"], "review": finding["vex_review"]})
    reached = any(item["symbol_reachable"] == "YES" for item in assessments)
    contradiction = included == "CONTRADICTORY" or (
        reached
        and any(
            v["review"]["state"]
            in {"not_affected", "false_positive", "resolved", "resolved_with_pedigree"}
            for v in vex
        )
    )
    return {
        "schema_version": "1.0",
        "package": package,
        "advisory": advisory,
        "package_present": "YES",
        "package_included": included,
        "symbols": assessments,
        "runtime_reachability": "UNKNOWN",
        "vex_assertions": vex,
        "contradiction": contradiction,
        "applicability_assessment": "conflicting-evidence"
        if contradiction
        else "supported-by-static-path"
        if reached
        else "unknown",
        "evidence_refs": sorted(evidence_refs),
        "limitations": [
            "Assessments do not update findings or prove deployed exposure.",
            "No path in a partial call graph is not proof of unreachable code.",
            "Package identities and symbol matches are exact and version-scoped.",
        ],
    }
