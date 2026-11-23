from __future__ import annotations

import pytest

from vigil_fuse.evidence_graph import EvidenceGraph
from vigil_fuse.dependency_reachability import (
    assess_dependency,
    import_advisory_symbols,
    import_calls,
)
from vigil_fuse.graph_query import paths


def fixture(
    *, included: str | None = None, present: bool = False, call: bool | None = None
) -> tuple[EvidenceGraph, dict]:
    g = EvidenceGraph("product")
    package = g.node("Package", ["pkg:pypi/demo@1", "1"])
    advisory = g.node("Advisory", "CVE-fixture")
    build = g.node("BuildTarget", "product")
    entry, helper, sink = [
        g.node("Function", ["CodeQL", name]) for name in ("api", "decode", "foo_parse")
    ]
    run = g.run("fixture", "partial")
    if included:
        g.edge(
            build,
            package,
            "includes",
            producer=run,
            method="build",
            evidence_refs=["build:1"],
            assertion=included,
        )
    if present:
        binary = g.node("Binary", "a" * 64)
        for a, b in ((package, binary), (binary, sink)):
            g.edge(
                a,
                b,
                "contains",
                producer=run,
                method="binary-inventory",
                evidence_refs=["binary:1"],
            )
    if call is not None:
        import_calls(
            g,
            {
                "engine": "CodeQL",
                "version": "fixture",
                "artifact": "calls:1",
                "status": "partial",
                "calls": [
                    {
                        "caller": entry,
                        "callee": helper,
                        "direct": True,
                        "evidence_refs": ["calls:1"],
                    },
                    {
                        "caller": helper,
                        "callee": sink,
                        "direct": call,
                        "evidence_refs": ["calls:2"],
                    },
                ],
            },
        )
    symbols = import_advisory_symbols(
        g,
        {
            "package": package,
            "advisory": advisory,
            "artifact": "advisory:1",
            "symbols": [
                {"namespace": "CodeQL", "name": "foo_parse", "node": sink if present else None}
            ],
        },
    )
    return g, {
        "package": package,
        "advisory": advisory,
        "symbols": symbols,
        "build_target": build,
        "entry_points": [entry],
    }


@pytest.mark.parametrize(
    "included,present,call,expected",
    [
        (None, False, None, "UNKNOWN"),
        ("OBSERVED", True, None, "UNKNOWN"),
        ("OBSERVED", True, True, "YES"),
        ("NEGATED", True, True, "NO"),
        ("OBSERVED", True, False, "UNKNOWN"),
    ],
)
def test_presence_inclusion_reference_reachability_are_separate(
    included: str | None, present: bool, call: bool | None, expected: str
) -> None:
    g, request = fixture(included=included, present=present, call=call)
    before = g.to_dict()
    result = assess_dependency(g, request)
    assert result["symbols"][0]["symbol_reachable"] == expected
    assert result["runtime_reachability"] == "UNKNOWN"
    assert result["package_present"] == "YES"
    assert g.to_dict() == before


def test_package_only_and_multiple_versions() -> None:
    g, request = fixture()
    request["symbols"] = []
    assert assess_dependency(g, request)["applicability_assessment"] == "unknown"
    g, request = fixture(present=True)
    other = g.node("Package", ["pkg:pypi/demo@2", "2"])
    request["package"] = other
    with pytest.raises(ValueError):
        assess_dependency(g, request)


def test_vex_and_build_contradictions_preserve_findings() -> None:
    g, request = fixture(included="OBSERVED", present=True, call=True)
    run = g.run("vex-fixture", "completed")
    finding = {
        "component": {"purl": "pkg:pypi/demo@1", "version": "1"},
        "vex_review": {"state": "not_affected"},
        "severity": "high",
        "applicability": "unknown",
    }
    node = g.node("Finding", "finding:1", finding=finding)
    g.edge(
        node,
        request["advisory"],
        "derived_from",
        producer=run,
        method="fixture",
        evidence_refs=["vex:1"],
    )
    before = g.to_dict()
    assert assess_dependency(g, request)["contradiction"] is True
    assert g.to_dict() == before
    g.edge(
        request["build_target"],
        request["package"],
        "includes",
        producer=run,
        method="exclusion",
        evidence_refs=["build:2"],
        assertion="NEGATED",
    )
    assert assess_dependency(g, request)["package_included"] == "CONTRADICTORY"


def test_query_limits_cycles_and_malformed_calls() -> None:
    g, request = fixture(included="OBSERVED", present=True, call=True)
    with pytest.raises(ValueError):
        paths(g, [], [], max_depth=0)
    result = paths(g, request["entry_points"], [], max_depth=1)
    assert result["truncated"] is True
    run = g.run("cycle", "completed")
    entry = request["entry_points"][0]
    g.edge(entry, entry, "calls", producer=run, method="fixture", evidence_refs=["cycle:1"])
    assert paths(g, [entry], [])["visits"] < 10
    edge = next(
        e
        for e in g.edges.values()
        if e["source"] == entry and e["relation"] == "calls" and e["target"] != entry
    )
    g.edge(
        entry,
        edge["target"],
        "calls",
        producer=run,
        method="negative-call",
        evidence_refs=["negative:1"],
        assertion="NEGATED",
    )
    assert assess_dependency(g, request)["symbols"][0]["symbol_reachable"] == "UNKNOWN"
    with pytest.raises(ValueError):
        import_calls(
            g,
            {
                "engine": "CodeQL",
                "version": "fixture",
                "artifact": "bad:1",
                "status": "completed",
                "calls": [
                    {
                        "caller": entry,
                        "callee": "missing",
                        "direct": True,
                        "evidence_refs": ["bad:1"],
                    }
                ],
            },
        )
