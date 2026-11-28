from __future__ import annotations

from pathlib import Path
import runpy
from types import SimpleNamespace as NS

import pytest

from vigil_fuse.binary_intelligence import (
    add_binary,
    import_call_graph,
    import_correspondence,
    validate_binary,
)
from vigil_fuse.evidence_graph import EvidenceGraph, import_ghidra


@pytest.mark.parametrize("format_name", ["ELF", "PE", "Mach-O"])
def test_external_metadata_script_and_hardening_states(format_name: str) -> None:
    script = Path(__file__).parents[1] / "src/vigil_fuse/resources/lief_metadata.py"
    functions = runpy.run_path(str(script))
    fake = NS(
        __version__="fixture",
        ELF=NS(Segment=NS(TYPE=NS(GNU_STACK="stack", GNU_RELRO="relro"), FLAGS=NS(X="x"))),
    )
    binary = NS(
        segments=[NS(type="stack", has=lambda flag: False), NS(type="relro")],
        is_pie=True,
        has_interpreter=True,
        imported_symbols=[NS(name="__stack_chk_fail"), NS(name="__memcpy_chk")],
        symbols=[NS(name="foo", value=4096)],
        header=NS(machine_type="x86", machine="AMD64", cpu_type="ARM64", flags=0x200000),
        optional_header=NS(dll_characteristics=0x4140),
        load_configuration=NS(),
        has_signatures=True,
        has_code_signature=True,
    )
    document = functions["metadata"](binary, format_name, "a" * 64, fake)
    validate_binary(document)
    g = EvidenceGraph("binary")
    add_binary(g, document)
    assert len(g.edges) > 0
    assert "confirmed vulnerability" in next(
        n["attributes"]["interpretation"]
        for n in g.nodes.values()
        if "interpretation" in n["attributes"]
    )
    binary.symbols = []
    stripped = functions["metadata"](binary, format_name, "a" * 64, fake)
    assert stripped["symbols"] == []
    if format_name == "ELF":
        binary.imported_symbols = []
        assert (
            functions["metadata"](binary, format_name, "a" * 64, fake)["hardening"]["stack canary"]
            == "unknown"
        )
    if format_name == "Mach-O":
        assert document["hardening"]["hardened runtime"] == "unknown"
    document["hardening"][next(iter(document["hardening"]))] = "confirmed-vulnerability"
    with pytest.raises(ValueError):
        validate_binary(document)


def test_calls_candidates_correspondence_and_dangling_output() -> None:
    g = EvidenceGraph("binary")
    document = {
        "schema_version": "fuse-ghidra-calls-1.0",
        "producer": "Ghidra",
        "sha256": "a" * 64,
        "functions": [{"name": "main", "address": "1000"}, {"name": "system", "address": "2000"}],
        "calls": [
            {"caller": "1000", "callee": "2000", "site": "1010", "indirect": False},
            {"caller": "1000", "callee": "2000", "site": "1020", "indirect": True},
        ],
        "truncated": False,
    }
    import_call_graph(g, document)
    assert {"calls", "may_call"} <= {e["relation"] for e in g.edges.values()}
    assert all(
        e["assertion"] == "INFERRED" for e in g.edges.values() if e["relation"] == "may_call"
    )
    source = g.node("Function", ["CodeQL", "source.c", "main"])
    target = next(
        n["id"] for n in g.nodes.values() if n["type"] == "Function" and n["id"] != source
    )
    import_correspondence(
        g, {"source": source, "binary": target, "method": "DWARF-match", "artifact": "debug:1"}
    )
    assert EvidenceGraph.from_dict(g.to_dict()).to_dict() == g.to_dict()
    document["calls"][0]["callee"] = "missing"
    with pytest.raises(ValueError):
        import_call_graph(EvidenceGraph("bad"), document)


def test_current_ghidra_import_maps_api_and_redacted_string_references() -> None:
    from test_ghidra_analyzer import _document

    g = EvidenceGraph("current-ghidra")
    import_ghidra(g, _document("a" * 64, "ELF", 32))
    assert any(e["relation"] == "references" for e in g.edges.values())
    assert any(n["attributes"].get("redacted") is True for n in g.nodes.values())
