"""Binary evidence adapters. External engines own parsing and disassembly."""

from __future__ import annotations

from importlib.resources import as_file, files
import re
from pathlib import Path
from typing import Any

from .analyzer_contract import AnalyzerRequest, AnalyzerResult, run_analyzer
from .evidence_graph import EvidenceGraph, identity, object_fields, strings, text

CONTROLS = {
    "ELF": {"NX", "PIE", "RELRO", "stack canary", "FORTIFY"},
    "PE": {"ASLR", "DEP", "CFG", "signing"},
    "Mach-O": {"PIE", "code signing", "hardened runtime"},
}


def validate_binary(document: dict[str, Any]) -> dict[str, Any]:
    object_fields(
        document,
        {
            "schema_version",
            "producer",
            "sha256",
            "format",
            "architecture",
            "hardening",
            "symbols",
            "truncated",
            "limitations",
        },
    )
    object_fields(document["producer"], {"name", "version"})
    if (
        document["schema_version"] != "1.0"
        or document["producer"]["name"] != "LIEF"
        or document["format"] not in CONTROLS
    ):
        raise ValueError("Unsupported binary evidence")
    if not re.fullmatch(r"[a-f0-9]{64}", text(document["sha256"])):
        raise ValueError("Invalid binary digest")
    text(document["producer"]["version"])
    text(document["architecture"])
    object_fields(document["hardening"], CONTROLS[document["format"]])
    if any(v not in {"present", "absent", "unknown"} for v in document["hardening"].values()):
        raise ValueError("Invalid hardening state")
    if (
        type(document["truncated"]) is not bool
        or not isinstance(document["symbols"], list)
        or len(document["symbols"]) > 4096
    ):
        raise ValueError("Binary symbol limit exceeded")
    for symbol in document["symbols"]:
        object_fields(symbol, {"name", "address"})
        text(symbol["name"])
        text(symbol["address"])
    strings(document["limitations"])
    return document


def add_binary(graph: EvidenceGraph, document: dict[str, Any]) -> str:
    validate_binary(document)
    run = graph.run(
        "LIEF",
        "partial" if document["truncated"] else "completed",
        version=document["producer"]["version"],
        artifact=identity("binary-metadata", document),
    )
    binary = graph.node("Binary", document["sha256"])
    artifact = graph.node(
        "EvidenceArtifact",
        identity("hardening", document),
        hardening=document["hardening"],
        architecture=document["architecture"],
        format=document["format"],
        interpretation="hardening control absent is not a confirmed vulnerability",
    )
    graph.edge(
        artifact,
        binary,
        "supports",
        producer=run,
        method="binary-hardening-metadata",
        evidence_refs=[document["sha256"]],
        limitations=document["limitations"],
    )
    for symbol in document["symbols"]:
        node = graph.node("Symbol", ["LIEF", document["sha256"], symbol["address"], symbol["name"]])
        graph.edge(
            binary,
            node,
            "contains",
            producer=run,
            method="binary-symbol-inventory",
            evidence_refs=[document["sha256"]],
        )
    return binary


def import_call_graph(graph: EvidenceGraph, document: dict[str, Any]) -> None:
    object_fields(
        document, {"schema_version", "producer", "sha256", "functions", "calls", "truncated"}
    )
    if (
        document["schema_version"] != "fuse-ghidra-calls-1.0"
        or document["producer"] != "Ghidra"
        or not re.fullmatch(r"[a-f0-9]{64}", text(document["sha256"]))
    ):
        raise ValueError("Invalid Ghidra call graph")
    if (
        type(document["truncated"]) is not bool
        or not isinstance(document["functions"], list)
        or not isinstance(document["calls"], list)
        or len(document["functions"]) > 2048
        or len(document["calls"]) > 8192
    ):
        raise ValueError("Ghidra call graph limit exceeded")
    run = graph.run(
        "Ghidra-callgraph",
        "partial" if document["truncated"] else "completed",
        artifact=identity("ghidra-calls", document),
    )
    binary = graph.node("Binary", document["sha256"])
    functions = {}
    for function in document["functions"]:
        object_fields(function, {"name", "address"})
        address = text(function["address"])
        if address in functions:
            raise ValueError("Duplicate Ghidra function address")
        node = graph.node(
            "Function", ["ghidra", document["sha256"], address, text(function["name"])]
        )
        functions[address] = node
        graph.edge(
            binary,
            node,
            "contains",
            producer=run,
            method="ghidra-function-inventory",
            evidence_refs=[document["sha256"]],
        )
    for call in document["calls"]:
        object_fields(call, {"caller", "callee", "site", "indirect"})
        if (
            call["caller"] not in functions
            or call["callee"] not in functions
            or type(call["indirect"]) is not bool
        ):
            raise ValueError("Dangling or malformed binary call")
        graph.edge(
            functions[call["caller"]],
            functions[call["callee"]],
            "may_call" if call["indirect"] else "calls",
            producer=run,
            method="ghidra-reference",
            evidence_refs=[document["sha256"] + ":" + text(call["site"])],
            assertion="INFERRED" if call["indirect"] else "OBSERVED",
            limitations=["Disassembled call does not prove runtime execution."],
        )


def import_correspondence(graph: EvidenceGraph, document: dict[str, Any]) -> None:
    object_fields(document, {"source", "binary", "method", "artifact"})
    if any(
        n not in graph.nodes or graph.nodes[n]["type"] != "Function"
        for n in (document["source"], document["binary"])
    ):
        raise ValueError("Correspondence requires explicit function identities")
    run = graph.run(
        "source-binary-correspondence", "completed", artifact=text(document["artifact"])
    )
    graph.edge(
        document["source"],
        document["binary"],
        "corresponds_to",
        producer=run,
        method=text(document["method"]),
        evidence_refs=[document["artifact"]],
        assertion="ASSERTED",
        limitations=["Producer correspondence, not a name-only match."],
    )


def analyze_binary(
    path: Path, *, image: str, version: str, authorized: bool = False
) -> AnalyzerResult:
    if not path.is_file() or path.stat().st_size > 128 * 1024 * 1024:
        raise ValueError("Binary input limit exceeded")
    with as_file(files("vigil_fuse").joinpath("resources/lief_metadata.py")) as script:
        return run_analyzer(
            AnalyzerRequest(
                "LIEF", version, image, ("python3", "/input1"), (path, script), authorized
            )
        )


_GHIDRA_SCRIPT = """import hashlib,os,subprocess,sys
os.makedirs('/work/projects')
with open('/input0','rb') as stream: digest=hashlib.file_digest(stream,'sha256').hexdigest()
subprocess.run(['analyzeHeadless','/work/projects','fuse-calls','-import','/input0','-scriptPath','/input1','-postScript','FuseCallGraph.java','/work/calls.json',digest,'-analysisTimeoutPerFile','250','-deleteProject'],stdout=sys.stderr,stderr=sys.stderr,check=True,timeout=280)
with open('/work/calls.json','rb') as stream: payload=stream.read(8388609)
if len(payload)>8388608: raise ValueError('artifact limit')
sys.stdout.buffer.write(payload)
"""


def analyze_ghidra_calls(
    path: Path, *, image: str, version: str, authorized: bool = False
) -> AnalyzerResult:
    if not path.is_file() or path.stat().st_size > 128 * 1024 * 1024:
        raise ValueError("Binary input limit exceeded")
    with as_file(files("vigil_fuse").joinpath("resources/ghidra")) as scripts:
        return run_analyzer(
            AnalyzerRequest(
                "Ghidra",
                version,
                image,
                ("python3", "-c", _GHIDRA_SCRIPT),
                (path, scripts),
                authorized,
            )
        )
