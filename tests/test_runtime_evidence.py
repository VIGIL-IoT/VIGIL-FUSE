from __future__ import annotations

import copy
import json
from pathlib import Path
import sys

import pytest

from vigil_fuse.deep_evidence import main
from vigil_fuse.evidence_graph import EvidenceGraph, identity
from vigil_fuse.runtime_evidence import add_runtime, ingest_runtime, validate_observation


def metadata(tool: str = "ASan") -> dict:
    return {
        "tool": tool,
        "tool_version": "clang-fixture",
        "binary_sha256": "b" * 64,
        "artifact_reference": "artifact:sanitizer-log",
        "source_root": "/build/source",
        "reproducer_reference": "artifact:reproducer",
    }


LOGS = {
    "ASan": "==42==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x1234\n",
    "MSan": "==42==WARNING: MemorySanitizer: use-of-uninitialized-value\n",
    "TSan": "WARNING: ThreadSanitizer: data race (pid=42)\n",
    "LSan": "==42==ERROR: LeakSanitizer: detected memory leaks\n",
    "UBSan": "/build/source/main.c:12:7: runtime error: signed integer overflow: 123 + 456\n",
}
FRAME = "    #0 0x1234 in decode(int) /build/source/main.c:12:7\n"


@pytest.mark.parametrize("tool", LOGS)
def test_all_sanitizers_preserve_runtime_identity_and_redact_values(tool: str) -> None:
    result = ingest_runtime(
        (LOGS[tool] + FRAME + "secret stdout TOKEN_VALUE\n").encode(), metadata(tool)
    )
    row = result["observations"][0]
    assert result["status"] == "completed" and row["tool"] == tool
    assert row["source_location"] == {"file": "main.c", "line": 12, "column": 7}
    assert row["stack_trace"][0]["function"] == "decode"
    assert row["validation_state"] == "runtime-observed"
    assert row["artifact"]["sha256"] and row["process"]["binary_sha256"] == "b" * 64
    serialized = json.dumps(result)
    assert (
        "TOKEN_VALUE" not in serialized
        and "0x1234" not in serialized
        and "/build/source" not in serialized
    )


def test_duplicate_logs_unknown_paths_and_no_findings_are_not_clean_execution() -> None:
    log = (LOGS["ASan"] + FRAME) * 2
    assert len(ingest_runtime(log.encode(), metadata())["observations"]) == 1
    unknown = ingest_runtime(
        (LOGS["ASan"] + FRAME.replace("/build/source", "/private/elsewhere")).encode(), metadata()
    )
    assert unknown["observations"][0]["source_location"] is None
    empty = ingest_runtime(b"program exited normally", metadata())
    assert empty["status"] == "partial" and empty["observations"] == []


@pytest.mark.parametrize(
    "mode", ["tool", "version", "binary", "oversized", "location", "state", "secret"]
)
def test_malformed_runtime_artifacts_and_validation_overclaims_rejected(mode: str) -> None:
    meta = metadata()
    if mode == "tool":
        meta["tool"] = "shell"
    if mode == "version":
        meta["tool_version"] = ""
    if mode == "binary":
        meta["binary_sha256"] = "bad"
    if mode in {"tool", "version", "binary", "oversized"}:
        with pytest.raises(ValueError):
            ingest_runtime(
                b"x" * (4 * 1024 * 1024 + 1) if mode == "oversized" else LOGS["ASan"].encode(), meta
            )
        return
    row = ingest_runtime((LOGS["ASan"] + FRAME).encode(), meta)["observations"][0]
    if mode == "location":
        row["source_location"]["file"] = "../escape"
    if mode == "state":
        row["validation_state"] = "deployed-exploit-confirmed"
    if mode == "secret":
        row["process"]["arguments"] = "secret"
    with pytest.raises(ValueError):
        validate_observation(row)


def test_runtime_support_requires_explicit_targets_and_preserves_static_finding() -> None:
    result = ingest_runtime((LOGS["ASan"] + FRAME).encode(), metadata())
    graph = EvidenceGraph("product")
    finding = graph.node(
        "Finding", "static-id", severity="medium", confidence=0.4, validation="unverified"
    )
    before = copy.deepcopy(graph.nodes[finding])
    ids = add_runtime(graph, result)
    assert not any(e["relation"] == "supports" for e in graph.edges.values())
    assert ids == [
        graph.node(
            "RuntimeObservation",
            identity("runtime", result["observations"][0]),
            observation=result["observations"][0],
        )
    ]
    link = {
        "observation": ids[0],
        "target": finding,
        "artifact": "review:matching-build-and-location",
        "method": "reviewed-location-and-build",
    }
    add_runtime(graph, result, [link])
    assert graph.nodes[finding] == before
    assert (
        next(e for e in graph.edges.values() if e["relation"] == "supports")["assertion"]
        == "ASSERTED"
    )
    assert EvidenceGraph.from_dict(graph.to_dict()).to_dict() == graph.to_dict()
    link["target"] = "missing"
    with pytest.raises(ValueError):
        add_runtime(graph, result, [link])


def test_future_passive_adapter_and_cli(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    result = ingest_runtime(LOGS["ASan"].encode(), metadata())
    result["observations"][0]["tool"] = "Valgrind-fixture-adapter"
    assert ingest_runtime(b"", {}, adapter=lambda _p, _m: result) == result
    raw, meta, output = (tmp_path / name for name in ("asan.log", "metadata.json", "result.json"))
    raw.write_text(LOGS["ASan"] + FRAME)
    meta.write_text(json.dumps(metadata()))
    monkeypatch.setattr(
        sys, "argv", ["deep-evidence", "runtime", str(raw), str(meta), "--output", str(output)]
    )
    assert main() == 0
    imported = json.loads(output.read_text())
    assert imported["observations"][0]["source_location"]["file"] == "main.c"
    assert "RuntimeObservation" in {n["type"] for n in imported["evidence_graph"]["nodes"]}
