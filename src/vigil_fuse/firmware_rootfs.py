"""Filesystem intelligence from mature extractor output. No extraction implementation."""

from __future__ import annotations

from importlib.resources import as_file, files
from pathlib import Path
import re
from typing import Any

from .analyzer_contract import AnalyzerRequest, AnalyzerResult, run_analyzer
from .evidence_graph import EvidenceGraph, identity, object_fields, relative_path, strings, text

FIELDS = {
    "entries": {"path", "kind", "sha256", "byte_size"},
    "services": {"path", "sha256", "name"},
    "accounts": {"name_sha256", "uid", "password_state"},
    "packages": {"purl", "version"},
    "certificates": {"path", "sha256", "kind"},
    "keys": {"path", "sha256", "kind"},
    "web_interfaces": {"path", "package", "exposure"},
    "kernel_config": {"name", "value", "path"},
    "binaries": {"path", "sha256", "kind"},
}


def digest(value: object) -> str:
    value = text(value)
    if not re.fullmatch(r"[a-f0-9]{64}", value):
        raise ValueError("Invalid firmware digest")
    return value


def validate_rootfs(document: dict[str, Any]) -> dict[str, Any]:
    object_fields(
        document,
        {"schema_version", "producer", "firmware_sha256", "architecture", "limitations", *FIELDS},
    )
    if document["schema_version"] != "1.0" or document["producer"] not in {
        "Binwalk",
        "EMBA",
        "FACT",
    }:
        raise ValueError("Unsupported filesystem evidence")
    digest(document["firmware_sha256"])
    text(document["architecture"])
    strings(document["limitations"])
    total = 0
    seen = set()
    for group, fields in FIELDS.items():
        rows = document[group]
        if not isinstance(rows, list) or len(rows) > (4000 if group == "entries" else 2000):
            raise ValueError("Filesystem inventory limit")
        for row in rows:
            object_fields(row, fields)
            for key, value in row.items():
                if key == "path":
                    relative_path(value)
                elif key in {"sha256", "name_sha256"}:
                    if value is not None or group != "entries":
                        digest(value)
                elif key not in {"byte_size", "uid"}:
                    text(value)
            if group == "entries":
                if (
                    row["path"] in seen
                    or row["kind"] not in {"file", "directory", "symlink"}
                    or type(row["byte_size"]) is not int
                    or not 0 <= row["byte_size"] <= 16 * 1024 * 1024
                ):
                    raise ValueError("Invalid filesystem entry")
                if (row["kind"] == "file") != (row["sha256"] is not None):
                    raise ValueError("Filesystem entry digest mismatch")
                seen.add(row["path"])
                total += row["byte_size"]
            if group == "accounts" and (
                type(row["uid"]) is not int
                or not 0 <= row["uid"] <= 4294967295
                or row["password_state"] != "not-imported"
            ):
                raise ValueError("Invalid account metadata")
            if group == "kernel_config" and row["value"] not in {"y", "n", "m"}:
                raise ValueError("Unsafe kernel setting")
            if group == "web_interfaces" and row["exposure"] != "unknown":
                raise ValueError("Unproven web exposure")
            kinds = {
                "keys": {"private-key"},
                "certificates": {"certificate"},
                "binaries": {"binary", "library"},
            }
            if group in kinds and row["kind"] not in kinds[group]:
                raise ValueError("Invalid filesystem metadata kind")
    if total > 64 * 1024 * 1024:
        raise ValueError("Filesystem aggregate size limit")
    if any(
        row["path"] not in seen
        for group in (
            "services",
            "certificates",
            "keys",
            "web_interfaces",
            "kernel_config",
            "binaries",
        )
        for row in document[group]
    ):
        raise ValueError("Dangling filesystem metadata")
    return document


def add_rootfs(graph: EvidenceGraph, document: dict[str, Any]) -> None:
    validate_rootfs(document)
    artifact = identity("rootfs-inventory", document)
    run = graph.run(document["producer"], "partial", artifact=artifact)
    firmware = graph.node("FirmwareImage", document["firmware_sha256"])
    filesystem = graph.node(
        "Filesystem", [document["firmware_sha256"], artifact], architecture=document["architecture"]
    )

    def edge(a: str, b: str) -> None:
        graph.edge(
            a,
            b,
            "contains",
            producer=run,
            method="filesystem-inventory",
            evidence_refs=[artifact],
            limitations=document["limitations"],
        )

    edge(firmware, filesystem)
    for entry in document["entries"]:
        node = graph.node(
            "File",
            [document["firmware_sha256"], entry["path"], entry["sha256"] or "unknown"],
            file_kind=entry["kind"],
        )
        edge(filesystem, node)
    for package in document["packages"]:
        edge(filesystem, graph.node("Package", [package["purl"], package["version"]]))
    for service in document["services"]:
        edge(
            filesystem,
            graph.node(
                "Service", [document["firmware_sha256"], service["path"]], name=service["name"]
            ),
        )
    for binary in document["binaries"]:
        edge(filesystem, graph.node("Binary", binary["sha256"]))
    for group in ("accounts", "keys", "certificates", "kernel_config", "web_interfaces"):
        for item in document[group]:
            edge(
                filesystem,
                graph.node(
                    "EvidenceArtifact", [artifact, group, item], metadata=item, evidence_kind=group
                ),
            )


def extract_firmware(
    path: Path, *, image: str, version: str, recursive: bool = False, authorized: bool = False
) -> AnalyzerResult:
    if not path.is_file() or path.stat().st_size > 128 * 1024 * 1024:
        raise ValueError("Firmware input limit")
    with as_file(files("vigil_fuse").joinpath("resources/rootfs_inventory.py")) as script:
        command = ("python3", "/input1", "--recursive") if recursive else ("python3", "/input1")
        return run_analyzer(
            AnalyzerRequest("Binwalk", version, image, command, (path, script), authorized)
        )
