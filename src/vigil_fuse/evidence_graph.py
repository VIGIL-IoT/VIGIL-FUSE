"""Versioned evidence connections. Graph operations never update finding verdicts."""

from __future__ import annotations

import hashlib
import json
import math
from pathlib import Path, PurePosixPath
from typing import Any

VERSION = "1.0"
MAX_BYTES = 16 * 1024 * 1024
MAX_NODES = 10000
MAX_EDGES = 30000
NODE_TYPES = frozenset(
    "Finding File Function Symbol Component Package Advisory FirmwareImage Binary HardwareComponent Net Pin Interface BuildTarget TranslationUnit Policy AnalyzerRun EvidenceArtifact Filesystem Service Configuration RuntimeObservation CallPath VulnerableSymbol".split()
)
EDGE_TYPES = frozenset(
    "contains builds includes depends_on calls may_call flows_to connected_to configured_by derived_from verified_by supports contradicts corresponds_to sanitized_by references".split()
)
ASSERTIONS = frozenset("OBSERVED ASSERTED INFERRED NEGATED UNKNOWN".split())
STATUSES = frozenset(
    "completed partial unsupported unavailable timeout failed skipped incompatible".split()
)


def canonical(value: object) -> str:
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)
    except (ValueError, TypeError, RecursionError) as exc:
        raise ValueError("Invalid evidence JSON") from exc


def identity(kind: str, value: object) -> str:
    return kind + ":" + hashlib.sha256(canonical(value).encode()).hexdigest()


def text(value: object) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > 4096
        or any(ord(c) < 32 for c in value)
    ):
        raise ValueError("Expected bounded evidence text")
    return value


def strings(value: object) -> list[str]:
    if not isinstance(value, list) or len(value) > 1000:
        raise ValueError("Expected bounded evidence list")
    return [text(item) for item in value]


def object_fields(value: object, fields: set[str]) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != fields:
        raise ValueError("Missing or unknown evidence fields")
    return value


def relative_path(value: object) -> str:
    path = text(value).replace("\\", "/")
    if path.startswith("/") or ":" in path or ".." in PurePosixPath(path).parts:
        raise ValueError("Evidence paths must be relative")
    return str(PurePosixPath(path))


def read_json(path: Path, limit: int = MAX_BYTES) -> Any:
    with path.open("rb") as stream:
        payload = stream.read(limit + 1)
    return decode_json(payload, limit)


def decode_json(payload: bytes, limit: int = MAX_BYTES) -> Any:
    if len(payload) > limit:
        raise ValueError("Evidence exceeds byte limit")

    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in items:
            if key in result:
                raise ValueError("Duplicate JSON key")
            result[key] = value
        return result

    def constant(_: str) -> None:
        raise ValueError("Nonfinite evidence number")

    try:
        value = json.loads(payload, object_pairs_hook=pairs, parse_constant=constant)
        if len(canonical(value)) > limit:
            raise ValueError("Evidence exceeds canonical size limit")
        return value
    except (UnicodeError, RecursionError, json.JSONDecodeError) as exc:
        raise ValueError("Malformed evidence JSON") from exc


class EvidenceGraph:
    def __init__(self, target_identity: str) -> None:
        self.target_identity = text(target_identity)
        self.nodes: dict[str, dict[str, Any]] = {}
        self.edges: dict[str, dict[str, Any]] = {}
        self.producer_runs: dict[str, dict[str, Any]] = {}
        self.coverage: dict[str, str] = {}
        self.provenance: list[str] = []

    def node(self, kind: str, key: object, **attributes: Any) -> str:
        if kind not in NODE_TYPES or len(canonical(attributes)) > 32768:
            raise ValueError("Invalid node type or oversized attributes")
        node_id = identity(kind, [self.target_identity, key])
        row = {"id": node_id, "type": kind, "identity": key, "attributes": attributes}
        if node_id in self.nodes and self.nodes[node_id] != row:
            raise ValueError("Conflicting attributes for the same evidence identity")
        if node_id not in self.nodes and len(self.nodes) >= MAX_NODES:
            raise ValueError("Graph node limit exceeded")
        self.nodes[node_id] = row
        return node_id

    def run(
        self, producer: str, status: str, *, version: str = "unknown", artifact: str = "unknown"
    ) -> str:
        text(producer)
        text(version)
        text(artifact)
        if status not in STATUSES:
            raise ValueError("Invalid producer coverage status")
        run_id = self.node("AnalyzerRun", [producer, version, artifact, status])
        self.producer_runs[run_id] = {
            "producer": producer,
            "status": status,
            "version": version,
            "artifact": artifact,
        }
        self.coverage[run_id] = status
        return run_id

    def edge(
        self,
        source: str,
        target: str,
        relation: str,
        *,
        producer: str,
        method: str,
        evidence_refs: list[str],
        assertion: str = "OBSERVED",
        confidence: float | None = None,
        limitations: list[str] | None = None,
    ) -> str:
        if (
            source not in self.nodes
            or target not in self.nodes
            or producer not in self.producer_runs
        ):
            raise ValueError("Dangling edge or producer")
        if relation not in EDGE_TYPES or assertion not in ASSERTIONS:
            raise ValueError("Invalid edge relation or assertion")
        if confidence is not None and (
            type(confidence) not in (int, float)
            or not math.isfinite(confidence)
            or not 0 <= confidence <= 1
        ):
            raise ValueError("Invalid edge confidence")
        refs = sorted(set(strings(evidence_refs)))
        if not refs:
            raise ValueError("Edge evidence references required")
        row = {
            "source": source,
            "target": target,
            "relation": relation,
            "assertion": assertion,
            "confidence": confidence,
            "method": text(method),
            "producer": producer,
            "evidence_refs": refs,
            "limitations": sorted(set(strings(limitations or []))),
        }
        edge_id = identity("edge", row)
        if edge_id not in self.edges and len(self.edges) >= MAX_EDGES:
            raise ValueError("Graph edge limit exceeded")
        self.edges[edge_id] = {"id": edge_id, **row}
        return edge_id

    def to_dict(self) -> dict[str, Any]:
        value = {
            "schema_version": VERSION,
            "target_identity": self.target_identity,
            "nodes": sorted(self.nodes.values(), key=lambda n: n["id"]),
            "edges": sorted(self.edges.values(), key=lambda e: e["id"]),
            "producer_runs": dict(sorted(self.producer_runs.items())),
            "coverage": dict(sorted(self.coverage.items())),
            "provenance": sorted(set(strings(self.provenance))),
        }
        if len(canonical(value).encode()) > MAX_BYTES:
            raise ValueError("Graph byte limit exceeded")
        return value

    @classmethod
    def from_dict(cls, value: object) -> EvidenceGraph:
        row = object_fields(
            value,
            {
                "schema_version",
                "target_identity",
                "nodes",
                "edges",
                "producer_runs",
                "coverage",
                "provenance",
            },
        )
        if row["schema_version"] != VERSION or len(canonical(row).encode()) > MAX_BYTES:
            raise ValueError("Unsupported or oversized graph")
        graph = cls(row["target_identity"])
        if not isinstance(row["nodes"], list) or not isinstance(row["edges"], list):
            raise ValueError("Invalid graph collections")
        if len(row["nodes"]) > MAX_NODES or len(row["edges"]) > MAX_EDGES:
            raise ValueError("Graph size limit exceeded")
        for node in row["nodes"]:
            n = object_fields(node, {"id", "type", "identity", "attributes"})
            if not isinstance(n["attributes"], dict) or n["id"] in graph.nodes:
                raise ValueError("Invalid or duplicate graph node")
            if graph.node(n["type"], n["identity"], **n["attributes"]) != n["id"]:
                raise ValueError("Graph node identity mismatch")
        if not isinstance(row["producer_runs"], dict) or not isinstance(row["coverage"], dict):
            raise ValueError("Invalid graph coverage")
        for run_id, run in row["producer_runs"].items():
            r = object_fields(run, {"producer", "status", "version", "artifact"})
            if run_id not in graph.nodes or graph.run(**r) != run_id:
                raise ValueError("Graph producer mismatch")
        if graph.coverage != row["coverage"]:
            raise ValueError("Graph coverage mismatch")
        for edge in row["edges"]:
            e = object_fields(
                edge,
                {
                    "id",
                    "source",
                    "target",
                    "relation",
                    "assertion",
                    "confidence",
                    "method",
                    "producer",
                    "evidence_refs",
                    "limitations",
                },
            )
            arguments = {k: v for k, v in e.items() if k != "id"}
            if e["id"] in graph.edges or graph.edge(**arguments) != e["id"]:
                raise ValueError("Invalid or duplicate graph edge")
        graph.provenance = strings(row["provenance"])
        return graph


def graph_from_report(report: dict[str, Any]) -> EvidenceGraph:
    """Map report evidence only. Never open paths named by an untrusted report."""
    graph = EvidenceGraph(
        identity("project", [report["target"], report["scan"]["input_manifest_sha256"]])
    )
    graph.provenance = [identity("report", report)]
    run = graph.run(
        "fuse-report",
        "completed",
        version=str(report["schema_version"]),
        artifact=graph.provenance[0],
    )

    def link(a: str, b: str, relation: str, assertion: str = "OBSERVED") -> str:
        return graph.edge(
            a,
            b,
            relation,
            producer=run,
            method="report-import",
            evidence_refs=graph.provenance,
            assertion=assertion,
            limitations=[
                "Presence does not prove reachability, execution or physical accessibility."
            ],
        )

    def file(path: str, digest: str = "unknown") -> str:
        return graph.node("File", [relative_path(path), digest])

    for item in report["coverage"]["analyzers"]:
        graph.run(item["name"], item["status"], version=item.get("version") or "unknown")
    for finding in report["findings"]:
        f = graph.node("Finding", finding["fingerprint"], finding=finding)
        path = finding["location"]["file"]
        # External-tool pseudo locations have no filesystem identity.
        if path and not Path(path).is_absolute() and ":" not in path:
            link(f, file(path), "derived_from")
        component = finding.get("component")
        if component:
            p = graph.node(
                "Package",
                [
                    component.get("purl") or [component["ecosystem"], component["name"]],
                    component["version"],
                ],
            )
            a = graph.node("Advisory", [finding["analyzer"], finding["rule_id"]])
            link(f, a, "derived_from")
            link(a, p, "supports", "ASSERTED")
            if finding.get("vex_review"):
                vex = graph.node(
                    "EvidenceArtifact",
                    ["vex", finding["fingerprint"]],
                    review=finding["vex_review"],
                )
                state = finding["vex_review"]["state"]
                link(
                    vex,
                    f,
                    "contradicts"
                    if state
                    in {"not_affected", "false_positive", "resolved", "resolved_with_pedigree"}
                    else "supports",
                    "UNKNOWN" if state == "in_triage" else "ASSERTED",
                )
    context = report.get("project_context", {})
    if context.get("target"):
        target = graph.node(
            "BuildTarget", [context.get("framework"), context["target"], context.get("build_dir")]
        )
        for item in context.get("configuration_files", []):
            link(target, file(item["path"], item.get("sha256") or "unknown"), "configured_by")
    for item in report.get("hardware_inventory", {}).get("rtl_analysis", {}).get("files", []):
        if isinstance(item, dict) and item.get("path"):
            f = file(item["path"], item.get("sha256") or "unknown")
            candidate = graph.node("BuildTarget", ["rtl-candidate", item["path"]])
            link(candidate, f, "includes", "INFERRED")
    for item in report.get("hardware_bom", {}).get("components", []):
        graph.node("HardwareComponent", [report["hardware_bom"].get("sha256"), item["reference"]])
    netlist = report.get("hardware_netlist", {})
    for name in netlist.get("debug_net_candidates", []):
        net = graph.node("Net", [netlist.get("sha256"), name])
        interface = graph.node("Interface", [netlist.get("sha256"), name])
        link(net, interface, "supports", "INFERRED")
    for item in report.get("artifacts", []):
        artifact = graph.node(
            "EvidenceArtifact", [item["path"], item["sha256"]], media_type=item["media_type"]
        )
        link(artifact, run, "derived_from")
    return graph


def import_sbom(graph: EvidenceGraph, document: dict[str, Any]) -> None:
    if document.get("bomFormat") != "CycloneDX" or not isinstance(document.get("components"), list):
        raise ValueError("Expected CycloneDX components")
    run = graph.run("cyclonedx", "completed", artifact=identity("sbom", document))
    refs: dict[str, str] = {}
    for component in document["components"]:
        purl, version = text(component["purl"]), text(component["version"])
        node = graph.node("Package", [purl, version])
        if component.get("bom-ref"):
            refs[text(component["bom-ref"])] = node
    for dependency in document.get("dependencies", []):
        for target in dependency["dependsOn"]:
            if dependency["ref"] not in refs or target not in refs:
                raise ValueError("Unresolved SBOM relationship")
            graph.edge(
                refs[dependency["ref"]],
                refs[target],
                "depends_on",
                producer=run,
                method="cyclonedx-relationship",
                evidence_refs=[graph.producer_runs[run]["artifact"]],
                assertion="ASSERTED",
            )


def import_netlist(graph: EvidenceGraph, topology: Any) -> None:
    """Consume the existing bounded KiCad parser's topology, never infer accessibility."""
    status = {"parsed": "completed", "invalid": "failed"}.get(topology.status, topology.status)
    run = graph.run("kicad", status, artifact=topology.sha256 or "unknown")
    if status not in {"completed", "partial"}:
        return
    components = {
        ref: graph.node("HardwareComponent", [topology.sha256, ref]) for ref in topology.components
    }
    for net in topology.nets:
        n = graph.node("Net", [topology.sha256, net.name])
        for endpoint in net.endpoints:
            pin = graph.node("Pin", [topology.sha256, endpoint.reference, endpoint.pin])
            for a, b, relation in (
                (components[endpoint.reference], pin, "contains"),
                (pin, n, "connected_to"),
            ):
                graph.edge(
                    a,
                    b,
                    relation,
                    producer=run,
                    method="kicad-netlist",
                    evidence_refs=[topology.sha256],
                    limitations=["Connectivity does not establish physical accessibility."],
                )


def import_ghidra(graph: EvidenceGraph, document: dict[str, Any]) -> None:
    from .ghidra_analyzer import _validate_result_document

    digest = text(document["input"]["sha256"])
    _validate_result_document(document, digest, document["input"]["format"])
    run = graph.run(
        "ghidra",
        document["analysis"]["status"],
        version=document["tool"]["version"],
        artifact=identity("ghidra", document),
    )
    binary = graph.node("Binary", digest)
    for group, kind, address in (
        ("functions", "Function", "entry_address"),
        ("imports", "Symbol", "address"),
    ):
        for record in document[group]["records"]:
            node = graph.node(kind, ["ghidra", digest, record[address], record["name"]])
            graph.edge(
                binary,
                node,
                "contains",
                producer=run,
                method="ghidra-inventory",
                evidence_refs=[digest],
            )
    for record in document["api_references"]["records"]:
        source = graph.node(
            "Function", ["ghidra", digest, record["function_entry_address"], record["function"]]
        )
        target = graph.node("Symbol", ["ghidra", digest, record["address"], record["symbol"]])
        graph.edge(
            source,
            target,
            "references",
            producer=run,
            method="ghidra-import-reference",
            evidence_refs=[digest],
            limitations=["An imported API reference is not necessarily a direct call."],
        )
    for record in document["cross_references"]["records"]:
        source = graph.node(
            "Function", ["ghidra", digest, record["function_entry_address"], record["function"]]
        )
        target = graph.node(
            "EvidenceArtifact", ["binary-string", digest, record["string_address"]], redacted=True
        )
        graph.edge(
            target,
            source,
            "references",
            producer=run,
            method="ghidra-string-reference",
            evidence_refs=[digest + ":" + record["from_address"]],
        )


def import_build(graph: EvidenceGraph, document: dict[str, Any]) -> None:
    """Normalized build inclusion supplied by an adapter, never compiler commands."""
    object_fields(document, {"target", "translation_units", "artifact"})
    run = graph.run("build-metadata", "completed", artifact=text(document["artifact"]))
    target = graph.node("BuildTarget", text(document["target"]))
    if not isinstance(document["translation_units"], list):
        raise ValueError("Expected translation units")
    for unit in document["translation_units"]:
        object_fields(unit, {"path", "sha256", "included"})
        if type(unit["included"]) is not bool:
            raise ValueError("Build inclusion must be explicit")
        key = [relative_path(unit["path"]), text(unit["sha256"])]
        f, tu = graph.node("File", key), graph.node("TranslationUnit", [document["target"], key])
        for a, b, relation in ((target, tu, "builds"), (tu, f, "includes")):
            graph.edge(
                a,
                b,
                relation,
                producer=run,
                method="build-metadata",
                evidence_refs=[document["artifact"]],
                assertion="OBSERVED" if unit["included"] else "NEGATED",
            )


def import_policy(graph: EvidenceGraph, document: dict[str, Any]) -> None:
    object_fields(document, {"policy", "evidence_nodes", "artifact"})
    run = graph.run("policy", "completed", artifact=text(document["artifact"]))
    policy = graph.node("Policy", text(document["policy"]))
    for node in strings(document["evidence_nodes"]):
        graph.edge(
            policy,
            node,
            "derived_from",
            producer=run,
            method="policy-evidence",
            evidence_refs=[document["artifact"]],
            assertion="ASSERTED",
        )
