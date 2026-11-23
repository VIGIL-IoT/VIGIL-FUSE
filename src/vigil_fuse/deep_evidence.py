"""Explicit, offline evidence import CLI: python -m vigil_fuse.deep_evidence."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from .evidence_graph import (
    graph_from_report,
    import_sbom,
    import_ghidra,
    import_build,
    import_policy,
    import_netlist,
    read_json,
)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    graph = commands.add_parser(
        "graph", help="connect a FUSE JSON report without changing findings"
    )
    graph.add_argument("report", type=Path)
    graph.add_argument("--sbom", type=Path)
    graph.add_argument("--ghidra", type=Path)
    graph.add_argument("--build", type=Path)
    graph.add_argument("--policy", type=Path)
    graph.add_argument("--netlist", type=Path)
    graph.add_argument("--output", type=Path, required=True)
    semantic = commands.add_parser("semantic", help="import CodeQL SARIF or offline Joern paths")
    semantic.add_argument("input", type=Path)
    semantic.add_argument("--engine", choices=("CodeQL", "Joern"), default="CodeQL")
    semantic.add_argument("--language", default="python")
    semantic.add_argument("--graph", type=Path)
    semantic.add_argument("--output", type=Path, required=True)
    codeql = commands.add_parser(
        "codeql", help="explicitly query an existing database in a sandbox"
    )
    codeql.add_argument("database", type=Path)
    codeql.add_argument("queries", type=Path)
    codeql.add_argument("--image", required=True)
    codeql.add_argument("--tool-version", required=True)
    codeql.add_argument("--authorize-query", action="store_true")
    codeql.add_argument("--output", type=Path, required=True)
    reachability = commands.add_parser(
        "reachability", help="assess exact package and symbol reachability"
    )
    reachability.add_argument("graph", type=Path)
    reachability.add_argument("request", type=Path)
    reachability.add_argument("--calls", type=Path)
    reachability.add_argument("--advisory-symbols", type=Path)
    reachability.add_argument("--output", type=Path, required=True)
    binary = commands.add_parser("binary", help="import LIEF metadata or Ghidra calls")
    binary.add_argument("input", type=Path)
    binary.add_argument("--kind", choices=("lief", "ghidra-calls"), default="lief")
    binary.add_argument("--graph", type=Path)
    binary.add_argument("--correspondence", type=Path)
    binary.add_argument("--output", type=Path, required=True)
    analyze = commands.add_parser(
        "binary-analyze", help="explicit sandboxed binary metadata or call analysis"
    )
    analyze.add_argument("input", type=Path)
    analyze.add_argument("--engine", choices=("LIEF", "Ghidra"), default="LIEF")
    analyze.add_argument("--image", required=True)
    analyze.add_argument("--tool-version", required=True)
    analyze.add_argument("--authorize-analysis", action="store_true")
    analyze.add_argument("--output", type=Path, required=True)
    rootfs = commands.add_parser("rootfs", help="import redacted filesystem intelligence")
    rootfs.add_argument("input", type=Path)
    rootfs.add_argument("--graph", type=Path)
    rootfs.add_argument("--output", type=Path, required=True)
    extract = commands.add_parser("firmware-extract", help="explicit sandboxed Binwalk extraction")
    extract.add_argument("input", type=Path)
    extract.add_argument("--image", required=True)
    extract.add_argument("--tool-version", required=True)
    extract.add_argument("--recursive", action="store_true")
    extract.add_argument("--authorize-extraction", action="store_true")
    extract.add_argument("--output", type=Path, required=True)
    runtime = commands.add_parser("runtime", help="passively import a sanitizer log")
    runtime.add_argument("input", type=Path)
    runtime.add_argument("metadata", type=Path)
    runtime.add_argument("--graph", type=Path)
    runtime.add_argument("--links", type=Path)
    runtime.add_argument("--output", type=Path, required=True)
    correlation = commands.add_parser("correlate", help="evaluate deterministic cross-layer rules")
    correlation.add_argument("graph", type=Path)
    correlation.add_argument("--facts", type=Path)
    correlation.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        if args.command == "correlate":
            from .evidence_graph import EvidenceGraph
            from .cross_layer import correlate, import_facts, materialize_correlations

            imported = EvidenceGraph.from_dict(read_json(args.graph))
            if args.facts:
                import_facts(imported, read_json(args.facts))
            correlations = correlate(imported)
            materialize_correlations(imported, correlations)
            correlations["evidence_graph"] = imported.to_dict()
            args.output.write_text(json.dumps(correlations, indent=2) + "\n", encoding="utf-8")
            return 0
        if args.command == "runtime":
            from .evidence_graph import EvidenceGraph
            from .runtime_evidence import MAX_LOG, add_runtime, ingest_runtime

            metadata = read_json(args.metadata)
            with args.input.open("rb") as stream:
                evidence = ingest_runtime(stream.read(MAX_LOG + 1), metadata)
            imported = (
                EvidenceGraph.from_dict(read_json(args.graph))
                if args.graph
                else EvidenceGraph(metadata["binary_sha256"])
            )
            add_runtime(imported, evidence, read_json(args.links) if args.links else None)
            evidence["evidence_graph"] = imported.to_dict()
            args.output.write_text(json.dumps(evidence, indent=2) + "\n", encoding="utf-8")
            return 0
        if args.command in {"rootfs", "firmware-extract"}:
            from .evidence_graph import EvidenceGraph, decode_json
            from .firmware_rootfs import add_rootfs, extract_firmware

            if args.command == "firmware-extract":
                from dataclasses import asdict

                outcome = extract_firmware(
                    args.input,
                    image=args.image,
                    version=args.tool_version,
                    recursive=args.recursive,
                    authorized=args.authorize_extraction,
                )
                if outcome.status != "completed":
                    args.output.write_text(
                        json.dumps(asdict(outcome), indent=2) + "\n", encoding="utf-8"
                    )
                    return 2
                document = decode_json(outcome.stdout.encode())
                imported = EvidenceGraph(document["firmware_sha256"])
                add_rootfs(imported, document)
                args.output.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
                return 0
            document = read_json(args.input)
            imported = (
                EvidenceGraph.from_dict(read_json(args.graph))
                if args.graph
                else EvidenceGraph(document["firmware_sha256"])
            )
            add_rootfs(imported, document)
            args.output.write_text(
                json.dumps(imported.to_dict(), indent=2) + "\n", encoding="utf-8"
            )
            return 0
        if args.command in {"binary", "binary-analyze"}:
            from .evidence_graph import EvidenceGraph, decode_json, identity
            from .binary_intelligence import (
                add_binary,
                import_call_graph,
                import_correspondence,
                analyze_binary,
                analyze_ghidra_calls,
            )

            if args.command == "binary-analyze":
                from dataclasses import asdict

                binary_adapter = analyze_binary if args.engine == "LIEF" else analyze_ghidra_calls
                outcome = binary_adapter(
                    args.input,
                    image=args.image,
                    version=args.tool_version,
                    authorized=args.authorize_analysis,
                )
                if outcome.status != "completed":
                    args.output.write_text(
                        json.dumps(asdict(outcome), indent=2) + "\n", encoding="utf-8"
                    )
                    return 2
                document = decode_json(outcome.stdout.encode())
                imported = EvidenceGraph(identity("binary-project", document["sha256"]))
                (add_binary if args.engine == "LIEF" else import_call_graph)(imported, document)
                args.output.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
                return 0
            document = read_json(args.input)
            imported = (
                EvidenceGraph.from_dict(read_json(args.graph))
                if args.graph
                else EvidenceGraph(identity("binary-project", document["sha256"]))
            )
            (add_binary if args.kind == "lief" else import_call_graph)(imported, document)
            if args.correspondence:
                import_correspondence(imported, read_json(args.correspondence))
            args.output.write_text(
                json.dumps(imported.to_dict(), indent=2) + "\n", encoding="utf-8"
            )
            return 0
        if args.command == "reachability":
            from .evidence_graph import EvidenceGraph
            from .dependency_reachability import (
                assess_dependency,
                import_calls,
                import_advisory_symbols,
            )

            imported = EvidenceGraph.from_dict(read_json(args.graph))
            request = read_json(args.request)
            if args.calls:
                import_calls(imported, read_json(args.calls))
            if args.advisory_symbols:
                request["symbols"] = import_advisory_symbols(
                    imported, read_json(args.advisory_symbols)
                )
            assessment = assess_dependency(imported, request)
            assessment["evidence_graph"] = imported.to_dict()
            args.output.write_text(json.dumps(assessment, indent=2) + "\n", encoding="utf-8")
            return 0
        if args.command == "codeql":
            from dataclasses import asdict
            from .semantic_flow import analyze_codeql

            outcome = analyze_codeql(
                args.database,
                args.queries,
                image=args.image,
                version=args.tool_version,
                authorized=args.authorize_query,
            )
            if outcome.status == "completed":
                from .semantic_flow import normalize_sarif

                from .evidence_graph import decode_json

                document = decode_json(outcome.stdout.encode())
                normalize_sarif(document, "python")
                args.output.write_text(outcome.stdout, encoding="utf-8")
            else:
                args.output.write_text(
                    json.dumps(asdict(outcome), indent=2) + "\n", encoding="utf-8"
                )
            return 0 if outcome.status == "completed" else 2
        if args.command == "semantic":
            from .evidence_graph import EvidenceGraph
            from .semantic_flow import normalize_sarif, normalize_joern, add_flows

            document = read_json(args.input)
            evidence = (
                normalize_sarif(document, args.language)
                if args.engine == "CodeQL"
                else normalize_joern(document)
            )
            if args.graph:
                imported = EvidenceGraph.from_dict(read_json(args.graph))
                add_flows(imported, evidence)
                evidence["evidence_graph"] = imported.to_dict()
            args.output.write_text(json.dumps(evidence, indent=2) + "\n", encoding="utf-8")
            return 0
        result = graph_from_report(read_json(args.report))
        if args.sbom:
            import_sbom(result, read_json(args.sbom))
        for name, adapter in (
            ("ghidra", import_ghidra),
            ("build", import_build),
            ("policy", import_policy),
        ):
            if path := getattr(args, name):
                adapter(result, read_json(path))
        if args.netlist:
            from .hardware_netlist import read_netlist_topology

            import_netlist(
                result, read_netlist_topology(args.netlist.resolve().parent, args.netlist.resolve())
            )
        args.output.write_text(json.dumps(result.to_dict(), indent=2) + "\n", encoding="utf-8")
    except (ValueError, KeyError, TypeError, OSError) as exc:
        parser.exit(2, f"Invalid evidence: {type(exc).__name__}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
