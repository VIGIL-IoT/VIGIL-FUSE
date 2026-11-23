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
    args = parser.parse_args()
    try:
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
