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
    args = parser.parse_args()
    try:
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
