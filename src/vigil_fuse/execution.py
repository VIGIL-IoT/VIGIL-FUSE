"""Explicit file-based execution handoff, independent of scanner CLI and Kubernetes SDKs."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from .execution_contract import MAX_MESSAGE_BYTES, create_plan, decode_message, validate_result


def read_message(path: Path) -> object:
    with path.open("rb") as stream:
        return decode_message(stream.read(MAX_MESSAGE_BYTES + 1))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    create = commands.add_parser("plan", help="explicitly authorize a passive identity probe")
    create.add_argument("plan_id")
    create.add_argument("target_id")
    create.add_argument("sha256")
    create.add_argument("--backend", choices=("local", "docker", "kubernetes"), default="local")
    check = commands.add_parser("validate", help="validate a captured worker envelope")
    check.add_argument("plan", type=Path)
    check.add_argument("result", type=Path)
    check.add_argument("worker_id")
    args = parser.parse_args()
    try:
        if args.command == "plan":
            output = create_plan(args.plan_id, args.target_id, args.sha256, args.backend)
        else:
            output = validate_result(
                read_message(args.result), read_message(args.plan), args.worker_id
            )
    except (ValueError, OSError) as exc:
        parser.exit(2, f"Execution handoff rejected: {exc}\n")
    print(json.dumps(output, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
