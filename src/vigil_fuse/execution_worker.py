"""Deterministic stdin/stdout probe. Does not read or analyze target files."""

from __future__ import annotations

import json
import sys
from pathlib import Path

from .execution_contract import MAX_MESSAGE_BYTES, decode_message, validate_plan, validate_result


def main() -> int:
    try:
        if len(sys.argv) == 3:
            with Path(sys.argv[2]).open("rb") as stream:
                payload = stream.read(MAX_MESSAGE_BYTES + 1)
        else:
            payload = sys.stdin.buffer.read(MAX_MESSAGE_BYTES + 1)
        plan = validate_plan(decode_message(payload))
        worker_id = sys.argv[1] if len(sys.argv) >= 2 else "probe"
        result = validate_result(
            {
                "schema_version": "0.1",
                "plan_id": plan["plan_id"],
                "worker": {"worker_id": worker_id, "analyzer": "probe"},
                "status": "completed",
                "artifacts": [],
                "findings": [],
                "evidence": [{"kind": "target-identity", "target": plan["target"]}],
                "coverage": {},
                "limitations": ["Probe echoes identity; no target analysis performed"],
            },
            plan,
            worker_id,
        )
    except (ValueError, OSError) as exc:
        print(str(exc), file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
