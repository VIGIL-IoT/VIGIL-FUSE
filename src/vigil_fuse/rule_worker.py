from __future__ import annotations

import json
import sys

from .model import SourceFile
from .rules.registry import RULES


def _write(message: dict[str, object]) -> None:
    sys.stdout.write(json.dumps(message, ensure_ascii=False, separators=(",", ":")) + "\n")
    sys.stdout.flush()


def main() -> int:
    rules = {rule.id: rule for rule in RULES}
    _write({"event": "ready"})

    for line in sys.stdin:
        try:
            request = json.loads(line)
            source_data = request["source"]
            source = SourceFile(
                path=str(source_data["path"]),
                text=str(source_data["text"]),
                sha256=str(source_data["sha256"]),
                byte_size=int(source_data["byte_size"]),
                generated_config=bool(source_data["generated_config"]),
            )
            rule_ids = request["rule_ids"]
            if not isinstance(rule_ids, list) or any(not isinstance(rule_id, str) for rule_id in rule_ids):
                raise ValueError("invalid rule list")
        except Exception as error:
            _write({"event": "request-error", "error": type(error).__name__})
            continue

        for rule_id in rule_ids:
            rule = rules.get(rule_id)
            if rule is None:
                _write({"event": "rule-error", "rule_id": rule_id, "error": "UnknownRule"})
                continue
            _write({"event": "rule-start", "rule_id": rule_id})
            try:
                findings = [finding.to_dict() for finding in rule.scan(source)]
            except Exception as error:
                _write({"event": "rule-error", "rule_id": rule_id, "error": type(error).__name__})
            else:
                _write({"event": "rule-result", "rule_id": rule_id, "findings": findings})
        _write({"event": "done"})

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
