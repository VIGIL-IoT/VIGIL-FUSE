from __future__ import annotations

from collections.abc import Iterable
from contextlib import redirect_stdout
from io import StringIO
import json
from unittest.mock import patch
import unittest

from vigil_fuse.model import Finding, SourceFile
from vigil_fuse.rule_worker import main
from vigil_fuse.rules.base import RuleDefinition


def _finding_rule(source: SourceFile, rule: RuleDefinition) -> Iterable[Finding]:
    return [rule.finding(source, 1, 'password = "[REDACTED]"')]


def _raising_rule(_source: SourceFile, _rule: RuleDefinition) -> Iterable[Finding]:
    raise RuntimeError("private exception detail")


def _rule(rule_id: str, scanner: object = _finding_rule) -> RuleDefinition:
    return RuleDefinition(
        id=rule_id,
        title="Credential test rule",
        severity="medium",
        confidence="high",
        category="secrets",
        explanation="Test-only rule explanation.",
        potential_impact="Test-only impact.",
        remediation="Test-only remediation.",
        scanner=scanner,  # type: ignore[arg-type]
    )


def _request(rule_id: str) -> dict[str, object]:
    return {
        "source": {
            "path": "device.c",
            "text": 'password = "worker-secret-value"\n',
            "sha256": "a" * 64,
            "byte_size": 32,
            "generated_config": False,
        },
        "rule_ids": [rule_id],
    }


class RuleWorkerProtocolTests(unittest.TestCase):
    def _run_worker(
        self, requests: list[str], rules: list[RuleDefinition]
    ) -> list[dict[str, object]]:
        output = StringIO()
        input_stream = StringIO("\n".join(requests) + "\n")
        with (
            patch("sys.stdin", input_stream),
            patch("vigil_fuse.rule_worker.RULES", rules),
            redirect_stdout(output),
        ):
            self.assertEqual(0, main())
        return [json.loads(line) for line in output.getvalue().splitlines()]

    def test_worker_serializes_rule_findings_without_source_secret(self) -> None:
        events = self._run_worker([json.dumps(_request("FUSE001"))], [_rule("FUSE001")])

        self.assertEqual(
            ["ready", "rule-start", "rule-result", "done"],
            [str(event.get("event")) for event in events],
        )
        finding = events[2]["findings"][0]
        self.assertEqual("device.c", finding["location"]["file"])
        self.assertNotIn("worker-secret-value", json.dumps(events))

    def test_worker_reports_invalid_requests_unknown_rules_and_rule_exceptions(self) -> None:
        requests = [
            "{}",
            json.dumps(_request("FUSE999")),
            json.dumps(_request("FUSE001")),
        ]
        events = self._run_worker(
            requests,
            [_rule("FUSE001", _raising_rule)],
        )

        self.assertEqual("request-error", events[1]["event"])
        self.assertEqual("rule-error", events[2]["event"])
        self.assertEqual("UnknownRule", events[2]["error"])
        self.assertEqual("rule-start", events[4]["event"])
        self.assertEqual("rule-error", events[5]["event"])
        self.assertEqual("RuntimeError", events[5]["error"])
        self.assertNotIn("private exception detail", json.dumps(events))


if __name__ == "__main__":
    unittest.main()
