from __future__ import annotations

from io import StringIO
import json
import math
import queue
import subprocess
import time
import unittest
from unittest.mock import patch

from vigil_fuse.model import SourceFile
from vigil_fuse.rule_execution import (
    IsolatedRuleExecutor,
    _finding_from_dict,
    validate_rule_timeout,
)
from vigil_fuse.rules.registry import RULES


class _FakeProcess:
    def __init__(self, *, timeout_on_first_wait: bool = False) -> None:
        self.stdin = StringIO()
        self.stdout = StringIO()
        self.timeout_on_first_wait = timeout_on_first_wait
        self.wait_calls = 0
        self.terminated = False
        self.killed = False

    def poll(self) -> int | None:
        return None if not self.terminated else 1

    def terminate(self) -> None:
        self.terminated = True

    def wait(self, timeout: float | None = None) -> int:
        self.wait_calls += 1
        if self.timeout_on_first_wait and self.wait_calls == 1:
            raise subprocess.TimeoutExpired("fuse-rule-worker", timeout)
        return 1

    def kill(self) -> None:
        self.killed = True


class _BrokenInput:
    def write(self, _value: str) -> int:
        raise BrokenPipeError

    def flush(self) -> None:
        return None


class RuleExecutionProtocolTests(unittest.TestCase):
    def test_rule_timeout_rejects_non_finite_and_out_of_range_values(self) -> None:
        for value in (math.nan, math.inf, 0.09, 30.01):
            with self.subTest(value=value), self.assertRaises(ValueError):
                validate_rule_timeout(value)

    @staticmethod
    def _source() -> SourceFile:
        content = 'const char *password = "embedded-secret-value";\n'
        return SourceFile(
            path="device.c",
            text=content,
            sha256="a" * 64,
            byte_size=len(content.encode("utf-8")),
        )

    def _finding_row(self) -> dict[str, object]:
        source = self._source()
        rule = next(item for item in RULES if item.id == "FUSE001")
        finding = next(iter(rule.scan(source)))
        return finding.to_dict()

    def _executor(
        self, events: list[dict[str, object] | None]
    ) -> tuple[IsolatedRuleExecutor, _FakeProcess, list[bool]]:
        executor = IsolatedRuleExecutor(timeout_seconds=1.0)
        process = _FakeProcess()
        executor._process = process  # type: ignore[assignment]
        executor._start = lambda _deadline: None  # type: ignore[method-assign]
        event_iter = iter(events)
        executor._next_event = lambda _deadline: next(event_iter, None)  # type: ignore[method-assign]
        stop_calls: list[bool] = []
        executor._stop = lambda *, force: stop_calls.append(force)  # type: ignore[method-assign]
        self.addCleanup(lambda: setattr(executor, "_process", None))
        return executor, process, stop_calls

    def test_successful_worker_protocol_deserializes_findings_and_request(self) -> None:
        row = self._finding_row()
        executor, process, _ = self._executor(
            [
                {"event": "rule-start", "rule_id": "FUSE001"},
                {"event": "rule-result", "rule_id": "FUSE001", "findings": [row]},
                {"event": "done"},
            ]
        )

        result = executor.execute(self._source(), ("FUSE001",), scan_deadline=time.monotonic() + 5)

        self.assertEqual({"FUSE001"}, result.completed_rule_ids)
        self.assertEqual({}, result.failed)
        self.assertEqual(1, len(result.findings))
        self.assertEqual("device.c", result.findings[0].file)
        self.assertEqual(1, len(process.stdin.getvalue().splitlines()))
        request = json.loads(process.stdin.getvalue())
        self.assertEqual(["FUSE001"], request["rule_ids"])
        self.assertNotIn("embedded-secret-value", json.dumps(row))

    def test_invalid_finding_marks_only_its_rule_failed_and_continues(self) -> None:
        executor, _, _ = self._executor(
            [
                {"event": "rule-start", "rule_id": "FUSE001"},
                {"event": "rule-result", "rule_id": "FUSE001", "findings": [{"location": []}]},
                {"event": "rule-start", "rule_id": "FUSE004"},
                {"event": "rule-result", "rule_id": "FUSE004", "findings": []},
                {"event": "done"},
            ]
        )

        result = executor.execute(
            self._source(), ("FUSE001", "FUSE004"), scan_deadline=time.monotonic() + 5
        )

        self.assertEqual({"FUSE001": "rule worker returned an invalid finding"}, result.failed)
        self.assertEqual({"FUSE004"}, result.completed_rule_ids)

    def test_timeout_disables_timed_out_rule_and_restarts_worker_for_next_rule(self) -> None:
        executor, _, stop_calls = self._executor(
            [
                {"event": "rule-start", "rule_id": "FUSE001"},
                {"event": "rule-start", "rule_id": "FUSE004"},
                {"event": "rule-result", "rule_id": "FUSE004", "findings": []},
                {"event": "done"},
            ]
        )
        clock_values = iter((101.0, 101.0, 103.0, 104.0, 104.0, 104.0, 104.0))

        with patch(
            "vigil_fuse.rule_execution.time.monotonic",
            side_effect=lambda: next(clock_values, 104.0),
        ):
            result = executor.execute(self._source(), ("FUSE001", "FUSE004"), scan_deadline=200.0)

        self.assertIn("FUSE001", result.timed_out)
        self.assertEqual({"FUSE004"}, result.completed_rule_ids)
        self.assertEqual([True], stop_calls)

    def test_scan_deadline_marks_all_pending_rules_unfinished(self) -> None:
        executor, _, stop_calls = self._executor([])

        with patch("vigil_fuse.rule_execution.time.monotonic", return_value=10.0):
            result = executor.execute(self._source(), ("FUSE001", "FUSE004"), scan_deadline=9.0)

        self.assertTrue(result.scan_deadline_reached)
        self.assertEqual({"FUSE001", "FUSE004"}, result.unfinished_rule_ids)
        self.assertEqual([True], stop_calls)

    def test_worker_start_failures_report_partial_scan_state(self) -> None:
        executor = IsolatedRuleExecutor()
        executor._start = lambda _deadline: "worker launch failed (OSError)"  # type: ignore[method-assign]

        failed = executor.execute(
            self._source(), ("FUSE001", "FUSE004"), scan_deadline=time.monotonic() + 5
        )

        self.assertEqual(
            {
                "FUSE001": "worker launch failed (OSError)",
                "FUSE004": "worker launch failed (OSError)",
            },
            failed.failed,
        )

        executor = IsolatedRuleExecutor()
        executor._start = lambda _deadline: (  # type: ignore[method-assign]
            "scan-wide time limit reached while starting the rule worker"
        )
        expired = executor.execute(
            self._source(), ("FUSE001", "FUSE004"), scan_deadline=time.monotonic() + 5
        )

        self.assertTrue(expired.scan_deadline_reached)
        self.assertEqual({"FUSE001", "FUSE004"}, expired.unfinished_rule_ids)

    def test_worker_protocol_failures_are_reported_with_bounded_diagnostics(self) -> None:
        cases = (
            (
                "unexpected rule start",
                [{"event": "rule-start", "rule_id": "FUSE999"}],
                ("FUSE001",),
                {"FUSE001": "rule worker returned an unexpected rule ID"},
                [True],
            ),
            (
                "result without start",
                [{"event": "rule-result", "rule_id": "FUSE001", "findings": []}],
                ("FUSE001",),
                {"FUSE001": "rule worker returned a result without an active rule"},
                [True],
            ),
            (
                "mismatched result id",
                [
                    {"event": "rule-start", "rule_id": "FUSE001"},
                    {"event": "rule-result", "rule_id": "FUSE004", "findings": []},
                    {"event": "done"},
                ],
                ("FUSE001",),
                {"FUSE001": "rule worker returned an invalid finding"},
                [],
            ),
            (
                "request rejected",
                [{"event": "request-error"}],
                ("FUSE001", "FUSE004"),
                {
                    "FUSE001": "rule worker rejected the scan request",
                    "FUSE004": "rule worker rejected the scan request",
                },
                [True],
            ),
            (
                "missing rule result",
                [{"event": "done"}],
                ("FUSE001",),
                {"FUSE001": "rule worker omitted a result"},
                [],
            ),
            (
                "unknown event",
                [{"event": "unexpected-event"}],
                ("FUSE001",),
                {"FUSE001": "rule worker returned an unknown response"},
                [True],
            ),
            (
                "idle timeout",
                [{"event": "wait-timeout"}],
                ("FUSE001",),
                {"FUSE001": "rule worker stopped responding between rules"},
                [True],
            ),
            (
                "mismatched rule error",
                [
                    {"event": "rule-start", "rule_id": "FUSE001"},
                    {"event": "rule-error", "rule_id": "FUSE004"},
                ],
                ("FUSE001",),
                {"FUSE001": "rule worker returned an unexpected rule error"},
                [True],
            ),
        )
        for name, events, rule_ids, expected_failures, expected_stops in cases:
            with self.subTest(name=name):
                executor, _, stop_calls = self._executor(events)

                result = executor.execute(
                    self._source(), rule_ids, scan_deadline=time.monotonic() + 5
                )

                self.assertEqual(expected_failures, result.failed)
                self.assertEqual(expected_stops, stop_calls)

    def test_worker_closed_input_marks_every_pending_rule_failed(self) -> None:
        executor, process, stop_calls = self._executor([])
        process.stdin = _BrokenInput()  # type: ignore[assignment]

        result = executor.execute(
            self._source(), ("FUSE001", "FUSE004"), scan_deadline=time.monotonic() + 5
        )

        self.assertEqual(
            {
                "FUSE001": "rule worker closed its input",
                "FUSE004": "rule worker closed its input",
            },
            result.failed,
        )
        self.assertEqual([True], stop_calls)

    def test_invalid_protocol_and_worker_errors_fail_without_leaking_exception_text(self) -> None:
        executor, _, stop_calls = self._executor([{"event": "protocol-error"}])
        invalid = executor.execute(self._source(), ("FUSE001",), scan_deadline=time.monotonic() + 5)
        self.assertEqual(
            {"FUSE001": "rule worker exited or returned an invalid response"}, invalid.failed
        )
        self.assertEqual([True], stop_calls)

        executor, _, _ = self._executor(
            [
                {"event": "rule-start", "rule_id": "FUSE001"},
                {
                    "event": "rule-error",
                    "rule_id": "FUSE001",
                    "error": "RuntimeError",
                    "detail": "must not appear in diagnostics",
                },
                {"event": "done"},
            ]
        )
        failed = executor.execute(self._source(), ("FUSE001",), scan_deadline=time.monotonic() + 5)
        self.assertEqual({"FUSE001": "rule raised RuntimeError"}, failed.failed)
        self.assertNotIn("must not appear", str(failed.failed))

    def test_finding_deserializer_rejects_non_object_location(self) -> None:
        with self.assertRaisesRegex(ValueError, "location must be an object"):
            _finding_from_dict({"location": []})

    def test_reader_converts_malformed_or_non_object_events_to_protocol_errors(self) -> None:
        executor = IsolatedRuleExecutor()
        events: queue.Queue[dict[str, object] | None] = queue.Queue()

        executor._read_events(StringIO('{"event":"ready"}\n[]\nnot-json\n'), events)

        self.assertEqual({"event": "ready"}, events.get_nowait())
        self.assertEqual({"event": "protocol-error"}, events.get_nowait())
        self.assertEqual({"event": "protocol-error"}, events.get_nowait())
        self.assertIsNone(events.get_nowait())

    def test_stop_kills_worker_when_termination_does_not_finish(self) -> None:
        executor = IsolatedRuleExecutor()
        process = _FakeProcess(timeout_on_first_wait=True)
        executor._process = process  # type: ignore[assignment]

        executor._stop(force=True)

        self.assertTrue(process.terminated)
        self.assertTrue(process.killed)
        self.assertIsNone(executor._process)


if __name__ == "__main__":
    unittest.main()
