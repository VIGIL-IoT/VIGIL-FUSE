from __future__ import annotations

import json
import math
import os
import queue
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .model import Finding, SourceFile

DEFAULT_RULE_TIMEOUT_SECONDS = 2.0
MIN_RULE_TIMEOUT_SECONDS = 0.1
MAX_RULE_TIMEOUT_SECONDS = 30.0
WORKER_START_TIMEOUT_SECONDS = 10.0
WORKER_IDLE_TIMEOUT_SECONDS = 5.0


def validate_rule_timeout(value: float) -> float:
    if (
        not math.isfinite(value)
        or not MIN_RULE_TIMEOUT_SECONDS <= value <= MAX_RULE_TIMEOUT_SECONDS
    ):
        raise ValueError(
            f"rule timeout must be between {MIN_RULE_TIMEOUT_SECONDS:g} and "
            f"{MAX_RULE_TIMEOUT_SECONDS:g} seconds"
        )
    return value


@dataclass
class RuleExecutionResult:
    findings: list[Finding] = field(default_factory=list)
    completed_rule_ids: set[str] = field(default_factory=set)
    timed_out: dict[str, str] = field(default_factory=dict)
    failed: dict[str, str] = field(default_factory=dict)
    unfinished_rule_ids: set[str] = field(default_factory=set)
    scan_deadline_reached: bool = False


def _finding_from_dict(data: dict[str, Any]) -> Finding:
    location = data["location"]
    if not isinstance(location, dict):
        raise ValueError("finding location must be an object")
    return Finding(
        id=str(data["id"]),
        fingerprint=str(data["fingerprint"]),
        rule_id=str(data["rule_id"]),
        rule_version=str(data["rule_version"]),
        analyzer=str(data["analyzer"]),
        title=str(data["title"]),
        severity=data["severity"],
        confidence=data["confidence"],
        category=str(data["category"]),
        file=str(location["file"]),
        start_line=location.get("start_line"),
        end_line=location.get("end_line"),
        evidence=str(data["evidence"]),
        explanation=str(data["explanation"]),
        potential_impact=str(data["potential_impact"]),
        remediation=str(data["remediation"]),
        references=tuple(data.get("references", [])),
        applicability=data.get("applicability", "unknown"),
        validation_method=data.get("validation_method", "static"),
        validation_status=data.get("validation_status", "not-validated"),
        severity_basis=data.get("severity_basis", "rule"),
        severity_score=data.get("severity_score"),
        severity_vector=data.get("severity_vector"),
        severity_version=data.get("severity_version"),
    )


class IsolatedRuleExecutor:
    """Run trusted native rules in a killable worker process."""

    def __init__(self, timeout_seconds: float = DEFAULT_RULE_TIMEOUT_SECONDS) -> None:
        self.timeout_seconds = validate_rule_timeout(timeout_seconds)
        self._process: subprocess.Popen[str] | None = None
        self._events: queue.Queue[dict[str, Any] | None] = queue.Queue()
        self._reader: threading.Thread | None = None

    def _read_events(
        self,
        stream,
        events: queue.Queue[dict[str, Any] | None],
    ) -> None:
        try:
            for line in stream:
                try:
                    event = json.loads(line)
                    if not isinstance(event, dict):
                        raise ValueError("worker event must be an object")
                except (json.JSONDecodeError, ValueError):
                    event = {"event": "protocol-error"}
                events.put(event)
        finally:
            events.put(None)

    def _stop(self, *, force: bool) -> None:
        process = self._process
        self._process = None
        self._reader = None
        if process is None:
            return
        if force and process.poll() is None:
            process.terminate()
        if process.stdin is not None:
            try:
                process.stdin.close()
            except OSError:
                pass
        try:
            process.wait(timeout=0.5 if force else 1.0)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
        if process.stdout is not None:
            try:
                process.stdout.close()
            except OSError:
                pass

    def _start(self, scan_deadline: float) -> str | None:
        if self._process is not None and self._process.poll() is None:
            return None
        if self._process is not None:
            self._stop(force=False)
        self._events = queue.Queue()
        source_root = str(Path(__file__).resolve().parent.parent)
        environment = os.environ.copy()
        environment["PYTHONPATH"] = source_root
        environment["PYTHONDONTWRITEBYTECODE"] = "1"
        try:
            process = subprocess.Popen(
                [sys.executable, "-m", "vigil_fuse.rule_worker"],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
                encoding="utf-8",
                bufsize=1,
                env=environment,
                cwd=source_root,
            )
        except OSError as error:
            return f"worker launch failed ({type(error).__name__})"
        self._process = process
        assert process.stdout is not None
        self._reader = threading.Thread(
            target=self._read_events,
            args=(process.stdout, self._events),
            name="vigil-fuse-rule-worker-reader",
            daemon=True,
        )
        self._reader.start()
        wait_until = min(time.monotonic() + WORKER_START_TIMEOUT_SECONDS, scan_deadline)
        event = self._next_event(wait_until)
        if event is not None and event.get("event") == "ready":
            return None
        if time.monotonic() >= scan_deadline:
            self._stop(force=True)
            return "scan-wide time limit reached while starting the rule worker"
        self._stop(force=True)
        return "rule worker did not become ready"

    def _next_event(self, wait_until: float) -> dict[str, Any] | None:
        timeout = max(0.0, wait_until - time.monotonic())
        try:
            return self._events.get(timeout=timeout)
        except queue.Empty:
            return {"event": "wait-timeout"}

    def execute(
        self,
        source: SourceFile,
        rule_ids: tuple[str, ...],
        *,
        scan_deadline: float,
    ) -> RuleExecutionResult:
        result = RuleExecutionResult()
        pending = list(dict.fromkeys(rule_ids))
        handled: set[str] = set()

        while pending:
            start_error = self._start(scan_deadline)
            if start_error is not None:
                if "scan-wide time limit" in start_error:
                    result.scan_deadline_reached = True
                    result.unfinished_rule_ids.update(pending)
                else:
                    result.failed.update({rule_id: start_error for rule_id in pending})
                break

            process = self._process
            assert process is not None and process.stdin is not None
            request = {
                "source": {
                    "path": source.path,
                    "text": source.text,
                    "sha256": source.sha256,
                    "byte_size": source.byte_size,
                    "generated_config": source.generated_config,
                },
                "rule_ids": pending,
            }
            try:
                process.stdin.write(json.dumps(request, ensure_ascii=False) + "\n")
                process.stdin.flush()
            except (BrokenPipeError, OSError):
                self._stop(force=True)
                result.failed.update(
                    {rule_id: "rule worker closed its input" for rule_id in pending}
                )
                break

            current_rule: str | None = None
            current_deadline = scan_deadline
            restart_for_timeout = False
            worker_failed = False
            while True:
                now = time.monotonic()
                if now >= scan_deadline:
                    result.scan_deadline_reached = True
                    result.unfinished_rule_ids.update(
                        rule_id for rule_id in pending if rule_id not in handled
                    )
                    self._stop(force=True)
                    worker_failed = True
                    break
                if current_rule is not None and now >= current_deadline:
                    result.timed_out[current_rule] = (
                        f"Exceeded {self.timeout_seconds:g} seconds on {source.path}; "
                        "this rule will be disabled for the remainder of the scan."
                    )
                    handled.add(current_rule)
                    self._stop(force=True)
                    pending = [rule_id for rule_id in pending if rule_id not in handled]
                    restart_for_timeout = True
                    break

                wait_until = (
                    current_deadline
                    if current_rule is not None
                    else min(now + WORKER_IDLE_TIMEOUT_SECONDS, scan_deadline)
                )
                event = self._next_event(wait_until)
                if event is None or event.get("event") == "protocol-error":
                    message = "rule worker exited or returned an invalid response"
                    unresolved = [rule_id for rule_id in pending if rule_id not in handled]
                    result.failed.update({rule_id: message for rule_id in unresolved})
                    self._stop(force=True)
                    worker_failed = True
                    break
                event_type = event.get("event")
                if event_type == "wait-timeout":
                    if current_rule is None:
                        unresolved = [rule_id for rule_id in pending if rule_id not in handled]
                        result.failed.update(
                            {
                                rule_id: "rule worker stopped responding between rules"
                                for rule_id in unresolved
                            }
                        )
                        self._stop(force=True)
                        worker_failed = True
                        break
                    continue
                if event_type == "rule-start":
                    rule_id = event.get("rule_id")
                    if not isinstance(rule_id, str) or rule_id not in pending or rule_id in handled:
                        unresolved = [item for item in pending if item not in handled]
                        result.failed.update(
                            {
                                item: "rule worker returned an unexpected rule ID"
                                for item in unresolved
                            }
                        )
                        self._stop(force=True)
                        worker_failed = True
                        break
                    current_rule = rule_id
                    current_deadline = min(
                        time.monotonic() + self.timeout_seconds,
                        scan_deadline,
                    )
                    continue
                if event_type == "rule-result":
                    rule_id = event.get("rule_id")
                    try:
                        if rule_id != current_rule:
                            raise ValueError("unexpected rule result")
                        rows = event.get("findings")
                        if not isinstance(rows, list):
                            raise ValueError("invalid findings list")
                        parsed_findings = [_finding_from_dict(row) for row in rows]
                        result.findings.extend(parsed_findings)
                    except (KeyError, TypeError, ValueError):
                        if current_rule is not None:
                            result.failed[current_rule] = "rule worker returned an invalid finding"
                            handled.add(current_rule)
                        current_rule = None
                        continue
                    handled.add(current_rule)
                    result.completed_rule_ids.add(current_rule)
                    current_rule = None
                    continue
                if event_type == "rule-error":
                    rule_id = event.get("rule_id")
                    if rule_id != current_rule:
                        unresolved = [item for item in pending if item not in handled]
                        result.failed.update(
                            {
                                item: "rule worker returned an unexpected rule error"
                                for item in unresolved
                            }
                        )
                        self._stop(force=True)
                        worker_failed = True
                        break
                    error_name = event.get("error")
                    result.failed[current_rule] = (
                        f"rule raised {error_name if isinstance(error_name, str) else 'an error'}"
                    )
                    handled.add(current_rule)
                    current_rule = None
                    continue
                if event_type == "request-error":
                    unresolved = [item for item in pending if item not in handled]
                    result.failed.update(
                        {item: "rule worker rejected the scan request" for item in unresolved}
                    )
                    self._stop(force=True)
                    worker_failed = True
                    break
                if event_type == "done":
                    missing = [item for item in pending if item not in handled]
                    result.failed.update({item: "rule worker omitted a result" for item in missing})
                    pending = []
                    break
                if event_type == "ready":
                    continue
                unresolved = [item for item in pending if item not in handled]
                result.failed.update(
                    {item: "rule worker returned an unknown response" for item in unresolved}
                )
                self._stop(force=True)
                worker_failed = True
                break

            if restart_for_timeout:
                continue
            if worker_failed:
                pending = []

        return result

    def close(self) -> None:
        self._stop(force=False)

    def __enter__(self) -> IsolatedRuleExecutor:
        return self

    def __exit__(self, exc_type, exc, traceback) -> None:
        self.close()

    def __del__(self) -> None:
        self.close()
