"""Versioned, bounded execution messages. Worker evidence is never a security verdict."""

from __future__ import annotations

import json
import re
from typing import Any

SCHEMA_VERSION = "0.1"
MAX_MESSAGE_BYTES = 1024 * 1024
_ID = re.compile(r"[a-z0-9][a-z0-9-]{0,62}\Z")
_DIGEST = re.compile(r"[a-f0-9]{64}\Z")


def _object(value: object, fields: set[str]) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != fields:
        raise ValueError("Execution message has missing or unknown fields")
    return value


def _identifier(value: object) -> None:
    if not isinstance(value, str) or not _ID.fullmatch(value):
        raise ValueError("Invalid execution identifier")


def _integer(value: object, maximum: int) -> None:
    if type(value) is not int or not 1 <= value <= maximum:
        raise ValueError("Invalid resource budget")


def decode_message(payload: bytes) -> object:
    """Reject oversized, duplicate-key, nonfinite and deeply nested input."""
    if len(payload) > MAX_MESSAGE_BYTES:
        raise ValueError("Execution message exceeds byte limit")

    def pairs(items: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in items:
            if key in result:
                raise ValueError("Duplicate execution field")
            result[key] = value
        return result

    def constant(value: str) -> None:
        raise ValueError("Nonfinite JSON number")

    try:
        return json.loads(payload, object_pairs_hook=pairs, parse_constant=constant)
    except (UnicodeError, RecursionError, json.JSONDecodeError) as exc:
        raise ValueError("Invalid execution JSON") from exc


def validate_plan(value: object) -> dict[str, Any]:
    """Accept only explicitly authorized, passive, isolated worker plans."""
    plan = _object(
        value,
        {
            "schema_version",
            "plan_id",
            "target",
            "requested_analyzers",
            "execution_mode",
            "authorization",
            "limits",
            "network_policy",
            "evidence_requirements",
            "created_by",
        },
    )
    if plan["schema_version"] != SCHEMA_VERSION or plan["created_by"] != "vigil-fuse":
        raise ValueError("Unsupported execution schema or producer")
    _identifier(plan["plan_id"])
    target = _object(plan["target"], {"target_id", "sha256"})
    _identifier(target["target_id"])
    if not isinstance(target["sha256"], str) or not _DIGEST.fullmatch(target["sha256"]):
        raise ValueError("Target digest required")
    if plan["requested_analyzers"] != ["probe"]:
        raise ValueError("Only the deterministic probe worker is enabled")
    if plan["execution_mode"] not in ("local", "docker", "kubernetes"):
        raise ValueError("Unsupported execution backend")
    authorization = _object(plan["authorization"], {"passive_execution"})
    if authorization["passive_execution"] is not True:
        raise ValueError("Explicit passive execution authorization required")
    limits = _object(plan["limits"], {"cpu_millis", "memory_mb", "timeout_seconds"})
    for key, maximum in (("cpu_millis", 4000), ("memory_mb", 4096), ("timeout_seconds", 3600)):
        _integer(limits[key], maximum)
    if plan["network_policy"] != "deny" or plan["evidence_requirements"] != ["target-identity"]:
        raise ValueError("Unsupported network policy or evidence requirements")
    return plan


def create_plan(
    plan_id: str, target_id: str, sha256: str, execution_mode: str = "local"
) -> dict[str, Any]:
    """Create an authorized probe plan; calling this API is an explicit execution choice."""
    return validate_plan(
        {
            "schema_version": SCHEMA_VERSION,
            "plan_id": plan_id,
            "target": {"target_id": target_id, "sha256": sha256},
            "requested_analyzers": ["probe"],
            "execution_mode": execution_mode,
            "authorization": {"passive_execution": True},
            "limits": {"cpu_millis": 1000, "memory_mb": 512, "timeout_seconds": 300},
            "network_policy": "deny",
            "evidence_requirements": ["target-identity"],
            "created_by": "vigil-fuse",
        }
    )


def validate_result(value: object, plan: object, worker_id: str) -> dict[str, Any]:
    """Bind an untrusted envelope to the expected plan and scheduler worker identity."""
    expected = validate_plan(plan)
    _identifier(worker_id)
    result = _object(
        value,
        {
            "schema_version",
            "plan_id",
            "worker",
            "status",
            "artifacts",
            "findings",
            "evidence",
            "coverage",
            "limitations",
        },
    )
    if result["schema_version"] != SCHEMA_VERSION or result["plan_id"] != expected["plan_id"]:
        raise ValueError("Result schema or plan identity mismatch")
    if result["worker"] != {"worker_id": worker_id, "analyzer": "probe"}:
        raise ValueError("Result worker identity mismatch")
    if result["status"] not in ("completed", "partial", "failed", "blocked", "timeout"):
        raise ValueError("Invalid operational result status")
    if result["artifacts"] != [] or result["findings"] != [] or result["coverage"] != {}:
        raise ValueError("Probe cannot emit artifacts, findings or security coverage")
    limitations = result["limitations"]
    if (
        not isinstance(limitations, list)
        or len(limitations) > 16
        or any(not isinstance(item, str) or not 1 <= len(item) <= 512 for item in limitations)
    ):
        raise ValueError("Invalid result limitations")
    evidence = result["evidence"]
    expected_evidence = [{"kind": "target-identity", "target": expected["target"]}]
    if result["status"] == "completed":
        if evidence != expected_evidence:
            raise ValueError("Completed probe requires bound target identity evidence")
    elif evidence not in ([], expected_evidence) or not limitations:
        raise ValueError("Incomplete execution requires bounded evidence and limitations")
    return result
