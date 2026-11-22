import json
import subprocess
import sys
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from vigil_fuse.execution_contract import (
    create_plan,
    decode_message,
    validate_plan,
    validate_result,
)


def test_worker_roundtrip_and_identity_binding():
    plan = create_plan("test", "firmware", "a" * 64)
    process = subprocess.run(
        [sys.executable, "-m", "vigil_fuse.execution_worker", "worker"],
        input=json.dumps(plan).encode(),
        capture_output=True,
        timeout=10,
    )
    assert process.returncode == 0, process.stderr
    result = decode_message(process.stdout)
    assert validate_result(result, plan, "worker")["status"] == "completed"
    for name, value in (("analysis-plan", plan), ("evidence-envelope", result)):
        schema = json.loads(
            (
                Path(__file__).parents[1] / "src/vigil_fuse/schemas" / f"{name}-0.1.schema.json"
            ).read_text(encoding="utf-8")
        )
        Draft202012Validator.check_schema(schema)
        Draft202012Validator(schema).validate(value)
    with pytest.raises(ValueError):
        validate_result(result, plan, "different-worker")
    other = create_plan("other", "firmware", "b" * 64)
    with pytest.raises(ValueError):
        validate_result(result, other, "worker")


@pytest.mark.parametrize(
    "payload", [b'{"x":1,"x":2}', b'{"x":NaN}', b"[]" * 1000000, b"\xff", b"[" * 2000]
)
def test_reject_malformed_messages(payload):
    with pytest.raises(ValueError):
        decode_message(payload)


@pytest.mark.parametrize(
    "field,value",
    [
        ("network_policy", "allow"),
        ("requested_analyzers", ["shell"]),
        ("schema_version", "9"),
        ("authorization", {}),
        ("authorization", {"passive_execution": 1}),
        ("limits", {"cpu_millis": True, "memory_mb": 512, "timeout_seconds": 300}),
    ],
)
def test_reject_unsafe_plans(field, value):
    plan = create_plan("test", "target", "a" * 64)
    plan[field] = value
    with pytest.raises(ValueError):
        validate_plan(plan)


@pytest.mark.parametrize("status", ["partial", "failed", "blocked", "timeout"])
def test_failure_never_grants_security_coverage(status):
    plan = create_plan("test", "target", "a" * 64)
    result = {
        "schema_version": "0.1",
        "plan_id": "test",
        "status": status,
        "worker": {"worker_id": "worker", "analyzer": "probe"},
        "artifacts": [],
        "findings": [],
        "evidence": [],
        "coverage": {},
        "limitations": ["Execution incomplete"],
    }
    assert validate_result(result, plan, "worker")["status"] == status
    result["coverage"] = {"SAFE": True}
    with pytest.raises(ValueError):
        validate_result(result, plan, "worker")


def test_file_handoff_and_invalid_worker_output(tmp_path):
    plan = create_plan("test", "target", "a" * 64)
    path = tmp_path / "plan.json"
    path.write_text(json.dumps(plan), encoding="utf-8")
    process = subprocess.run(
        [sys.executable, "-m", "vigil_fuse.execution_worker", "worker", str(path)],
        capture_output=True,
        timeout=10,
    )
    assert process.returncode == 0
    result = decode_message(process.stdout)
    assert validate_result(result, plan, "worker")["status"] == "completed"
    for field, value in (("schema_version", "wrong"), ("evidence", []), ("status", "SAFE")):
        invalid = dict(result)
        invalid[field] = value
        with pytest.raises(ValueError):
            validate_result(invalid, plan, "worker")
