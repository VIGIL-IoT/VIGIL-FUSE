"""Opt-in probe integration: set FUSE_EXECUTION_WORKER_IMAGE to a built worker image."""

import json
import os
import subprocess
import uuid

import pytest

from vigil_fuse.execution_contract import create_plan, decode_message, validate_result

IMAGE = os.environ.get("FUSE_EXECUTION_WORKER_IMAGE")
pytestmark = pytest.mark.skipif(not IMAGE, reason="explicit worker image required")


def run_worker(arguments, payload=None, memory="512m", entrypoint=None):
    name = "fuse-contract-test-" + uuid.uuid4().hex
    command = [
        "docker",
        "run",
        "--rm",
        "--name",
        name,
        "-i",
        "--network",
        "none",
        "--memory",
        memory,
        "--cpus",
        "1",
        "--read-only",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges",
    ]
    if entrypoint:
        command.extend(["--entrypoint", entrypoint])
    command.extend([IMAGE, *arguments])
    try:
        return subprocess.run(command, input=payload, capture_output=True, timeout=40)
    finally:
        subprocess.run(["docker", "rm", "--force", name], capture_output=True, timeout=15)


def test_restricted_worker_roundtrip():
    plan = create_plan("docker-probe", "firmware", "a" * 64, "docker")
    process = run_worker(["worker"], json.dumps(plan).encode())
    assert process.returncode == 0, process.stderr
    assert validate_result(decode_message(process.stdout), plan, "worker")["status"] == "completed"


def test_invalid_input_is_process_failure():
    process = run_worker(["worker"], b"{invalid")
    assert process.returncode == 2
    assert process.stdout == b""


def test_oom_is_process_failure():
    process = run_worker(
        ["-c", "data=bytearray(400*1024*1024); print(len(data))"], memory="64m", entrypoint="python"
    )
    assert process.returncode == 137, process.stderr


def test_successful_process_cannot_bypass_output_validation():
    process = run_worker(["-c", 'print("{invalid")'], entrypoint="python")
    assert process.returncode == 0
    with pytest.raises(ValueError):
        decode_message(process.stdout)
