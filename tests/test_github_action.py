"""Integration tests exercise the real CLI through the Action adapter."""

from __future__ import annotations

import json
import importlib.util
import os
import subprocess
import sys
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]


def test_scanner_subprocess_does_not_inherit_tokens(tmp_path: Path, monkeypatch):
    spec = importlib.util.spec_from_file_location("fuse_action_review", ROOT / "action/review.py")
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    monkeypatch.setenv("GITHUB_TOKEN", "sensitive-fixture-token")
    monkeypatch.setenv("FUSE_COMMENT_TOKEN", "sensitive-fixture-token")
    with patch.object(module.subprocess, "run") as run:
        module.run_fuse(["doctor"], ROOT, tmp_path)
    environment = run.call_args.kwargs["env"]
    assert "GITHUB_TOKEN" not in environment
    assert "FUSE_COMMENT_TOKEN" not in environment


def git(repo: Path, *args: str) -> str:
    env = {**os.environ, "GIT_CONFIG_COUNT": "0"}
    result = subprocess.run(
        ["git", "-C", str(repo), *args], env=env, check=True, text=True, capture_output=True
    )
    return result.stdout.strip()


def run_action(tmp_path: Path, repo: Path, **overrides: str):
    summary = tmp_path / "summary"
    output = tmp_path / "outputs"
    env = {
        **os.environ,
        "GIT_CONFIG_COUNT": "0",
        "FUSE_ACTION_PATH": str(ROOT),
        "GITHUB_WORKSPACE": str(repo),
        "RUNNER_TEMP": str(tmp_path),
        "GITHUB_STEP_SUMMARY": str(summary),
        "GITHUB_OUTPUT": str(output),
        "FUSE_PATH": ".",
        "FUSE_PROFILE": "generic",
        "FUSE_FAIL_ON": "none",
        "FUSE_BASELINE": "false",
        "FUSE_NETWORK": "offline",
        "FUSE_DEPENDENCIES": "false",
        "FUSE_BASE_SHA": "",
        "FUSE_EVENT": "push",
    }
    env.update(overrides)
    proc = subprocess.run(
        [sys.executable, str(ROOT / "action/review.py")],
        cwd=tmp_path,
        env=env,
        text=True,
        capture_output=True,
        timeout=120,
    )
    values = (
        dict(line.split("=", 1) for line in output.read_text().splitlines())
        if output.exists()
        else {}
    )
    return proc, values, summary


def test_real_scan_baseline_and_gate(tmp_path: Path):
    repo = tmp_path / "project with spaces"
    repo.mkdir()
    git(repo, "init", "--quiet")
    (repo / "device.py").write_text('password = "device-value-123"\n', encoding="utf-8")
    git(repo, "add", "device.py")
    git(
        repo,
        "-c",
        "user.name=FUSE test",
        "-c",
        "user.email=test@example.invalid",
        "commit",
        "-qm",
        "fixture",
    )
    base = git(repo, "rev-parse", "HEAD")
    proc, values, _ = run_action(tmp_path, repo, FUSE_FAIL_ON="medium")
    assert proc.returncode == 0, proc.stderr
    assert values["gate"] == "fail"
    directory = Path(values["report-directory"])
    assert all(
        (directory / name).is_file() for name in ("findings.json", "findings.txt", "findings.sarif")
    )
    assert json.loads((directory / "findings.json").read_text(encoding="utf-8"))["findings"]
    (repo / "device.py").write_text(
        'import os\npassword = os.environ["DEVICE_PASSWORD"]\n', encoding="utf-8"
    )
    proc, values, summary = run_action(
        tmp_path,
        repo,
        FUSE_EVENT="pull_request",
        FUSE_BASELINE="true",
        FUSE_BASE_SHA=base,
        FUSE_FAIL_ON="medium",
    )
    assert proc.returncode == 0, proc.stderr
    assert values["gate"] == "pass"
    diff = json.loads(
        (Path(values["report-directory"]) / "baseline-diff.json").read_text(encoding="utf-8")
    )
    assert diff["summary"]["resolved"] == 1
    assert "Static evidence only" in summary.read_text(encoding="utf-8")
    git(repo, "add", "device.py")
    git(
        repo,
        "-c",
        "user.name=FUSE test",
        "-c",
        "user.email=test@example.invalid",
        "commit",
        "-qm",
        "clean",
    )
    clean_base = git(repo, "rev-parse", "HEAD")
    (repo / "device.py").write_text('password = "new-device-secret"\n', encoding="utf-8")
    proc, values, _ = run_action(
        tmp_path,
        repo,
        FUSE_EVENT="pull_request",
        FUSE_BASELINE="true",
        FUSE_BASE_SHA=clean_base,
        FUSE_FAIL_ON="medium",
    )
    assert proc.returncode == 0, proc.stderr
    assert values["gate"] == "fail"
    diff = json.loads(
        (Path(values["report-directory"]) / "baseline-diff.json").read_text(encoding="utf-8")
    )
    assert diff["summary"]["new"] == 1


def test_rejects_untrusted_paths_and_privileged_pr(tmp_path: Path):
    repo = tmp_path / "repo"
    repo.mkdir()
    for settings in ({"FUSE_PATH": "../"}, {"FUSE_EVENT": "pull_request_target"}):
        proc, _, _ = run_action(tmp_path, repo, **settings)
        assert proc.returncode != 0


def test_missing_base_is_unknown_not_a_clean_diff(tmp_path: Path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "test.py").write_text("print('ok')\n", encoding="utf-8")
    proc, values, summary = run_action(
        tmp_path, repo, FUSE_EVENT="pull_request", FUSE_BASELINE="true", FUSE_BASE_SHA="invalid"
    )
    assert proc.returncode == 0, proc.stderr
    assert values["gate"] == "unknown"
    assert "Baseline comparison unavailable" in summary.read_text(encoding="utf-8")


def test_missing_optional_analyzers_are_reported_as_unknown(tmp_path: Path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "test.py").write_text("print('ok')\n", encoding="utf-8")
    proc, values, summary = run_action(tmp_path, repo, FUSE_DEPENDENCIES="true", PATH="")
    assert proc.returncode == 0, proc.stderr
    assert values["gate"] == "unknown"
    assert "unavailable" in summary.read_text(encoding="utf-8").lower()
