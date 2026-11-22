from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from vigil_fuse.gui import backend
from vigil_fuse.gui.backend import (
    Runner,
    ScanOptions,
    export_reports,
    filter_findings,
    load_report,
    paginate_findings,
    prepare_export_metadata,
)

ROOT = Path(__file__).resolve().parents[1]


def test_scan_options_validate_directory_profile_and_special_path(tmp_path: Path):
    project = tmp_path / "project with spaces"
    project.mkdir()
    options = ScanOptions(project, profile="rtl")
    args = options.arguments()
    assert str(project.resolve()) in args
    assert "--profile" in args and args[args.index("--profile") + 1] == "rtl"
    assert "--no-network" in args
    with pytest.raises(ValueError, match="directory"):
        ScanOptions(tmp_path / "missing").arguments()
    with pytest.raises(ValueError, match="profile"):
        ScanOptions(project, profile="unknown").arguments()


def test_load_report_rejects_symlinks_and_malformed_data(tmp_path: Path):
    malformed = tmp_path / "bad.json"
    malformed.write_text('{"findings": [], "coverage": []}', encoding="utf-8")
    with pytest.raises(ValueError, match="supported"):
        load_report(malformed)
    if hasattr(os, "symlink"):
        link = tmp_path / "linked.json"
        try:
            link.symlink_to(malformed)
        except OSError:
            return
        with pytest.raises(ValueError, match="regular"):
            load_report(link)


def test_findings_filter_keeps_severity_confidence_and_unknown_independent():
    findings = [
        {
            "rule_id": "FUSE001",
            "title": "Credential",
            "severity": "high",
            "confidence": "medium",
            "applicability": "unknown",
            "location": {"file": "src/a.py"},
        },
        {
            "rule_id": "FUSE002",
            "title": "Unsafe call",
            "severity": "medium",
            "confidence": "high",
            "applicability": "potentially-applicable",
            "location": {"file": "src/b.py"},
        },
    ]
    assert len(filter_findings(findings, "src/", "severity", "high")) == 1
    assert len(filter_findings(findings, "unsafe", "confidence", "high")) == 1
    assert len(filter_findings(findings, "", "applicability", "unknown")) == 1


def test_large_findings_reports_are_paged_and_page_indices_are_bounded():
    findings = [{"rule_id": f"FUSE{index:04d}"} for index in range(601)]
    first, page, max_page = paginate_findings(findings, 0)
    assert (len(first), page, max_page) == (250, 0, 2)
    second, page, _ = paginate_findings(findings, 1)
    assert (len(second), page, second[0]["rule_id"]) == (250, 1, "FUSE0250")
    last, page, _ = paginate_findings(findings, 99)
    assert (len(last), page, last[-1]["rule_id"]) == (101, 2, "FUSE0600")
    empty, page, max_page = paginate_findings([], -1)
    assert (empty, page, max_page) == ([], 0, 0)
    with pytest.raises(ValueError, match="positive"):
        paginate_findings(findings, 0, page_size=0)


def test_export_copies_canonical_reports_and_refuses_overwrite(tmp_path: Path):
    source, destination = tmp_path / "source", tmp_path / "empty"
    source.mkdir()
    destination.mkdir()
    for name in ("findings.json", "findings.txt", "findings.sarif"):
        (source / name).write_text(name, encoding="utf-8")
    copied = export_reports(source, destination)
    assert {item.name for item in copied} == {"findings.json", "findings.txt", "findings.sarif"}
    with pytest.raises(FileExistsError):
        export_reports(source, destination)


def test_export_includes_provenance_and_versioned_citation(tmp_path: Path):
    report = {"tool": {"version": "0.4.0"}, "provenance": {"status": "not-requested"}}
    prepare_export_metadata(tmp_path, report)
    assert (
        json.loads((tmp_path / "provenance.json").read_text(encoding="utf-8"))
        == report["provenance"]
    )
    citation = (tmp_path / "fuse-citation.txt").read_text(encoding="utf-8")
    assert "version 0.4.0" in citation
    assert "https://github.com/VIGIL-IoT/VIGIL-FUSE" in citation


def test_cancel_before_runner_launch_returns_cancelled_result(tmp_path: Path):
    runner = Runner(tmp_path)
    assert runner.cancel()
    result = runner.run(["doctor"])
    assert result.cancelled
    assert result.returncode == -1
    assert "Cancelled before launch" in result.stderr


def test_runner_cancellation_terminates_windows_process_tree(monkeypatch, tmp_path: Path):
    if os.name != "nt":
        pytest.skip("Windows process-tree cancellation")

    runner = Runner(tmp_path)
    calls: list[list[str]] = []

    class FakeProcess:
        pid = 4321
        returncode = 1

        def poll(self):
            return None

        def communicate(self, timeout: int):
            assert timeout == 1800
            runner.cancel()
            return "", "terminated"

    process = FakeProcess()
    monkeypatch.setattr(backend.subprocess, "Popen", lambda *args, **kwargs: process)
    monkeypatch.setattr(
        backend.subprocess,
        "run",
        lambda args, **kwargs: calls.append(args),
    )

    result = runner.run(["scan", "fixture"])
    assert result.cancelled
    assert result.returncode == 1
    assert calls == [["taskkill", "/PID", "4321", "/T", "/F"]]


def test_load_report_preserves_failed_and_unavailable_analyzers(tmp_path: Path):
    coverage = {
        "analyzers": [
            {"name": "syft", "status": "failed", "detail": "fixture failure"},
            {"name": "osv-scanner", "status": "unavailable", "detail": "not installed"},
        ]
    }
    report_path = tmp_path / "coverage.json"
    report_path.write_text(json.dumps({"findings": [], "coverage": coverage}), encoding="utf-8")
    assert load_report(report_path)["coverage"] == coverage


def test_clean_scan_and_unavailable_optional_analyzers_are_reported(tmp_path: Path):
    env = {**os.environ, "PYTHONPATH": str(ROOT / "src"), "GIT_CONFIG_COUNT": "0"}
    clean_project = tmp_path / "clean project"
    clean_project.mkdir()
    (clean_project / "safe.py").write_text('print("hello")\n', encoding="utf-8")
    clean_output = tmp_path / "clean reports"
    clean_scan = subprocess.run(
        [
            sys.executable,
            "-m",
            "vigil_fuse",
            "scan",
            str(clean_project),
            "--no-network",
            "--no-sbom",
            "--no-vulnerabilities",
            "--no-firmware",
            "--no-ghidra",
            "--no-git-history",
            "--output-dir",
            str(clean_output),
        ],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert clean_scan.returncode == 0, clean_scan.stderr
    assert load_report(clean_output / "findings.json")["findings"] == []

    analyzer_project = tmp_path / "dependency project"
    analyzer_project.mkdir()
    (analyzer_project / "package.json").write_text(
        '{"name":"gui-fixture","version":"1.0.0","dependencies":{"left-pad":"1.3.0"}}',
        encoding="utf-8",
    )
    analyzer_output = tmp_path / "analyzer reports"
    no_tools_env = {**env, "PATH": ""}
    scan = subprocess.run(
        [
            sys.executable,
            "-m",
            "vigil_fuse",
            "scan",
            str(analyzer_project),
            "--no-network",
            "--sbom",
            "--vulnerabilities",
            "--no-firmware",
            "--no-ghidra",
            "--no-git-history",
            "--output-dir",
            str(analyzer_output),
        ],
        cwd=tmp_path,
        env=no_tools_env,
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert scan.returncode in {0, 1, 2}, scan.stderr
    analyzers = load_report(analyzer_output / "findings.json")["coverage"]["analyzers"]
    statuses = {item["name"]: item["status"] for item in analyzers}
    assert statuses["syft"] == "unavailable"
    assert statuses["osv-scanner"] == "unavailable"


def test_real_fuse_plan_scan_coverage_and_baseline(tmp_path: Path):
    project = tmp_path / "FUSE GUI special path"
    project.mkdir()
    output = tmp_path / "reports"
    env = {**os.environ, "PYTHONPATH": str(ROOT / "src"), "GIT_CONFIG_COUNT": "0"}
    (project / "device.py").write_text('password = "gui-fixture-secret"\n', encoding="utf-8")
    plan = subprocess.run(
        [sys.executable, "-m", "vigil_fuse", "scan", str(project), "--no-network", "--plan"],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        text=True,
        check=True,
        timeout=60,
    )
    assert "No analyzer ran" in plan.stdout
    scan = subprocess.run(
        [
            sys.executable,
            "-m",
            "vigil_fuse",
            "scan",
            str(project),
            "--no-network",
            "--output-dir",
            str(output),
        ],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert scan.returncode in {0, 1}
    report = load_report(output / "findings.json")
    assert report["findings"][0]["rule_id"] == "FUSE001"
    assert "analyzers" in report["coverage"]
    previous = tmp_path / "previous.json"
    previous.write_text((output / "findings.json").read_text(encoding="utf-8"), encoding="utf-8")
    baseline = tmp_path / "baseline.json"
    create = subprocess.run(
        [
            sys.executable,
            "-m",
            "vigil_fuse",
            "baseline",
            "create",
            str(previous),
            "--output",
            str(baseline),
        ],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert create.returncode == 0, create.stderr
    (project / "device.py").write_text(
        'import os\npassword = os.environ["DEVICE_PASSWORD"]\n', encoding="utf-8"
    )
    current = tmp_path / "current"
    subprocess.run(
        [
            sys.executable,
            "-m",
            "vigil_fuse",
            "scan",
            str(project),
            "--no-network",
            "--output-dir",
            str(current),
        ],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
        check=True,
    )
    diff = subprocess.run(
        [
            sys.executable,
            "-m",
            "vigil_fuse",
            "baseline",
            "diff",
            str(current / "findings.json"),
            "--baseline",
            str(baseline),
            "--format",
            "json",
        ],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert diff.returncode == 0, diff.stderr
    assert json.loads(diff.stdout)["summary"]["resolved"] == 1
