from __future__ import annotations

import json

from scripts.benchmark_scan import create_synthetic_project, run_benchmark


def test_synthetic_project_generation_is_deterministic(tmp_path) -> None:
    first = create_synthetic_project(tmp_path / "first", file_count=8)
    second = create_synthetic_project(tmp_path / "second", file_count=8)

    assert first.file_count == second.file_count == 8
    assert first.source_bytes == second.source_bytes
    assert first.sha256 == second.sha256
    assert sorted(path.name for path in (tmp_path / "first").iterdir()) == [
        f"module_{index:06d}.c" for index in range(8)
    ]


def test_scan_benchmark_reports_complete_path_free_evidence() -> None:
    report = run_benchmark(
        file_count=8,
        warmups=0,
        repetitions=1,
        sample_interval_ms=5,
        timeout_seconds=45,
    )

    measurements = report["measurements"]
    assert report["benchmark"] == "fuse-synthetic-project-scan"
    assert report["input"]["files"] == 8
    assert measurements["files_scanned"] == 8
    assert measurements["source_bytes_read"] == report["input"]["source_bytes"]
    assert measurements["finding_count"] == 0
    assert measurements["completed_native_rules"]
    assert measurements["wall_time_seconds"]["median"] > 0
    assert measurements["sampled_process_tree_rss_bytes"]["maximum"] > 0
    assert measurements["sampled_process_tree_rss_bytes"]["sampling_complete"] is True

    serialized = json.dumps(report)
    assert "synthetic-embedded-project" not in serialized
    assert str(__file__) not in serialized
