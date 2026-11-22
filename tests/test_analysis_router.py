from pathlib import Path

import pytest

from vigil_fuse.analysis_router import plan_analysis
from vigil_fuse.project_identity import inspect_project_identity
from vigil_fuse.repo_dna import inspect_repository
from vigil_fuse.target_model import Target


def test_router_never_enables_active_tools(tmp_path: Path) -> None:
    plan = plan_analysis(inspect_repository(tmp_path)["project_identity"])
    assert {d["stage"] for d in plan if d["status"] == "blocked_by_policy"} == {
        "nikto",
        "metasploit-check",
    }


def test_incomplete_identity_only_adds_advisory_discovery_status(tmp_path: Path) -> None:
    root = tmp_path / "project"
    root.mkdir()
    (root / "nested").mkdir()
    identity = inspect_project_identity(root, max_depth=0)

    plan = plan_analysis(identity)

    assert {decision["stage"] for decision in plan if decision["status"] == "selected"} == {
        "native"
    }
    assert any(
        decision["stage"] == "discovery" and decision["status"] == "unsupported"
        for decision in plan
    )
    assert all(
        decision["stage"] != "nikto" or decision["status"] == "blocked_by_policy"
        for decision in plan
    )


def test_missing_identity_rejected() -> None:
    with pytest.raises(ValueError):
        Target(target_id="", kind="repository", label="repo", source=".")


def test_inspection_does_not_grant_authorization() -> None:
    assert (
        Target(target_id="x", kind="repository", label="repo", source=".").authorization
        == "unknown"
    )
