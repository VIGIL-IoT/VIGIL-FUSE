from pathlib import Path

import pytest

from vigil_fuse.analysis_router import plan_analysis
from vigil_fuse.repo_dna import inspect_repository
from vigil_fuse.target_model import Target


def test_router_never_enables_active_tools(tmp_path: Path) -> None:
    plan = plan_analysis(inspect_repository(tmp_path))
    assert {d["stage"] for d in plan if d["status"] == "blocked_by_policy"} == {
        "nikto",
        "metasploit-check",
    }


def test_missing_identity_rejected() -> None:
    with pytest.raises(ValueError):
        Target(target_id="", kind="repository", label="repo", source=".")


def test_inspection_does_not_grant_authorization() -> None:
    assert (
        Target(target_id="x", kind="repository", label="repo", source=".").authorization
        == "unknown"
    )
