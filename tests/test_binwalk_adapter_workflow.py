from __future__ import annotations

import re
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "binwalk-adapter.yml"
BINWALK_SOURCE_COMMIT = "4fdab3d464d97b68e0af9088df3f9e2e1545b21c"


def test_binwalk_workflow_is_manual_and_uses_windows_and_ubuntu() -> None:
    workflow = yaml.load(WORKFLOW.read_text(encoding="utf-8"), Loader=yaml.BaseLoader)

    assert workflow["on"] == {"workflow_dispatch": ""}
    assert workflow["permissions"] == {}
    assert workflow["jobs"]["adapter-smoke"]["strategy"]["matrix"]["os"] == [
        "ubuntu-latest",
        "windows-latest",
    ]


def test_binwalk_workflow_pins_upstream_source_and_actions() -> None:
    workflow = yaml.load(WORKFLOW.read_text(encoding="utf-8"), Loader=yaml.BaseLoader)
    job = workflow["jobs"]["adapter-smoke"]
    steps = job["steps"]

    assert workflow["env"]["BINWALK_SOURCE_COMMIT"] == BINWALK_SOURCE_COMMIT
    action_uses = [step["uses"] for step in steps if "uses" in step]
    assert len(action_uses) == 3
    for use in action_uses:
        assert re.fullmatch(r".+@[0-9a-f]{40}(?:\s+#\s+v\S+)?", use)


def test_binwalk_workflow_builds_locked_source_and_runs_both_controls() -> None:
    workflow = yaml.load(WORKFLOW.read_text(encoding="utf-8"), Loader=yaml.BaseLoader)
    steps = workflow["jobs"]["adapter-smoke"]["steps"]
    build_steps = [
        step for step in steps if "cargo build --release --locked" in step.get("run", "")
    ]

    assert len(build_steps) == 2
    assert "--expected-version 3.1.0" in build_steps[0]["run"]
    assert "--expected-version 3.1.0" in build_steps[1]["run"]
    assert all("--binwalk-executable" in step["run"] for step in build_steps)
