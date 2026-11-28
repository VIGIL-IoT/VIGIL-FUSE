from __future__ import annotations

import re
import tomllib
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "pypi-publish.yml"


def _workflow() -> dict[str, object]:
    return yaml.load(WORKFLOW.read_text(encoding="utf-8"), Loader=yaml.BaseLoader)


def test_only_the_protected_publish_job_receives_oidc_permission() -> None:
    workflow = _workflow()
    jobs = workflow["jobs"]
    build = jobs["build"]
    publish = jobs["publish"]

    assert workflow["permissions"] == {}
    assert build["permissions"] == {"contents": "read"}
    assert "id-token" not in build["permissions"]
    assert publish["needs"] == "build"
    assert publish["permissions"] == {"id-token": "write"}
    assert publish["environment"]["name"] == "pypi"

    steps = publish["steps"]
    actions = [step["uses"] for step in steps if "uses" in step]
    assert actions == [
        "actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c",
        "pypa/gh-action-pypi-publish@7245906fb61fa33a13554f9d5fb856fe61758086",
    ]
    assert all("actions/checkout" not in action for action in actions)
    publish_commands = "\n".join(step.get("run", "") for step in steps)
    assert "python -m build" not in publish_commands
    assert "pip install" not in publish_commands
    assert "sha256sum --check SHA256SUMS" in publish_commands
    assert "RELEASE_TAG" in publish_commands


def test_build_job_uses_explicit_tool_pins_and_uploads_checked_hashes() -> None:
    workflow = _workflow()
    build = workflow["jobs"]["build"]
    steps = build["steps"]
    commands = "\n".join(step.get("run", "") for step in steps)

    assert "build==1.6.1" in commands
    assert "twine==7.0.0" in commands
    assert "setuptools==84.2.1" in commands
    assert "python -m build" in commands
    assert "python -m twine check dist/*" in commands
    assert "sha256sum dist/* > dist/SHA256SUMS" in commands
    assert "RELEASE_TAG" in commands

    upload = next(step for step in steps if "upload-artifact" in step.get("uses", ""))
    assert upload["uses"] == "actions/upload-artifact@cf430e030ddbb5b0abf93d22962f4752f3646cd9"
    assert upload["with"]["name"] == "pypi-distributions"
    assert upload["with"]["if-no-files-found"] == "error"

    pyproject = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    assert pyproject["build-system"]["requires"] == ["setuptools==84.2.1"]


def test_all_workflow_actions_are_immutable_commit_pins() -> None:
    workflow = _workflow()
    for job_name, job in workflow["jobs"].items():
        for step in job["steps"]:
            action = step.get("uses")
            if action:
                assert re.fullmatch(r".+@[0-9a-f]{40}", action), (job_name, action)
