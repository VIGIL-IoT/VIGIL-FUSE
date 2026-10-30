from __future__ import annotations

import tomllib
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]


def test_test_extras_exclude_pytest_versions_with_known_advisories() -> None:
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    extras = project["project"]["optional-dependencies"]

    assert "pytest>=9.0.3,<10" in extras["test"]
    assert "pytest>=9.0.3,<10" in extras["dev"]


def test_dependabot_covers_python_and_github_actions_weekly() -> None:
    configuration = yaml.safe_load(
        (ROOT / ".github" / "dependabot.yml").read_text(encoding="utf-8")
    )

    updates = {entry["package-ecosystem"]: entry for entry in configuration["updates"]}
    assert set(updates) == {"pip", "github-actions"}
    assert all(entry["schedule"]["interval"] == "weekly" for entry in updates.values())


def test_dependency_audit_workflow_is_read_only_and_scheduled() -> None:
    workflow = yaml.safe_load(
        (ROOT / ".github" / "workflows" / "dependency-audit.yml").read_text(encoding="utf-8")
    )
    triggers = workflow.get("on", workflow.get(True, {}))

    assert "schedule" in triggers
    assert "workflow_dispatch" in triggers
    assert workflow["permissions"] == {"contents": "read"}
    assert "audit" in workflow["jobs"]
