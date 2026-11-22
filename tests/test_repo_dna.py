from pathlib import Path

import pytest

from vigil_fuse.repo_dna import inspect_repository
from vigil_fuse.cli import main
from vigil_fuse.component_graph import build_component_graph


def test_mixed_project_is_deterministic_and_passive(tmp_path: Path) -> None:
    for name in (
        "frontend/next.config.js",
        "firmware/platformio.ini",
        "infra/main.tf",
        "firmware/main.c",
    ):
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("not executed", encoding="utf-8")
    result = inspect_repository(tmp_path)
    assert result == inspect_repository(tmp_path)
    assert {item["type"] for item in result["classifications"]} >= {
        "web-frontend",
        "embedded",
        "terraform/iac",
    }
    assert result["components"] == ["firmware"]
    assert result["languages"] == ["C", "JavaScript"]
    assert result["complete"]
    assert all(item["confidence"] is None for item in result["classifications"])


def test_inspect_cli_emits_json(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    import json

    (tmp_path / "Dockerfile").write_text("FROM scratch", encoding="utf-8")
    assert main(["inspect", str(tmp_path)]) == 0
    output = json.loads(capsys.readouterr().out)
    assert output["classifications"][0]["type"] == "container"


def test_invalid_target_is_rejected(tmp_path: Path) -> None:
    with pytest.raises(ValueError):
        inspect_repository(tmp_path / "missing")


def test_depth_limit_is_visible(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from vigil_fuse import repo_dna

    monkeypatch.setattr(repo_dna, "MAX_DEPTH", 0)
    (tmp_path / "child").mkdir()
    result = inspect_repository(tmp_path)
    assert not result["complete"]
    assert "directory depth limit reached" in result["limitations"]


def test_dependency_metadata_distinguishes_frontend_and_backend(tmp_path: Path) -> None:
    (tmp_path / "package.json").write_text(
        '{"dependencies":{"next":"1", "express":"1"}}', encoding="utf-8"
    )
    result = inspect_repository(tmp_path)
    assert result["frameworks"] == ["Express", "Next.js"]
    assert {c["type"] for c in result["classifications"]} >= {"web-backend", "web-frontend"}


def test_malformed_manifest_reports_incomplete(tmp_path: Path) -> None:
    (tmp_path / "package.json").write_text("{", encoding="utf-8")
    result = inspect_repository(tmp_path)
    assert not result["complete"]
    assert "package manifest could not be parsed" in result["limitations"]


def test_component_graph_contains_components_deterministically(tmp_path: Path) -> None:
    (tmp_path / "app").mkdir()
    (tmp_path / "app" / "package.json").write_text("{}", encoding="utf-8")
    dna = inspect_repository(tmp_path)
    graph = build_component_graph(dna)
    assert graph == build_component_graph(dna)
    assert graph["edges"] == [
        {"source": "repository", "relation": "contains", "target": "component:app"}
    ]
    assert graph["complete"]


def test_esp_idf_framework_hints_reuse_existing_detection(tmp_path: Path) -> None:
    (tmp_path / "CMakeLists.txt").write_text(
        "include($ENV{IDF_PATH}/tools/cmake/project.cmake)", encoding="utf-8"
    )
    result = inspect_repository(tmp_path)
    assert "esp-idf" in result["frameworks"]
    assert any(item["type"] == "embedded" for item in result["classifications"])
