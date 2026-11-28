from vigil_fuse.model import SourceFile
from vigil_fuse.rules.software_container import RULE as CONTAINER
from vigil_fuse.rules.software_dynamic_eval import RULE as DYNAMIC_EVAL
from vigil_fuse.rules.software_yaml import RULE as YAML
from vigil_fuse.scanner import scan


def test_named_dockerfile_is_selected_and_scanned(tmp_path):
    (tmp_path / "Dockerfile.dev").write_text("FROM app:latest\n", encoding="utf-8")
    result = scan(tmp_path)
    assert any(finding.rule_id == "FUSE-SW002" for finding in result.findings)


def test_container_boundaries() -> None:
    for content, expected in [
        ("FROM app:latest\n", 1),
        ("# FROM app:latest\n", 0),
        ("FROM app:latest@sha256:abc\n", 0),
        ("FROM app:Latest\n", 0),
        ("FROM ${IMAGE}:latest\n", 0),
    ]:
        assert len(list(CONTAINER.scan(SourceFile("Dockerfile", content)))) == expected
    assert not list(CONTAINER.scan(SourceFile("notes.txt", "FROM app:latest")))


def test_yaml_boundaries() -> None:
    for content, expected in [
        ("import yaml as y\ny.unsafe_load(data)", 1),
        ("import yaml\nyaml.safe_load(data)", 0),
        ("# yaml.unsafe_load(data)", 0),
        ("import yaml\ndef f(yaml):\n yaml.unsafe_load(data)", 0),
    ]:
        assert len(list(YAML.scan(SourceFile("app.py", content)))) == expected


def test_dynamic_eval_boundaries() -> None:
    for content, expected in [
        ("import builtins as b\nb.eval(data)", 1),
        ("from builtins import exec as run_code\nrun_code(data)", 1),
        ("import builtins as b\ndef f(b):\n b.exec(data)", 0),
        ("def eval(value):\n return value\neval(data)", 0),
        ("import ast\nast.literal_eval(data)", 0),
        ("# builtins.exec(data)", 0),
    ]:
        assert len(list(DYNAMIC_EVAL.scan(SourceFile("app.py", content)))) == expected
