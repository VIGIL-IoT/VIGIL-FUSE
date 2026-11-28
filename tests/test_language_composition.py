from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from scripts.generate_language_composition import (
    aggregate_inventory,
    fallback_color,
    format_percentage,
    render_svg,
    write_outputs,
)


def _inventory() -> dict[str, object]:
    return {
        "commit": "0123456789abcdef0123456789abcdef01234567",
        "generated_at": "2026-11-23T10:00:00Z",
        "files": [
            {
                "path": "src/main.py",
                "bytes": 900_000,
                "language": "Python",
                "color": "#3572A5",
                "text": True,
            },
            {
                "path": "src/tiny.rs",
                "bytes": 1,
                "language": "Rust",
                "color": None,
                "text": True,
            },
            {
                "path": "notes & <draft>.unknown",
                "bytes": 9,
                "language": None,
                "text": True,
            },
            {
                "path": "assets/picture.png",
                "bytes": 90,
                "language": None,
                "text": False,
                "mime_type": "image/png",
            },
            {
                "path": "vendor/tool.py",
                "bytes": 20,
                "language": "Python",
                "color": "#3572A5",
                "text": True,
                "generated": True,
                "vendored": True,
            },
        ],
    }


def test_aggregates_all_languages_by_bytes_and_sorts_without_a_bucket() -> None:
    data = aggregate_inventory(_inventory())
    names = {item["name"] for item in data["languages"]}

    assert [item["name"] for item in data["languages"]] == ["Python", "Rust"]
    assert data["languages"][0]["bytes"] == 900_020
    assert data["languages"][0]["files"] == 2
    assert data["total_classified_bytes"] == 900_021
    assert data["total_classified_files"] == 3
    assert sum(item["percentage"] for item in data["languages"]) == pytest.approx(100)
    assert "Other" not in names
    assert all(
        item["name"].casefold()
        not in {"other", "misc", "miscellaneous", "remaining", "everything else"}
        for item in data["languages"]
    )
    assert data["unclassified_files"] == [{"path": "notes & <draft>.unknown", "bytes": 9}]
    assert data["non_language_assets"][0]["path"] == "assets/picture.png"
    assert data["file_inventory"][-1]["generated"] is True


def test_tiny_language_percentage_never_rounds_to_zero() -> None:
    assert format_percentage(1, 1_000_000) == "0.0001%"
    raw = {
        "commit": "0123456789abcdef0123456789abcdef01234567",
        "generated_at": "2026-11-23T10:00:00Z",
        "files": [
            {"path": "main.py", "bytes": 999_999, "language": "Python", "text": True},
            {"path": "tiny.rs", "bytes": 1, "language": "Rust", "text": True},
        ],
    }
    assert 'width="0.000712"' in render_svg(aggregate_inventory(raw))


def test_zero_byte_language_does_not_divide_by_zero() -> None:
    raw = {
        "commit": "0123456789abcdef0123456789abcdef01234567",
        "generated_at": "2026-11-23T10:00:00Z",
        "files": [{"path": "empty.py", "bytes": 0, "language": "Python", "text": True}],
    }
    data = aggregate_inventory(raw)

    assert data["languages"][0]["percentage"] == 0.0
    assert "0.00%" in render_svg(data)


def test_svg_escapes_language_names_and_has_every_language_row() -> None:
    raw = _inventory()
    raw["files"].append(
        {
            "path": "tools/template.py",
            "bytes": 10,
            "language": 'C & <Template> "Tools"',
            "color": None,
            "text": True,
        }
    )
    data = aggregate_inventory(raw)
    svg = render_svg(data)

    assert 'C &amp; &lt;Template&gt; "Tools"' in svg
    assert svg.count("<rect x=") == len(data["languages"]) * 2
    assert "<script" not in svg
    assert "https://" not in svg


def test_outputs_are_deterministic_and_include_special_paths(tmp_path: Path) -> None:
    first_svg, first_json = write_outputs(aggregate_inventory(_inventory()), tmp_path / "first")
    second_svg, second_json = write_outputs(aggregate_inventory(_inventory()), tmp_path / "second")

    assert first_svg.read_bytes() == second_svg.read_bytes()
    assert first_json.read_bytes() == second_json.read_bytes()
    saved = json.loads(first_json.read_text(encoding="utf-8"))
    assert saved["file_inventory"][1]["path"] == "notes & <draft>.unknown"
    assert fallback_color("Unknown Lang") == fallback_color("Unknown Lang")


@pytest.mark.skipif(
    not os.environ.get("FUSE_LINGUIST_IMAGE"), reason="requires pinned Linguist image"
)
def test_linguist_fixture_classifications(tmp_path: Path) -> None:
    repo = tmp_path / "linguist-fixtures"
    repo.mkdir()
    fixtures = {
        "main.py": "print('fixture')\n",
        "sample.c": "int main(void) { return 0; }\n",
        "sample.cpp": "int main() { return 0; }\n",
        "sample.go": "package fixture\n",
        "sample.ps1": "Write-Output 'fixture'\n",
        "sample.psm1": "function Invoke-Fixture { }\n",
        "sample.R": "value <- 1\n",
        "sample.jl": "value = 1\n",
        "Sample.java": "class Sample {}\n",
        "policy.rego": "package fixture\n",
        "rtl.v": "module fixture; endmodule\n",
        "rtl.vh": "`define FIXTURE 1\n",
        "rtl.sv": "module fixture; endmodule\n",
        "rtl.svh": "`define FIXTURE 1\n",
        "README.md": "# Fixture\n",
        "paper.tex": "\\documentclass{article}\n",
        "config.yml": "enabled: true\n",
        "config.json": '{"enabled": true}\n',
        "config.toml": "enabled = true\n",
        "CMakeLists.txt": "project(Fixture)\n",
        "Makefile": "all:\n\ttrue\n",
        "Dockerfile": "FROM scratch\n",
        "run.sh": "#!/bin/sh\ntrue\n",
        "run.bat": "@echo off\r\n",
        "index.html": "<html></html>\n",
        "style.css": "body { color: red; }\n",
        "app.js": "const fixture = true;\n",
        "app.ts": "const fixture: boolean = true;\n",
        "data.xml": "<fixture />\n",
        "settings.ini": "[fixture]\nenabled=true\n",
        "rtl.vhd": "entity fixture is end;\n",
        "sample.rs": "fn main() {}\n",
        "sample.zig": "pub fn main() void {}\n",
        "notes & draft.unknown": "plain text with no known file type\n",
    }
    for relative_path, content in fixtures.items():
        path = repo / relative_path
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
    (repo / "image.png").write_bytes(b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR")
    subprocess.run(["git", "init", "-b", "main"], cwd=repo, check=True, capture_output=True)
    subprocess.run(["git", "config", "user.name", "FUSE fixture"], cwd=repo, check=True)
    subprocess.run(["git", "config", "user.email", "fixture@example.invalid"], cwd=repo, check=True)
    subprocess.run(["git", "add", "--all"], cwd=repo, check=True)
    subprocess.run(["git", "commit", "-m", "add Linguist fixtures"], cwd=repo, check=True)

    output_dir = tmp_path / "output"
    generator = Path(__file__).parents[1] / "scripts" / "generate_language_composition.py"
    subprocess.run(
        [
            sys.executable,
            str(generator),
            "--repo",
            str(repo),
            "--ref",
            "HEAD",
            "--output-dir",
            str(output_dir),
            "--image",
            os.environ["FUSE_LINGUIST_IMAGE"],
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    data = json.loads((output_dir / "language-composition.json").read_text(encoding="utf-8"))
    actual = {item["path"]: item["language"] for item in data["file_inventory"]}
    expected = {
        "main.py": "Python",
        "sample.c": "C",
        "sample.cpp": "C++",
        "sample.go": "Go",
        "sample.ps1": "PowerShell",
        "sample.psm1": "PowerShell",
        "sample.R": "R",
        "sample.jl": "Julia",
        "Sample.java": "Java",
        "policy.rego": "Rego",
        "rtl.v": "Verilog",
        "rtl.vh": "Verilog",
        "rtl.sv": "SystemVerilog",
        "rtl.svh": "SystemVerilog",
        "README.md": "Markdown",
        "paper.tex": "TeX",
        "config.yml": "YAML",
        "config.json": "JSON",
        "config.toml": "TOML",
        "CMakeLists.txt": "CMake",
        "Makefile": "Makefile",
        "Dockerfile": "Dockerfile",
        "run.sh": "Shell",
        "run.bat": "Batchfile",
        "index.html": "HTML",
        "style.css": "CSS",
        "app.js": "JavaScript",
        "app.ts": "TypeScript",
        "data.xml": "XML",
        "settings.ini": "INI",
        "rtl.vhd": "VHDL",
        "sample.rs": "Rust",
        "sample.zig": "Zig",
    }
    assert {path: actual[path] for path in expected} == expected
    assert actual["notes & draft.unknown"] is None
    assert "image.png" in {item["path"] for item in data["non_language_assets"]}
