from __future__ import annotations

import subprocess
from pathlib import Path
from unittest.mock import patch

import pytest

from scripts.render_mermaid_docs import (
    MermaidBlock,
    extract_mermaid_blocks,
    render_blocks,
    validate_svg,
)


def test_extract_mermaid_blocks_tracks_lines_and_fence_styles(tmp_path: Path) -> None:
    source = tmp_path / "diagrams.md"
    source.write_text(
        """```mermaid
flowchart LR
  A --> B
```

~~~mermaid
sequenceDiagram
  A->>B: hello
~~~
""",
        encoding="utf-8",
    )

    blocks = extract_mermaid_blocks(source)

    assert [(block.line, block.content) for block in blocks] == [
        (2, "flowchart LR\n  A --> B\n"),
        (7, "sequenceDiagram\n  A->>B: hello\n"),
    ]


def test_validate_svg_requires_well_formed_svg_root(tmp_path: Path) -> None:
    svg = tmp_path / "diagram.svg"
    svg.write_text('<svg xmlns="http://www.w3.org/2000/svg"/>', encoding="utf-8")

    validate_svg(svg)

    svg.write_text("<html/>", encoding="utf-8")
    with pytest.raises(ValueError, match="not svg"):
        validate_svg(svg)


def test_render_blocks_runs_pinned_renderer_and_checks_output(tmp_path: Path) -> None:
    block = MermaidBlock(tmp_path / "architecture.md", 12, "flowchart LR\n  A --> B\n")

    def fake_docker(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        mount = next(item for item in command if item.startswith("type=bind,source="))
        source = mount.removeprefix("type=bind,source=").removesuffix(",target=/data")
        output_argument = command[command.index("--output") + 1]
        output_path = Path(source) / Path(output_argument).name
        output_path.write_text(
            '<svg xmlns="http://www.w3.org/2000/svg"><g/></svg>', encoding="utf-8"
        )
        return subprocess.CompletedProcess(command, 0, "", "")

    with patch("scripts.render_mermaid_docs.subprocess.run", side_effect=fake_docker) as run:
        count = render_blocks([block], root=tmp_path, image="test-image")

    assert count == 1
    command = run.call_args.args[0]
    assert "--pull=missing" in command
    assert "test-image" in command


def test_render_blocks_reports_renderer_failure(tmp_path: Path) -> None:
    block = MermaidBlock(tmp_path / "architecture.md", 12, "flowchart LR\n  A --> B\n")
    failure = subprocess.CompletedProcess(["docker"], 1, "", "Parse error")

    with patch("scripts.render_mermaid_docs.subprocess.run", return_value=failure):
        with pytest.raises(
            RuntimeError, match=r"architecture\.md:12: Mermaid render failed: Parse error"
        ):
            render_blocks([block], root=tmp_path, image="test-image")
