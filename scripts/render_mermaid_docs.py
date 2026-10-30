"""Render Markdown Mermaid blocks in a pinned container for CI validation."""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import Path

try:
    from scripts.validate_docs import markdown_files
except ModuleNotFoundError:  # Direct script execution places scripts/ on sys.path.
    from validate_docs import markdown_files


MERMAID_RENDERER_IMAGE = (
    "ghcr.io/mermaid-js/mermaid-cli/mermaid-cli"
    "@sha256:2c5d27365df71da06c288beebe531ea3637cf9b422b871239a3b016233591d24"
)
FENCE_PATTERN = re.compile(r"^\s*(`{3,}|~{3,})(.*)$")


@dataclass(frozen=True)
class MermaidBlock:
    source: Path
    line: int
    content: str


def extract_mermaid_blocks(path: Path) -> list[MermaidBlock]:
    """Return Mermaid fenced blocks and their source line numbers."""
    lines = path.read_text(encoding="utf-8").splitlines()
    blocks: list[MermaidBlock] = []
    fence_character: str | None = None
    fence_length = 0
    is_mermaid = False
    start_line = 0
    content: list[str] = []

    for line_number, line in enumerate(lines, start=1):
        match = FENCE_PATTERN.match(line)
        if match:
            marker, info = match.groups()
            if fence_character is None:
                fence_character = marker[0]
                fence_length = len(marker)
                is_mermaid = info.strip().lower() == "mermaid"
                start_line = line_number + 1
                content = []
            elif marker[0] == fence_character and len(marker) >= fence_length:
                if is_mermaid:
                    blocks.append(
                        MermaidBlock(
                            source=path,
                            line=start_line,
                            content="\n".join(content).rstrip() + "\n",
                        )
                    )
                fence_character = None
                fence_length = 0
                is_mermaid = False
                content = []
            continue

        if fence_character is not None and is_mermaid:
            content.append(line)

    return blocks


def validate_svg(path: Path) -> None:
    """Reject renderer outputs that are missing or are not valid SVG XML."""
    if not path.is_file() or path.stat().st_size == 0:
        raise ValueError(f"renderer did not produce {path.name}")
    try:
        root = ET.parse(path).getroot()
    except ET.ParseError as error:
        raise ValueError(f"renderer produced invalid SVG XML in {path.name}: {error}") from error
    if root.tag.rsplit("}", maxsplit=1)[-1] != "svg":
        raise ValueError(f"renderer output {path.name} has root element {root.tag!r}, not svg")


def render_blocks(
    blocks: list[MermaidBlock],
    *,
    root: Path,
    docker_executable: str = "docker",
    image: str = MERMAID_RENDERER_IMAGE,
    timeout_seconds: int = 120,
) -> int:
    """Render each block in an isolated temporary directory and validate SVG output."""
    if not blocks:
        print("No Markdown Mermaid blocks found to render.")
        return 0

    rendered = 0
    with tempfile.TemporaryDirectory(prefix="fuse-mermaid-") as temporary:
        temp_dir = Path(temporary).resolve()
        mount_source = temp_dir.as_posix()
        for index, block in enumerate(blocks, start=1):
            stem = f"diagram-{index:03d}"
            source_path = temp_dir / f"{stem}.mmd"
            output_path = temp_dir / f"{stem}.svg"
            source_path.write_text(block.content, encoding="utf-8", newline="\n")

            command = [
                docker_executable,
                "run",
                "--rm",
                "--pull=missing",
                "--mount",
                f"type=bind,source={mount_source},target=/data",
                "--workdir",
                "/data",
                image,
                "--input",
                f"/data/{stem}.mmd",
                "--output",
                f"/data/{stem}.svg",
            ]
            try:
                result = subprocess.run(
                    command,
                    cwd=root,
                    capture_output=True,
                    text=True,
                    check=False,
                    timeout=timeout_seconds,
                )
            except (OSError, subprocess.TimeoutExpired) as error:
                raise RuntimeError(
                    f"{block.source}:{block.line}: Mermaid renderer could not run: {error}"
                ) from error
            if result.returncode != 0:
                detail = result.stderr.strip() or result.stdout.strip() or "no renderer output"
                raise RuntimeError(f"{block.source}:{block.line}: Mermaid render failed: {detail}")
            try:
                validate_svg(output_path)
            except ValueError as error:
                raise RuntimeError(f"{block.source}:{block.line}: {error}") from error
            print(f"Rendered {block.source.relative_to(root)}:{block.line}")
            rendered += 1

    return rendered


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--docker", default="docker", help="Docker executable to use")
    parser.add_argument(
        "--timeout-seconds",
        type=int,
        default=120,
        help="Maximum time for each diagram render",
    )
    args = parser.parse_args()
    if args.timeout_seconds < 1:
        parser.error("--timeout-seconds must be at least 1")

    root = Path(__file__).resolve().parents[1]
    blocks = [block for path in markdown_files(root) for block in extract_mermaid_blocks(path)]
    try:
        count = render_blocks(
            blocks,
            root=root,
            docker_executable=args.docker,
            timeout_seconds=args.timeout_seconds,
        )
    except RuntimeError as error:
        print(error, file=sys.stderr)
        return 1
    print(f"Validated {count} Mermaid diagrams with the pinned renderer image.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
