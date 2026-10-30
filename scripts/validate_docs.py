"""Validate local Markdown links and fenced Mermaid blocks without extra dependencies."""

from __future__ import annotations

import re
import os
import subprocess
import sys
from pathlib import Path
from urllib.parse import unquote, urlsplit


LINK_PATTERN = re.compile(r"!?\[[^\]]*\]\(([^)]*)\)")
REFERENCE_PATTERN = re.compile(r"^\s*\[[^\]]+\]:\s*(.+?)\s*$")
MERMAID_DIAGRAMS = {
    "classDiagram",
    "erDiagram",
    "flowchart",
    "gantt",
    "graph",
    "journey",
    "mindmap",
    "pie",
    "sequenceDiagram",
    "stateDiagram",
    "stateDiagram-v2",
    "timeline",
}


def markdown_files(root: Path) -> list[Path]:
    try:
        result = subprocess.run(
            ["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"],
            cwd=root,
            check=True,
            capture_output=True,
        )
    except (OSError, subprocess.CalledProcessError):
        candidates = root.rglob("*.md")
    else:
        candidates = (
            root / Path(os.fsdecode(entry))
            for entry in result.stdout.split(b"\0")
            if entry and Path(os.fsdecode(entry)).suffix.lower() == ".md"
        )

    excluded_directories = {".git", "build", "dist", ".venv"}
    return sorted(
        path
        for path in candidates
        if path.is_file()
        and not any(part in excluded_directories for part in path.relative_to(root).parts)
    )


def link_target(markdown: str) -> str | None:
    target = markdown.strip()
    if not target:
        return None
    if target.startswith("<"):
        close = target.find(">")
        if close < 0:
            return None
        target = target[1:close]
    else:
        target = target.split(maxsplit=1)[0]
    return target.replace("\\(", "(").replace("\\)", ")")


def validate_markdown(path: Path, root: Path) -> list[str]:
    errors: list[str] = []
    content = path.read_text(encoding="utf-8")
    relative_file = path.relative_to(root)

    source_lines = content.splitlines()
    visible_lines: list[tuple[int, str]] = []
    fence_character: str | None = None
    fence_length = 0
    for line_number, line in enumerate(source_lines, start=1):
        fence = re.match(r"\s*(`{3,}|~{3,})", line)
        if fence:
            marker = fence.group(1)
            if fence_character is None:
                fence_character = marker[0]
                fence_length = len(marker)
            elif marker[0] == fence_character and len(marker) >= fence_length:
                fence_character = None
                fence_length = 0
            continue
        if fence_character is None:
            visible_lines.append((line_number, line))

    for line_number, line in visible_lines:
        targets = [match.group(1) for match in LINK_PATTERN.finditer(line)]
        reference = REFERENCE_PATTERN.match(line)
        if reference:
            targets.append(reference.group(1))
        for raw_target in targets:
            target = link_target(raw_target)
            if target is None:
                errors.append(f"{relative_file}:{line_number}: malformed Markdown link")
                continue
            parsed = urlsplit(target)
            if parsed.scheme or target.startswith("//"):
                continue
            local_path = unquote(parsed.path)
            candidate = (path.parent / local_path).resolve() if local_path else path.resolve()
            if not candidate.exists():
                errors.append(
                    f"{relative_file}:{line_number}: missing local link target {local_path!r}"
                )

    fence_character = None
    fence_length = 0
    in_mermaid = False
    mermaid_content: list[str] = []
    for line_number, line in enumerate(source_lines, start=1):
        stripped = line.lstrip()
        fence = re.match(r"(`{3,}|~{3,})(.*)$", stripped)
        if fence:
            marker, info = fence.groups()
            if fence_character is None:
                fence_character = marker[0]
                fence_length = len(marker)
                in_mermaid = info.strip().lower() == "mermaid"
                mermaid_content = []
            elif marker[0] == fence_character and len(marker) >= fence_length:
                if in_mermaid:
                    if not mermaid_content:
                        errors.append(f"{relative_file}:{line_number}: empty Mermaid block")
                    else:
                        first_token = mermaid_content[0].split(maxsplit=1)[0]
                        if first_token not in MERMAID_DIAGRAMS:
                            errors.append(
                                f"{relative_file}:{line_number}: unrecognized Mermaid diagram type "
                                f"{first_token!r}"
                            )
                fence_character = None
                fence_length = 0
                in_mermaid = False
                mermaid_content = []
            continue
        if fence_character is not None and in_mermaid and line.strip():
            mermaid_content.append(line.strip())

    if fence_character is not None:
        errors.append(f"{relative_file}: unclosed Markdown code fence")
    return errors


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    files = markdown_files(root)
    errors = [error for path in files for error in validate_markdown(path, root)]
    if errors:
        print("Documentation validation failed:")
        print("\n".join(errors))
        return 1
    print(f"Documentation validation passed for {len(files)} Markdown files.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
