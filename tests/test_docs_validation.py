from __future__ import annotations

import subprocess
from pathlib import Path

from scripts.validate_docs import markdown_files, validate_markdown


def test_markdown_files_include_tracked_and_nonignored_untracked_files(
    tmp_path: Path,
) -> None:
    subprocess.run(["git", "init", "--quiet"], cwd=tmp_path, check=True)
    (tmp_path / ".gitignore").write_text("ignored.md\nignored_dir/\n", encoding="utf-8")
    tracked = tmp_path / "README.md"
    untracked = tmp_path / "draft.md"
    ignored = tmp_path / "ignored.md"
    ignored_nested = tmp_path / "ignored_dir" / "notes.md"
    tracked.write_text("# Tracked\n", encoding="utf-8")
    untracked.write_text("# Untracked\n", encoding="utf-8")
    ignored.write_text("# Ignored\n", encoding="utf-8")
    ignored_nested.parent.mkdir()
    ignored_nested.write_text("# Ignored nested\n", encoding="utf-8")
    subprocess.run(["git", "add", ".gitignore", "README.md"], cwd=tmp_path, check=True)

    assert markdown_files(tmp_path) == sorted([tracked, untracked])


def test_docs_validator_accepts_existing_link_and_mermaid(tmp_path: Path) -> None:
    target = tmp_path / "target.md"
    source = tmp_path / "source.md"
    target.write_text("# Target\n", encoding="utf-8")
    source.write_text(
        "[Target](target.md)\n\n```mermaid\nflowchart LR\n  A --> B\n```\n",
        encoding="utf-8",
    )

    assert validate_markdown(source, tmp_path) == []


def test_docs_validator_reports_missing_local_target(tmp_path: Path) -> None:
    source = tmp_path / "source.md"
    source.write_text("[Missing](missing.md)\n", encoding="utf-8")

    errors = validate_markdown(source, tmp_path)

    assert len(errors) == 1
    assert "missing local link target" in errors[0]


def test_docs_validator_rejects_empty_or_unclosed_mermaid_blocks(tmp_path: Path) -> None:
    source = tmp_path / "source.md"
    source.write_text("```mermaid\n```\n\n```mermaid\nflowchart LR\n", encoding="utf-8")

    errors = validate_markdown(source, tmp_path)

    assert any("empty Mermaid block" in error for error in errors)
    assert any("unclosed Markdown code fence" in error for error in errors)
