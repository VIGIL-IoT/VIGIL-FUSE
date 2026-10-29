from __future__ import annotations

from pathlib import Path

from scripts.validate_docs import validate_markdown


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
