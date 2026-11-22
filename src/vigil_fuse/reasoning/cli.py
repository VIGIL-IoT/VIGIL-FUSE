"""Small CLI hooks kept separate from the main parser for parallel CLI consolidation."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from ..text_safety import safe_terminal_text
from .config import ReasoningConfig
from .context import build_context, load_report, read_report
from .engine import reason_report, render, write_artifact
from .ollama import Ollama


def add_commands(commands: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    for name, help_text in (
        ("reason", "explain completed FUSE findings using an optional local model"),
        ("reasoning-context", "inspect bounded evidence packets without a model"),
    ):
        parser = commands.add_parser(name, help=help_text)
        parser.add_argument("report", type=Path, help="canonical FUSE findings.json")
        parser.add_argument(
            "--finding",
            required=name == "reasoning-context",
            help=(
                "exact finding instance ID or a unique rule ID"
                if name == "reasoning-context"
                else "exact finding instance ID or rule ID"
            ),
        )
        parser.add_argument("--config", type=Path, help="load reasoning settings from TOML")
        if name == "reason":
            parser.add_argument("--output", type=Path, help="separate reasoning JSON artifact")
        else:
            parser.add_argument("--output", type=Path, help="write the selected context packet")
            parser.add_argument("--pretty", action="store_true", help="indent the output JSON")


def run_command(args: argparse.Namespace, config: ReasoningConfig) -> int:
    args.report = args.report.expanduser()
    raw = read_report(args.report)
    if args.command == "reasoning-context":
        report = load_report(raw)
        findings = report["findings"]
        selected = [item for item in findings if item["id"] == args.finding]
        if not selected:
            selected = [item for item in findings if item["rule_id"] == args.finding]
        if not selected:
            raise ValueError("Selected finding instance ID does not exist in the report")
        if len(selected) > 1:
            raise ValueError("Rule ID matches multiple findings; select one exact finding instance ID")
        packet = build_context(report, selected[0], config.context_tokens)
        rendered = json.dumps(
            packet,
            sort_keys=True,
            ensure_ascii=False,
            allow_nan=False,
            indent=2 if args.pretty else None,
            separators=None if args.pretty else (",", ":"),
        )
        if args.output is None:
            print(rendered)
        else:
            output = args.output.expanduser()
            if output.is_symlink():
                raise ValueError("Refusing to write context through a symbolic link")
            if output.resolve() == args.report.expanduser().resolve():
                raise ValueError("Context output must not replace its input report")
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_text(rendered + "\n", encoding="utf-8")
            print(safe_terminal_text(f"Reasoning context written to {output}"), file=sys.stderr)
        return 0
    artifact = reason_report(raw, config, args.finding)
    path = args.output or args.report.with_suffix(".reasoning.json")
    write_artifact(path, artifact, args.report)
    print(render(artifact), end="")
    print(safe_terminal_text(f"Reasoning written to {path}"), file=sys.stderr)
    return 2 if any(item["reasoning_status"] == "failed" for item in artifact["findings"]) else 0


def doctor_status(config: ReasoningConfig) -> dict[str, bool]:
    return Ollama(config).inspect()


def doctor_text(config: ReasoningConfig, status: dict[str, bool] | None = None) -> str:
    status = status or doctor_status(config)
    return (
        "Optional local reasoning\n"
        f"  Ollama endpoint: {'available' if status['available'] else 'unavailable'}\n"
        f"  Configured model: {config.model}\n"
        f"  Model installed: {'yes' if status['installed'] else 'no'}\n"
        "  Impact: optional reasoning only; deterministic scans unaffected\n"
    )


def enrich_scan(
    canonical: str,
    config: ReasoningConfig,
    report_path: Path | None,
    artifact_path: Path,
    *,
    show: bool,
) -> None:
    # All deterministic reports have already been written. Enrichment cannot change scan status.
    try:
        raw = read_report(report_path) if report_path is not None else canonical.encode("utf-8")
        artifact = reason_report(raw, config)
        artifact["source_hash_basis"] = "report-bytes" if report_path else "canonical-json-utf8"
        write_artifact(artifact_path, artifact, report_path)
        if show:
            print(render(artifact), end="")
        print(safe_terminal_text(f"Reasoning written to {artifact_path}"), file=sys.stderr)
    except (OSError, ValueError) as error:
        print(
            safe_terminal_text(f"Reasoning unavailable: {error}; deterministic scan unaffected"),
            file=sys.stderr,
        )
