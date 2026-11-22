from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from time import perf_counter
from typing import Any

from .config import ReasoningConfig
from .context import (
    CONTEXT_SCHEMA,
    build_context,
    encode_context,
    load_report,
    report_hash,
    select_findings,
)
from .ollama import Ollama
from .validation import validate_response


def reason_report(
    raw: bytes,
    config: ReasoningConfig,
    finding_id: str | None = None,
) -> dict[str, Any]:
    report = load_report(raw)
    selected = select_findings(report, finding_id)
    provider = Ollama(config)
    inspection = provider.inspect() if selected else {"available": True, "installed": True}
    results: list[dict[str, Any]] = []
    for finding in selected:
        result: dict[str, Any] = {
            "finding_id": finding["id"],
            "finding_fingerprint": finding["fingerprint"],
            "title": finding["title"],
            "severity": finding["severity"],
            "reasoning_status": "failed",
        }
        started = perf_counter()
        try:
            context = build_context(report, finding, config.context_tokens)
            result["context_sha256"] = report_hash(encode_context(context))
            result["context_bytes"] = len(encode_context(context))
            result["context_truncated"] = context["context_truncated"]
            result["truncated_categories"] = context["truncated_categories"]
            result["evidence_counts"] = {
                key: len(items) for key, items in context["evidence"].items()
            }
            if not inspection["available"]:
                raise ValueError("Ollama endpoint unavailable; deterministic scan unaffected")
            if not inspection["installed"]:
                raise ValueError("Configured local model is not installed; install it manually")
            response = provider.generate(context)
            result["response_bytes"] = len(response)
            result["output"] = validate_response(response, context)
            result["reasoning_status"] = "completed"
        except ValueError as error:
            result["error"] = str(error)
        result["latency_seconds"] = round(perf_counter() - started, 4)
        results.append(result)
    return {
        "schema_version": "reasoning_artifact_v1",
        "source_report_sha256": report_hash(raw),
        "provider": config.provider,
        "model": config.model,
        "context_schema": CONTEXT_SCHEMA,
        "reasoning_schema": "reasoning_output_v1",
        "runtime": {
            "context_tokens": config.context_tokens,
            "temperature": config.temperature,
            "keep_alive": config.keep_alive,
        },
        "findings": results,
    }


def write_artifact(path: Path, artifact: dict[str, Any], source: Path | None = None) -> None:
    if source is not None and (
        path.resolve() == source.resolve()
        or (path.exists() and source.exists() and path.samefile(source))
    ):
        raise ValueError("Reasoning artifact must not overwrite the canonical report")
    if path.is_symlink() or path.parent.is_symlink() or (path.exists() and not path.is_file()):
        raise ValueError("Reasoning output must be a regular file, not a symbolic link")
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=".reasoning-", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as output:
            json.dump(artifact, output, indent=2, ensure_ascii=False, allow_nan=False)
            output.write("\n")
        os.replace(temporary, path)
    finally:
        Path(temporary).unlink(missing_ok=True)


def render(artifact: dict[str, Any]) -> str:
    lines = ["FUSE REASONING", "Optional explanation; deterministic findings remain authoritative."]
    for finding in artifact["findings"]:
        lines.extend(
            ["", f"{finding['finding_id']} | {finding['severity'].upper()}", finding["title"]]
        )
        if finding["reasoning_status"] != "completed":
            lines.append("Reasoning unavailable: " + finding["error"])
            continue
        lines.append(
            "Evidence state: "
            + ", ".join(f"{key} {count}" for key, count in finding["evidence_counts"].items())
        )
        output = finding["output"]
        lines.extend(["Summary", "  " + output["summary"], "Reasoning", "  " + output["reasoning"]])
        for key, label in (
            ("missing_evidence", "Missing evidence"),
            ("recommended_checks", "Recommended checks"),
            ("remediation", "Remediation"),
            ("limitations", "Limitations"),
        ):
            lines.append(label)
            for item in output[key]:
                lines.append("  - " + (item["item"] if isinstance(item, dict) else item))
        lines.append("Unknown evidence: " + ", ".join(output["unknown_evidence_ids"]))
    if not artifact["findings"]:
        lines.append("No findings to explain.")
    from ..text_safety import safe_terminal_text

    return safe_terminal_text("\n".join(lines) + "\n")
