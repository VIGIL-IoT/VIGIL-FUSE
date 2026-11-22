"""Manually evaluate one installed local model; never downloads or starts anything."""

from __future__ import annotations

import argparse
import json
from dataclasses import replace
from pathlib import Path
from time import perf_counter
from typing import Any

from vigil_fuse.config import load_config
from vigil_fuse.reasoning.config import ReasoningConfig
from vigil_fuse.reasoning.context import (
    build_context,
    encode_context,
    load_report,
    read_report,
    select_findings,
)
from vigil_fuse.reasoning.ollama import Ollama
from vigil_fuse.reasoning.validation import strict_json, validate_response

FIXTURES = Path(__file__).resolve().parents[1] / "tests" / "fixtures" / "reasoning"


def evaluate_response(
    raw: bytes,
    context: dict[str, Any],
    metadata: dict[str, Any],
) -> dict[str, Any]:
    result: dict[str, Any] = {
        "json_valid": False,
        "grounding_pass": False,
        "unknown_preservation": False,
        "expected_evidence_ids": False,
        "forbidden_claims_absent": False,
        "response_bytes": len(raw),
    }
    try:
        value = strict_json(raw)
        result["json_valid"] = True
        output = validate_response(raw, context)
        result["grounding_pass"] = True
        prose = " ".join(
            [
                output["summary"],
                output["reasoning"],
                *output["limitations"],
                *(item["item"] for item in output["missing_evidence"]),
            ]
        ).casefold()
        result["unknown_preservation"] = all(
            phrase.casefold() in prose for phrase in metadata["must_preserve_unknown"]
        )
        result["expected_evidence_ids"] = set(metadata["expected_evidence_ids"]) <= set(
            value["evidence_ids"]
        )
        result["forbidden_claims_absent"] = not any(
            phrase.casefold() in prose for phrase in metadata["forbidden_claims"]
        )
        result["validated_output"] = output
    except ValueError as error:
        result["error"] = str(error)
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--model", default=None, help="one installed model; default qwen3.5:4b")
    parser.add_argument("--config", type=Path, help="FUSE TOML reasoning settings")
    parser.add_argument("--fixtures", type=Path, default=FIXTURES, help="directory of *.case.json")
    args = parser.parse_args(argv)
    config = load_config(args.config).reasoning if args.config else ReasoningConfig()
    if args.model is not None:
        config = replace(config, model=args.model)
    provider = Ollama(config)
    inspection = provider.inspect()
    if not inspection["available"] or not inspection["installed"]:
        print(
            json.dumps(
                {
                    "provider": "ollama",
                    "model": config.model,
                    **inspection,
                    "error": "Local reasoning unavailable. Install/start prerequisites manually; no model was downloaded.",
                }
            )
        )
        return 2
    results: list[dict[str, Any]] = []
    cases = sorted(args.fixtures.glob("*.case.json"))
    if not cases:
        parser.error("No *.case.json fixtures found")
    for path in cases:
        metadata = strict_json(read_report(path))
        report_path = (path.parent / metadata["report"]).resolve()
        if not report_path.is_relative_to(path.parent.resolve()):
            raise ValueError("Fixture report must remain inside the fixture directory")
        report = load_report(read_report(report_path))
        finding = select_findings(report, metadata["finding"])[0]
        context = build_context(report, finding, config.context_tokens)
        started = perf_counter()
        try:
            response = provider.generate(context)
            result = evaluate_response(response, context, metadata)
        except ValueError as error:
            result = {
                "error": str(error),
                "json_valid": False,
                "grounding_pass": False,
                "unknown_preservation": False,
                "response_bytes": 0,
            }
        result.update(
            {
                "case": path.name,
                "latency_seconds": round(perf_counter() - started, 4),
                "context_bytes": len(encode_context(context)),
                "context_token_upper_bound": len(encode_context(context)),
                "context_truncated": context["context_truncated"],
            }
        )
        results.append(result)
    print(json.dumps({"provider": "ollama", "model": config.model, "results": results}, indent=2))
    return (
        0
        if all(
            all(
                item.get(key) is True
                for key in (
                    "json_valid",
                    "grounding_pass",
                    "unknown_preservation",
                    "expected_evidence_ids",
                    "forbidden_claims_absent",
                )
            )
            for item in results
        )
        else 2
    )


if __name__ == "__main__":
    raise SystemExit(main())
