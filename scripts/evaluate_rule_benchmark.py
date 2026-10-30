#!/usr/bin/env python3
"""Evaluate the labeled synthetic fixture set against all native FUSE rules."""

from __future__ import annotations

import argparse
import hashlib
import json
import platform
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
DATASET_PATH = ROOT / "tests" / "fixtures" / "rules" / "benchmark.json"
FIXTURE_ROOT = DATASET_PATH.parent


def _ratio(numerator: int, denominator: int) -> float | None:
    if denominator == 0:
        return None
    return numerator / denominator


def evaluate() -> dict[str, Any]:
    from vigil_fuse import __version__
    from vigil_fuse.model import SourceFile
    from vigil_fuse.rules.registry import RULES

    dataset_bytes = DATASET_PATH.read_bytes()
    dataset = json.loads(dataset_bytes)
    if not isinstance(dataset, dict) or not isinstance(dataset.get("cases"), list):
        raise ValueError("benchmark manifest must contain a cases list")
    rule_by_id = {rule.id: rule for rule in RULES}
    labels: dict[str, set[str]] = {}
    observations: dict[str, set[str]] = {}
    fixture_hash = hashlib.sha256()
    details: list[dict[str, Any]] = []

    for case in dataset["cases"]:
        if not isinstance(case, dict):
            raise ValueError("benchmark cases must be JSON objects")
        case_id = case["id"]
        if not isinstance(case_id, str) or not case_id:
            raise ValueError("benchmark case id must be a non-empty string")
        if not isinstance(case.get("fixture"), str) or not isinstance(case.get("source_path"), str):
            raise ValueError(f"{case_id} must define fixture and source_path strings")
        expected_rules = case.get("expected_rules")
        if not isinstance(expected_rules, list) or not all(
            isinstance(rule_id, str) for rule_id in expected_rules
        ):
            raise ValueError(f"{case_id} expected_rules must be a list of rule IDs")
        expected = set(expected_rules)
        if not isinstance(case.get("rationale"), str) or not case["rationale"].strip():
            raise ValueError(f"{case_id} is missing its label rationale")
        if case.get("split") not in {"development", "regression", "holdout"}:
            raise ValueError(f"{case_id} has an invalid benchmark split")
        if case.get("category") not in {
            "synthetic-vulnerable",
            "synthetic-secure",
            "known-vulnerable-embedded",
            "real-open-source",
            "negative-control",
        }:
            raise ValueError(f"{case_id} has an invalid benchmark category")
        disposition = case.get("expected_disposition")
        expected_disposition = "finding" if expected else "no-finding"
        if disposition != expected_disposition:
            raise ValueError(f"{case_id} disposition does not agree with expected_rules")
        pinned_commit = case.get("pinned_commit")
        if pinned_commit is not None and (
            not isinstance(pinned_commit, str)
            or len(pinned_commit) != 40
            or any(character not in "0123456789abcdefABCDEF" for character in pinned_commit)
        ):
            raise ValueError(f"{case_id} pinned_commit must be a full 40-character Git SHA")
        if case_id in labels:
            raise ValueError(f"duplicate benchmark case id: {case_id}")
        unknown = expected - rule_by_id.keys()
        if unknown:
            raise ValueError(f"{case_id} refers to unknown rules: {sorted(unknown)}")

        fixture_path = (FIXTURE_ROOT / case["fixture"]).resolve()
        if fixture_path.parent != FIXTURE_ROOT.resolve():
            raise ValueError(
                f"fixture must be directly under the rule fixture directory: {case['fixture']}"
            )
        content = fixture_path.read_bytes()
        fixture_hash.update(case_id.encode("utf-8") + b"\0" + content + b"\0")
        source = SourceFile(path=case["source_path"], text=content.decode("utf-8"))
        observed: set[str] = set()
        findings_by_rule: dict[str, int] = {}
        for rule in RULES:
            if not rule.may_scan(source):
                continue
            findings = list(rule.scan(source))
            if findings:
                observed.add(rule.id)
                findings_by_rule[rule.id] = len(findings)

        labels[case_id] = expected
        observations[case_id] = observed
        details.append(
            {
                "case_id": case_id,
                "fixture": case["fixture"],
                "source_path": case["source_path"],
                "pinned_commit": pinned_commit,
                "category": case["category"],
                "split": case["split"],
                "expected_disposition": disposition,
                "rationale": case["rationale"],
                "expected_rules": sorted(expected),
                "observed_rules": sorted(observed),
                "findings_by_rule": findings_by_rule,
            }
        )

    expected_rule_ids = set(rule_by_id)
    covered_rule_ids = {rule_id for expected in labels.values() for rule_id in expected}
    if covered_rule_ids != expected_rule_ids:
        missing = expected_rule_ids - covered_rule_ids
        raise ValueError(f"benchmark has no positive case for rules: {sorted(missing)}")

    metrics: list[dict[str, Any]] = []
    errors: list[str] = []
    for rule_id in sorted(rule_by_id):
        tp = fp = fn = tn = 0
        for case_id, expected in labels.items():
            predicted_positive = rule_id in observations[case_id]
            actually_positive = rule_id in expected
            if predicted_positive and actually_positive:
                tp += 1
            elif predicted_positive:
                fp += 1
                errors.append(f"false positive: {case_id} -> {rule_id}")
            elif actually_positive:
                fn += 1
                errors.append(f"false negative: {case_id} -> {rule_id}")
            else:
                tn += 1

        precision = _ratio(tp, tp + fp)
        recall = _ratio(tp, tp + fn)
        f1 = (
            2 * precision * recall / (precision + recall)
            if precision is not None and recall is not None and precision + recall
            else None
        )
        metrics.append(
            {
                "rule_id": rule_id,
                "cases": len(labels),
                "positive_cases": tp + fn,
                "tp": tp,
                "fp": fp,
                "fn": fn,
                "tn": tn,
                "precision": precision,
                "recall": recall,
                "f1": f1,
                "specificity": _ratio(tn, tn + fp),
            }
        )

    return {
        "schema_version": "1.0",
        "tool": {"name": "FUSE", "version": __version__},
        "python_version": platform.python_version(),
        "rules": [
            {"rule_id": rule.id, "rule_version": rule.version}
            for rule in sorted(RULES, key=lambda item: item.id)
        ],
        "dataset_id": dataset["dataset_id"],
        "dataset_sha256": hashlib.sha256(dataset_bytes).hexdigest(),
        "fixture_content_sha256": fixture_hash.hexdigest(),
        "evaluation_unit": "case-rule pair; a rule is positive for a case when it emits one or more findings",
        "interpretation": dataset["description"],
        "rule_count": len(rule_by_id),
        "case_count": len(labels),
        "metrics": metrics,
        "cases": details,
        "errors": errors,
    }


def _format_percent(value: float | None) -> str:
    return "n/a" if value is None else f"{value * 100:.1f}%"


def render_text(result: dict[str, Any]) -> str:
    lines = [
        f"Fixture benchmark: {result['dataset_id']}",
        f"{result['case_count']} cases, {result['rule_count']} native rules",
        "Synthetic fixtures only. These metrics do not measure real-world accuracy.",
        "",
        "| Rule | TP | FP | FN | TN | Precision | Recall | F1 |",
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    for metric in result["metrics"]:
        lines.append(
            f"| {metric['rule_id']} | {metric['tp']} | {metric['fp']} | {metric['fn']} | {metric['tn']} | "
            f"{_format_percent(metric['precision'])} | {_format_percent(metric['recall'])} | "
            f"{_format_percent(metric['f1'])} |"
        )
    if result["errors"]:
        lines.extend(["", "Mismatches:", *[f"- {error}" for error in result["errors"]]])
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--json", action="store_true", help="print the full machine-readable report"
    )
    parser.add_argument("--output", type=Path, help="write the full JSON report to this path")
    parser.add_argument(
        "--check", action="store_true", help="return nonzero if any fixture label mismatches"
    )
    args = parser.parse_args()

    try:
        result = evaluate()
    except (OSError, UnicodeError, ValueError, KeyError, TypeError, json.JSONDecodeError) as error:
        print(f"benchmark failed: {error}", file=sys.stderr)
        return 2

    rendered_json = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.output:
        output_path = args.output if args.output.is_absolute() else ROOT / args.output
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(rendered_json, encoding="utf-8")
    print(rendered_json if args.json else render_text(result))
    return 1 if args.check and result["errors"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
