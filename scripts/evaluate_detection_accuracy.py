"""Compute scope-specific detection metrics from labeled, coverage-qualified cases."""

from __future__ import annotations

import argparse
from collections import Counter
import csv
import hashlib
import json
import math
from pathlib import Path
import re

LABELS = {"positive", "negative", "unknown", "uncertain", "not_applicable"}
STATUSES = {"completed", "partial", "unsupported", "failed", "timeout", "not_run"}
SPLITS = {"regression", "benchmark", "controlled-binary", "independent-holdout"}


def wilson(successes: int, trials: int) -> list[float] | None:
    if trials == 0:
        return None
    z = 1.959963984540054
    p = successes / trials
    denominator = 1 + z * z / trials
    center = (p + z * z / (2 * trials)) / denominator
    margin = z * math.sqrt(p * (1 - p) / trials + z * z / (4 * trials * trials)) / denominator
    return [max(0.0, center - margin), min(1.0, center + margin)]


def summarize(counts: Counter) -> dict:
    tp, fp, tn, fn = (counts[k] for k in ("tp", "fp", "tn", "fn"))
    return {
        "tp": tp,
        "fp": fp,
        "tn": tn,
        "fn": fn,
        "support": tp + fp + tn + fn,
        "positive_support": tp + fn,
        "negative_support": tn + fp,
        "precision": tp / (tp + fp) if tp + fp else None,
        "recall": tp / (tp + fn) if tp + fn else None,
        "f1": 2 * tp / (2 * tp + fp + fn) if 2 * tp + fp + fn else None,
        "precision_wilson_95": wilson(tp, tp + fp),
        "recall_wilson_95": wilson(tp, tp + fn),
    }


def validate(dataset: dict, excluded: list[dict] = ()) -> None:
    if dataset.get("schema_version") != "1.0" or dataset.get("split") not in SPLITS:
        raise ValueError("Unsupported dataset schema or split")
    for key in ("dataset_id", "scope", "ground_truth", "fuse_commit"):
        if not isinstance(dataset.get(key), str) or not dataset[key]:
            raise ValueError(f"Missing dataset metadata: {key}")
    if not re.fullmatch(r"[a-f0-9]{40}", dataset["fuse_commit"]):
        raise ValueError("Invalid frozen commit")
    if not isinstance(dataset.get("rules"), list) or not dataset["rules"]:
        raise ValueError("Dataset must declare evaluated rules, including zero-support rules")
    if len(set(dataset["rules"])) != len(dataset["rules"]):
        raise ValueError("Duplicate rule declaration")
    if not isinstance(dataset.get("cases"), list):
        raise ValueError("Missing case list")
    leaked = {case["input_sha256"] for other in excluded for case in other["cases"]}
    ids, inputs = set(), set()
    for case in dataset["cases"]:
        for key in ("id", "rule_id", "input_sha256", "expected", "observed", "status", "coverage"):
            if key not in case:
                raise ValueError(f"Missing case field: {key}")
        if not isinstance(case["id"], str) or not case["id"] or case["id"] in ids:
            raise ValueError("Missing or duplicate case ID")
        ids.add(case["id"])
        if case["rule_id"] not in dataset["rules"]:
            raise ValueError("Case references an undeclared rule")
        digest = case["input_sha256"]
        if not isinstance(digest, str) or not re.fullmatch(r"[a-f0-9]{64}", digest):
            raise ValueError("Invalid input hash")
        identity = (digest, case["rule_id"])
        if identity in inputs:
            raise ValueError("Duplicate input/rule pair would inflate support")
        inputs.add(identity)
        if dataset["split"] == "independent-holdout" and digest in leaked:
            raise ValueError("Holdout leakage: input already appears in an excluded dataset")
        if case["expected"] not in LABELS or case["status"] not in STATUSES:
            raise ValueError("Invalid label or status")
        if case["observed"] is not None and type(case["observed"]) is not bool:
            raise ValueError("Observed must be boolean or null")
        coverage = case["coverage"]
        if not isinstance(coverage, dict):
            raise ValueError("Missing coverage object")
        for key in ("files_discovered", "files_scanned", "files_skipped", "bytes_scanned"):
            value = coverage.get(key)
            if type(value) is not int or value < 0:
                raise ValueError(f"Invalid coverage: {key}")
        if type(coverage.get("complete")) is not bool:
            raise ValueError("Coverage must explicitly declare completeness")
        if coverage["files_scanned"] + coverage["files_skipped"] > coverage["files_discovered"]:
            raise ValueError("Coverage file totals exceed discovery")
        if coverage["complete"] and (
            case["status"] != "completed"
            or case["observed"] is None
            or coverage["files_scanned"] != coverage["files_discovered"]
            or coverage["files_skipped"]
            or not coverage["files_scanned"]
        ):
            raise ValueError("Complete coverage contradicts status, observation, or file counts")


def evaluate(dataset: dict, excluded: list[dict] = ()) -> dict:
    validate(dataset, excluded)
    results = {}
    totals = Counter()
    for rule in sorted(dataset["rules"]):
        cases = [case for case in dataset["cases"] if case["rule_id"] == rule]
        counts, exclusions = Counter(), Counter()
        for case in cases:
            if case["expected"] not in {"positive", "negative"}:
                exclusions[case["expected"]] += 1
            elif case["status"] != "completed" or not case["coverage"]["complete"]:
                exclusions["incomplete_analysis"] += 1
            elif case["observed"] is None:
                exclusions["missing_observation"] += 1
            else:
                counts[
                    ("t" if case["observed"] == (case["expected"] == "positive") else "f")
                    + ("p" if case["observed"] else "n")
                ] += 1
        totals.update(counts)
        results[rule] = {
            **summarize(counts),
            "cases": len(cases),
            "excluded": dict(sorted(exclusions.items())),
            "status_counts": dict(sorted(Counter(c["status"] for c in cases).items())),
        }
    macros = {}
    for metric in ("precision", "recall", "f1"):
        participating = [rule for rule, result in results.items() if result[metric] is not None]
        macros[metric] = {
            "value": sum(results[r][metric] for r in participating) / len(participating)
            if participating
            else None,
            "rules": participating,
        }
    # Coverage totals are per unique input, not per rule decision.
    coverage = {c["input_sha256"]: c["coverage"] for c in dataset["cases"]}
    return {
        "schema_version": "1.0",
        "dataset_id": dataset["dataset_id"],
        "split": dataset["split"],
        "scope": dataset["scope"],
        "ground_truth": dataset["ground_truth"],
        "fuse_commit": dataset["fuse_commit"],
        "rules": results,
        "micro": summarize(totals),
        "macro": macros,
        "coverage": {
            "unique_inputs": len(coverage),
            **{
                key: sum(v[key] for v in coverage.values())
                for key in ("files_discovered", "files_scanned", "files_skipped", "bytes_scanned")
            },
        },
        "uncertainty_method": "two-sided 95% Wilson score interval; cases assumed independent; compiler variants are correlated",
        "interpretation": "Scope-specific labeled case decisions only. No overall FUSE accuracy or field-security claim.",
    }


def write_results(dataset: dict, output: Path, excluded: list[dict] = ()) -> dict:
    result = evaluate(dataset, excluded)
    result["dataset_sha256"] = hashlib.sha256(
        json.dumps(dataset, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    output.mkdir(parents=True, exist_ok=True)
    (output / "metrics.json").write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    rows = [
        {
            "rule": rule,
            **{
                k: values[k]
                for k in ("tp", "fp", "tn", "fn", "support", "precision", "recall", "f1")
            },
        }
        for rule, values in result["rules"].items()
    ]
    with (output / "metrics.csv").open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    lines = [
        f"# {dataset['dataset_id']}",
        "",
        f"Split: {dataset['split']}. Scope: {dataset['scope']}.",
        "",
        "| Rule | TP | FP | TN | FN | n | Precision | Recall | F1 |",
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    for row in rows:
        lines.append(
            "| "
            + " | ".join(
                "undefined" if v is None else f"{v:.4f}" if isinstance(v, float) else str(v)
                for v in row.values()
            )
            + " |"
        )
    lines.extend(
        [
            "",
            result["interpretation"],
            "",
            result["uncertainty_method"] + ".",
            "",
            "Unknown, uncertain, inapplicable and incomplete cases are excluded, never counted as negatives.",
            "See metrics.json for exclusions, intervals, status counts and coverage.",
            "",
        ]
    )
    (output / "metrics.md").write_text("\n".join(lines), encoding="utf-8")
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("dataset", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--exclude-dataset", type=Path, action="append", default=[])
    args = parser.parse_args()

    def read(path):
        return json.loads(path.read_text(encoding="utf-8"))

    write_results(read(args.dataset), args.output, [read(path) for path in args.exclude_dataset])


if __name__ == "__main__":
    main()
