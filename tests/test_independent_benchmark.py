from __future__ import annotations

import copy
import json
from pathlib import Path
import sys

import pytest

from vigil_fuse.deep_evidence import main
from vigil_fuse.independent_benchmark import (
    CAPABILITIES,
    evaluate,
    manifest_digest,
    prepare_owasp,
    run_native_transfer,
)


def corpus(root: Path) -> dict:
    directory = root / "src/main/java/org/owasp/benchmark/testcode"
    directory.mkdir(parents=True)
    # These generated cases test the harness contract only, never detector accuracy.
    labels = ["# contract fixture, not accuracy evidence"]
    for index in range(1, 7):
        name = f"BenchmarkTest{index:05d}"
        (directory / (name + ".java")).write_text("class " + name + " {}\n")
        labels.append(name + ",cmdi," + ("true" if index % 2 else "false") + ",78")
    (root / "expectedresults-1.2.csv").write_text("\n".join(labels))
    return prepare_owasp(root, revision="a" * 40, analysis_commit="b" * 40)


def predictions(manifest: dict) -> dict:
    return {
        "schema_version": "1.0",
        "manifest_sha256": manifest_digest(manifest),
        "analysis_commit": manifest["corpus"]["analysis_commit"],
        "producer": "contract-fixture",
        "producer_version": "fixture",
        "coverage": [
            {
                "capability": "semantic_sast",
                "metric": "detection",
                "status": "completed",
                "reason": "Contract test only",
            }
        ],
        "observations": [],
        "performance": [],
        "runs": [],
        "unscored_findings": [],
    }


def metric(report: dict, capability: str = "semantic_sast", name: str = "detection") -> dict:
    return next(
        m for m in report["metrics"] if m["capability"] == capability and m["metric"] == name
    )


def test_all_six_outcomes_and_missing_prediction_preserve_unknown(tmp_path: Path) -> None:
    manifest = corpus(tmp_path)
    manifest["cases"][5]["truth"] = "UNREVIEWED"
    pred = predictions(manifest)
    states = ["POSITIVE", "POSITIVE", "NEGATIVE", "NEGATIVE", "UNKNOWN", "POSITIVE"]
    pred["observations"] = [
        {"case_id": case["id"], "state": state, "evidence_refs": ["artifact:prediction"]}
        for case, state in zip(manifest["cases"], states)
    ]
    report = evaluate(manifest, pred)
    value = metric(report)
    assert value["counts"] == {"TP": 1, "FP": 1, "TN": 1, "FN": 1, "UNKNOWN": 1, "UNREVIEWED": 1}
    assert value["precision"] is None and value["recall"] is None
    assert value["resolved_subset_precision"] == value["resolved_subset_recall"] == 0.5
    pred["observations"] = []
    assert metric(evaluate(manifest, pred))["counts"]["UNKNOWN"] == 5
    assert len(report["cases"]) == 6


def test_complete_review_scores_findings_and_nonfindings(tmp_path: Path) -> None:
    manifest = corpus(tmp_path)
    manifest["cases"] = manifest["cases"][:4]
    pred = predictions(manifest)
    pred["observations"] = [
        {"case_id": case["id"], "state": state, "evidence_refs": ["review:external-label"]}
        for case, state in zip(manifest["cases"], ["POSITIVE", "POSITIVE", "NEGATIVE", "NEGATIVE"])
    ]
    value = metric(evaluate(manifest, pred))
    assert all(
        value[name] == 0.5
        for name in ("precision", "recall", "f1", "fp_rate", "fn_rate", "accuracy")
    )
    assert value["review_coverage"] == 1 and value["unknown_rate"] == 0
    for observation, case in zip(pred["observations"], manifest["cases"]):
        observation["state"] = "NEGATIVE" if case["truth"] == "POSITIVE" else "POSITIVE"
    assert metric(evaluate(manifest, pred))["f1"] == 0.0


@pytest.mark.parametrize("capability", CAPABILITIES)
def test_per_capability_metrics_and_run_failure_denominators(
    tmp_path: Path, capability: str
) -> None:
    manifest = corpus(tmp_path)
    name = sorted(CAPABILITIES[capability])[0]
    for case in manifest["cases"]:
        case.update(capability=capability, metric=name)
    pred = predictions(manifest)
    pred["coverage"] = [
        {
            "capability": capability,
            "metric": name,
            "status": "partial",
            "reason": "mixed contract runs",
        }
    ]
    pred["runs"] = [
        {
            "capability": capability,
            "metric": name,
            "run_id": str(i),
            "status": status,
            "artifact_reference": "artifact:run",
        }
        for i, status in enumerate(["completed", "failed", "timeout", "unavailable"])
    ]
    value = metric(evaluate(manifest, pred), capability, name)
    assert value["failure_rate"] == value["timeout_rate"] == 1 / 3
    assert value["population"] == 6 and value["unknown_rate"] == 1


@pytest.mark.parametrize(
    "mode",
    [
        "provenance",
        "duplicate",
        "unsupported-negative",
        "partial-negative",
        "unknown-id",
        "no-evidence",
        "measurement",
        "traversal",
        "duplicate-case",
    ],
)
def test_invalid_inputs_and_false_negative_conversion_rejected(tmp_path: Path, mode: str) -> None:
    manifest = corpus(tmp_path)
    pred = predictions(manifest)
    pred["observations"] = [
        {
            "case_id": manifest["cases"][0]["id"],
            "state": "NEGATIVE",
            "evidence_refs": ["artifact:review"],
        }
    ]
    if mode == "provenance":
        pred["manifest_sha256"] = "c" * 64
    if mode == "duplicate":
        pred["observations"] *= 2
    if mode == "unsupported-negative":
        pred["coverage"][0]["status"] = "unsupported"
    if mode == "partial-negative":
        pred["coverage"][0]["status"] = "partial"
    if mode == "unknown-id":
        pred["observations"][0]["case_id"] = "outside-population"
    if mode == "no-evidence":
        pred["observations"][0]["evidence_refs"] = []
    if mode == "measurement":
        pred["performance"] = [
            {
                "wall_seconds": 1,
                "peak_rss_bytes": -1,
                "time_to_first_finding_seconds": 2,
                "cache_behavior": "unknown",
                "artifact_reference": "artifact:timing",
            }
        ]
    if mode == "traversal":
        manifest["cases"][0]["source_path"] = "../escape"
    if mode == "duplicate-case":
        manifest["cases"] *= 2
    with pytest.raises(ValueError):
        evaluate(manifest, pred)


def test_native_transfer_measures_repeats_without_claiming_semantic_accuracy(
    tmp_path: Path,
) -> None:
    manifest = corpus(tmp_path)
    pred = run_native_transfer(manifest, tmp_path)
    report = evaluate(manifest, pred)
    assert metric(report)["counts"]["UNKNOWN"] == 6
    assert metric(report)["precision"] is None
    assert len(pred["performance"]) == 2
    assert all(p["wall_seconds"] >= 0 for p in pred["performance"])
    assert "OS cache uncontrolled" in pred["performance"][1]["cache_behavior"]
    altered = copy.deepcopy(manifest)
    altered["corpus"]["analyzer_fingerprint"] = "c" * 64
    with pytest.raises(ValueError):
        run_native_transfer(altered, tmp_path)
    (tmp_path / manifest["cases"][0]["source_path"]).write_text("changed source")
    with pytest.raises(ValueError):
        run_native_transfer(manifest, tmp_path)


def test_offline_evaluation_cli(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    manifest = corpus(tmp_path)
    source, pred, output = (
        tmp_path / name for name in ("manifest.json", "predictions.json", "results.json")
    )
    source.write_text(json.dumps(manifest))
    pred.write_text(json.dumps(predictions(manifest)))
    monkeypatch.setattr(
        sys,
        "argv",
        ["deep-evidence", "benchmark-evaluate", str(source), str(pred), "--output", str(output)],
    )
    assert main() == 0 and metric(json.loads(output.read_text()))["unknown_rate"] == 1
