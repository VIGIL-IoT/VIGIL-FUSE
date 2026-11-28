"""Independent corpus evaluation. Missing analysis is UNKNOWN, never a negative."""

from __future__ import annotations

from collections import Counter, defaultdict
import csv
import hashlib
from importlib.resources import files
import io
import math
import os
from pathlib import Path
import re
import time
from typing import Any

from .evidence_graph import canonical, object_fields, relative_path, strings, text
from .firmware_rootfs import digest

CAPABILITIES = {
    "semantic_sast": {"detection", "path_validity"},
    "dependency_reachability": {"package_identity", "symbol_identification", "call_path"},
    "firmware": {"extraction_completeness", "package_identification"},
    "cross_layer": {"edge_precision", "overclaim", "unknown_preservation"},
    "native_sast": {"detection"},
}
STATES = {"POSITIVE", "NEGATIVE", "UNKNOWN", "UNREVIEWED"}


def _commit(value: object) -> str:
    value = text(value)
    if not re.fullmatch(r"[a-f0-9]{40}", value):
        raise ValueError("Expected a full pinned commit")
    return value


def _bytes(path: Path, limit: int = 2 * 1024 * 1024) -> bytes:
    if path.is_symlink() or not path.is_file():
        raise ValueError("Benchmark source must be a regular file")
    with path.open("rb") as stream:
        result = stream.read(limit + 1)
    if len(result) > limit:
        raise ValueError("Benchmark input size limit")
    return result


def _source(root: Path, name: str) -> Path:
    name = relative_path(name)
    path = root / name
    if root.is_symlink() or any(
        part.is_symlink() for part in (path, *path.parents) if part != root.parent
    ):
        raise ValueError("Benchmark symlinks are unsupported")
    path.resolve().relative_to(root.resolve())
    return path


def native_fingerprint() -> str:
    root = files("vigil_fuse")
    resources = [
        root.joinpath("model.py"),
        *(p for p in root.joinpath("rules").iterdir() if p.name.endswith(".py")),
    ]
    hasher = hashlib.sha256()
    for resource in sorted(resources, key=lambda p: p.name):
        hasher.update(
            resource.name.encode()
            + b"\0"
            + resource.read_text(encoding="utf-8").replace("\r\n", "\n").encode()
            + b"\0"
        )
    return hasher.hexdigest()


def prepare_owasp(root: Path, *, revision: str, analysis_commit: str) -> dict[str, Any]:
    """Import every official Java 1.2 label, without using it to tune a detector."""
    _commit(revision)
    _commit(analysis_commit)
    payload = _bytes(_source(root, "expectedresults-1.2.csv"))
    cases = []
    for values in csv.reader(io.StringIO(payload.decode("utf-8-sig"))):
        if not values or values[0].startswith("#"):
            continue
        if (
            len(values) != 4
            or not re.fullmatch(r"BenchmarkTest[0-9]{5}", values[0])
            or values[2] not in {"true", "false"}
            or not values[3].isdigit()
        ):
            raise ValueError("Invalid OWASP ground truth row")
        name, category, vulnerable, cwe = values
        source = "src/main/java/org/owasp/benchmark/testcode/" + name + ".java"
        data = _bytes(_source(root, source))
        cases.append(
            {
                "id": name,
                "capability": "semantic_sast",
                "metric": "detection",
                "truth": "POSITIVE" if vulnerable == "true" else "NEGATIVE",
                "source_path": source,
                "source_sha256": hashlib.sha256(data).hexdigest(),
                "label_reference": "https://github.com/OWASP-Benchmark/BenchmarkJava/blob/"
                + revision
                + "/expectedresults-1.2.csv",
                "metadata": {"category": category, "cwe": "CWE-" + cwe},
            }
        )
    result = {
        "schema_version": "1.0",
        "corpus": {
            "name": "OWASP Benchmark Java 1.2",
            "repository": "https://github.com/OWASP-Benchmark/BenchmarkJava",
            "revision": revision,
            "license": "GPL-2.0-only (upstream; sources not redistributed)",
            "ground_truth_sha256": hashlib.sha256(payload).hexdigest(),
            "split": "held-out",
            "selection": "all official expectedresults-1.2.csv rows",
            "independence": "external-corpus-labels",
            "analysis_commit": analysis_commit,
            "analyzer_fingerprint": native_fingerprint(),
        },
        "cases": cases,
    }
    validate_manifest(result)
    return result


def validate_manifest(value: dict[str, Any]) -> None:
    object_fields(value, {"schema_version", "corpus", "cases"})
    corpus = object_fields(
        value["corpus"],
        {
            "name",
            "repository",
            "revision",
            "license",
            "ground_truth_sha256",
            "split",
            "selection",
            "independence",
            "analysis_commit",
            "analyzer_fingerprint",
        },
    )
    if (
        value["schema_version"] != "1.0"
        or corpus["split"] not in {"held-out", "regression"}
        or corpus["independence"] != "external-corpus-labels"
    ):
        raise ValueError("Invalid independent benchmark manifest")
    _commit(corpus["revision"])
    _commit(corpus["analysis_commit"])
    for key in ("ground_truth_sha256", "analyzer_fingerprint"):
        digest(corpus[key])
    for key in ("name", "repository", "license", "selection"):
        text(corpus[key])
    if not corpus["repository"].startswith("https://"):
        raise ValueError("Independent corpus needs a published source")
    if not isinstance(value["cases"], list) or not 1 <= len(value["cases"]) <= 20000:
        raise ValueError("Benchmark population limit")
    seen = set()
    for row in value["cases"]:
        object_fields(
            row,
            {
                "id",
                "capability",
                "metric",
                "truth",
                "source_path",
                "source_sha256",
                "label_reference",
                "metadata",
            },
        )
        text(row["id"])
        if (
            row["id"] in seen
            or row["capability"] not in CAPABILITIES
            or row["metric"] not in CAPABILITIES[row["capability"]]
            or row["truth"] not in STATES
        ):
            raise ValueError("Invalid benchmark label or duplicate case")
        seen.add(row["id"])
        relative_path(row["source_path"])
        digest(row["source_sha256"])
        text(row["label_reference"])
        if not isinstance(row["metadata"], dict) or len(canonical(row["metadata"])) > 4096:
            raise ValueError("Invalid benchmark metadata")


def manifest_digest(manifest: dict[str, Any]) -> str:
    return hashlib.sha256(canonical(manifest).encode()).hexdigest()


def _ratio(a: int, b: int) -> float | None:
    return a / b if b else None


def evaluate(manifest: dict[str, Any], predictions: dict[str, Any]) -> dict[str, Any]:
    validate_manifest(manifest)
    object_fields(
        predictions,
        {
            "schema_version",
            "manifest_sha256",
            "analysis_commit",
            "producer",
            "producer_version",
            "coverage",
            "observations",
            "performance",
            "runs",
            "unscored_findings",
        },
    )
    if (
        predictions["schema_version"] != "1.0"
        or predictions["manifest_sha256"] != manifest_digest(manifest)
        or predictions["analysis_commit"] != manifest["corpus"]["analysis_commit"]
    ):
        raise ValueError("Benchmark prediction provenance mismatch")
    text(predictions["producer"])
    text(predictions["producer_version"])
    cases = {row["id"]: row for row in manifest["cases"]}
    coverage = {}
    if not isinstance(predictions["coverage"], list) or len(predictions["coverage"]) > 100:
        raise ValueError("Benchmark coverage limit")
    for row in predictions["coverage"]:
        object_fields(row, {"capability", "metric", "status", "reason"})
        text(row["reason"])
        if (
            row["capability"] not in CAPABILITIES
            or row["metric"] not in CAPABILITIES[row["capability"]]
            or row["status"]
            not in {"completed", "partial", "unsupported", "unavailable", "failed", "timeout"}
        ):
            raise ValueError("Invalid benchmark coverage")
        key = row["capability"], row["metric"]
        if key in coverage:
            raise ValueError("Duplicate benchmark coverage")
        coverage[key] = row
    if (
        not isinstance(predictions["observations"], list)
        or len(predictions["observations"]) > 20000
    ):
        raise ValueError("Benchmark observation limit")
    observed = {}
    for row in predictions["observations"]:
        object_fields(row, {"case_id", "state", "evidence_refs"})
        if row["case_id"] not in cases or row["case_id"] in observed or row["state"] not in STATES:
            raise ValueError("Invalid benchmark observation")
        refs = strings(row["evidence_refs"])
        case = cases[row["case_id"]]
        status = coverage.get((case["capability"], case["metric"]), {}).get("status")
        if row["state"] in {"POSITIVE", "NEGATIVE"} and (
            not refs or status not in {"completed", "partial"}
        ):
            raise ValueError("Unavailable analysis cannot emit a definitive prediction")
        # A partial scan cannot turn an absence into a reviewed negative.
        if row["state"] == "NEGATIVE" and status != "completed":
            raise ValueError("Partial analysis cannot establish a negative")
        observed[row["case_id"]] = row
    performance = predictions["performance"]
    if not isinstance(performance, list) or len(performance) > 100:
        raise ValueError("Benchmark performance limit")
    for sample in performance:
        object_fields(
            sample,
            {
                "wall_seconds",
                "peak_rss_bytes",
                "time_to_first_finding_seconds",
                "cache_behavior",
                "artifact_reference",
            },
        )
        for measurement in ("wall_seconds", "peak_rss_bytes", "time_to_first_finding_seconds"):
            number = sample[measurement]
            if number is not None and (
                type(number) not in {int, float} or not math.isfinite(number) or number < 0
            ):
                raise ValueError("Invalid performance measurement")
        if sample["time_to_first_finding_seconds"] is not None and (
            sample["wall_seconds"] is None
            or sample["time_to_first_finding_seconds"] > sample["wall_seconds"]
        ):
            raise ValueError("Invalid time-to-first-finding")
        text(sample["cache_behavior"])
        text(sample["artifact_reference"])
    if (
        not isinstance(predictions["unscored_findings"], list)
        or len(predictions["unscored_findings"]) > 20000
    ):
        raise ValueError("Unscored finding limit")
    for signal in predictions["unscored_findings"]:
        object_fields(signal, {"case_id", "rule", "fingerprint"})
        if signal["case_id"] not in cases:
            raise ValueError("Unknown unscored case")
        text(signal["rule"])
        digest(signal["fingerprint"])
    run_counts: dict[tuple[str, str], Counter[str]] = defaultdict(Counter)
    if not isinstance(predictions["runs"], list) or len(predictions["runs"]) > 20000:
        raise ValueError("Benchmark run limit")
    run_ids = set()
    for run in predictions["runs"]:
        object_fields(run, {"capability", "metric", "run_id", "status", "artifact_reference"})
        text(run["run_id"])
        text(run["artifact_reference"])
        run_key = run["capability"], run["metric"], run["run_id"]
        if (
            run_key in run_ids
            or run["capability"] not in CAPABILITIES
            or run["metric"] not in CAPABILITIES[run["capability"]]
            or run["status"]
            not in {"completed", "partial", "failed", "timeout", "unsupported", "unavailable"}
        ):
            raise ValueError("Invalid benchmark run record")
        run_ids.add(run_key)
        run_counts[run["capability"], run["metric"]][run["status"]] += 1
    counts: dict[tuple[str, str], Counter[str]] = defaultdict(Counter)
    details = []
    for case in sorted(cases.values(), key=lambda r: r["id"]):
        prediction = observed.get(case["id"], {"state": "UNKNOWN", "evidence_refs": []})
        truth, state = case["truth"], prediction["state"]
        if "UNREVIEWED" in {truth, state}:
            outcome = "UNREVIEWED"
        elif "UNKNOWN" in {truth, state}:
            outcome = "UNKNOWN"
        else:
            outcome = {
                ("POSITIVE", "POSITIVE"): "TP",
                ("NEGATIVE", "POSITIVE"): "FP",
                ("POSITIVE", "NEGATIVE"): "FN",
                ("NEGATIVE", "NEGATIVE"): "TN",
            }[truth, state]
        counts[case["capability"], case["metric"]][outcome] += 1
        details.append(
            {
                "case_id": case["id"],
                "truth": truth,
                "prediction": state,
                "outcome": outcome,
                "label_reference": case["label_reference"],
                "evidence_refs": prediction["evidence_refs"],
            }
        )
    metrics = []
    for capability, names in CAPABILITIES.items():
        for metric in sorted(names):
            tally = counts[capability, metric]
            tp, fp, tn, fn, unknown, unreviewed = (
                tally[key] for key in ("TP", "FP", "TN", "FN", "UNKNOWN", "UNREVIEWED")
            )
            total = sum(tally.values())
            precision, recall = _ratio(tp, tp + fp), _ratio(tp, tp + fn)
            f1 = _ratio(2 * tp, 2 * tp + fp + fn)
            complete = total > 0 and unknown + unreviewed == 0
            status = coverage.get((capability, metric), {}).get("status", "unavailable")
            attempts = run_counts[capability, metric]
            denominator = sum(attempts[s] for s in ("completed", "partial", "failed", "timeout"))
            metrics.append(
                {
                    "capability": capability,
                    "metric": metric,
                    "population": total,
                    "counts": {
                        key: tally[key] for key in ("TP", "FP", "TN", "FN", "UNKNOWN", "UNREVIEWED")
                    },
                    "precision": precision if complete else None,
                    "recall": recall if complete else None,
                    "f1": f1 if complete else None,
                    "resolved_subset_precision": precision,
                    "resolved_subset_recall": recall,
                    "fp_rate": _ratio(fp, fp + tn) if complete else None,
                    "fn_rate": _ratio(fn, fn + tp) if complete else None,
                    "accuracy": _ratio(tp + tn, tp + tn + fp + fn) if complete else None,
                    "unknown_rate": _ratio(unknown, total),
                    "review_coverage": _ratio(tp + fp + tn + fn, total),
                    "overclaim_rate": _ratio(fp, tp + fp)
                    if complete and capability == "cross_layer"
                    else None,
                    "run_counts": dict(sorted(attempts.items())),
                    "failure_rate": _ratio(attempts["failed"], denominator),
                    "timeout_rate": _ratio(attempts["timeout"], denominator),
                    "coverage": status,
                }
            )
    return {
        "schema_version": "1.0",
        "corpus": manifest["corpus"],
        "manifest_sha256": manifest_digest(manifest),
        "producer": predictions["producer"],
        "producer_version": predictions["producer_version"],
        "metrics": metrics,
        "cases": details,
        "performance": performance,
        "unscored_findings": predictions["unscored_findings"],
        "limitations": [
            "Corpus-label evaluation is not a blind independent human field review.",
            "UNKNOWN and UNREVIEWED never count as TP, FP, TN or FN; whole-population metrics remain null until resolved.",
            "Resolved-subset metrics are conditional diagnostics, not whole-population accuracy.",
            "Failure and timeout rates describe this submitted capability run, not an estimated population rate.",
            "Unpopulated capabilities have no accuracy evidence. Authored fixtures remain regression tests.",
        ],
    }


def peak_rss_bytes() -> int | None:
    """Process lifetime RSS high-water mark; includes interpreter/harness overhead."""
    if os.name == "nt":
        import ctypes
        from ctypes import wintypes

        class Counters(ctypes.Structure):
            _fields_ = [
                ("cb", wintypes.DWORD),
                ("PageFaultCount", wintypes.DWORD),
                *(
                    (name, ctypes.c_size_t)
                    for name in (
                        "PeakWorkingSetSize",
                        "WorkingSetSize",
                        "QuotaPeakPagedPoolUsage",
                        "QuotaPagedPoolUsage",
                        "QuotaPeakNonPagedPoolUsage",
                        "QuotaNonPagedPoolUsage",
                        "PagefileUsage",
                        "PeakPagefileUsage",
                    )
                ),
            ]

        counters = Counters()
        counters.cb = ctypes.sizeof(counters)
        process = ctypes.windll.kernel32.GetCurrentProcess
        process.restype = wintypes.HANDLE
        memory_info = ctypes.windll.psapi.GetProcessMemoryInfo
        memory_info.argtypes = [wintypes.HANDLE, ctypes.POINTER(Counters), wintypes.DWORD]
        memory_info.restype = wintypes.BOOL
        if not memory_info(process(), ctypes.byref(counters), counters.cb):
            return None
        return int(counters.PeakWorkingSetSize)
    try:
        import resource
        import sys

        return int(getattr(resource, "getrusage")(getattr(resource, "RUSAGE_SELF")).ru_maxrss) * (
            1 if sys.platform == "darwin" else 1024
        )
    except ImportError:
        return None


def run_native_transfer(manifest: dict[str, Any], root: Path, *, repeat: int = 2) -> dict[str, Any]:
    """Run frozen native rules as transfer signals, without inventing Java taint coverage."""
    from . import __version__
    from .model import SourceFile
    from .rules.registry import RULES as native_rules

    validate_manifest(manifest)
    if (
        manifest["corpus"]["analyzer_fingerprint"] != native_fingerprint()
        or type(repeat) is not int
        or not 1 <= repeat <= 3
    ):
        raise ValueError("Frozen analyzer changed or invalid repeat count")
    performance: list[dict[str, Any]] = []
    unscored: list[dict[str, str]] = []
    for iteration in range(repeat):
        started, first = time.perf_counter(), None
        signals = []
        total_bytes = 0
        for case in manifest["cases"]:
            payload = _bytes(_source(root, case["source_path"]))
            total_bytes += len(payload)
            if total_bytes > 128 * 1024 * 1024 or time.perf_counter() - started > 300:
                raise ValueError("Benchmark execution budget exceeded")
            if hashlib.sha256(payload).hexdigest() != case["source_sha256"]:
                raise ValueError("Benchmark source digest mismatch")
            source = SourceFile(
                case["source_path"],
                payload.decode("utf-8"),
                sha256=case["source_sha256"],
                byte_size=len(payload),
            )
            for rule in native_rules:
                if rule.may_scan(source):
                    for finding in rule.scan(source):
                        if first is None:
                            first = time.perf_counter() - started
                        signals.append(
                            {
                                "case_id": case["id"],
                                "rule": rule.id,
                                "fingerprint": finding.fingerprint,
                            }
                        )
                        if len(signals) > 20000:
                            raise ValueError("Benchmark unscored finding limit")
        if iteration and signals != unscored:
            raise ValueError("Nondeterministic benchmark repeat")
        unscored = signals
        performance.append(
            {
                "wall_seconds": time.perf_counter() - started,
                "peak_rss_bytes": peak_rss_bytes(),
                "time_to_first_finding_seconds": first,
                "cache_behavior": "first pass; no application cache; OS cache uncontrolled"
                if iteration == 0
                else "repeat pass; no application cache; OS cache uncontrolled",
                "artifact_reference": "manifest:sha256:" + manifest_digest(manifest),
            }
        )
    groups = sorted({(c["capability"], c["metric"]) for c in manifest["cases"]})
    return {
        "schema_version": "1.0",
        "manifest_sha256": manifest_digest(manifest),
        "analysis_commit": manifest["corpus"]["analysis_commit"],
        "producer": "fuse-native-transfer-signals",
        "producer_version": __version__,
        "coverage": [
            {
                "capability": cap,
                "metric": metric,
                "status": "unsupported",
                "reason": "Native posture rules do not implement OWASP Java semantic source-to-sink coverage. Optional semantic engines were not run.",
            }
            for cap, metric in groups
        ],
        "observations": [
            {
                "case_id": c["id"],
                "state": "UNKNOWN",
                "evidence_refs": ["sha256:" + c["source_sha256"]],
            }
            for c in manifest["cases"]
        ],
        "performance": performance,
        "runs": [
            {
                "capability": "native_sast",
                "metric": "detection",
                "run_id": "native-transfer-" + str(i),
                "status": "completed",
                "artifact_reference": "manifest:sha256:" + manifest_digest(manifest),
            }
            for i in range(repeat)
        ],
        "unscored_findings": unscored,
    }
