"""Tiny call-evidence benchmark, not a vulnerability or production performance score."""

from __future__ import annotations

import argparse
from dataclasses import asdict
import importlib
import hashlib
import json
from pathlib import Path
import platform
import time

from vigil_fuse.clang_analyzer import analyze
from vigil_fuse.model import Finding, SourceFile
from vigil_fuse.rules.registry import RULES


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=("text", "combined"), required=True)
    parser.add_argument("--executable")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1] / "tests/fixtures/semantic_c"
    entries = json.loads((root / "compile_commands.json").read_text())
    start = time.perf_counter()
    findings: list[Finding] = []
    for entry in entries:
        source = SourceFile(entry["file"], (root / entry["file"]).read_text())
        for rule in RULES:
            findings.extend(rule.scan(source))
    result = (
        analyze(root, root / "compile_commands.json", executable=args.executable)
        if args.mode == "combined"
        else None
    )
    elapsed = time.perf_counter() - start
    expected = json.loads((root / "expected_calls.json").read_text())
    wanted = {(file, name) for file, names in expected.items() for name in names}
    actual = {(item["file"], item["name"]) for item in result.sensitive_calls} if result else set()
    input_hashes = {
        entry["file"]: hashlib.sha256((root / entry["file"]).read_bytes()).hexdigest()
        for entry in entries
    }
    database = root / "compile_commands.json"
    input_hashes[database.name] = hashlib.sha256(database.read_bytes()).hexdigest()
    report = {
        "mode": args.mode,
        "python": platform.python_version(),
        "platform": platform.platform(),
        "elapsed_seconds": elapsed,
        "source_files": len(entries),
        "input_sha256": input_hashes,
        "engine_source_sha256": hashlib.sha256(
            (root.parents[2] / "native/clang-analyzer/src/main.cpp").read_bytes()
        ).hexdigest(),
        "adapter_source_sha256": hashlib.sha256(
            (root.parents[2] / "src/vigil_fuse/clang_analyzer.py").read_bytes()
        ).hexdigest(),
        "text_findings": len(findings),
        "new_security_findings": 0,
        "semantic_status": asdict(result.status) if result else None,
        "semantic_observations": len(result.evidence["observations"])
        if result and result.evidence
        else 0,
        "sensitive_call_observations": len(result.sensitive_calls) if result else 0,
        "expected_api_call_sites": len(wanted),
        "call_evidence_true_positive_sites": len(actual & wanted) if result else None,
        "call_evidence_false_positive_sites": len(actual - wanted) if result else None,
        "call_evidence_false_negative_sites": len(wanted - actual) if result else None,
        "coverage": list(result.coverage) if result else [],
        "security_finding_true_positives": None,
        "security_finding_false_positives": None,
        "limitations": [
            "One fresh process on a tiny synthetic corpus; not a scalability benchmark",
            "Ground truth covers direct API call existence, not vulnerabilities or runtime reachability",
            "Existing text rules do not implement these memory/API observation policies",
            "Peak RSS is maximum individual process usage, not summed concurrent process-tree RSS",
        ],
    }
    try:
        resource = importlib.import_module("resource")

        report["peak_individual_process_rss_kib"] = max(
            resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
            resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss,
        )
    except ImportError:
        report["peak_individual_process_rss_kib"] = None
        report["limitations"].append("RSS unavailable on this operating system")
    args.output.write_text(json.dumps(report, indent=2) + "\n")
    return 0 if result is None or result.evidence is not None else 1


if __name__ == "__main__":
    raise SystemExit(main())
