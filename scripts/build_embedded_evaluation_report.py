"""Collect hosted evaluation artifacts and render descriptive plots and a report."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import shutil
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scripts.evaluate_detection_accuracy import write_results  # noqa: E402


def build(source: Path, destination: Path) -> None:
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    plt.rcParams["svg.hashsalt"] = "fuse-evaluation-2026-11-14"

    evidence = destination / "evidence"
    evidence.mkdir(parents=True, exist_ok=True)
    for path in sorted(source.rglob("compatibility.json")):
        record = json.loads(path.read_text())
        target = evidence / record["target"]
        target.mkdir(exist_ok=True)
        record["source_artifact_sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
        record["build"]["compiler_version"] = "\n".join(
            line
            for line in record["build"]["compiler_version"].splitlines()
            if not line.startswith("InstalledDir:")
        )
        (target / "compatibility.json").write_text(
            json.dumps(record, indent=2, sort_keys=True) + "\n"
        )
        shutil.copyfile(path.parent / "dataset.json", target / "dataset.json")
        shutil.copytree(path.parent / "outputs", target / "outputs", dirs_exist_ok=True)
        write_results(json.loads((target / "dataset.json").read_text()), target / "metrics")
    documents = [
        json.loads(path.read_text()) for path in sorted(evidence.glob("*/compatibility.json"))
    ]
    if len(documents) != 5:
        raise ValueError("Expected evidence for all five preregistered targets")
    figures = destination / "figures"
    figures.mkdir(exist_ok=True)
    plt.rcParams.update(
        {
            "font.family": "DejaVu Sans",
            "font.size": 10,
            "axes.spines.top": False,
            "axes.spines.right": False,
        }
    )
    labels = [d["target"] for d in documents]
    fig, ax = plt.subplots(figsize=(9, 4), layout="constrained")
    complete = [d["status_counts"].get("completed", 0) for d in documents]
    partial = [d["status_counts"].get("partial", 0) for d in documents]
    ax.bar(labels, complete, label="Completed", color="#685091")
    ax.bar(labels, partial, bottom=complete, label="Partial", color="#dc9357")
    for i, d in enumerate(documents):
        ax.text(i, complete[i] + partial[i] + 0.15, f"n={len(d['records'])}", ha="center")
    ax.set(
        ylabel="Binary analyses",
        title="Compatibility, including raw controls and real firmware",
        ylim=(0, 15),
    )
    ax.legend(frameon=False)
    fig.savefig(
        figures / "compatibility.svg", metadata={"Date": None, "Creator": "FUSE evaluation"}
    )
    plt.close(fig)
    fig, ax = plt.subplots(figsize=(9, 4), layout="constrained")
    for index, d in enumerate(documents):
        values = [r["elapsed_seconds"] for r in d["records"]]
        ax.scatter([index] * len(values), values, color="#685091", alpha=0.7)
        ax.text(index, max(values) + 1, f"n={len(values)}", ha="center")
    ax.set(
        xticks=range(len(labels)),
        xticklabels=labels,
        ylabel="Wall time (seconds)",
        title="Fresh Ghidra processes on hosted runners; descriptive only",
    )
    fig.savefig(figures / "duration.svg", metadata={"Date": None, "Creator": "FUSE evaluation"})
    plt.close(fig)
    lines = [
        "# FUSE embedded binary evaluation: 2026-11-14",
        "",
        "A VIGIL Project",
        "",
        "Controlled compatibility gates passed for five targets across four processor families. All three real ESP-IDF example ELFs produced **partial** results because bounded inventories were truncated. This establishes useful but incomplete real-firmware analysis, not full firmware coverage or security.",
        "",
        "## Frozen configuration",
        "",
        "The original [manifest](manifest.json) froze revision `2453884`. Run [43600357841](https://github.com/VIGIL-IoT/VIGIL-FUSE/actions/runs/43600357841) exposed URL credentials retained in Ghidra-generated label names. Commit `cca712e` fixes metadata sanitization only; native rule patterns and binary detection predicates are unchanged. The [replacement freeze](post-redaction/manifest.json) records that exception before independent sampling. No detector tuning was performed.",
        "",
        "The successful run is [43600925661](https://github.com/VIGIL-IoT/VIGIL-FUSE/actions/runs/43600925661), harness revision `d84fe49`. Ghidra 12.2, Java 25, a 300-second adapter timeout, 128 MiB inputs, 8 MiB artifacts and 10 MiB diagnostics remain enforced. Exact Java patch, compiler versions, build flags, ELF hashes, language IDs, entry points, byte sizes and per-case timings are preserved in evidence/*/compatibility.json.",
        "",
        "## Architecture compatibility",
        "",
        "| Target | Completed | Partial | Total | Median seconds |",
        "| --- | ---: | ---: | ---: | ---: |",
    ]
    for d in documents:
        lines.append(
            f"| {d['target']} | {d['status_counts'].get('completed', 0)} | {d['status_counts'].get('partial', 0)} | {len(d['records'])} | {d['median_elapsed_seconds']:.2f} |"
        )
    lines += [
        "",
        "![Compatibility counts](figures/compatibility.svg)",
        "",
        "## Controlled binary accuracy",
        "",
        "Construction labels mean a code-referenced plaintext endpoint should be reported, while HTTPS, MQTTS and retained unreferenced plaintext strings should not. They do not label exploitable vulnerabilities. ELF controls use O0/O1/O2/Os and stripped O2 variants. Identical binary hashes are deduplicated before metrics, but every compatibility run is retained. ARM raw controls are excluded from ELF accuracy.",
        "",
        "| Target | Rule | TP | FP | TN | FN | n | Precision | Recall | F1 | 95% precision / recall interval |",
        "| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- |",
    ]
    for d in documents:
        metrics = json.loads((evidence / d["target"] / "metrics/metrics.json").read_text())
        for rule, row in metrics["rules"].items():
            interval = row["precision_wilson_95"]
            lines.append(
                f"| {d['target']} | {rule} | {row['tp']} | {row['fp']} | {row['tn']} | {row['fn']} | {row['support']} | {row['precision']:.3f} | {row['recall']:.3f} | {row['f1']:.3f} | [{interval[0]:.3f}, {interval[1]:.3f}] |"
            )
    lines += [
        "",
        "Intervals use the two-sided Wilson score method. They assume independent Bernoulli cases; compiler variants share source and are correlated. Treat these as descriptive case-count intervals, not calibrated population bounds. The small cohort cannot justify broad accuracy claims. Per-target macro participation, micro totals, exclusions and coverage are generated in metrics.json. No overall FUSE accuracy score is reported.",
        "",
        "## Real embedded firmware corpus",
        "",
        "The official ESP-IDF CC0-1.0 hello_world example was built for ESP32, ESP32-S3 and ESP32-C6 at commit `880a203ae603d08a94d06aa01e0d6761958e5e9e`, inside digest-pinned `espressif/idf@sha256:bf72fe7a15c22849a9a94147301165a545fb8905d97c176cf748e3e4614cac84`. ESP-IDF and linked components retain their individual licenses, including Apache-2.0 components. Only analysis reports are committed; third-party binaries are rebuilt by the workflow. These are real SDK example applications, not representative production products.",
        "",
        "| Target | Language ID | Functions | Strings | Xrefs | Status | Truncated groups |",
        "| --- | --- | ---: | ---: | ---: | --- | --- |",
    ]
    for d in documents:
        for r in d["records"]:
            if "provenance" in r:
                lines.append(
                    f"| {d['target']} | {r['analysis']['language_id']} | {r['counts']['functions']} | {r['counts']['strings']} | {r['counts']['cross_references']} | {r['status']} | {', '.join(k for k, v in r['truncation'].items() if v)} |"
                )
    lines += [
        "",
        "## Coverage and safety",
        "",
        "55 controlled ELFs completed; 2 Cortex-M raw controls completed with an explicitly declared Cortex language and linker origin 0x08000000. These flat raw fixtures have no vector table and do not establish generic raw firmware support. Three real ELFs were partial, never clean negatives. Schema checks, credential sentinel redaction and temporary-workspace cleanup passed the controlled gates. Per-case peak process-tree RSS is sampled every 50 ms; it is not a hard memory limit. Targets were never executed. No safety limits were increased to improve results.",
        "",
        "## Native rules and public benchmarks",
        "",
        "The existing [SARD catalogue](../../benchmark/sard-fuse001-cwe259-c-catalogue-results-2026-10-31.json) remains development-informed benchmark evidence. Mixed good/bad paths and SARIF file targets do not label every emitted literal or every negative file, so no native precision or recall was derived from it. Regression fixtures are explicitly separate from the controlled binary corpus and independent review material.",
        "",
        "## Independent holdout and human review",
        "",
        "[Selection](holdout-selection.json) was committed before fetching the pinned NetX Duo and TinyUSB source. [Reviewer packets](review/README.md) include pinned URLs, hashes, seven rule scopes, two unanswered independent forms and an empty adjudication form. Source text and machine observations are withheld from the packets. The selected snapshots were absent from earlier scan manifests, and sampled source hashes were checked against frozen regression hashes. The initial scan emitted no findings, so the packet currently supplies no-finding review cases only. A separately preregistered emitted-candidate supplement and two independent human reviewers are still required. Expected labels remain unknown. Reviewer count, agreement, disagreements and adjudications are all pending, not zero-quality outcomes. No independent field accuracy is established.",
        "",
        "## Comparators and semantic prototype",
        "",
        "No source scanner was presented as a comparator for Ghidra binary xrefs. A source comparison requires its own overlapping rule specification, pinned ruleset and human labels. It remains unmeasured. A P-code network-call argument prototype is deferred: bounded inventory truncation on real examples and the lack of independently labeled cross-architecture call-path controls make semantic claims premature. The current two binary rules establish code references only, not calls, reachability, taint analysis or exploitability.",
        "",
        "## Performance",
        "",
        "![Hosted-runner durations](figures/duration.svg)",
        "",
        "Exact input bytes, artifact bytes, function/string/xref counts, wall times, memory samples and inaccessible-process observations are recorded per case. Hosted timing differences are descriptive and not architecture speed rankings.",
        "",
        "## Claim and evidence policy",
        "",
        "| Supported claim | Evidence | Not established |",
        "| --- | --- | --- |",
        "| Controlled Cortex-M4, Xtensa and RV32 ELFs produce repeatable endpoint evidence | Per-case reports and successful workflow | All firmware for those platforms |",
        "| Two binary rules match the frozen construction labels | Per-target confusion matrices | General vulnerability detection or field precision |",
        "| Explicit flat Cortex-M raw fixtures can be analyzed | Two raw records | Automatic firmware mapping or architecture inference |",
        "| Official ESP-IDF examples yield bounded metadata | Three partial real-project records | Complete real-firmware coverage |",
        "| Independent review packets exist | Blank A/B/adjudication forms | Completed human review or independent accuracy |",
        "",
        "## Reproduction",
        "",
        "1. Dispatch `.github/workflows/embedded-ghidra-matrix.yml` using GitHub Actions. The workflow verifies frozen detector hashes, pinned Ghidra and Arm archive checksums, and the ESP-IDF image digest and source commit.",
        "2. Download its five `embedded-evaluation-*` artifacts to a fresh local directory.",
        "3. Run `python scripts/build_embedded_evaluation_report.py --source ARTIFACT_DIRECTORY --output reports/evaluation/2026-11-14`. Matplotlib is needed only for report figures.",
        "4. Recalculate a target with `python scripts/evaluate_detection_accuracy.py reports/evaluation/2026-11-14/evidence/cortex_m4/dataset.json --output OUTPUT_DIRECTORY`.",
        "5. Prepare review packets in a new directory with `python scripts/prepare_independent_review.py --selection reports/evaluation/2026-11-14/holdout-selection.json --work SOURCE_CACHE --output REVIEW_DIRECTORY`. GitHub CLI authentication and network access are required; no source builds or execution occur.",
        "",
        "## Threats to validity and release decision",
        "",
        "Known endpoints, one Cortex-M variant, one RV32 configuration, two closely related Xtensa chips, no hardware execution, no production-image diversity, small correlated controls and partial real-example inventories limit generalization. Optimization can remove evidence; xrefs need not imply network use. Default path exclusions can prevent key/test files from being scanned. No comparator study or human adjudication has completed. No maturity score was raised and no release was published for this experiment.",
        "",
        "Primary references: [Ghidra headless interface](https://github.com/NationalSecurityAgency/ghidra/blob/Ghidra_12.2_build/Ghidra/RuntimeScripts/support/analyzeHeadlessREADME.md), [official Arm LLVM release](https://github.com/ARM-software/LLVM-embedded-toolchain-for-Arm/releases/tag/release-19.1.5), [pinned ESP-IDF toolchain definitions](https://github.com/espressif/esp-idf/tree/880a203ae603d08a94d06aa01e0d6761958e5e9e/tools/cmake), [official example](https://github.com/espressif/esp-idf/blob/880a203ae603d08a94d06aa01e0d6761958e5e9e/examples/get-started/hello_world/main/hello_world_main.c).",
        "",
    ]
    (destination / "README.md").write_text("\n".join(lines), encoding="utf-8")
    hashes = {
        p.relative_to(destination).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
        for p in sorted(evidence.rglob("*"))
        if p.is_file()
    }
    (destination / "evidence-hashes.json").write_text(
        json.dumps(hashes, indent=2, sort_keys=True) + "\n"
    )
    provenance = {
        "generator_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "matplotlib": matplotlib.__version__,
        "input_hashes": {k: v for k, v in hashes.items() if k.endswith("compatibility.json")},
        "figure_hashes": {
            p.name: hashlib.sha256(p.read_bytes()).hexdigest()
            for p in sorted(figures.glob("*.svg"))
        },
    }
    (destination / "figure-provenance.json").write_text(
        json.dumps(provenance, indent=2, sort_keys=True) + "\n"
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    build(args.source, args.output)
