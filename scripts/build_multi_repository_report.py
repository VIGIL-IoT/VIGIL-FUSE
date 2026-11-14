"""Generate publication tables and Matplotlib charts from preserved FUSE reports."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import matplotlib

from run_repository_scan_pilot import report_has_incomplete_coverage

matplotlib.use("Agg")
import matplotlib.pyplot as plt

ROOT = Path(__file__).resolve().parents[1]
COHORT = ROOT / "reports/repository-scans/multi-repository-2026-11-14"
BASELINE = ROOT / "reports/repository-scans/release-0.3.0-transfer-2026-11-12"


def tex(value: object) -> str:
    replacements = {
        "\\": r"\textbackslash{}",
        "_": r"\_",
        "&": r"\&",
        "%": r"\%",
        "#": r"\#",
        "$": r"\$",
        "{": r"\{",
        "}": r"\}",
        "~": r"\textasciitilde{}",
        "^": r"\textasciicircum{}",
    }
    return "".join(replacements.get(char, char) for char in str(value))


def main() -> None:
    manifest = json.loads((COHORT / "manifest.json").read_text(encoding="utf-8"))
    publication = COHORT / "publication"
    publication.mkdir(exist_ok=True)
    rows = []
    snapshots = []
    pins = []
    limitations = []
    findings = []
    for repository in manifest["repositories"]:
        for scope in repository["scans"]:
            relative = Path("reports") / scope["id"] / "findings.json"
            raw = (COHORT / relative).read_bytes()
            report = json.loads(raw)
            previous = json.loads((BASELINE / relative).read_text(encoding="utf-8"))
            summary = report["summary"]
            pio = report["build_context"]["platformio"]
            old_pio = previous["build_context"]["platformio"]
            partial = report_has_incomplete_coverage(report)
            row = {
                "repository": repository["name"],
                "scope": scope["id"],
                "commit": repository["commit"],
                "profile": repository["profile"],
                "scanned": summary["files_scanned"],
                "selected": summary["files_selected"],
                "skipped": summary["files_skipped"],
                "findings": summary["finding_count"],
                "status": "partial" if partial else "complete",
                "platformio_before": len(old_pio["environments"]),
                "platformio_after": len(pio["environments"]),
                "platformio_status": pio["status"],
                "report_sha256": hashlib.sha256(raw).hexdigest(),
            }
            rows.append(row)
            snapshots.append(
                tex(repository["name"])
                + f" & {row['scanned']}/{row['selected']} & {row['findings']} & {row['status']} "
                + r"\\"
            )
            pins.append(
                r"\item "
                + tex(repository["name"])
                + ": "
                + r"\texttt{"
                + repository["commit"]
                + "}. "
                + tex(scope["scope"])
            )
            for item in pio["limitations"]:
                limitations.append(r"\item " + tex(repository["name"] + ": " + item))
            for finding in report["findings"]:
                findings.append(
                    r"\item "
                    + tex(
                        repository["name"]
                        + ": "
                        + finding["rule_id"]
                        + ", "
                        + finding["severity"]
                        + " severity, "
                        + finding["confidence"]
                        + " confidence. "
                        + finding["title"]
                    )
                    + r" Location: \texttt{"
                    + tex(finding["location"]["file"])
                    + "}, line "
                    + tex(finding["location"]["start_line"])
                    + "."
                )
    output = {"scan_date": manifest["scan_date"], "scanner": manifest["fuse"], "rows": rows}
    (publication / "metrics.json").write_text(json.dumps(output, indent=2) + "\n", encoding="utf-8")
    total = sum(row["findings"] for row in rows)
    selected = sum(row["selected"] for row in rows)
    scanned = sum(row["scanned"] for row in rows)
    generated = (
        r"\newcommand{\ScannedFiles}{"
        + str(scanned)
        + "}\n"
        + r"\newcommand{\SelectedFiles}{"
        + str(selected)
        + "}\n"
        + r"\newcommand{\RawFindings}{"
        + str(total)
        + "}\n"
        + r"\newcommand{\ScannerCommit}{"
        + manifest["fuse"]["commit"]
        + "}\n"
        + r"\newcommand{\ResultRows}{"
        + "\n".join(snapshots)
        + "}\n"
        + r"\newcommand{\PinnedScopes}{"
        + "\n".join(pins)
        + "}\n"
        + r"\newcommand{\FindingItems}{"
        + "\n".join(findings)
        + "}\n"
        + r"\newcommand{\MetadataLimits}{"
        + "\n".join(limitations or [r"\item No PlatformIO metadata limitations recorded."])
        + "}\n"
    )
    (publication / "results.tex").write_text(generated, encoding="utf-8")
    plt.rcParams.update({"font.size": 10, "axes.spines.top": False, "axes.spines.right": False})
    names = [row["repository"].split("/")[0] for row in rows]
    fig, axes = plt.subplots(1, 2, figsize=(10, 3.6), layout="constrained")
    axes[0].barh(names, [row["scanned"] for row in rows], color="#517d89")
    axes[0].set_xlabel("Selected source files scanned")
    axes[1].barh(names, [row["findings"] for row in rows], color="#c84335")
    axes[1].set_xlabel("Raw static findings (review candidates)")
    axes[1].set_xticks(range(max(row["findings"] for row in rows) + 1))
    for ax in axes:
        ax.set_xlim(left=0)
    fig.savefig(publication / "scan-results.pdf", metadata={"CreationDate": None})
    fig.savefig(publication / "scan-results.png", dpi=180)
    plt.close(fig)
    pio_rows = [row for row in rows if row["platformio_before"] or row["platformio_after"]]
    fig, ax = plt.subplots(figsize=(7, 3), layout="constrained")
    ax.bar(
        ["12 November baseline", "14 November refinement"],
        [
            sum(r["platformio_before"] for r in pio_rows),
            sum(r["platformio_after"] for r in pio_rows),
        ],
        color=["#517d89", "#c84335"],
    )
    ax.set_ylabel("Declared PlatformIO environments")
    ax.set_title("Metadata inventory, not tested boards or effective builds")
    fig.savefig(publication / "platformio-context.pdf", metadata={"CreationDate": None})
    fig.savefig(publication / "platformio-context.png", dpi=180)
    plt.close(fig)
    print(f"Generated report inputs: {scanned}/{selected} files, {total} raw findings")


if __name__ == "__main__":
    main()
