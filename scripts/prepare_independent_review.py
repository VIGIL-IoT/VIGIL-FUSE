"""Fetch preregistered public source and prepare blinded, unanswered reviewer forms."""

from __future__ import annotations

import argparse
import base64
from concurrent.futures import ThreadPoolExecutor
import csv
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scripts.freeze_evaluation import verify  # noqa: E402
from scripts.run_embedded_ghidra_matrix import write_json  # noqa: E402


def api(path: str) -> dict:
    return json.loads(subprocess.check_output(["gh", "api", path], timeout=120))


def select_paths(tree: list[dict], seed: str) -> list[dict]:
    ranked = sorted(
        tree, key=lambda item: hashlib.sha256((seed + item["path"]).encode()).hexdigest()
    )
    for item in ranked:
        path = PurePosixPath(item["path"])
        if path.is_absolute() or ".." in path.parts or "\\" in item["path"]:
            raise ValueError("Unsafe upstream path")
    source = [
        item
        for item in ranked
        if item["type"] == "blob" and PurePosixPath(item["path"]).suffix in {".c", ".h"}
    ]
    keys = [
        item
        for item in ranked
        if item["type"] == "blob" and PurePosixPath(item["path"]).suffix in {".pem", ".key"}
    ]
    return source[:16] + keys[:8]


def prepare(selection_path: Path, work: Path, output: Path) -> None:
    selection = json.loads(selection_path.read_text())
    frozen = json.loads((selection_path.parent / selection["frozen_manifest"]).read_text())
    verify(frozen)
    known = set(frozen["detector_files"].values())
    prior = "\n".join(
        path.read_text(encoding="utf-8")
        for path in (ROOT / "reports/repository-scans").rglob("*manifest*.json")
    )
    output.mkdir(parents=True, exist_ok=True)
    if (output / "cases.json").exists():
        raise ValueError("Refusing to overwrite a completed reviewer packet")
    cases, inventories, observations = [], [], []
    for project in selection["projects"]:
        repository, commit = project["repository"], project["commit"]
        if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository) or not re.fullmatch(
            r"[a-f0-9]{40}", commit
        ):
            raise ValueError("Invalid pinned project")
        if "https://github.com/" + repository in prior:
            raise ValueError("Project already appears in a prior scan manifest")
        response = api(f"repos/{repository}/git/trees/{commit}?recursive=1")
        if response.get("truncated"):
            raise ValueError("Truncated upstream tree cannot define a reproducible selection")
        selected = select_paths(response["tree"], selection["seed"])
        root = work / repository.replace("/", "_")
        root.mkdir(parents=True, exist_ok=True)

        def fetch(item: dict) -> dict:
            path = root / item["path"]
            if path.is_symlink():
                raise ValueError("Symlink in local source cache")
            if path.is_file():
                blob = path.read_bytes()
            else:
                data = api(f"repos/{repository}/git/blobs/{item['sha']}")
                blob = base64.b64decode(data["content"], validate=False)
            if (
                len(blob) > 1024 * 1024
                or hashlib.sha1(f"blob {len(blob)}\0".encode() + blob).hexdigest() != item["sha"]
            ):
                raise ValueError("Upstream blob failed size or identity verification")
            digest = hashlib.sha256(blob.replace(b"\r\n", b"\n")).hexdigest()
            if digest in known:
                raise ValueError("Holdout overlaps frozen development/regression inputs")
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(blob)
            return {
                "path": item["path"],
                "sha256": digest,
                "git_blob": item["sha"],
                "bytes": len(blob),
            }

        with ThreadPoolExecutor(max_workers=6) as executor:
            sources = list(executor.map(fetch, selected))
        report_path = root.parent / (root.name + "-report.json")
        subprocess.run(
            [
                sys.executable,
                "-m",
                "vigil_fuse",
                "scan",
                str(root),
                "--no-network",
                "--format",
                "json",
                "--output",
                str(report_path),
            ],
            check=True,
            stdout=subprocess.DEVNULL,
        )
        report = json.loads(report_path.read_text())
        by_path = {}
        for finding in report["findings"]:
            by_path.setdefault(finding["file"], []).append(finding)
        ranked = sorted(
            sources,
            key=lambda item: hashlib.sha256(
                (selection["seed"] + item["path"]).encode()
            ).hexdigest(),
        )
        sample = [item for item in ranked if item["path"] in by_path][:4] + [
            item for item in ranked if item["path"] not in by_path
        ][:4]
        inventories.append(
            {
                **project,
                "selected_sources": sources,
                "files_discovered": report["summary"]["files_discovered"]
                if "files_discovered" in report["summary"]
                else report["coverage"].get("files_discovered"),
                "files_scanned": report["summary"]["files_scanned"],
                "coverage": report["coverage"],
                "sample_count": len(sample),
            }
        )
        for source in sample:
            identifier = hashlib.sha256(
                (repository + commit + source["path"]).encode()
            ).hexdigest()[:16]
            cases.append(
                {
                    "case_id": identifier,
                    "project": repository,
                    "commit": commit,
                    "file": source["path"],
                    "input_sha256": source["sha256"],
                    "source_url": f"https://github.com/{repository}/blob/{commit}/{source['path']}",
                    "license": project["license"],
                    "scope": selection["rule_scope"],
                    "instructions": "Review the complete linked file for each native rule. Record presence of the rule's narrowly defined condition, separately from deployment applicability. Do not infer that an example key is a deployed secret.",
                }
            )
            observations.append(
                {
                    "case_id": identifier,
                    "input_sha256": source["sha256"],
                    "emitted_rules": sorted(
                        {f["rule_id"] for f in by_path.get(source["path"], [])}
                    ),
                    "expected": "unknown",
                    "review_status": "not_started",
                }
            )
    cases.sort(key=lambda item: item["case_id"])
    write_json(
        output / "cases.json",
        {
            "fuse_commit": frozen["fuse_commit"],
            "cases": cases,
            "review_status": "not_started",
            "source_text": "not redistributed; pinned URLs and hashes only",
        },
    )
    write_json(
        output / "source-manifest.json",
        {
            "selection_sha256": hashlib.sha256(selection_path.read_bytes()).hexdigest(),
            "projects": inventories,
            "labels": "unopened; review pending",
        },
    )
    # Keep machine observations outside the reviewer packet to avoid answer leakage.
    write_json(work / "sealed-machine-observations.json", {"observations": observations})
    fields = [
        "case_id",
        "rule_id",
        "decision",
        "reason",
        "evidence_url_and_lines",
        "confidence",
        "applicability",
        "reviewer_id",
    ]
    for role in ("reviewer-a", "reviewer-b", "adjudication"):
        with (output / (role + ".csv")).open("w", newline="", encoding="utf-8") as stream:
            writer = csv.DictWriter(stream, fieldnames=fields)
            writer.writeheader()
            writer.writerows(
                {"case_id": case["case_id"], "rule_id": rule}
                for case in cases
                for rule in selection["rule_scope"]
            )
    instructions = """# Independent review packet

Status: not started. No human decisions, agreement or accuracy estimates exist.

Reviewers A and B must be independent people, work separately, and not inspect machine observations or each other's forms. Use cases.json for pinned source URLs and hashes. Source is linked, not copied. Review the complete file, including no-finding candidates, using the frozen rule descriptions in the repository's docs/rules.md at the recorded FUSE revision.

For each case/rule choose supported, unsupported, uncertain or not applicable. Supported means the specific static condition is present, not that a deployed vulnerability exists. Unsupported means the condition is absent. Provide source line evidence, reason, confidence (high/medium/low), and deployment applicability separately. Leave nothing blank at submission; explain uncertainty. Test fixtures and sample credentials need explicit applicability review.

Submit forms separately. A third person adjudicates disagreements after both forms are locked. The empty adjudication template does not contain either reviewer's decisions. Never turn uncertain or inapplicable records into positive labels. No field recall can be claimed without reviewed, applicable no-finding samples and defensible positive labels. Stratified sampling is deliberately enriched; it is not an estimate of natural repository prevalence.

Expected labels remain unknown until adjudication. Do not run accuracy metrics on fabricated decisions. Do not reuse this dataset for tuning while retaining its independent designation.
"""
    (output / "README.md").write_text(instructions, encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--selection", type=Path, required=True)
    parser.add_argument("--work", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    prepare(args.selection, args.work, args.output)


if __name__ == "__main__":
    main()
