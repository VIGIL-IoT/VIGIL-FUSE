"""Run the pinned NIST SARD CWE-259 C catalogue against FUSE001."""

from __future__ import annotations

import argparse
from collections import Counter
from datetime import UTC, datetime
import hashlib
import json
import re
from pathlib import Path, PurePosixPath, PureWindowsPath
import subprocess
import sys
import tempfile
from typing import TYPE_CHECKING, Any

ROOT = Path(__file__).resolve().parents[1]
if TYPE_CHECKING:
    from . import evaluate_sard_fuse001_cohort as cohort
elif __package__:
    from . import evaluate_sard_fuse001_cohort as cohort
else:  # Support direct execution from the repository root.
    sys.path.insert(0, str(ROOT))
    from scripts import evaluate_sard_fuse001_cohort as cohort

DEFAULT_MANIFEST = (
    ROOT / "reports/benchmark/sard-fuse001-cwe259-c-catalogue-manifest-2026-10-31.json"
)
DEFAULT_OUTPUT = ROOT / "reports/benchmark/sard-fuse001-cwe259-c-catalogue-results-2026-10-31.json"
_SHA256_PATTERN = re.compile(r"[0-9a-f]{64}\Z")
_VERSION_PATTERN = re.compile(r"[0-9]+(?:\.[0-9]+){1,2}\Z")


def _safe_manifest_path(value: Any) -> str:
    if not isinstance(value, str) or not value or "\x00" in value or "\\" in value:
        raise ValueError("manifest contains an invalid relative path")
    path = PurePosixPath(value)
    if (
        path.is_absolute()
        or PureWindowsPath(value).drive
        or ".." in path.parts
        or path.as_posix() != value
    ):
        raise ValueError("manifest contains an unsafe relative path")
    return path.as_posix()


def load_manifest(path: Path) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    manifest = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(manifest, dict) or manifest.get("manifest_version") != 1:
        raise ValueError("unsupported SARD manifest format")
    selection = manifest.get("selection")
    cases = manifest.get("cases")
    if not isinstance(selection, dict) or not isinstance(cases, list) or not cases:
        raise ValueError("SARD manifest is missing its selection or case list")
    criteria = selection.get("criteria")
    if criteria != {"flaw": "CWE-259", "language": "c", "status": "accepted"}:
        raise ValueError("SARD manifest selection does not match the documented query")
    if selection.get("observed_state") != "mixed":
        raise ValueError("SARD manifest contains an unexpected test-case state")
    if selection.get("case_count") != len(cases) or selection.get("api_total") != len(cases):
        raise ValueError("SARD manifest case count does not match the recorded API total")

    identifiers: set[str] = set()
    for case in cases:
        if not isinstance(case, dict):
            raise ValueError("SARD manifest contains a malformed case")
        case_id = case.get("case_id")
        version = case.get("version")
        if not isinstance(case_id, str) or not case_id.isdecimal() or case_id in identifiers:
            raise ValueError("SARD manifest case identifiers must be unique decimal strings")
        identifiers.add(case_id)
        if not isinstance(version, str) or _VERSION_PATTERN.fullmatch(version) is None:
            raise ValueError(f"invalid version for SARD case {case_id}")
        if case.get("state") != "mixed" or case.get("language") != "c":
            raise ValueError(f"unexpected state or language for SARD case {case_id}")
        archive_hash = case.get("archive_sha256")
        if not isinstance(archive_hash, str) or _SHA256_PATTERN.fullmatch(archive_hash) is None:
            raise ValueError(f"invalid archive digest for SARD case {case_id}")
        archive_bytes = case.get("archive_bytes")
        if (
            not isinstance(archive_bytes, int)
            or isinstance(archive_bytes, bool)
            or not 0 < archive_bytes <= cohort.MAX_ARCHIVE_BYTES
        ):
            raise ValueError(f"invalid archive size for SARD case {case_id}")
        expected_url = f"https://samate.nist.gov/SARD/downloads/versions/{case_id}-v{version}.zip"
        if case.get("archive_url") != expected_url:
            raise ValueError(f"unexpected archive URL for SARD case {case_id}")

        targets = case.get("target_files")
        sarif_targets = case.get("sarif_targets")
        if not isinstance(targets, list) or not targets or not isinstance(sarif_targets, list):
            raise ValueError(f"SARD case {case_id} has missing target metadata")
        target_paths: set[str] = set()
        target_basenames: set[str] = set()
        for target in targets:
            if not isinstance(target, dict):
                raise ValueError(f"SARD case {case_id} has a malformed source target")
            relative_path = _safe_manifest_path(target.get("path"))
            target_hash = target.get("sha256")
            target_length = target.get("length")
            if (
                relative_path in target_paths
                or PurePosixPath(relative_path).name in target_basenames
            ):
                raise ValueError(f"SARD case {case_id} has duplicate source targets")
            if not isinstance(target_hash, str) or _SHA256_PATTERN.fullmatch(target_hash) is None:
                raise ValueError(f"SARD case {case_id} has an invalid source digest")
            if (
                not isinstance(target_length, int)
                or isinstance(target_length, bool)
                or target_length < 0
            ):
                raise ValueError(f"SARD case {case_id} has an invalid source length")
            target_paths.add(relative_path)
            target_basenames.add(PurePosixPath(relative_path).name)
        normalized_sarif = {_safe_manifest_path(target) for target in sarif_targets}
        if not normalized_sarif or not normalized_sarif.issubset(target_paths):
            raise ValueError(f"SARD case {case_id} SARIF targets do not match its source artifacts")

    return manifest, cases


def _verify_source_targets(case: dict[str, Any], root: Path) -> None:
    resolved_root = root.resolve()
    for target in case["target_files"]:
        relative = PurePosixPath(_safe_manifest_path(target["path"]))
        source_path = root.joinpath(*relative.parts)
        if not source_path.resolve(strict=True).is_relative_to(resolved_root):
            raise ValueError(f"SARD source target escapes case {case['case_id']}")
        content = source_path.read_bytes()
        if len(content) != target["length"]:
            raise ValueError(f"source length mismatch for SARD case {case['case_id']}")
        if hashlib.sha256(content).hexdigest() != target["sha256"]:
            raise ValueError(f"source SHA-256 mismatch for SARD case {case['case_id']}")


def _finding_file(finding: dict[str, Any]) -> str:
    location = finding.get("location")
    value = location.get("file") if isinstance(location, dict) else None
    if not isinstance(value, str) or not value:
        return "(unresolved)"
    return value.replace("\\", "/").rsplit("/", 1)[-1]


def summarize_findings(case: dict[str, Any], findings: list[dict[str, Any]]) -> dict[str, Any]:
    counts = Counter(_finding_file(finding) for finding in findings)
    targets = [PurePosixPath(path).name for path in case["sarif_targets"]]
    target_results = [
        {"file": target, "detected": counts[target] > 0, "finding_count": counts[target]}
        for target in targets
    ]
    additional_files = sorted(set(counts) - set(targets))
    versions = sorted(
        {
            version
            for finding in findings
            if isinstance((version := finding.get("rule_version")), str)
        }
    )
    return {
        "finding_count": len(findings),
        "files_with_findings": dict(sorted(counts.items())),
        "nist_sarif_targets": target_results,
        "additional_fuse001_files": additional_files,
        "rule_versions": versions,
    }


def _git_revision() -> str | None:
    try:
        return subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=ROOT,
            capture_output=True,
            check=True,
            text=True,
            timeout=5,
        ).stdout.strip()
    except (OSError, subprocess.SubprocessError):
        return None


def evaluate(manifest_path: Path, case_limit: int | None = None) -> dict[str, Any]:
    manifest, manifest_cases = load_manifest(manifest_path)
    selected_cases = manifest_cases if case_limit is None else manifest_cases[:case_limit]
    result_cases: list[dict[str, Any]] = []
    with tempfile.TemporaryDirectory(prefix="fuse-sard-catalogue-") as temporary:
        temporary_root = Path(temporary)
        for index, case_data in enumerate(selected_cases, start=1):
            case_id = case_data["case_id"]
            target_files = case_data["target_files"]
            sarif_targets = case_data["sarif_targets"]
            sarif_target_basenames = tuple(PurePosixPath(path).name for path in sarif_targets)
            case = cohort.SardCase(
                case_id=case_id,
                flow_variant=str(case_data.get("flow_variant", "unknown")),
                archive_sha256=case_data["archive_sha256"],
                target_filename=sarif_target_basenames[0],
                expected_fuse_files=tuple(
                    PurePosixPath(target["path"]).name for target in target_files
                ),
                version=case_data["version"],
            )
            case_root = temporary_root / case_id
            case_root.mkdir()
            archive_path = case_root / "case.zip"
            source_root = case_root / "source"
            report_path = case_root / "findings.json"
            cohort.download_case(case, archive_path)
            if archive_path.stat().st_size != case_data["archive_bytes"]:
                raise ValueError(f"archive length mismatch for SARD case {case_id}")
            cohort._safe_extract_zip(archive_path, source_root)
            _verify_source_targets(case_data, source_root)
            findings, files_scanned = cohort._run_scan(case_id, source_root, report_path)
            case_result = summarize_findings(case_data, findings)
            case_result.update(
                {
                    "case_id": case_id,
                    "flow_variant": case.flow_variant,
                    "files_scanned": files_scanned,
                    "target_source_files": len(target_files),
                    "status": "completed",
                }
            )
            result_cases.append(case_result)
            hits = sum(target["detected"] for target in case_result["nist_sarif_targets"])
            print(
                f"[{index}/{len(selected_cases)}] case {case_id}: "
                f"{hits}/{len(sarif_targets)} NIST SARIF target files matched, "
                f"{case_result['finding_count']} FUSE001 findings",
                flush=True,
            )

    total_targets = sum(len(case["sarif_targets"]) for case in selected_cases)
    target_hits = sum(
        target["detected"] for case in result_cases for target in case["nist_sarif_targets"]
    )
    target_findings = sum(
        target["finding_count"] for case in result_cases for target in case["nist_sarif_targets"]
    )
    findings_total = sum(case["finding_count"] for case in result_cases)
    try:
        tree_state = subprocess.run(
            ["git", "status", "--porcelain"],
            cwd=ROOT,
            capture_output=True,
            check=True,
            text=True,
            timeout=5,
        ).stdout.strip()
        working_tree_clean = not tree_state
    except (OSError, subprocess.SubprocessError):
        working_tree_clean = None

    return {
        "schema_version": 1,
        "experiment": {
            "name": "FUSE001 NIST SARD CWE-259 C catalogue regression",
            "dataset": manifest["dataset"],
            "manifest_sha256": hashlib.sha256(manifest_path.read_bytes()).hexdigest(),
            "source_revision": _git_revision(),
            "source_working_tree_clean": working_tree_clean,
            "generated_at_utc": datetime.now(UTC).isoformat(timespec="seconds"),
            "selection": manifest["selection"],
            "reproduction": "python scripts/evaluate_sard_fuse001_catalogue.py",
            "scope_limit": (
                "Rule-specific regression only. SARD Juliet cases are synthetic mixed-path inputs. "
                "This result is not a precision, recall, field-accuracy, or firmware-coverage estimate."
            ),
        },
        "summary": {
            "catalogue_case_count": len(manifest_cases),
            "cases_evaluated": len(result_cases),
            "complete_catalogue_evaluated": len(result_cases) == len(manifest_cases),
            "nist_sarif_target_files": total_targets,
            "nist_sarif_target_files_detected": target_hits,
            "nist_sarif_target_findings": target_findings,
            "fuse001_findings": findings_total,
            "additional_fuse001_file_observations": sum(
                len(case["additional_fuse001_files"]) for case in result_cases
            ),
            "accuracy_metrics": "not-computed",
            "accuracy_metric_limit": (
                "The catalogue's SARIF source targets label weakness flows, while each mixed case "
                "also contains good paths. File-level matches outside the SARIF target cannot be "
                "classified as false positives from these labels alone."
            ),
        },
        "cases": result_cases,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--limit", type=int, help="evaluate only the first N cases")
    arguments = parser.parse_args()
    if arguments.limit is not None and arguments.limit < 1:
        parser.error("--limit must be a positive integer")
    result = evaluate(arguments.manifest, arguments.limit)
    arguments.output.parent.mkdir(parents=True, exist_ok=True)
    arguments.output.write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    summary = result["summary"]
    print(
        "Result: "
        f"{summary['nist_sarif_target_files_detected']}/"
        f"{summary['nist_sarif_target_files']} NIST SARIF target files detected; "
        f"{summary['fuse001_findings']} FUSE001 findings across "
        f"{summary['cases_evaluated']} cases."
    )
    print(f"Structured result: {arguments.output}")
    print("Precision, recall, false-positive rate, and field accuracy were not computed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
