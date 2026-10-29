from __future__ import annotations

import argparse
import hashlib
import json
import math
import subprocess
import sys
import time
from pathlib import Path
import tomllib


ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "reports" / "repository-scans" / "scan-manifest.json"
REPORT_ROOT = ROOT / "reports" / "repository-scans"
MAX_MANIFEST_FILE_BYTES = 100 * 1024 * 1024


def git_head(repository: Path) -> str:
    result = subprocess.run(
        ["git", "-C", str(repository), "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


def git_status(repository: Path, pathspecs: tuple[str, ...] = ()) -> str:
    command = ["git", "-C", str(repository), "status", "--porcelain", "--untracked-files=all"]
    if pathspecs:
        command.extend(("--", *pathspecs))
    result = subprocess.run(
        command,
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


def update_scanner_provenance(manifest_path: Path = MANIFEST) -> dict:
    source_root = ROOT / "src" / "vigil_fuse"
    files = sorted(
        (*source_root.rglob("*.py"), *source_root.rglob("*.json"), ROOT / "pyproject.toml"),
        key=lambda path: path.relative_to(ROOT).as_posix(),
    )
    digest = hashlib.sha256()
    for path in files:
        digest.update(path.relative_to(ROOT).as_posix().encode("utf-8"))
        digest.update(b"\0")
        digest.update(path.read_bytes())
        digest.update(b"\0")

    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    provenance = {
        "version": project["version"],
        "commit": git_head(ROOT),
        "source_tree_sha256": digest.hexdigest(),
        "source_tree_dirty": bool(git_status(ROOT, ("src/vigil_fuse", "pyproject.toml"))),
        "source_tree_scope": "src/vigil_fuse Python and JSON files plus pyproject.toml",
        "source_tree_hash_algorithm": "SHA-256 over sorted relative path, NUL, file bytes, NUL",
    }
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["fuse"] = provenance
    manifest_path.write_text(
        json.dumps(manifest, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    return provenance


def build_scan_command(checkout: Path, profile: str, scan: dict, output: Path) -> list[str]:
    command = [
        sys.executable,
        "-m",
        "vigil_fuse",
        "scan",
        str(checkout),
        "--profile",
        profile,
    ]
    for include in scan.get("includes", ()):
        if not isinstance(include, str):
            raise ValueError("Repository scan include patterns must be strings")
        command.extend(("--include", include))
    target_label = scan.get("target_label")
    if target_label is not None:
        if not isinstance(target_label, str) or not target_label.strip():
            raise ValueError("Repository scan target_label must be a non-empty string")
        command.extend(("--target-label", target_label))
    rule_timeout = scan.get("rule_timeout_seconds")
    if rule_timeout is not None:
        if (
            isinstance(rule_timeout, bool)
            or not isinstance(rule_timeout, (int, float))
            or not math.isfinite(rule_timeout)
            or not 0.1 <= rule_timeout <= 30
        ):
            raise ValueError("Repository scan rule_timeout_seconds must be between 0.1 and 30")
        command.extend(("--rule-timeout", str(rule_timeout)))
    max_file_bytes = scan.get("max_file_bytes")
    if max_file_bytes is not None:
        if (
            isinstance(max_file_bytes, bool)
            or not isinstance(max_file_bytes, int)
            or not 1 <= max_file_bytes <= MAX_MANIFEST_FILE_BYTES
        ):
            raise ValueError("max_file_bytes must be between 1 and 104857600")
        command.extend(("--max-file-bytes", str(max_file_bytes)))
    command.extend(("--output-dir", str(output)))
    return command


def report_has_incomplete_coverage(report: dict) -> bool:
    summary = report.get("summary")
    coverage = report.get("coverage")
    if not isinstance(summary, dict) or not summary.get("analysis_performed", False):
        return True
    if not isinstance(coverage, dict) or not isinstance(coverage.get("analyzers"), list):
        return True
    for analyzer in coverage["analyzers"]:
        if not isinstance(analyzer, dict):
            return True
        status = analyzer.get("status")
        if status in {"partial", "unavailable", "failed"}:
            return True
        if status == "skipped":
            intentional_rule_skip = (
                str(analyzer.get("name", "")).startswith("native-rule:")
                and analyzer.get("detail") in {
                    "No selected input was passed to this rule.",
                    "No selected input matched this rule's supported input scope.",
                }
            )
            if not intentional_rule_skip:
                return True
    module_statuses = (
        (report.get("build_context", {}), "platformio", {"partial", "invalid"}),
        (report.get("build_context", {}), "compilation_database", {"partial", "invalid"}),
        (report, "firmware_candidates", {"partial"}),
        (report, "github_actions", {"partial"}),
        (report, "hardware_netlist", {"partial", "invalid"}),
        (report, "hardware_bom", {"partial", "invalid"}),
        (report.get("product_context", {}), "vex_import", {"partial", "invalid"}),
    )
    for parent, key, incomplete_statuses in module_statuses:
        value = parent.get(key) if isinstance(parent, dict) else None
        if isinstance(value, dict) and value.get("status") in incomplete_statuses:
            return True
    provenance = report.get("provenance")
    if isinstance(provenance, dict) and provenance.get("status") not in {
        "not-requested",
        "subject-match",
    }:
        return True
    return False


def run(
    checkouts_root: Path,
    repository_ids: set[str] | None = None,
    *,
    manifest_path: Path = MANIFEST,
    report_root: Path = REPORT_ROOT,
) -> None:
    manifest_path = manifest_path.resolve()
    report_root = report_root.resolve()
    provenance = update_scanner_provenance(manifest_path)
    print(
        f"Scanner provenance: {provenance['version']} at {provenance['commit'][:12]}, "
        f"source SHA-256 {provenance['source_tree_sha256'][:12]}, "
        f"source tree {'dirty' if provenance['source_tree_dirty'] else 'clean'}",
        flush=True,
    )
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if not isinstance(manifest.get("repositories"), list):
        raise ValueError(f"Repository scan manifest has no repositories list: {manifest_path}")
    for repository in manifest["repositories"]:
        if repository_ids and repository["id"] not in repository_ids:
            continue
        checkout = checkouts_root / repository["id"]
        if not checkout.is_dir():
            raise FileNotFoundError(f"Missing checkout for {repository['name']}: {checkout}")
        actual_commit = git_head(checkout)
        if actual_commit != repository["commit"]:
            raise RuntimeError(
                f"Pinned checkout mismatch for {repository['name']}: "
                f"expected {repository['commit']}, got {actual_commit}"
            )
        dirty = git_status(checkout)
        if dirty:
            raise RuntimeError(
                f"Checkout for {repository['name']} has local changes; "
                f"refusing to scan an unpinned tree:\n{dirty}"
            )

        for scan in repository["scans"]:
            scan_id = scan.get("id")
            if not isinstance(scan_id, str) or not scan_id or Path(scan_id).is_absolute() or ".." in Path(scan_id).parts:
                raise ValueError(f"Invalid repository scan ID: {scan_id!r}")
            output = (report_root / scan_id).resolve()
            if not output.is_relative_to(report_root):
                raise ValueError(f"Repository scan output escapes report root: {scan_id!r}")
            command = build_scan_command(checkout, repository["profile"], scan, output)
            report_path = output / "findings.json"
            run_started_ns = time.time_ns()
            completed = subprocess.run(command, cwd=ROOT, check=False)
            if completed.returncode not in {0, 2}:
                raise RuntimeError(
                    f"FUSE failed for {repository['name']} scope {scan['id']} "
                    f"with exit code {completed.returncode}"
                )
            if not report_path.is_file() or report_path.stat().st_mtime_ns < run_started_ns:
                raise RuntimeError(
                    f"FUSE did not write a fresh JSON report for {repository['name']} scope {scan['id']}"
                )
            report = json.loads(report_path.read_text(encoding="utf-8"))
            if not isinstance(report.get("coverage"), dict) or not isinstance(report.get("summary"), dict):
                raise RuntimeError(f"FUSE report is missing coverage for {repository['name']} scope {scan['id']}")
            incomplete = report_has_incomplete_coverage(report)
            if (completed.returncode == 2) != incomplete:
                raise RuntimeError(
                    f"FUSE exit code and report coverage disagree for {repository['name']} scope {scan['id']}"
                )
            support = report["coverage"].get("support", {})
            print(
                f"Scanned {repository['name']} scope {scan['id']}: "
                f"exit {completed.returncode}, status {support.get('status', 'unknown')}, "
                f"support {support.get('label', 'unknown')}",
                flush=True,
            )


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Rescan the pinned repositories and scopes in the FUSE pilot manifest."
    )
    parser.add_argument(
        "checkouts_root",
        nargs="?",
        type=Path,
        default=ROOT.parent / "fuse-scan-targets",
        help="directory containing checkouts named after manifest repository IDs",
    )
    parser.add_argument(
        "--repository",
        action="append",
        dest="repository_ids",
        help="rescan one manifest repository ID; may be repeated",
    )
    parser.add_argument(
        "--provenance-only",
        action="store_true",
        help="refresh the manifest's FUSE source snapshot without rescanning repositories",
    )
    parser.add_argument(
        "--manifest",
        type=Path,
        default=MANIFEST,
        help="scan manifest to run; defaults to the main repository corpus",
    )
    parser.add_argument(
        "--report-root",
        type=Path,
        default=REPORT_ROOT,
        help="directory for per-scope reports; defaults to reports/repository-scans",
    )
    args = parser.parse_args()
    if args.provenance_only:
        provenance = update_scanner_provenance(args.manifest.resolve())
        print(
            f"Updated scanner provenance: {provenance['version']} at {provenance['commit'][:12]}, "
            f"source SHA-256 {provenance['source_tree_sha256'][:12]}, "
            f"source tree {'dirty' if provenance['source_tree_dirty'] else 'clean'}"
        )
        return
    selected = set(args.repository_ids) if args.repository_ids else None
    if selected:
        manifest_ids = {
            item["id"] for item in json.loads(args.manifest.read_text(encoding="utf-8"))["repositories"]
        }
        unknown = selected - manifest_ids
        if unknown:
            parser.error(f"unknown repository ID(s): {', '.join(sorted(unknown))}")
    run(
        args.checkouts_root.expanduser().resolve(),
        selected,
        manifest_path=args.manifest.expanduser().resolve(),
        report_root=args.report_root.expanduser().resolve(),
    )


if __name__ == "__main__":
    main()
