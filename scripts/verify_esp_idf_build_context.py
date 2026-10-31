from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

from vigil_fuse.scanner import scan

BOOT_VALIDATION_RULES = frozenset({"FUSE006", "FUSE007"})


def build_report(
    project_dir: Path,
    *,
    expected_target: str,
    expected_version: str,
    idf_commit: str,
    image_digest: str,
    source_project: str,
    build_dir: str = "build",
) -> dict[str, object]:
    """Verify FUSE's selected-build observations against an ESP-IDF build."""
    result = scan(project_dir.resolve(), profile="esp-idf", build_dir=build_dir)
    context = result.project_context
    origin = context.configuration_origin
    observed_version = context.framework_version
    boot_findings = [
        finding for finding in result.findings if finding.rule_id in BOOT_VALIDATION_RULES
    ]
    errors: list[str] = []

    if context.framework != "esp-idf":
        errors.append(f"Expected ESP-IDF context, observed {context.framework!r}.")
    if context.target != expected_target:
        errors.append(f"Expected target {expected_target!r}, observed {context.target!r}.")
    if observed_version is None or observed_version.removeprefix(
        "v"
    ) != expected_version.removeprefix("v"):
        errors.append(f"Expected ESP-IDF {expected_version!r}, observed {observed_version!r}.")
    if origin.status != "selected" or origin.selected_sdkconfig is None:
        errors.append(
            "Expected a readable selected sdkconfig, "
            f"observed origin status {origin.status!r} and path {origin.selected_sdkconfig!r}."
        )
    if boot_findings:
        rules = ", ".join(sorted({finding.rule_id for finding in boot_findings}))
        errors.append(
            f"Clean upstream example unexpectedly triggered boot-validation rules: {rules}."
        )

    report: dict[str, object] = {
        "schema_version": 1,
        "verification_status": "failed" if errors else "passed",
        "source": {
            "project": source_project,
            "idf_version": expected_version,
            "idf_commit": idf_commit,
            "container_image": f"espressif/idf@{image_digest}",
        },
        "build": {
            "target_expected": expected_target,
            "target_observed": context.target,
            "idf_version_observed": observed_version,
            "configuration_origin_status": origin.status,
            "selected_sdkconfig": origin.selected_sdkconfig,
            "selected_sdkconfig_source": origin.selected_sdkconfig_source,
            "defaults_source": origin.defaults_source,
            "defaults_order_resolved": origin.defaults_order_resolved,
            "default_files": [
                {
                    "path": item.path,
                    "target_specific": item.target_specific,
                    "state": item.state,
                    "sha256": item.sha256,
                }
                for item in origin.default_files
            ],
        },
        "scan": {
            "input_manifest_sha256": result.input_manifest_sha256,
            "files_discovered": result.files_discovered,
            "files_scanned": result.files_scanned,
            "native_findings": len(result.findings),
            "boot_validation_findings": [
                {"rule_id": finding.rule_id, "file": finding.file} for finding in boot_findings
            ],
        },
        "verification_errors": errors,
    }
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("project_dir", type=Path)
    parser.add_argument("--build-dir", default="build")
    parser.add_argument("--expected-target", required=True)
    parser.add_argument("--expected-version", required=True)
    parser.add_argument("--idf-commit", required=True)
    parser.add_argument("--image-digest", required=True)
    parser.add_argument("--source-project", required=True)
    parser.add_argument("--report", type=Path)
    args = parser.parse_args()

    report = build_report(
        args.project_dir,
        build_dir=args.build_dir,
        expected_target=args.expected_target,
        expected_version=args.expected_version,
        idf_commit=args.idf_commit,
        image_digest=args.image_digest,
        source_project=args.source_project,
    )
    output = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.report is not None:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(output, encoding="utf-8")
    sys.stdout.write(output)
    return 0 if report["verification_status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
