"""Run local positive and clean-control checks for FUSE's Syft and OSV adapters."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
RUN_TIMEOUT_SECONDS = 240
POSITIVE_REQUIREMENT = "urllib3==1.25.2"
CLEAN_REQUIREMENT = "idna==3.15"


def run(
    command: list[str],
    *,
    cwd: Path | None = None,
    env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        cwd=cwd,
        env=env,
        capture_output=True,
        check=False,
        text=True,
        timeout=RUN_TIMEOUT_SECONDS,
    )


def require_success(result: subprocess.CompletedProcess[str], label: str) -> None:
    if result.returncode != 0:
        raise RuntimeError(f"{label} failed with exit status {result.returncode}; output omitted.")


def tool_version(executable: str, arguments: list[str], expected: str | None) -> str:
    result = run([executable, *arguments])
    require_success(result, Path(executable).name + " version check")
    version = f"{result.stdout}\n{result.stderr}".strip()
    if not version:
        raise RuntimeError(f"{Path(executable).name} did not report its version.")
    if expected and expected not in version:
        raise RuntimeError(f"{Path(executable).name} did not match the expected version.")
    return version


def analyzer_status(report: dict[str, Any], name: str) -> dict[str, Any]:
    coverage = report.get("coverage")
    analyzers = coverage.get("analyzers", []) if isinstance(coverage, dict) else []
    if not isinstance(analyzers, list):
        raise RuntimeError("FUSE report did not contain analyzer coverage records.")
    status = next(
        (item for item in analyzers if isinstance(item, dict) and item.get("name") == name),
        None,
    )
    if not isinstance(status, dict):
        raise RuntimeError(f"FUSE report did not contain {name} status.")
    return status


def scan_case(
    *,
    label: str,
    requirement: str | None,
    expected_syft: str | None,
    expected_osv: str | None,
    root: Path,
    env: dict[str, str],
) -> int:
    target = root / f"{label}-project"
    output = root / f"{label}-reports"
    target.mkdir()
    if requirement is None:
        (target / "README.md").write_text(
            "Synthetic project without dependencies.\n", encoding="utf-8"
        )
    else:
        (target / "requirements.txt").write_text(requirement + "\n", encoding="utf-8")

    result = run(
        [
            sys.executable,
            "-m",
            "vigil_fuse",
            "scan",
            str(target),
            "--sbom",
            "--vulnerabilities",
            "--format",
            "json",
            "--output-dir",
            str(output),
        ],
        cwd=ROOT,
        env=env,
    )
    expected_exit = 2 if label == "no-sources" else 0
    if result.returncode != expected_exit:
        raise RuntimeError(
            f"FUSE {label} scan returned {result.returncode}, expected {expected_exit}; output omitted."
        )

    report_path = output / "findings.json"
    sbom_path = output / "components.cdx.json"
    osv_path = output / "osv-results.json"
    if not report_path.is_file() or not sbom_path.is_file():
        raise RuntimeError(f"FUSE {label} scan did not produce its scan and SBOM reports.")
    if label != "no-sources" and not osv_path.is_file():
        raise RuntimeError(f"FUSE {label} scan did not produce OSV results.")
    try:
        report = json.loads(report_path.read_text(encoding="utf-8"))
        sbom = json.loads(sbom_path.read_text(encoding="utf-8"))
        osv = json.loads(osv_path.read_text(encoding="utf-8")) if osv_path.is_file() else None
    except (OSError, json.JSONDecodeError) as error:
        raise RuntimeError(f"FUSE {label} scan produced unreadable JSON.") from error
    if not isinstance(report, dict) or not isinstance(sbom, dict):
        raise RuntimeError(f"FUSE {label} scan produced an unexpected JSON structure.")
    components = sbom.get("components", [])
    if sbom.get("bomFormat") != "CycloneDX" or not isinstance(components, list):
        raise RuntimeError(f"FUSE {label} scan did not produce a component inventory.")
    if label == "no-sources" and components:
        raise RuntimeError("The no-source fixture unexpectedly produced SBOM components.")
    if label != "no-sources" and not components:
        raise RuntimeError(f"FUSE {label} fixture produced an empty component inventory.")
    if label != "no-sources" and (
        not isinstance(osv, dict) or not isinstance(osv.get("results"), list)
    ):
        raise RuntimeError(f"FUSE {label} scan did not produce OSV results.")

    syft_status = analyzer_status(report, "syft")
    osv_status = analyzer_status(report, "osv-scanner")
    expected_osv_status = "partial" if label == "no-sources" else "completed"
    if syft_status.get("status") != "completed" or osv_status.get("status") != expected_osv_status:
        raise RuntimeError(f"FUSE {label} scan reported unexpected dependency adapter status.")
    if expected_syft and expected_syft not in str(syft_status.get("version", "")):
        raise RuntimeError("FUSE reported a different Syft version.")
    if expected_osv and expected_osv not in str(osv_status.get("version", "")):
        raise RuntimeError("FUSE reported a different OSV-Scanner version.")

    findings = report.get("findings")
    if not isinstance(findings, list):
        raise RuntimeError("FUSE report did not contain a findings list.")
    osv_findings = [
        finding
        for finding in findings
        if isinstance(finding, dict) and finding.get("analyzer") == "osv-scanner"
    ]
    if label == "positive" and not osv_findings:
        raise RuntimeError("The vulnerable dependency fixture produced no OSV finding.")
    if label in {"clean", "no-sources"} and osv_findings:
        raise RuntimeError("A clean dependency control produced an OSV finding.")
    if label == "no-sources":
        if osv_path.exists():
            raise RuntimeError(
                "FUSE wrote a synthetic OSV result artifact without package sources."
            )
        if "not performed" not in str(osv_status.get("detail", "")):
            raise RuntimeError("FUSE did not explain why OSV analysis was partial.")
        return 0
    return len(osv_findings)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--expected-syft-version", help="require this Syft version substring")
    parser.add_argument("--expected-osv-version", help="require this OSV-Scanner version substring")
    args = parser.parse_args()

    syft = shutil.which("syft")
    osv_scanner = shutil.which("osv-scanner")
    if syft is None or osv_scanner is None:
        parser.error("Syft and OSV-Scanner must be available on PATH")
    syft_version = tool_version(syft, ["version"], args.expected_syft_version)
    osv_version = tool_version(osv_scanner, ["--version"], args.expected_osv_version)

    env = os.environ.copy()
    source_path = str(ROOT / "src")
    env["PYTHONPATH"] = os.pathsep.join(
        part for part in (source_path, env.get("PYTHONPATH", "")) if part
    )

    with tempfile.TemporaryDirectory(prefix="fuse-dependency-adapters-e2e-") as temporary:
        root = Path(temporary)
        positive = scan_case(
            label="positive",
            requirement=POSITIVE_REQUIREMENT,
            expected_syft=args.expected_syft_version,
            expected_osv=args.expected_osv_version,
            root=root,
            env=env,
        )
        clean = scan_case(
            label="clean",
            requirement=CLEAN_REQUIREMENT,
            expected_syft=args.expected_syft_version,
            expected_osv=args.expected_osv_version,
            root=root,
            env=env,
        )
        no_sources = scan_case(
            label="no-sources",
            requirement=None,
            expected_syft=args.expected_syft_version,
            expected_osv=args.expected_osv_version,
            root=root,
            env=env,
        )

    syft_label = next(
        (line.strip() for line in syft_version.splitlines() if "Version:" in line),
        syft_version.splitlines()[0],
    )
    osv_label = osv_version.splitlines()[0]
    print(
        "Dependency adapter smoke check passed: "
        f"{syft_label}; {osv_label}; findings positive={positive}, clean={clean}, "
        f"no-sources={no_sources} with partial OSV status."
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, RuntimeError, subprocess.TimeoutExpired) as error:
        raise SystemExit(f"Dependency adapter smoke check failed: {error}") from error
