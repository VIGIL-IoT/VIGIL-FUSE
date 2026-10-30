"""Run a local end-to-end smoke check for FUSE's optional Gitleaks adapter."""

from __future__ import annotations

import argparse
import json
import os
import secrets
import shutil
import string
import subprocess
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
RUN_TIMEOUT_SECONDS = 240


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


def create_fixture_repository(repository: Path, *, positive: bool) -> str | None:
    repository.mkdir()
    token: str | None = None
    if positive:
        alphabet = string.ascii_letters + string.digits
        token = "ghp_" + "".join(secrets.choice(alphabet) for _ in range(40))
        contents = f"GITHUB_TOKEN={token}\n"
    else:
        contents = "FIRMWARE_MODE=production\n"
    (repository / ".env").write_text(contents, encoding="utf-8")

    commands = [
        ["git", "init", "--quiet"],
        ["git", "add", ".env"],
        [
            "git",
            "-c",
            "user.name=FUSE integration fixture",
            "-c",
            "user.email=fuse-fixture@example.invalid",
            "commit",
            "--quiet",
            "-m",
            "add synthetic integration fixture",
        ],
    ]
    for command in commands:
        require_success(run(command, cwd=repository), "Local fixture setup")
    return token


def scan_fixture(
    repository: Path,
    output: Path,
    env: dict[str, str],
    *,
    token: str | None,
    positive: bool,
    expected_version: str | None,
) -> int:
    result = run(
        [
            sys.executable,
            "-m",
            "vigil_fuse",
            "scan",
            str(repository),
            "--git-history",
            "--no-sbom",
            "--no-vulnerabilities",
            "--no-firmware",
            "--format",
            "json",
            "--output-dir",
            str(output),
        ],
        cwd=ROOT,
        env=env,
    )
    require_success(result, "FUSE scan")

    report_path = output / "findings.json"
    artifact_path = output / "git-history-findings.json"
    if not report_path.is_file() or not artifact_path.is_file():
        raise RuntimeError("FUSE did not produce the expected scan and history reports.")
    report_text = report_path.read_text(encoding="utf-8")
    artifact_text = artifact_path.read_text(encoding="utf-8")
    ensure_secret_not_persisted(output, token, result.stdout + result.stderr)
    try:
        report = json.loads(report_text)
        artifact = json.loads(artifact_text)
    except json.JSONDecodeError as error:
        raise RuntimeError("FUSE output was not readable JSON.") from error
    if not isinstance(report, dict) or not isinstance(artifact, dict):
        raise RuntimeError("FUSE output had an unexpected JSON structure.")
    if artifact.get("secrets_redacted") is not True:
        raise RuntimeError("Gitleaks history artifact does not declare secret redaction.")

    coverage = report.get("coverage")
    statuses = coverage.get("analyzers", []) if isinstance(coverage, dict) else []
    if not isinstance(statuses, list):
        raise RuntimeError("FUSE report did not contain analyzer coverage records.")
    status = next(
        (
            item
            for item in statuses
            if isinstance(item, dict) and item.get("name") == "gitleaks-history"
        ),
        None,
    )
    if not isinstance(status, dict) or status.get("status") != "completed":
        raise RuntimeError("FUSE did not report completed Gitleaks analysis.")
    reported_version = str(status.get("version", ""))
    if expected_version and expected_version not in reported_version:
        raise RuntimeError("FUSE reported a different Gitleaks version.")
    report_findings = report.get("findings")
    if not isinstance(report_findings, list):
        raise RuntimeError("FUSE report did not contain a findings list.")
    findings = [
        finding
        for finding in report_findings
        if isinstance(finding, dict) and finding.get("analyzer") == "gitleaks-history"
    ]
    if positive and not findings:
        raise RuntimeError("The synthetic positive fixture produced no finding.")
    if not positive and findings:
        raise RuntimeError("The clean control fixture produced a Gitleaks finding.")
    return len(findings)


def ensure_secret_not_persisted(output: Path, token: str | None, output_text: str) -> None:
    if token is None:
        return
    token_bytes = token.encode("utf-8")
    if token in output_text:
        raise RuntimeError("The synthetic value appeared in captured output.")
    for path in output.rglob("*"):
        if path.is_file() and token_bytes in path.read_bytes():
            raise RuntimeError("The synthetic value appeared in a generated report artifact.")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--expected-version",
        help="require the installed Gitleaks version string to include this value",
    )
    args = parser.parse_args()

    git = shutil.which("git")
    gitleaks = shutil.which("gitleaks")
    if git is None or gitleaks is None:
        parser.error("Git and Gitleaks must be available on PATH")

    version_result = run([gitleaks, "version"])
    require_success(version_result, "Gitleaks version check")
    version = (version_result.stdout or version_result.stderr).strip()
    if not version:
        raise RuntimeError("Gitleaks did not report its version.")
    if args.expected_version and args.expected_version not in version:
        raise RuntimeError("Installed Gitleaks version did not match --expected-version.")

    env = os.environ.copy()
    source_path = str(ROOT / "src")
    env["PYTHONPATH"] = os.pathsep.join(
        part for part in (source_path, env.get("PYTHONPATH", "")) if part
    )

    with tempfile.TemporaryDirectory(prefix="fuse-gitleaks-e2e-") as temporary:
        root = Path(temporary)
        cases = (
            ("positive", True),
            ("negative", False),
        )
        results: list[tuple[str, int]] = []
        for label, positive in cases:
            repository = root / label
            output = root / f"{label}-reports"
            token = create_fixture_repository(repository, positive=positive)
            finding_count = scan_fixture(
                repository,
                output,
                env=env,
                token=token,
                positive=positive,
                expected_version=args.expected_version,
            )
            results.append((label, finding_count))

    summary = ", ".join(f"{label}={count}" for label, count in results)
    print(
        f"Gitleaks adapter smoke check passed: {version}; findings {summary}; report values redacted."
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, RuntimeError, subprocess.TimeoutExpired) as error:
        raise SystemExit(f"Gitleaks adapter smoke check failed: {error}") from error
