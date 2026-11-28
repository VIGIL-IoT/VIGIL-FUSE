"""GitHub Actions adapter for the FUSE CLI; no detection logic lives here."""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path

PROFILES = {"generic", "esp-idf", "zephyr", "embedded-linux", "rtl"}
LEVELS = {"none", "info", "low", "medium", "high", "critical"}


def choice(name: str, allowed: set[str]) -> str:
    value = os.environ[name]
    if value not in allowed:
        raise ValueError(f"Invalid {name}: expected one of {sorted(allowed)}")
    return value


def target_inside(root: Path, relative: str) -> Path:
    part = Path(relative)
    if part.is_absolute() or ".." in part.parts:
        raise ValueError("Project path must be relative to the checkout")
    target = (root / part).resolve(strict=True)
    if not target.is_relative_to(root.resolve()) or not target.is_dir():
        raise ValueError("Project path must be a directory inside the checkout")
    return target


def extract_base(workspace: Path, sha: str, destination: Path, archive: Path) -> None:
    if not re.fullmatch(r"[0-9a-f]{40}", sha):
        raise ValueError("Baseline requires a full pull request base SHA")
    with archive.open("wb") as out:
        subprocess.run(
            ["git", "-C", str(workspace), "archive", "--format=tar", sha],
            stdout=out,
            check=True,
            timeout=120,
        )
    total = 0
    with tarfile.open(archive) as tar:
        for entry in tar:
            path = Path(entry.name)
            if path.is_absolute() or ".." in path.parts or not (entry.isfile() or entry.isdir()):
                if entry.issym() or entry.islnk():
                    continue  # FUSE does not follow symlinks.
                raise ValueError("Unsafe entry in base archive")
            total += entry.size
            if total > 512 * 1024 * 1024:
                raise ValueError("Base archive exceeds 512 MiB extraction limit")
            tar.extract(entry, destination, filter="data")


def run_fuse(args: list[str], action: Path, cwd: Path) -> subprocess.CompletedProcess[str]:
    # Do not pass tokens, GitHub event data, or caller PYTHONPATH to scanner subprocesses.
    allowed = {
        "PATH",
        "SYSTEMROOT",
        "WINDIR",
        "TEMP",
        "TMP",
        "HOME",
        "USERPROFILE",
        "LOCALAPPDATA",
        "HOMEDRIVE",
        "HOMEPATH",
        "LANG",
        "LC_ALL",
    }
    env = {key: value for key, value in os.environ.items() if key.upper() in allowed}
    env["PYTHONPATH"] = str(action / "src")
    env["PYTHONNOUSERSITE"] = "1"
    return subprocess.run(
        [sys.executable, "-m", "vigil_fuse", *args],
        cwd=cwd,
        env=env,
        text=True,
        capture_output=True,
        timeout=1200,
    )


def checked(result: subprocess.CompletedProcess[str], allowed: set[int] = {0}) -> None:
    if result.returncode not in allowed:
        raise RuntimeError(f"FUSE command exited {result.returncode}: {result.stderr[-2000:]}")


def prepare_github_sarif(output: Path) -> None:
    """Keep FUSE evidence hashes while leaving GitHub's reserved hash for GitHub."""
    source = json.loads((output / "findings.sarif").read_text(encoding="utf-8"))
    for run in source.get("runs", []):
        for finding in run.get("results", []):
            fingerprints = finding.get("partialFingerprints", {})
            value = fingerprints.pop("primaryLocationLineHash", None)
            if value is not None:
                fingerprints["vigilIoTLocationEvidenceHash/v1"] = value
    (output / "github.sarif").write_text(json.dumps(source), encoding="utf-8")


def run_review() -> tuple[Path, str]:
    action = Path(os.environ["FUSE_ACTION_PATH"]).resolve(strict=True)
    workspace = Path(os.environ["GITHUB_WORKSPACE"]).resolve(strict=True)
    runner_temp = Path(os.environ["RUNNER_TEMP"]).resolve(strict=True)
    relative = os.environ["FUSE_PATH"]
    target = target_inside(workspace, relative)
    profile = choice("FUSE_PROFILE", PROFILES)
    threshold = choice("FUSE_FAIL_ON", LEVELS)
    baseline = choice("FUSE_BASELINE", {"true", "false"}) == "true"
    network = choice("FUSE_NETWORK", {"offline", "online"})
    dependencies = choice("FUSE_DEPENDENCIES", {"true", "false"}) == "true"
    if os.environ.get("FUSE_EVENT") == "pull_request_target":
        raise ValueError("pull_request_target is not supported for scanning untrusted PRs")
    if baseline and os.environ.get("FUSE_EVENT") != "pull_request":
        raise ValueError("Baseline comparison requires a pull_request event")
    output = Path(tempfile.mkdtemp(prefix="fuse-review-", dir=runner_temp))
    label = "github/target"
    options = [
        "--profile",
        profile,
        "--target-label",
        label,
        "--no-firmware",
        "--no-ghidra",
        "--no-git-history",
    ]
    options += (
        ["--sbom", "--vulnerabilities"] if dependencies else ["--no-sbom", "--no-vulnerabilities"]
    )
    if network == "offline":
        options.append("--no-network")
    current = run_fuse(
        [
            "scan",
            str(target),
            *options,
            "--output-dir",
            str(output),
            "--fail-on",
            "none" if baseline else threshold,
        ],
        action,
        runner_temp,
    )
    checked(current, {0, 1, 2})
    report_file = output / "findings.json"
    report = json.loads(report_file.read_text(encoding="utf-8"))
    prepare_github_sarif(output)
    gate = {0: "pass", 1: "fail", 2: "unknown"}[current.returncode]
    diff = None
    note = "Baseline comparison not requested."
    if baseline:
        try:
            with tempfile.TemporaryDirectory(prefix="fuse-base-", dir=runner_temp) as temporary:
                root = Path(temporary)
                base = root / "tree"
                base.mkdir()
                extract_base(
                    workspace, os.environ.get("FUSE_BASE_SHA", ""), base, root / "base.tar"
                )
                base_target = target_inside(base, relative)
                base_report = root / "report"
                checked(
                    run_fuse(
                        ["scan", str(base_target), *options, "--output-dir", str(base_report)],
                        action,
                        runner_temp,
                    )
                )
                baseline_file = root / "baseline.json"
                checked(
                    run_fuse(
                        [
                            "baseline",
                            "create",
                            str(base_report / "findings.json"),
                            "--output",
                            str(baseline_file),
                        ],
                        action,
                        runner_temp,
                    )
                )
                result = run_fuse(
                    [
                        "baseline",
                        "diff",
                        str(report_file),
                        "--baseline",
                        str(baseline_file),
                        "--format",
                        "json",
                        "--fail-on-new",
                        threshold,
                    ],
                    action,
                    runner_temp,
                )
                checked(result, {0, 1, 2})
                diff = json.loads(result.stdout)
                (output / "baseline-diff.json").write_text(result.stdout, encoding="utf-8")
                gate = {0: "pass", 1: "fail", 2: "unknown"}[result.returncode]
                counts = diff["summary"]
                note = (
                    f"New: {counts['new']} | Existing: {counts['persistent']} | "
                    f"Moved: {counts['moved']} | Resolved: {counts['resolved']}"
                )
        except (
            ValueError,
            OSError,
            RuntimeError,
            subprocess.SubprocessError,
            json.JSONDecodeError,
        ) as error:
            gate = "unknown"
            note = f"Baseline comparison unavailable: {type(error).__name__}. Check workflow logs and coverage."
            print(f"Baseline comparison unavailable: {error}", file=sys.stderr)
    coverage = report.get("coverage", {})
    framework = re.sub(
        r"[^a-zA-Z0-9_.-]", "", str(report.get("project_context", {}).get("framework") or "unknown")
    )[:80]
    lines = [
        "<!-- fuse-security-review -->",
        "## FUSE Security Review",
        "",
        f"Project: `{label}` | Profile: `{profile}` | Framework: `{framework}`",
        "",
        f"Findings: {report['summary']['finding_count']}",
        "",
        note,
        "",
        f"Policy gate: **{gate.upper()}**",
        "",
        "### Coverage",
        "",
    ]
    for entry in coverage.get("analyzers", []):
        name = re.sub(r"[^a-zA-Z0-9_.-]", "", str(entry.get("name", "unknown")))[:80]
        status = re.sub(r"[^a-zA-Z0-9_.-]", "", str(entry.get("status", "unknown")))[:30]
        lines.append(f"- {name}: {status}")
    lines += ["", "### Findings (first 20)", ""]
    for finding in report.get("findings", [])[:20]:
        severity = re.sub(r"[^a-zA-Z0-9_.-]", "", str(finding.get("severity", "unknown")))[:20]
        rule = re.sub(r"[^a-zA-Z0-9_.-]", "", str(finding.get("rule_id", "unknown")))[:80]
        title = re.sub(r"[^a-zA-Z0-9 .,()_-]", "", str(finding.get("title", "")))[:120]
        lines.append(f"- {severity.upper()} `{rule}`: {title}")
    lines += [
        "",
        "Static evidence only. Runtime applicability remains unknown where not established.",
        "See the report artifact for findings, evidence, coverage and provenance.",
        "",
    ]
    summary = "\n".join(lines)
    (output / "review.md").write_text(summary, encoding="utf-8")
    with open(os.environ["GITHUB_STEP_SUMMARY"], "a", encoding="utf-8") as stream:
        stream.write(summary)
    return output, gate


def main() -> int:
    try:
        output, gate = run_review()
        with open(os.environ["GITHUB_OUTPUT"], "a", encoding="utf-8") as stream:
            stream.write(f"report-directory={output}\ngate={gate}\n")
        return 0
    except (
        ValueError,
        KeyError,
        OSError,
        RuntimeError,
        subprocess.SubprocessError,
        json.JSONDecodeError,
    ) as error:
        print(f"FUSE review failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
