from __future__ import annotations

import hashlib
import re
from pathlib import Path

from .model import Finding, GitHubActionsInventory, GitHubWorkflowFile
from .text_safety import safe_report_text

MAX_WORKFLOW_FILES = 200
MAX_WORKFLOW_FILE_BYTES = 1024 * 1024
MAX_WORKFLOW_TOTAL_BYTES = 10 * 1024 * 1024
MAX_WORKFLOW_FINDINGS = 500
_FLOATING_BRANCH_REFS = frozenset({"dev", "develop", "latest", "main", "master", "trunk"})
_PERMISSIONS_WRITE_ALL = re.compile(r"^permissions[ \t]*:[ \t]*write-all[ \t]*$", re.IGNORECASE)
_ACTION_USE = re.compile(
    r"^[ \t]*(?:-[ \t]+)?uses[ \t]*:[ \t]*(?P<target>(?:[A-Za-z0-9_.-]+/){1,2}[A-Za-z0-9_./-]+)@(?P<ref>[A-Za-z0-9_./-]+)[ \t]*$"
)
_FULL_SHA = re.compile(r"^[a-fA-F0-9]{40}$")
_WRITE_ALL_URL = "https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-syntax#permissions"
_PIN_ACTION_URL = "https://docs.github.com/en/actions/security-for-github-actions/security-guides/security-hardening-for-github-actions#using-third-party-actions"


def _strip_yaml_comment(line: str) -> str:
    quote: str | None = None
    escaped = False
    for index, char in enumerate(line):
        if escaped:
            escaped = False
            continue
        if quote == '"' and char == "\\":
            escaped = True
            continue
        if char in {'"', "'"}:
            if quote is None:
                quote = char
            elif quote == char:
                quote = None
            continue
        if char == "#" and quote is None and (index == 0 or line[index - 1].isspace()):
            return line[:index].rstrip()
    return line.rstrip()


def _finding(
    *,
    rule_id: str,
    file: str,
    line: int,
    evidence: str,
    title: str,
    explanation: str,
    impact: str,
    remediation: str,
    reference: str,
) -> Finding:
    bounded_evidence = safe_report_text(" ".join(evidence.split()), limit=240) or ""
    fingerprint = hashlib.sha256(
        f"{rule_id}\0{file}\0{line}\0{bounded_evidence}".encode("utf-8")
    ).hexdigest()
    return Finding(
        id=f"{rule_id}:{file}:{line}",
        fingerprint=fingerprint,
        rule_id=rule_id,
        rule_version="1.0.0",
        analyzer="github-actions-static",
        title=title,
        severity="medium" if rule_id == "FUSE-GHA-001" else "info",
        confidence="high",
        category="ci-workflow-security",
        file=file,
        start_line=line,
        end_line=line,
        evidence=bounded_evidence,
        explanation=explanation,
        potential_impact=impact,
        remediation=remediation,
        references=(reference,),
        applicability="candidate",
        validation_method="static",
        validation_status="not-validated",
    )


def inspect_github_actions(
    root: Path,
    *,
    exclude: tuple[str, ...] = (),
) -> tuple[GitHubActionsInventory, tuple[Finding, ...]]:
    """Inspect bounded workflow text for explicit broad permissions and floating action refs."""
    if not root.is_dir():
        return GitHubActionsInventory(), ()
    root_path = root.resolve(strict=True)
    workflow_dir = root_path / ".github" / "workflows"
    if (root_path / ".github").is_symlink() or workflow_dir.is_symlink():
        return GitHubActionsInventory(
            status="partial",
            limitations=("The .github/workflows directory is a symbolic link and was not followed.",),
        ), ()
    if not workflow_dir.is_dir():
        return GitHubActionsInventory(), ()

    limitations: list[str] = []
    files: list[GitHubWorkflowFile] = []
    findings: list[Finding] = []
    total_bytes = 0
    non_sha_action_reference_count = 0
    floating_branch_reference_count = 0
    try:
        entries = sorted(workflow_dir.iterdir(), key=lambda item: item.name.casefold())
    except OSError:
        return GitHubActionsInventory(
            status="partial",
            limitations=("The .github/workflows directory could not be read.",),
        ), ()

    for path in entries:
        if path.suffix.casefold() not in {".yml", ".yaml"}:
            continue
        relative = path.relative_to(root_path).as_posix()
        if any(_matches_exclude(relative, pattern) for pattern in exclude):
            continue
        if path.is_symlink() or not path.is_file():
            limitations.append(f"{relative} is not a regular workflow file and was not read.")
            continue
        if len(files) >= MAX_WORKFLOW_FILES:
            limitations.append(f"Workflow file count exceeded the {MAX_WORKFLOW_FILES}-file limit.")
            break
        try:
            size = path.stat().st_size
            if size > MAX_WORKFLOW_FILE_BYTES:
                limitations.append(f"{relative} exceeds the {MAX_WORKFLOW_FILE_BYTES}-byte workflow file limit.")
                continue
            if total_bytes + size > MAX_WORKFLOW_TOTAL_BYTES:
                limitations.append(f"Workflow inputs exceeded the {MAX_WORKFLOW_TOTAL_BYTES}-byte total limit.")
                break
            data = path.read_bytes()
        except OSError:
            limitations.append(f"{relative} could not be read.")
            continue
        total_bytes += len(data)
        files.append(
            GitHubWorkflowFile(
                path=safe_report_text(relative, limit=1000) or "unknown-path",
                sha256=hashlib.sha256(data).hexdigest(),
                byte_size=len(data),
            )
        )
        try:
            text = data.decode("utf-8-sig")
        except UnicodeDecodeError:
            limitations.append(f"{relative} is not UTF-8 text and was skipped.")
            continue

        for line_number, original in enumerate(text.splitlines(), 1):
            line = _strip_yaml_comment(original)
            if _PERMISSIONS_WRITE_ALL.fullmatch(line):
                findings.append(_finding(
                    rule_id="FUSE-GHA-001",
                    file=relative,
                    line=line_number,
                    evidence=original,
                    title="Workflow-level permissions grant write access to every supported permission",
                    explanation=(
                        "At workflow scope, this file explicitly uses the broad write-all permission setting. "
                        "FUSE does not infer whether every permission is needed or whether an untrusted event can reach this job."
                    ),
                    impact=(
                        "A compromised action or unsafe workflow path may receive a larger repository token capability than required."
                    ),
                    remediation=(
                        "Declare only the required permissions at workflow or job scope, then review event triggers and action trust boundaries."
                    ),
                    reference=_WRITE_ALL_URL,
                ))
            action = _ACTION_USE.fullmatch(line)
            if action and not _FULL_SHA.fullmatch(action.group("ref")):
                non_sha_action_reference_count += 1
            if action and action.group("ref").casefold() in _FLOATING_BRANCH_REFS:
                floating_branch_reference_count += 1
                findings.append(_finding(
                    rule_id="FUSE-GHA-002",
                    file=relative,
                    line=line_number,
                    evidence=original,
                    title="GitHub Action reference points to a floating branch",
                    explanation=(
                        "The workflow selects an action by a branch-like reference that can move without a workflow change. "
                        "Other non-SHA version references are counted in inventory but are not findings in this conservative check."
                    ),
                    impact=(
                        "The referenced code may change while the workflow text remains unchanged, weakening review and reproducibility."
                    ),
                    remediation=(
                        "Pin the action to a verified full commit SHA and use comments or Dependabot to track reviewed updates."
                    ),
                    reference=_PIN_ACTION_URL,
                ))
            if len(findings) >= MAX_WORKFLOW_FINDINGS:
                limitations.append(f"Workflow findings were capped at {MAX_WORKFLOW_FINDINGS} entries.")
                break
        if len(findings) >= MAX_WORKFLOW_FINDINGS:
            break

    return GitHubActionsInventory(
        status="partial" if limitations else "completed" if files else "not-detected",
        workflow_count=len(files),
        files=tuple(files),
        non_sha_action_reference_count=non_sha_action_reference_count,
        floating_branch_reference_count=floating_branch_reference_count,
        finding_count=len(findings),
        limitations=tuple(dict.fromkeys(limitations)),
    ), tuple(findings)


def _matches_exclude(path: str, pattern: str) -> bool:
    from fnmatch import fnmatchcase

    return fnmatchcase(path, pattern)
