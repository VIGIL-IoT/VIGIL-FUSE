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
_PERMISSIONS_WRITE_ALL = re.compile(
    r"^(?P<indent> *)permissions[ \t]*:[ \t]*write-all[ \t]*$", re.IGNORECASE
)
_JOB_KEY = re.compile(r"^[A-Za-z0-9_-]+[ \t]*:[ \t]*$")
_ACTION_USE = re.compile(
    r"^[ \t]*(?:-[ \t]+)?uses[ \t]*:[ \t]*(?P<target>(?:[A-Za-z0-9_.-]+/){1,2}[A-Za-z0-9_./-]+)@(?P<ref>[A-Za-z0-9_./-]+)[ \t]*$"
)
_FULL_SHA = re.compile(r"^[a-fA-F0-9]{40}$")
_PULL_REQUEST_HEAD_REFS = frozenset(
    {
        "github.event.pull_request.head.sha",
        "github.event.pull_request.head.ref",
    }
)
_DIRECT_UNTRUSTED_CONTEXT = re.compile(
    r"\$\{\{\s*(?:"
    r"github\.event\.(?:pull_request|issue|comment|review)\.(?:title|body)|"
    r"github\.event\.pull_request\.head\.(?:ref|label)|"
    r"github\.event\.head_commit\.message|github\.head_ref"
    r")\s*\}\}",
    re.IGNORECASE,
)
_WRITE_ALL_URL = "https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-syntax#jobsjob_idpermissions"
_PIN_ACTION_URL = "https://docs.github.com/en/actions/security-for-github-actions/security-guides/security-hardening-for-github-actions#using-third-party-actions"
_PULL_REQUEST_TARGET_URL = (
    "https://docs.github.com/en/actions/reference/security/securely-using-pull_request_target"
)
_SCRIPT_INJECTION_URL = "https://docs.github.com/en/actions/concepts/security/script-injections"


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
        rule_version={"FUSE-GHA-001": "1.1.0"}.get(rule_id, "1.0.0"),
        analyzer="github-actions-static",
        title=title,
        severity="medium"
        if rule_id in {"FUSE-GHA-001", "FUSE-GHA-003", "FUSE-GHA-004"}
        else "info",
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


def _yaml_key_value(content: str) -> tuple[str, str] | None:
    key, separator, value = content.partition(":")
    if not separator:
        return None
    return key.strip().strip("\"'"), value.strip()


def _has_pull_request_target_event(lines: list[str]) -> bool:
    """Recognize common line-oriented forms of the privileged event trigger."""
    in_events_mapping = False
    event_indent: int | None = None
    for original in lines:
        line = _strip_yaml_comment(original)
        if not line.strip():
            continue
        indent = len(line) - len(line.lstrip(" "))
        content = line[indent:]
        if indent == 0:
            pair = _yaml_key_value(content)
            in_events_mapping = pair is not None and pair[0] == "on"
            event_indent = None
            if (
                in_events_mapping
                and pair is not None
                and re.search(r"(?<![A-Za-z0-9_-])pull_request_target(?![A-Za-z0-9_-])", pair[1])
            ):
                return True
            continue
        if not in_events_mapping:
            continue
        if event_indent is None:
            event_indent = indent
        if indent == event_indent:
            pair = _yaml_key_value(content)
            if pair is not None and pair[0] == "pull_request_target":
                return True
    return False


def _pull_request_head_checkout_lines(lines: list[str]) -> tuple[int, ...]:
    """Return checkout ref lines that exactly use a pull request head expression."""
    matches: list[int] = []
    for index, original in enumerate(lines):
        line = _strip_yaml_comment(original)
        action = _ACTION_USE.fullmatch(line)
        if action is None or action.group("target").casefold() != "actions/checkout":
            continue
        action_indent = len(line) - len(line.lstrip(" "))
        with_indent: int | None = None
        input_indent: int | None = None
        for following_index in range(index + 1, len(lines)):
            following = _strip_yaml_comment(lines[following_index])
            if not following.strip():
                continue
            indent = len(following) - len(following.lstrip(" "))
            content = following[indent:]
            if indent <= action_indent:
                break
            pair = _yaml_key_value(content)
            if pair is None:
                continue
            key, value = pair
            if with_indent is None:
                if key.casefold() == "with" and not value:
                    with_indent = indent
                continue
            if indent <= with_indent:
                with_indent = None
                input_indent = None
                continue
            if input_indent is None:
                input_indent = indent
            if indent != input_indent or key.casefold() != "ref":
                continue
            expression = value.strip().strip("\"'").strip()
            if expression.startswith("${{") and expression.endswith("}}"):
                expression = expression[3:-2].strip()
            if expression in _PULL_REQUEST_HEAD_REFS:
                matches.append(following_index + 1)
                break
    return tuple(matches)


def _direct_untrusted_run_lines(lines: list[str]) -> tuple[int, ...]:
    """Find untrusted GitHub expressions interpolated directly into step scripts."""
    matches: list[int] = []
    in_jobs_section = False
    job_indent: int | None = None
    job_property_indent: int | None = None
    index = 0
    while index < len(lines):
        line = _strip_yaml_comment(lines[index])
        if not line.strip():
            index += 1
            continue
        indent = len(line) - len(line.lstrip(" "))
        content = line[indent:]
        if indent == 0:
            in_jobs_section = content == "jobs:"
            job_indent = None
            job_property_indent = None
            index += 1
            continue
        if not in_jobs_section:
            index += 1
            continue
        if job_indent is None and _JOB_KEY.fullmatch(content):
            job_indent = indent
            job_property_indent = None
            index += 1
            continue
        if job_indent is not None and indent == job_indent and _JOB_KEY.fullmatch(content):
            job_property_indent = None
            index += 1
            continue
        if job_indent is not None and indent > job_indent and job_property_indent is None:
            job_property_indent = indent

        pair = _yaml_key_value(content)
        if (
            job_indent is not None
            and indent == job_property_indent
            and pair is not None
            and pair[0].casefold() == "steps"
            and not pair[1]
        ):
            steps_indent = indent
            section_end = index + 1
            while section_end < len(lines):
                following = _strip_yaml_comment(lines[section_end])
                if following.strip():
                    following_indent = len(following) - len(following.lstrip(" "))
                    if following_indent <= steps_indent:
                        break
                section_end += 1

            step_indent: int | None = None
            step_starts: list[int] = []
            for step_line_index in range(index + 1, section_end):
                step_line = _strip_yaml_comment(lines[step_line_index])
                if not step_line.strip():
                    continue
                step_line_indent = len(step_line) - len(step_line.lstrip(" "))
                step_content = step_line[step_line_indent:]
                if not step_content.startswith("- "):
                    continue
                if step_indent is None:
                    step_indent = step_line_indent
                if step_line_indent == step_indent:
                    step_starts.append(step_line_index)

            for step_start_index, step_end_index in zip(
                step_starts,
                (*step_starts[1:], section_end),
            ):
                run_block_indent: int | None = None
                for step_line_index in range(step_start_index, step_end_index):
                    original = lines[step_line_index]
                    if run_block_indent is not None:
                        if not original.strip():
                            continue
                        original_indent = len(original) - len(original.lstrip(" "))
                        if original_indent > run_block_indent:
                            if _DIRECT_UNTRUSTED_CONTEXT.search(original):
                                matches.append(step_line_index + 1)
                            continue
                        run_block_indent = None

                    step_line = _strip_yaml_comment(original)
                    if not step_line.strip():
                        continue
                    step_line_indent = len(step_line) - len(step_line.lstrip(" "))
                    step_content = step_line[step_line_indent:]
                    if step_content.startswith("- "):
                        step_content = step_content[2:]
                    step_pair = _yaml_key_value(step_content)
                    if step_pair is None or step_pair[0].casefold() != "run":
                        continue
                    if _DIRECT_UNTRUSTED_CONTEXT.search(step_pair[1]):
                        matches.append(step_line_index + 1)
                    if step_pair[1].lstrip().startswith(("|", ">")):
                        run_block_indent = step_line_indent

            index = section_end
            continue
        index += 1
    return tuple(matches)


def inspect_github_actions(
    root: Path,
    *,
    exclude: tuple[str, ...] = (),
) -> tuple[GitHubActionsInventory, tuple[Finding, ...]]:
    """Inspect bounded workflow text for a few explicit supply-chain risk patterns."""
    if not root.is_dir():
        return GitHubActionsInventory(), ()
    root_path = root.resolve(strict=True)
    workflow_dir = root_path / ".github" / "workflows"
    if (root_path / ".github").is_symlink() or workflow_dir.is_symlink():
        return GitHubActionsInventory(
            status="partial",
            limitations=(
                "The .github/workflows directory is a symbolic link and was not followed.",
            ),
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
                limitations.append(
                    f"{relative} exceeds the {MAX_WORKFLOW_FILE_BYTES}-byte workflow file limit."
                )
                continue
            if total_bytes + size > MAX_WORKFLOW_TOTAL_BYTES:
                limitations.append(
                    f"Workflow inputs exceeded the {MAX_WORKFLOW_TOTAL_BYTES}-byte total limit."
                )
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

        workflow_lines = text.splitlines()
        pull_request_target_checkouts = (
            set(_pull_request_head_checkout_lines(workflow_lines))
            if _has_pull_request_target_event(workflow_lines)
            else set()
        )
        direct_untrusted_run_lines = set(_direct_untrusted_run_lines(workflow_lines))
        in_jobs_section = False
        job_indent: int | None = None
        job_property_indent: int | None = None

        for line_number, original in enumerate(workflow_lines, 1):
            line = (
                original
                if line_number in direct_untrusted_run_lines
                else _strip_yaml_comment(original)
            )
            if not line.strip():
                continue

            indent = len(line) - len(line.lstrip(" "))
            content = line[indent:]
            if indent == 0:
                in_jobs_section = content == "jobs:"
                job_indent = None
                job_property_indent = None
            elif in_jobs_section:
                if job_indent is None and _JOB_KEY.fullmatch(content):
                    job_indent = indent
                elif (
                    job_indent is not None and indent == job_indent and _JOB_KEY.fullmatch(content)
                ):
                    job_property_indent = None
                elif job_indent is not None and indent > job_indent and job_property_indent is None:
                    job_property_indent = indent

            permission = _PERMISSIONS_WRITE_ALL.fullmatch(line)
            permission_scope: str | None = None
            if permission:
                permission_indent = len(permission.group("indent"))
                if permission_indent == 0:
                    permission_scope = "workflow"
                elif (
                    in_jobs_section
                    and job_indent is not None
                    and permission_indent == job_property_indent
                ):
                    permission_scope = "job"

            if permission_scope is not None:
                if permission_scope == "workflow":
                    title = "Workflow-level permissions grant write access to every supported permission"
                    explanation = (
                        "At workflow scope, this file explicitly uses the broad write-all permission setting. "
                        "FUSE does not infer whether every permission is needed or whether an untrusted event can reach this job."
                    )
                else:
                    title = "Job-level permissions grant write access to every supported permission"
                    explanation = (
                        "At job scope, this file explicitly uses the broad write-all permission setting. "
                        "Actions and run commands in that job can use all supported GITHUB_TOKEN permission levels. "
                        "FUSE does not infer whether every permission is needed or whether untrusted input can reach the job."
                    )
                findings.append(
                    _finding(
                        rule_id="FUSE-GHA-001",
                        file=relative,
                        line=line_number,
                        evidence=original,
                        title=title,
                        explanation=explanation,
                        impact=(
                            "A compromised action or unsafe workflow path may receive a larger repository token capability than required."
                        ),
                        remediation=(
                            "Declare only the required permissions at workflow or job scope, then review event triggers and action trust boundaries."
                        ),
                        reference=_WRITE_ALL_URL,
                    )
                )
            action = _ACTION_USE.fullmatch(line)
            if action and not _FULL_SHA.fullmatch(action.group("ref")):
                non_sha_action_reference_count += 1
            if action and action.group("ref").casefold() in _FLOATING_BRANCH_REFS:
                floating_branch_reference_count += 1
                findings.append(
                    _finding(
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
                    )
                )
            if line_number in pull_request_target_checkouts:
                findings.append(
                    _finding(
                        rule_id="FUSE-GHA-003",
                        file=relative,
                        line=line_number,
                        evidence=original,
                        title="Privileged pull_request_target workflow checks out pull request code",
                        explanation=(
                            "This workflow combines the privileged pull_request_target event with an actions/checkout ref "
                            "that selects the pull request head. GitHub warns against building or running untrusted pull "
                            "request code in this context. FUSE does not determine whether a later step executes the "
                            "checked-out code, so this is a review candidate rather than a confirmed vulnerability."
                        ),
                        impact=(
                            "If a later step builds or executes the checked-out code, attacker-controlled content may run "
                            "with the workflow's available secrets, token permissions, or cache access."
                        ),
                        remediation=(
                            "Avoid checking out pull request head code in a pull_request_target workflow. Use pull_request "
                            "for build and test jobs, or separate privileged metadata handling from untrusted-code jobs."
                        ),
                        reference=_PULL_REQUEST_TARGET_URL,
                    )
                )
            if line_number in direct_untrusted_run_lines:
                findings.append(
                    _finding(
                        rule_id="FUSE-GHA-004",
                        file=relative,
                        line=line_number,
                        evidence=original,
                        title="Workflow shell script directly interpolates untrusted event data",
                        explanation=(
                            "A recognized event-derived value is interpolated directly into a workflow run script. "
                            "GitHub evaluates expressions before the shell runs, so attacker-controlled text may be "
                            "interpreted as shell syntax. FUSE does not determine event reachability, sanitization, "
                            "shell semantics, or the runner permissions available to this step; this is a review candidate, "
                            "not a confirmed exploit."
                        ),
                        impact=(
                            "If an attacker can control the value and the expression reaches an executable shell position, "
                            "injected commands may run with the permissions and accessible secrets of the job."
                        ),
                        remediation=(
                            "Pass the expression through a step-level env variable and use a quoted shell variable, "
                            "or pass it as an input to a reviewed action instead of embedding it in run script text."
                        ),
                        reference=_SCRIPT_INJECTION_URL,
                    )
                )
            if len(findings) >= MAX_WORKFLOW_FINDINGS:
                limitations.append(
                    f"Workflow findings were capped at {MAX_WORKFLOW_FINDINGS} entries."
                )
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
