"""Prepare clean, sparse checkouts for a pinned repository performance run."""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path, PurePosixPath
from typing import Any
from urllib.parse import urlsplit


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_MANIFEST = ROOT / "reports" / "repository-scans" / "fresh-validation-next" / "manifest.json"
DEFAULT_CHECKOUTS = ROOT.parent / "fuse-repository-benchmark-cohort"
REPOSITORY_ID_PATTERN = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
COMMIT_PATTERN = re.compile(r"^[0-9a-fA-F]{40}$")


class CohortPreparationError(RuntimeError):
    """Raised when a pinned source checkout cannot be prepared safely."""


def _load_cohort(manifest_path: Path) -> list[dict[str, Any]]:
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise CohortPreparationError("could not read the repository cohort manifest") from error
    repositories = manifest.get("repositories") if isinstance(manifest, dict) else None
    if not isinstance(repositories, list) or not repositories:
        raise CohortPreparationError("manifest must contain a non-empty repositories list")

    plans: list[dict[str, Any]] = []
    seen_ids: set[str] = set()
    for repository in repositories:
        if not isinstance(repository, dict):
            raise CohortPreparationError("repository entries must be JSON objects")
        repository_id = repository.get("id")
        commit = repository.get("commit")
        url = repository.get("url")
        profile = repository.get("profile")
        if (
            not isinstance(repository_id, str)
            or not REPOSITORY_ID_PATTERN.fullmatch(repository_id)
            or repository_id in seen_ids
        ):
            raise CohortPreparationError("repository IDs must be unique lowercase names")
        if not isinstance(commit, str) or not COMMIT_PATTERN.fullmatch(commit):
            raise CohortPreparationError(f"repository {repository_id} has an invalid commit SHA")
        try:
            parsed_url = urlsplit(url) if isinstance(url, str) else None
        except ValueError:
            parsed_url = None
        try:
            url_is_safe = (
                parsed_url is not None
                and parsed_url.scheme == "https"
                and parsed_url.hostname == "github.com"
                and parsed_url.port is None
                and parsed_url.username is None
                and parsed_url.password is None
                and not parsed_url.query
                and not parsed_url.fragment
                and re.fullmatch(r"/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(?:\.git)?/?", parsed_url.path)
                is not None
                and all(part not in {".", ".."} for part in parsed_url.path.strip("/").split("/"))
            )
        except ValueError:
            url_is_safe = False
        if not url_is_safe:
            raise CohortPreparationError(f"repository {repository_id} must use a public GitHub URL")
        if not isinstance(profile, str) or not profile.strip():
            raise CohortPreparationError(f"repository {repository_id} has no scan profile")

        scans = repository.get("scans")
        if not isinstance(scans, list) or not scans:
            raise CohortPreparationError(f"repository {repository_id} has no scan scopes")
        includes: set[str] = set()
        for scan in scans:
            patterns = scan.get("includes") if isinstance(scan, dict) else None
            if not isinstance(patterns, list) or not patterns:
                raise CohortPreparationError(
                    f"repository {repository_id} has an empty include list"
                )
            for pattern in patterns:
                if (
                    not isinstance(pattern, str)
                    or not pattern
                    or "\0" in pattern
                    or "\\" in pattern
                    or any(ord(character) < 32 for character in pattern)
                    or pattern.startswith(("-", "!"))
                    or ":" in pattern
                    or PurePosixPath(pattern).is_absolute()
                    or ".." in PurePosixPath(pattern).parts
                ):
                    raise CohortPreparationError(
                        f"repository {repository_id} has an unsafe sparse-checkout pattern"
                    )
                includes.add(pattern)
        plans.append(
            {
                "id": repository_id,
                "commit": commit.lower(),
                "url": url,
                "profile": profile,
                "includes": sorted(includes),
            }
        )
        seen_ids.add(repository_id)
    return plans


def _git(
    arguments: list[str],
    *,
    cwd: Path | None = None,
    environment: dict[str, str],
    timeout_seconds: int,
    repository_id: str,
) -> str:
    try:
        result = subprocess.run(
            ["git", *arguments],
            cwd=cwd,
            env=environment,
            check=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout_seconds,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise CohortPreparationError(
            f"Git operation timed out or could not start for {repository_id}"
        ) from error
    if result.returncode != 0:
        diagnostic = result.stderr.strip().splitlines()
        detail = diagnostic[-1] if diagnostic else "Git returned a non-zero exit status"
        raise CohortPreparationError(f"Git operation failed for {repository_id}: {detail}")
    return result.stdout.strip()


def _existing_checkout_is_ready(
    checkout: Path,
    *,
    repository: dict[str, Any],
    environment: dict[str, str],
    timeout_seconds: int,
) -> bool:
    if not checkout.exists():
        return False
    if not checkout.is_dir():
        raise CohortPreparationError(f"checkout destination already exists: {repository['id']}")
    actual_commit = _git(
        ["-C", str(checkout), "rev-parse", "HEAD"],
        environment=environment,
        timeout_seconds=timeout_seconds,
        repository_id=repository["id"],
    )
    dirty = _git(
        ["-C", str(checkout), "status", "--porcelain", "--untracked-files=all"],
        environment=environment,
        timeout_seconds=timeout_seconds,
        repository_id=repository["id"],
    )
    autocrlf = _git(
        ["-C", str(checkout), "config", "--get", "--default", "false", "core.autocrlf"],
        environment=environment,
        timeout_seconds=timeout_seconds,
        repository_id=repository["id"],
    )
    eol = _git(
        ["-C", str(checkout), "config", "--get", "--default", "native", "core.eol"],
        environment=environment,
        timeout_seconds=timeout_seconds,
        repository_id=repository["id"],
    )
    if autocrlf.lower() != "false" or eol.lower() != "lf":
        raise CohortPreparationError(
            f"existing checkout for {repository['id']} may use platform-specific line endings; "
            "choose a fresh output directory"
        )
    if actual_commit.lower() != repository["commit"] or dirty:
        raise CohortPreparationError(
            f"existing checkout for {repository['id']} is not the expected clean pinned revision"
        )
    return True


def prepare_cohort(
    *,
    manifest_path: Path = DEFAULT_MANIFEST,
    checkouts_root: Path = DEFAULT_CHECKOUTS,
    timeout_seconds: int = 900,
) -> list[Path]:
    if not 1 <= timeout_seconds <= 3600:
        raise ValueError("timeout must be between 1 and 3600 seconds")
    manifest_path = manifest_path.resolve()
    checkouts_root = checkouts_root.resolve()
    plans = _load_cohort(manifest_path)
    checkouts_root.mkdir(parents=True, exist_ok=True)

    environment = os.environ.copy()
    environment["GIT_TERMINAL_PROMPT"] = "0"
    environment["GIT_LFS_SKIP_SMUDGE"] = "1"
    prepared: list[Path] = []
    for repository in plans:
        checkout = (checkouts_root / repository["id"]).resolve()
        if not checkout.is_relative_to(checkouts_root):
            raise CohortPreparationError(
                "checkout destination escapes the requested output directory"
            )
        if _existing_checkout_is_ready(
            checkout,
            repository=repository,
            environment=environment,
            timeout_seconds=timeout_seconds,
        ):
            prepared.append(checkout)
            print(
                f"Reusing clean pinned checkout: {repository['id']} at {repository['commit'][:12]}"
            )
            continue

        _git(
            [
                "clone",
                "--depth=1",
                "--filter=blob:none",
                "--no-checkout",
                "--single-branch",
                repository["url"],
                str(checkout),
            ],
            environment=environment,
            timeout_seconds=timeout_seconds,
            repository_id=repository["id"],
        )
        _git(
            ["-C", str(checkout), "config", "core.autocrlf", "false"],
            environment=environment,
            timeout_seconds=timeout_seconds,
            repository_id=repository["id"],
        )
        _git(
            ["-C", str(checkout), "config", "core.eol", "lf"],
            environment=environment,
            timeout_seconds=timeout_seconds,
            repository_id=repository["id"],
        )
        _git(
            [
                "-C",
                str(checkout),
                "fetch",
                "--depth=1",
                "--filter=blob:none",
                "origin",
                repository["commit"],
            ],
            environment=environment,
            timeout_seconds=timeout_seconds,
            repository_id=repository["id"],
        )
        _git(
            ["-C", str(checkout), "sparse-checkout", "init", "--no-cone"],
            environment=environment,
            timeout_seconds=timeout_seconds,
            repository_id=repository["id"],
        )
        _git(
            [
                "-C",
                str(checkout),
                "sparse-checkout",
                "set",
                "--no-cone",
                *repository["includes"],
            ],
            environment=environment,
            timeout_seconds=timeout_seconds,
            repository_id=repository["id"],
        )
        _git(
            ["-C", str(checkout), "checkout", "--detach", repository["commit"]],
            environment=environment,
            timeout_seconds=timeout_seconds,
            repository_id=repository["id"],
        )
        prepared.append(checkout)
        print(
            f"Prepared pinned checkout: {repository['id']} at {repository['commit'][:12]} "
            f"({len(repository['includes'])} sparse path patterns)",
            flush=True,
        )
    return prepared


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--checkouts", type=Path, default=DEFAULT_CHECKOUTS)
    parser.add_argument("--timeout-seconds", type=int, default=900)
    args = parser.parse_args()
    try:
        prepare_cohort(
            manifest_path=args.manifest,
            checkouts_root=args.checkouts,
            timeout_seconds=args.timeout_seconds,
        )
    except (OSError, ValueError, CohortPreparationError) as error:
        print(f"repository benchmark preparation failed: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
