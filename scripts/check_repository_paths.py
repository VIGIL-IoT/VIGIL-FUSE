"""Reject absolute developer-profile paths in tracked files and Git objects."""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path


PERSONAL_PATH_PATTERNS = (
    re.compile(rb"(?i)[a-z]:[/\\]+users[/\\]+[a-z0-9._-]+(?:[/\\][^\x00\r\n\t\"<>]*)?"),
    re.compile(rb"(?i)/(?:users|home)/[a-z0-9._-]+(?:/[^\x00\r\n\t\"<>]*)?"),
)
CHUNK_SIZE = 1024 * 1024
OVERLAP_SIZE = 256


def has_personal_profile_path(content: bytes) -> bool:
    return any(pattern.search(content) for pattern in PERSONAL_PATH_PATTERNS)


def _tracked_files(root: Path) -> list[str]:
    result = subprocess.run(
        ["git", "ls-files", "-z"],
        cwd=root,
        check=True,
        capture_output=True,
    )
    return [path.decode("utf-8", "surrogateescape") for path in result.stdout.split(b"\0") if path]


def _scan_tracked_files(root: Path) -> list[str]:
    findings: list[str] = []
    for relative in _tracked_files(root):
        path = root / relative
        if not path.is_file():
            continue
        try:
            content = path.read_bytes()
        except OSError as error:
            raise RuntimeError(f"Unable to read tracked file {relative}: {error}") from error
        if has_personal_profile_path(content):
            findings.append(relative)
    return findings


def _scan_git_objects(root: Path) -> list[tuple[str, str]]:
    listing = subprocess.run(
        ["git", "cat-file", "--batch-all-objects", "--batch-check"],
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
        encoding="ascii",
    )
    object_ids = [row.split()[0] for row in listing.stdout.splitlines() if len(row.split()) > 1]
    process = subprocess.Popen(
        ["git", "cat-file", "--batch"],
        cwd=root,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
    )
    if process.stdin is None or process.stdout is None:
        raise RuntimeError("Unable to open Git object streams")

    findings: list[tuple[str, str]] = []
    try:
        for object_id in object_ids:
            process.stdin.write(f"{object_id}\n".encode("ascii"))
            process.stdin.flush()
            header = process.stdout.readline().split()
            if len(header) != 3:
                raise RuntimeError("Unexpected Git object header")
            object_type = header[1].decode("ascii")
            remaining = int(header[2])
            previous = b""
            matched = False
            while remaining:
                chunk = process.stdout.read(min(remaining, CHUNK_SIZE))
                if not chunk:
                    raise RuntimeError("Git object stream ended early")
                window = previous + chunk
                if has_personal_profile_path(window):
                    matched = True
                previous = window[-OVERLAP_SIZE:]
                remaining -= len(chunk)
            if process.stdout.read(1) != b"\n":
                raise RuntimeError("Unexpected Git object stream terminator")
            if matched:
                findings.append((object_id, object_type))
    finally:
        process.stdin.close()
        return_code = process.wait()
        if return_code:
            raise RuntimeError(f"git cat-file exited with status {return_code}")
    return findings


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    try:
        files = _scan_tracked_files(root)
        objects = _scan_git_objects(root)
    except (OSError, RuntimeError, subprocess.CalledProcessError) as error:
        print(f"Repository path audit failed: {error}", file=sys.stderr)
        return 2

    if files or objects:
        print("Personal machine paths detected in repository content:", file=sys.stderr)
        for relative in files:
            print(f"tracked file: {relative}", file=sys.stderr)
        for object_id, object_type in objects:
            print(f"Git object: {object_type} {object_id}", file=sys.stderr)
        return 1

    print(
        f"Repository path audit passed: {len(_tracked_files(root))} tracked files and Git history."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
