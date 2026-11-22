"""Reject absolute developer-profile paths in tracked files and Git objects."""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path


PERSONAL_PATH_PATTERNS = (
    re.compile(rb"(?i)[a-z]:[/\\]+users[/\\]+([a-z0-9._-]+)(?:[/\\][^\x00\r\n\t\"<>]*)?"),
    re.compile(rb"(?i)/(?:users|home)/([a-z0-9._-]+)(?:/[^\x00\r\n\t\"<>]*)?"),
)
# Exact historical test blobs retain synthetic paths used by privacy, reasoning, and
# tool-output fixtures. Current tests assemble those values at runtime so new absolute
# paths remain detectable in tracked files and newly created Git objects.
LEGACY_SYNTHETIC_PATH_FIXTURE_BLOBS = {
    "1e64466b0b5b9009cfa2cceacd93528893a625b6",
    "60910a707e17b28a491bc27d9769375314d69962",
    "b52613ecd99c73ac051621437b514b6543223851",
    "0673a89998cfda68c2045f23fd5f6dfb0216c5ff",
    "2cae7948e75dcfc676f77c6a89a4051ade83ba46",
    "3e0de5a32880e9ac49af428a06322b9a56d75791",
    "4e054cc2042a37e2a362ccaab243cc1041fc2c47",
    "4e5c201f1335dcc0c94f712ec06e4ddc349e7eba",
    "58a1ff5e073c8bb8622456cd6d48023301255423",
    "62ce5a12c11eeebabcea8bbf42fac71fd8f1fddf",
    "6c630e496c36422a10b78a8449d997962ee69ec6",
    "9afd84eee99b6b5bff5f091df5ad8867ed4f612b",
    "c132203f97aaf6bf1535c8d179ec57c2d39b2a5b",
    "d25eea0de6f6c1035d3dab2c43b432f855156b4b",
    "d85eedc5af89d091514cee72fcbb2cdc0e505b23",
    "ec04abae251af7bee3760da6b2c6997a9c609362",
}
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
            if matched and object_id not in LEGACY_SYNTHETIC_PATH_FIXTURE_BLOBS:
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
