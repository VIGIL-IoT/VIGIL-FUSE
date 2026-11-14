"""Freeze detector bytes and settings before opening an evaluation dataset."""

from __future__ import annotations

import argparse
import hashlib
import io
import json
from pathlib import Path
import subprocess
import sys
import tarfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from vigil_fuse import __version__  # noqa: E402
from vigil_fuse import ghidra_analyzer as ghidra  # noqa: E402
from vigil_fuse.rules.registry import RULES  # noqa: E402


def freeze() -> dict:
    revision = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    paths = subprocess.check_output(
        ["git", "ls-files", "src/vigil_fuse", "tests/fixtures"], cwd=ROOT, text=True
    ).splitlines()
    subprocess.run(["git", "diff", "--quiet", "HEAD", "--", *paths], cwd=ROOT, check=True)
    archive = subprocess.check_output(
        ["git", "archive", revision, "src/vigil_fuse", "tests/fixtures"], cwd=ROOT
    )
    hashes = {}
    with tarfile.open(fileobj=io.BytesIO(archive)) as source:
        for member in source:
            if member.isfile():
                stream = source.extractfile(member)
                assert stream is not None
                hashes[member.name] = hashlib.sha256(
                    stream.read().replace(b"\r\n", b"\n")
                ).hexdigest()
    return {
        "manifest_version": 1,
        "fuse_commit": revision,
        "fuse_version": __version__,
        "report_schema_version": "1.11",
        "detector_files": hashes,
        "hash_encoding": "Git blob bytes; CRLF worktrees normalized to LF for verification",
        "rule_versions": {
            **{r.id: r.version for r in RULES},
            "FUSE-BIN-001": "1.0.0",
            "FUSE-BIN-002": "1.0.0",
        },
        "configuration": {
            "profile": "generic",
            "network": False,
            "optional_analyzers": {
                "syft": "disabled",
                "osv-scanner": "disabled",
                "binwalk": "disabled",
                "ghidra": ghidra.GHIDRA_SUPPORTED_VERSION,
            },
            "java_major": ghidra.GHIDRA_MINIMUM_JAVA,
            "timeout_seconds": ghidra.GHIDRA_DEFAULT_TIMEOUT_SECONDS,
            "maximum_input_bytes": ghidra.GHIDRA_MAXIMUM_INPUT_BYTES,
            "maximum_artifact_bytes": ghidra.GHIDRA_MAXIMUM_ARTIFACT_BYTES,
            "maximum_diagnostic_bytes": ghidra.GHIDRA_MAXIMUM_DIAGNOSTIC_BYTES,
            "execution": "fresh temporary Ghidra project; no target execution",
            "platform": "Ubuntu 24.04 x86_64; exact runtime versions recorded per run",
            "raw_inputs": "explicit language and base address only; separate from ELF",
        },
        "splits": {
            "regression": "tests/fixtures; used during detector development",
            "benchmark": "NIST SARD CWE-259 catalogue; previously inspected; not independent",
            "controlled-binary": "purpose-built after freeze; known construction labels; not field accuracy",
            "independent-holdout": "selection and dual human review pending; labels unopened",
        },
        "leakage_policy": "No detector tuning after freeze. A reused or tuned dataset loses holdout status.",
    }


def verify(manifest: dict) -> None:
    for path, expected in manifest["detector_files"].items():
        actual = hashlib.sha256((ROOT / path).read_bytes().replace(b"\r\n", b"\n")).hexdigest()
        if actual != expected:
            raise ValueError(f"Frozen detector/fixture hash mismatch: {path}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    parser.add_argument("--verify", action="store_true")
    args = parser.parse_args()
    if args.verify:
        verify(json.loads(args.output.read_text(encoding="utf-8")))
    else:
        if args.output.exists():
            raise SystemExit(
                "Refusing to overwrite an existing freeze; choose a new evaluation directory."
            )
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(
            json.dumps(freeze(), indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )


if __name__ == "__main__":
    main()
