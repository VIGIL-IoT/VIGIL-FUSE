from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "reports" / "repository-scans" / "scan-manifest.json"


def git_head(repository: Path) -> str:
    result = subprocess.run(
        ["git", "-C", str(repository), "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


def run(checkouts_root: Path) -> None:
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    for repository in manifest["repositories"]:
        checkout = checkouts_root / repository["id"]
        if not checkout.is_dir():
            raise FileNotFoundError(f"Missing checkout for {repository['name']}: {checkout}")
        actual_commit = git_head(checkout)
        if actual_commit != repository["commit"]:
            raise RuntimeError(
                f"Pinned checkout mismatch for {repository['name']}: "
                f"expected {repository['commit']}, got {actual_commit}"
            )

        for scan in repository["scans"]:
            command = [
                sys.executable,
                "-m",
                "vigil_fuse",
                "scan",
                str(checkout),
                "--profile",
                repository["profile"],
            ]
            for include in scan.get("includes", ()):
                command.extend(("--include", include))
            output = ROOT / "reports" / "repository-scans" / scan["id"]
            command.extend(("--output-dir", str(output)))
            subprocess.run(command, cwd=ROOT, check=True)
            print(f"Scanned {repository['name']} scope {scan['id']}", flush=True)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Rescan the pinned repositories and scopes in the FUSE pilot manifest."
    )
    parser.add_argument(
        "checkouts_root",
        nargs="?",
        type=Path,
        default=ROOT.parent / "fuse-scan-targets",
        help="directory containing checkouts named after manifest repository IDs",
    )
    args = parser.parse_args()
    run(args.checkouts_root.expanduser().resolve())


if __name__ == "__main__":
    main()
