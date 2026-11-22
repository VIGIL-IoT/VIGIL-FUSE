# Installation and setup

FUSE's core scanner requires Python 3.11 or newer and has no third-party Python runtime dependencies. The setup command prepares optional external analysis tools separately.

## Install the published package

The published 0.4.0 package does not include the setup command from this branch. Install that version with:

```powershell
python -m pip install vigil-fuse==0.4.0
vigil-fuse --version
vigil-fuse doctor
```

## Preview the upcoming installer

The following flow is implemented on the `feat/pre-pypi-installer` branch and is not in the published 0.4.0 package. After the next package release, the intended user flow is:

```powershell
python -m pip install vigil-fuse
vigil-fuse setup --recommended
vigil-fuse doctor
```

To try this branch before release, build and install its wheel in a fresh virtual environment. The root README and `docs/releasing.md` describe the local validation commands.

## Setup modes

- `vigil-fuse setup --minimal` checks the core Python environment. It does not download or install tools.
- `vigil-fuse setup --recommended` detects Git, OPA/Rego, and Verible, and offers pinned Syft, OSV-Scanner, and Gitleaks releases. Only the pinned binaries are downloaded, after interactive or explicit `--yes` consent. They go to the current user's data directory.
- `vigil-fuse setup --full` also lists Binwalk, Docker, Ollama, Ghidra, Java, and pdfLaTeX. These tools have no managed installer in this stage and require their official manual installation steps.
- `vigil-fuse setup --research` reports Python research extras and R, Julia, Rust, and Zig. It never installs toolchains. Install the Python extras separately with `python -m pip install 'vigil-fuse[research]'`.
- Add `--dry-run` to print the plan without downloading or changing the machine.
- Add `--upgrade` to replace an older FUSE-managed copy. System-installed tools are left unchanged.

FUSE continues to run when optional tools are missing. The affected analyzer stage is skipped and its coverage is reported as partial or unavailable. `vigil-fuse doctor --format json` reports tool status and detected versions without contacting external services. Its optional reasoning check contacts only the configured loopback Ollama endpoint.

If a tool download fails or the machine is offline, setup reports the tool, failure, affected capability, and official recovery source. It does not retry indefinitely, and the pip-installed core CLI remains available.
