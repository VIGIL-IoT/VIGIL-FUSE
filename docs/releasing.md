# Local package validation

PyPI publishing is paused. The commands here build and verify local artifacts only. They do not publish to TestPyPI or PyPI and do not authorize a release.

## Build and validate locally

From the repository root with Python 3.11 or newer:

~~~powershell
python -m pip install "build>=1.2,<2" "twine>=7,<8"
python -m build
python -m twine check dist/*
python scripts/verify_installed_wheel.py
~~~

The wheel verifier installs the built wheel into a fresh environment, runs the installed CLI from outside the source checkout, checks packaged resources, and exercises a controlled scan. Keep generated artifacts and verifier workspaces outside the tracked source tree.

For a manual installed-package smoke check, create a new environment and run the commands from a directory outside the repository:

~~~powershell
py -3 -m venv .venv-install-test
.\.venv-install-test\Scripts\Activate.ps1
$wheel = Get-ChildItem .\dist\*.whl | Select-Object -First 1
python -m pip install $wheel.FullName
Set-Location $env:TEMP
vigil-fuse --version
vigil-fuse --help
vigil-fuse doctor
vigil-fuse scan --help
vigil-fuse scan path\to\controlled-fixture --plan
~~~

Confirm schemas, policies, the support matrix, the Ghidra exporter, PowerShell resources, and setup catalog are present in the wheel. Record artifact hashes when creating a reviewed release candidate.

## Future release gate

Any future release requires a separate explicit release decision. Before then, complete the repository's version, license, clean-wheel, platform CI, security review, and release-record checks. Do not tag or publish from this migration. Do not store upload tokens in the repository; if publication is later authorized, use the repository's trusted-publishing workflow and verify the resulting artifacts and metadata.
