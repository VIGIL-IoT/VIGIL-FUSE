# Local package validation

PyPI publishing is paused. The commands here build and verify local artifacts only. They do not publish to TestPyPI or PyPI and do not authorize a release.

## Build and validate locally

From the repository root with Python 3.11 or newer:

~~~powershell
python -m pip install "build==1.6.1" "twine==7.0.0" "setuptools==84.2.1"
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

The release workflow builds in a job with read-only repository access and no OIDC permission. It checks the wheel and source archive, writes a SHA-256 manifest, and uploads them as a workflow artifact. The protected `pypi` job receives only that artifact, verifies its manifest and release-tag filenames, and requests OIDC only for trusted publishing. It does not check out source or run package build commands.

Build-tool pins are deliberate: the workflow and local validation commands pin `build` and `twine`, while `[build-system].requires` pins the backend used by isolated builds. When updating a pin, check the package's current PyPI release metadata for Python compatibility, update the workflow, build-system requirement, and these commands together, then run the package build, Twine check, and installed-wheel verifier. Developer extras remain version ranges so routine development does not require pin maintenance.

## Future release gate

Any future release requires a separate explicit release decision. Before then, complete the repository's version, license, clean-wheel, platform CI, security review, and release-record checks. Do not tag or publish from this migration. Do not store upload tokens in the repository; if publication is later authorized, use the repository's trusted-publishing workflow and verify the resulting artifacts and metadata.
