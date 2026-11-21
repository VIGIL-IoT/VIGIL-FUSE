# PRE-PyPI release workflow

This branch prepares packaging and local validation. It does not publish to TestPyPI or PyPI, and its CI has no publishing job.

## Build and validate locally

From a clean checkout with Python 3.11 or newer:

```powershell
python -m pip install "build>=1.2,<2" "twine>=6,<7"
python -m build
python -c "import pathlib,subprocess,sys; files=[str(p) for p in pathlib.Path('dist').iterdir() if p.suffix in {'.whl','.gz'}]; subprocess.run([sys.executable,'-m','twine','check',*files],check=True)"
python scripts/verify_installed_wheel.py
```

For a manual fresh-environment install, select the produced wheel and run it from a separate directory:

```powershell
py -3 -m venv .venv-install-test
.\.venv-install-test\Scripts\Activate.ps1
$wheel = Get-ChildItem .\dist\*.whl | Select-Object -First 1
python -m pip install $wheel.FullName
Set-Location $env:TEMP
vigil-fuse --version
vigil-fuse doctor
vigil-fuse setup --dry-run
vigil-fuse setup --recommended
vigil-fuse doctor
```

`setup --recommended` asks before downloading pinned binaries. You can decline and still verify that the installed CLI and core scanner work without external analyzers.

The wheel verifier creates a fresh environment and a working directory with spaces outside the source checkout. It installs the wheel and its test extra, exercises the installed version and JSON doctor, runs setup dry-run, scans a small source fixture, and runs the unit suite against the installed package environment.

Generate a checksum file after the build, then compare the entries with the artifacts before sharing them:

```powershell
$artifacts = Get-ChildItem .\dist -File | Where-Object { $_.Name -ne 'SHA256SUMS.txt' }
$artifacts | ForEach-Object { "{0}  {1}" -f (Get-FileHash $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant(), $_.Name } | Set-Content .\dist\SHA256SUMS.txt
Get-Content .\dist\SHA256SUMS.txt
Get-ChildItem .\dist -File | Where-Object { $_.Name -ne 'SHA256SUMS.txt' } | Get-FileHash -Algorithm SHA256
```

The built wheel and source distribution include dependency metadata and the license. The CI packaging job builds both artifacts, runs Twine metadata validation on Linux, Windows, and macOS, and invokes the isolated wheel verifier on each platform. No release provenance or signatures are claimed by this stage.

## Later TestPyPI flow

After review and approval for a release, the intended sequence is:

1. Build wheel and sdist from a clean tagged commit.
2. Run local wheel, metadata, test, and checksum validation.
3. Publish to TestPyPI using trusted publishing where available.
4. Install from TestPyPI in a fresh environment and repeat CLI smoke checks.
5. Review TestPyPI metadata and artifacts.
6. Publish to production PyPI only after a separate explicit release authorization.

Do not store upload tokens in the repository. Future CI publishing should use an environment-scoped trusted publisher/OIDC connection rather than long-lived credentials.
