# Release process

VIGIL-FUSE remains in the 0.x alpha series. Version 0.4.0 was published on 2026-11-15 under the VIGIL-FUSE Restricted Use License v1.2 after the required technical checks passed. Shantanu is the copyright holder for current and future releases. VIGIL-IoT remains the project organization and repository namespace. The source is available under a custom license, not an OSI-approved open-source license. Initial feature development is complete and maintenance mode is active.

The license has not received external legal review. PyPI Support issue [#12999](https://github.com/pypi/support/issues/12999) remains open. The owner has authorized the release while policy guidance is pending. A successful upload is not PyPI policy approval. The current owner decision and historical license record are in the [rights and distribution record](governance/rights-review-packet.md).

## 0.4.0 release acceptance record

From a clean working tree on the release-preparation branch:

```powershell
python -m pip install -e ".[dev]"
python -m pytest -q
python -m coverage run -m pytest -q
python -m coverage report -m --fail-under=75
python -m ruff check src tests scripts
python -m ruff format --check src tests scripts
python -m mypy
python scripts/validate_docs.py
python scripts/evaluate_rule_benchmark.py --check
python -m build
python -m twine check dist/*
```

Install the built wheel in a fresh virtual environment and verify:

```powershell
vigil-fuse --version
vigil-fuse --help
vigil-fuse doctor
vigil-fuse scan --help
```

Exercise representative text, JSON, and SARIF scans. Confirm machine-readable output contains no terminal banner. Keep build artifacts and test reports out of the repository.

## Version and release gates

- Use `0.4.0` for this authorized final release of the initial development scope. Do not bump to `1.0.0`; the project does not promise stable 1.x APIs.
- Require passing Linux, Windows, and macOS CI, the package build and clean-install smoke test, the quality and coverage job, Docker fixture integration, CodeQL, and the dedicated Ghidra integration workflow.
- Confirm no open secret-scanning alerts, the active `Protect main` ruleset, the `vigil-fuse` package metadata, and inclusion of the license in both distributions.
- Review the final diff for personal paths, secrets, generated temporary files, historical report changes, and unsupported security or firmware claims.
- Merge the release-preparation pull request only after all required checks pass.
- Create the annotated `v0.4.0` tag from the verified main commit, then publish GitHub release `FUSE 0.4.0`. The existing `pypi-publish.yml` workflow builds from that tag, runs Twine validation, checks the artifact version, and publishes through GitHub Trusted Publishing in the `pypi` environment.
- Verify the public PyPI metadata, custom license identifier, included `LICENSE`, artifact hashes, and a clean installation reporting `vigil-fuse --version` as `0.4.0`.
- Record the commit and tag SHAs, wheel and source archive SHA-256 hashes, release and package URLs, publication date, and CI, CodeQL, and Ghidra workflow runs in the [completion record](PROJECT_COMPLETION.md).

PyPI's [Terms of Service](https://policies.python.org/pypi.org/Terms-of-Service/) describe the rights required for PSF, PyPI users, and mirrors to redistribute unmodified package files. License v1.2 includes a narrow grant for Official PyPI Distributions. This project has not received a PyPI-specific approval, and publication must not be described as approval. The [current Acceptable Use Policy](https://policies.python.org/pypi.org/Acceptable-Use-Policy/) and support issue remain documented in the rights record.

## Maintenance mode

Version 0.4.0 has been published and verified. Maintenance work is limited to confirmed defects, security fixes, dependency and supported-platform compatibility, packaging fixes, documentation corrections, and regression tests. New analyzers, rules, research features, firmware emulation, hardware programming, and UI redesigns require a separately approved future scope.
