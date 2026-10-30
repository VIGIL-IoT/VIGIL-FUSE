# Release process

FUSE remains in the 0.x alpha series. Completing code changes does not by itself make a release ready. Do not publish to PyPI or publish a GitHub release until an owner has made and documented the distribution decision.

## Local release candidate checks

From a clean working tree after the intended changes are reviewed:

```powershell
python -m pip install -e ".[dev]"
python -m pytest -q
python scripts/evaluate_rule_benchmark.py --check
python -m ruff check src tests scripts
python -m coverage run -m pytest
python -m coverage report -m --fail-under=70
python -m build
python -m twine check dist/*
```

Install the built wheel into a clean virtual environment and verify:

```powershell
vigil-fuse --version
vigil-fuse doctor
vigil-fuse scan --help
```

Also validate report schemas, run a small representative scan, inspect generated text/JSON/SARIF and artifacts, and confirm optional-stage failures and partial coverage are visible. Keep coverage artifacts out of version control.

## Version and release gates

- Keep the version in `0.x` while the documented release gates are incomplete.
- Require green supported-Python CI, package build and install smoke test, schema validation, security-specific tests, and the synthetic fixture benchmark.
- Reproduce validation reports from pinned manifests and preserve the distinction between development, regression, and holdout data.
- Review the full diff for secrets, user-owned scan artifacts, generated output, and unsupported claims.
- Confirm the restricted-use license and the selected distribution channel are compatible. The current license prohibits public and private registry uploads without written permission. This repository does not authorize an upload by itself.
- Create tags and releases only after an owner explicitly requests publication and the release contents have been reviewed.

There is no automatic release or package upload workflow. Keep local release artifacts in `dist/` out of the repository unless an owner explicitly chooses to publish them.

## Distribution and license gate

The current custom source-available license permits commercial use but restricts redistribution. Section 3 specifically bars uploading or mirroring the Software to public or private package registries, source repositories, container registries, and download services without written permission. A successful wheel build or metadata check does not grant that permission.

Before choosing a channel, the owner should resolve these options with qualified legal review:

- Keep installation limited to downloading or cloning the canonical source for the installer's own use, after checking how the repository host's public-fork and content terms interact with the license.
- Obtain a written, channel-specific permission for a GitHub Release asset, GitHub Packages, a private index, or another controlled download service. Do not assume that a private registry avoids the restriction.
- Approve revised distribution terms before using a public package registry. PyPI's upload and package terms need separate review against both the license and the project's intended defensive use.

Until that review is documented, build and test artifacts locally only. Do not upload to PyPI, GitHub Packages, a release page, or another registry or download service. This checklist is an engineering gate, not legal advice.
