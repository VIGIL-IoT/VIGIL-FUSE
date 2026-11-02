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
- Confirm the project rights decision and selected distribution channel before publishing. No project license is currently declared, and this repository does not establish permission to upload a package or release asset.
- Create tags and releases only after an owner explicitly requests publication and the release contents have been reviewed.

There is no automatic release or package upload workflow. Keep local release artifacts in `dist/` out of the repository unless an owner explicitly chooses to publish them.

## Distribution and rights gate

No project license is currently declared. A successful wheel build or metadata check does not establish permission to redistribute or publish FUSE. Removing the root license file does not alter earlier commits or releases that contained different license text. Review the repository's rights history and ownership with qualified counsel before selecting a distribution channel.

GitHub Packages does not currently provide a Python package registry. Its documented registries include Container, npm, RubyGems, Apache Maven, Gradle, and NuGet, so it cannot serve as a standard `pip`, `pipx`, or `uv` index for FUSE. See GitHub's [package registry list](https://docs.github.com/en/packages/learn-github-packages/introduction-to-github-packages). A GitHub Release can host wheel or source archive assets, but publishing those assets still needs a documented rights decision. See GitHub's [release asset documentation](https://docs.github.com/en/repositories/releasing-projects-on-github/about-releases).

Before choosing a channel, the owner should resolve these options with qualified legal review:

- Decide what rights will be granted for use, modification, redistribution, reports, and trademarks. Keep the current no-code-contributions pause until the decision is documented.
- Select a distribution channel and review its current terms. GitHub Packages is not a Python package index.
- Align `pyproject.toml` metadata and release documentation with the approved rights decision before creating public assets.

Until that review is documented, build and test artifacts locally only. Do not upload to PyPI, GitHub Packages, a release page, or another registry or download service. This checklist is an engineering gate, not legal advice.
