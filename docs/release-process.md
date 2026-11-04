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
- Review the custom VIGIL-FUSE Restricted Use License, version 1.1, with qualified counsel and confirm the selected distribution channel's terms before publishing. The license permits personal and commercial use, and a narrow distribution of unmodified official packages through PyPI and its mirrors. It continues to restrict distribution through other channels and publishing modifications.
- Create tags and releases only after an owner explicitly requests publication and the release contents have been reviewed.

There is no automatic release or package upload workflow. Keep local release artifacts in `dist/` out of the repository unless an owner explicitly chooses to publish them.

## Distribution and rights gate

The root `LICENSE` and Python package metadata declare the custom VIGIL-FUSE Restricted Use License, version 1.1. It grants a limited permission to publish unmodified official package distributions through PyPI and PyPI-compatible mirrors. A successful wheel build or metadata check does not establish that the license is legally sufficient, that the publisher holds all required rights, or that a channel accepts the package. The current license does not revoke permissions already granted for copies provided under earlier license text. Review the repository's rights history, ownership, third-party material, and selected channel terms with qualified counsel before publishing.

PyPI's current Acceptable Use Policy describes PyPI as a runtime distribution service rather than a research platform and discusses dual-use content related to vulnerability research under its active malware and exploits policy. FUSE is a defensive static security analyzer whose intended use includes inspecting software for vulnerabilities. Ask PyPI support whether this project fits the policy before uploading, and record the response in the rights review packet. The license change alone does not resolve this eligibility question.

Use the [rights and distribution review packet](governance/rights-review-packet.md) to collect ownership, prior-license, third-party asset, contribution, channel, and release-approval evidence. It is a checklist, not legal advice or a substitute for qualified review.

GitHub Packages does not currently provide a Python package registry. Its documented registries include Container, npm, RubyGems, Apache Maven, Gradle, and NuGet, so it cannot serve as a standard `pip`, `pipx`, or `uv` index for FUSE. See GitHub's [package registry list](https://docs.github.com/en/packages/learn-github-packages/introduction-to-github-packages). A GitHub Release can host wheel or source archive assets, but publishing those assets still needs a documented rights decision. See GitHub's [release asset documentation](https://docs.github.com/en/repositories/releasing-projects-on-github/about-releases).

Before publishing through a channel, the owner should resolve these options with qualified legal review:

- Confirm that the declared use, modification, redistribution, report, and trademark terms match the owner's intent. Keep the current no-code-contributions pause until contribution rights are documented.
- Select a distribution channel and review its current terms. GitHub Packages is not a Python package index.
- Confirm that `pyproject.toml` metadata and release documentation match the approved rights decision before creating public assets.

Until that review is documented, build and test artifacts locally only. Do not upload to PyPI, GitHub Packages, a release page, or another registry or download service. This checklist is an engineering gate, not legal advice.
