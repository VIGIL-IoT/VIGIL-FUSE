# Release process

FUSE remains in the 0.x alpha series. The repository owner authorized a first PyPI publication attempt for version 0.3.0 on 2026-11-11 while legal review and PyPI policy confirmation remain unresolved. This is an owner release decision, not legal advice or PyPI approval, and applies to this release only.

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
- For version 0.3.0, the owner chose to proceed before qualified license review and PyPI policy confirmation. The custom license permits personal and commercial use and grants narrow distribution rights for unmodified official packages through PyPI and its mirrors. The remaining review risk is recorded in the rights packet. Do not describe PyPI as having approved the package.
- Create tags and releases only after an owner explicitly requests publication and the release contents have been reviewed.

The PyPI publish workflow builds the GitHub release tag, validates the distributions, then publishes through a PyPI Trusted Publisher. Keep local release artifacts in dist/ out of the repository.

## Distribution and rights gate

The root LICENSE and Python package metadata declare the custom VIGIL-FUSE Restricted Use License, version 1.1. It grants a limited permission to publish unmodified official package distributions through PyPI and PyPI-compatible mirrors. A successful wheel build or metadata check does not establish that the license is legally sufficient, that the publisher holds all required rights, or that a channel accepts the package. The current license does not revoke permissions already granted for copies provided under earlier license text. The owner's authorization for version 0.3.0 does not resolve these rights-history, ownership, or legal-review questions.

PyPI's current Acceptable Use Policy describes PyPI as a runtime distribution service rather than a research platform and discusses dual-use content related to vulnerability research under its active malware and exploits policy. FUSE is a defensive static security analyzer. PyPI Support issue [#12999](https://github.com/pypi/support/issues/12999) was filed on 2026-11-04 and remained unanswered on 2026-11-11. The owner authorized the 0.3.0 publication attempt before a response. This does not resolve the policy question or indicate PyPI endorsement.

Use the [rights and distribution review packet](governance/rights-review-packet.md) to collect ownership, prior-license, third-party asset, contribution, channel, and release-approval evidence. It is a checklist, not legal advice or a substitute for qualified review.

GitHub Packages does not currently provide a Python package registry. Its documented registries include Container, npm, RubyGems, Apache Maven, Gradle, and NuGet, so it cannot serve as a standard `pip`, `pipx`, or `uv` index for FUSE. See GitHub's [package registry list](https://docs.github.com/en/packages/learn-github-packages/introduction-to-github-packages). A GitHub Release can host wheel or source archive assets, but publishing those assets still needs a documented rights decision. See GitHub's [release asset documentation](https://docs.github.com/en/repositories/releasing-projects-on-github/about-releases).

For later releases or distribution channels, the owner should resolve these options with qualified legal review:

- Confirm that the declared use, modification, redistribution, report, and trademark terms match the owner's intent. Keep the current no-code-contributions pause until contribution rights are documented.
- Select a distribution channel and review its current terms. GitHub Packages is not a Python package index.
- Confirm that `pyproject.toml` metadata and release documentation match the approved rights decision before creating public assets.

The owner decision authorizes only the first PyPI publication attempt for version 0.3.0. Other registries and future releases remain gated on a separate documented owner decision and rights review. The license-history, ownership, and PyPI policy questions remain open. This checklist is an engineering record, not legal advice.
