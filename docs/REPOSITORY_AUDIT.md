# Repository audit

**Audit date:** 2026-10-30
**Repository:** VIGIL-IoT/VIGIL-FUSE
**Workspace revision:** `121c74e` plus local documentation-validator hardening
**Scope:** Source, package metadata, tests, CI, documentation, reports, static site, figures, tags, license, badges, and locally available validation tools.

## Repository overview

FUSE is a CLI-first Python tool for bounded static inspection of embedded and IoT project source, configuration, selected build metadata, hardware artifacts, dependency inventories, and firmware candidates. It is part of VIGIL-IoT and complements SPECTRA-32's controlled lab experiments. FUSE does not itself build projects, execute scanned source or firmware, contact devices, or validate physical hardware.

The package has no required runtime dependencies, seven native rules, schema-versioned reports, optional external analyzer adapters, a static project site, and pinned repository scan evidence. The project is alpha software, version `0.2.0`, under a custom source-available restricted-use license. It is not OSI-approved open-source software.

## Initial condition

At the start of this audit pass, the workspace already contained substantial local engineering changes from the preceding improvement pass: hardened KiCad parsing and terminal output, the FUSE003 Python AST check, focused analyzer modules, a synthetic fixture scorecard, expanded tests, a 70% branch coverage gate, and release and threat-model documentation. The current baseline was stronger than the public tagged source alone.

Remaining gaps at the start of this pass were primarily project-level traceability and governance: no consolidated requirements and objective record, no end-to-end methodology, no dedicated limitations or benchmark overview, no requirement-to-evidence matrix, no ADR set, no formal evaluation protocol, no citation metadata, no root contribution guidance, and no automated local-link or Mermaid-block check.

## Major problems found

- The rich implementation and research evidence were spread across README, roadmap, architecture notes, and report folders, making it difficult to distinguish requirements, measured results, and planned work.
- No single traceability table connected objectives to code, tests, and evidence.
- There was no consolidated limitations page or experiment-style record for the repository scan cohort.
- Mermaid diagrams and local Markdown links had no repository validation gate.
- Citation metadata and GitHub issue/PR templates were absent.
- The current license restricts redistribution and package-registry uploads without written permission. This is a substantive release blocker, not a code defect.
- The public latest release endpoint reports `v0.2.0`, matching the local tag.

## Architecture findings

The `src/vigil_fuse/` package separates CLI, discovery, models, rule execution, native rules, platform context, hardware and firmware inventories, optional analyzers, and reporters. The `analyzers.py` compatibility facade preserves public import paths while optional tool implementations live in focused modules. The local CLI is the deployment boundary; `site/` is a static informational site, not a FUSE service.

FUSE's core analysis is bounded and read-only. Native rules operate on decoded selected text in a worker process with timeouts. Context adapters read selected metadata. Optional external programs are invoked only when selected and are not sandboxed by FUSE. Findings separate severity, confidence, applicability, and validation state. New Mermaid diagrams document the actual input, processing, reporting, and hardware boundaries.

## Improvements implemented

- Added project identity, problem, scope, functional and nonfunctional requirements, measurable objectives, assumptions, constraints, technology stack, and maturity boundaries.
- Added implementation methodology, explicit limitations, benchmark interpretation, repository structure, SBOM instructions, and requirements traceability.
- Added a dated descriptive repository-scan evaluation record that distinguishes observations from controlled experiments and field accuracy.
- Added four retrospective ADRs. Each identifies its rationale as retrospective rather than claiming unavailable historical intent.
- Added Mermaid system, sequence, module dependency, static-site configuration, and hardware-software boundary diagrams.
- Added `CITATION.cff`, a root `CONTRIBUTING.md`, GitHub issue forms, and a pull request template without changing the license.
- Added `scripts/validate_docs.py` and tests for local links and Mermaid fence structure; CI runs this documentation validation.
- Added a generated Anatomy-style finding model in dark and light SVG, plus a self-contained interactive view. It shows severity, confidence, applicability, and validation as separate fields. The locally vendored drawing kit is pinned in `scripts/vendor/anatomy/NOTICE.md`.
- Replaced the single README CI badge with verified Shields.io CI, release, Python-version, and custom-license badges. No PyPI or coverage badge is shown because those would imply unsupported publication or reporting setup.
- Added an Unreleased changelog section and roadmap horizons for immediate, short-term, medium-term, and long-term work.
- Preserved earlier engineering changes already in the workspace: analyzer module split, XML hardening, terminal control handling, subprocess input isolation, FUSE003 AST analysis, fixture benchmark, and stronger CI/package checks.

## Files added

- `CITATION.cff`, `CONTRIBUTING.md`
- `.github/ISSUE_TEMPLATE/bug_report.yml`, `.github/ISSUE_TEMPLATE/feature_request.yml`, `.github/PULL_REQUEST_TEMPLATE.md`
- `docs/REPOSITORY_AUDIT.md`, `docs/requirements.md`, `docs/methodology.md`, `docs/limitations.md`, `docs/traceability.md`, `docs/benchmarks.md`, `docs/repository-structure.md`, `docs/sbom.md`
- `docs/experiments/pilot-scan-2026-10.md`
- `docs/decisions/ADR-0001-cli-first-package.md`, `ADR-0002-bounded-non-executing-analysis.md`, `ADR-0003-normalized-findings-and-coverage.md`, `ADR-0004-optional-tool-adapters.md`
- `scripts/validate_docs.py`, `tests/test_docs_validation.py`
- `scripts/build_finding_model_figure.mjs`, `scripts/vendor/anatomy/iso-kit.mjs`, `scripts/vendor/anatomy/LICENSE`, `scripts/vendor/anatomy/NOTICE.md`
- `docs/figures/fuse-finding-model.svg`, `docs/figures/fuse-finding-model-light.svg`, `site/diagrams/fuse-finding-model.html`
- Earlier workspace additions include focused analyzer modules, the native-rule fixture evaluator, rule fixtures, and `reports/benchmark/native-rule-fixtures.json`.

## Files modified

- `README.md`, `CHANGELOG.md`, `CONTRIBUTING.md`, `.github/workflows/ci.yml`, `docs/architecture.md`, `docs/contributing.md`, and `docs/roadmap.md`
- Existing local engineering changes also touch `.gitignore`, `SECURITY.md`, `pyproject.toml`, scanner and analyzer modules, native TLS rule, reporting, terminal safety, parser and product context code, related tests, and report-building scripts.
- `LICENSE` was not modified.

## Testing performed

- Full pytest suite, including docs validation tests, plus the focused security and input-handling subset.
- Branch-aware coverage report and threshold check.
- Ruff lint and focused formatting check.
- Synthetic native-rule fixture benchmark.
- Local Markdown path and Mermaid block validation.
- YAML parsing for workflow and issue-form configuration; citation metadata YAML parsing.
- Package wheel and source distribution build, Twine metadata check, clean virtual environment wheel install, CLI version/doctor/help checks, and installed-package scan smoke test.
- FUSE local self-scan with network and optional external analyzers disabled.
- Git diff whitespace check and changed-file punctuation review.
- Anatomy generator syntax, generated inline JavaScript parsing, SVG XML structure, and Shields.io badge response checks.

## Test results

The complete suite passes locally with **187 tests** on Windows and Python 3.14. Workflow run `41005760221` on `121c74e` passed all eight jobs and all **186 tests**, with **75%** branch-aware coverage against the 70% gate. Adding PyYAML to the test extra enabled all four ESP-IDF YAML checks in CI. The synthetic fixture benchmark reports 16 cases across seven native rules, all matching their labels; these are synthetic fixtures and do not measure field accuracy. The documentation validator now uses Git's tracked and non-ignored untracked file list, so local validation covers **53 Markdown files**, matching the latest remote count. Package build and clean-install smoke checks passed on `dd1c043`. The FUSE self-scan in the latest remote quality job covered 203 files, completed discovery, and reported zero findings. The path audit passes over 494 tracked files and Git history. The Anatomy builder reports 56 named parts; the generator, inline JavaScript, and both SVG files pass structural checks. The documentation-validator change and its additional test have passed locally; remote verification is pending.

The original full-tree Ruff check identified 42 files for reformatting. Four were formatted with the path fix, and the remaining 38 are formatted in `121c74e`. CI now checks formatting across all Python files under `src`, `tests`, and `scripts`. Run #226 on `0f8d4ef` failed documentation validation because the README linked to supporting docs not yet in that commit. The docs increment resolved those links, and run #227 on `dd1c043` succeeded. Run #228 on `d219d1e` exercised the new Windows and macOS Python 3.11 jobs and exposed path-alias failures in four tests on each OS. The fix uses file identity to recognize OS aliases to the project root, checks in-target path components for symlinks, and adds regression cases for both behaviors. Run #229 on `fd15878` passed all eight jobs across Ubuntu Python 3.11 to 3.14, Windows Python 3.11, macOS Python 3.11, quality, and package smoke. The next run on `121c74e` also passed all eight jobs, including full-tree formatting and YAML-enabled tests. Both SVGs parse as XML and the interactive script parses, but browser rendering and live interaction have not been visually verified.

## Security findings

- No license changes or credentials were introduced by this pass. FUSE's own self-scan and focused security tests are part of local validation.
- KiCad XML parsing rejects DTD/entity declarations and enforces size, element, and depth limits. Terminal output escapes control and bidi characters. Optional analyzer subprocesses receive no inherited interactive stdin.
- The rule and scan reports are candidate evidence. They do not prove exploitability, reachability, or deployed-product applicability.
- External analyzers parse their own inputs and are not sandboxed. Syft, OSV-Scanner, Binwalk, and Gitleaks were not installed during this audit, so those end-to-end integrations remain unverified here.
- The custom license permits commercial use but restricts sharing and redistribution, including package registry uploads without written permission. Do not treat the successful package build as distribution authorization.

## Dependency findings

The core runtime dependency list is empty. `pyproject.toml` declares Python `>=3.11`, setuptools as the PEP 517 build backend, an optional PyYAML extra for ESP-IDF lock parsing, and bounded test/development dependency ranges. Syft, OSV-Scanner, Binwalk, and Gitleaks are external executables, not Python runtime dependencies.

No complete dependency vulnerability audit was run because OSV-Scanner was unavailable. The [PyPI JSON endpoint for `vigil-fuse`](https://pypi.org/pypi/vigil-fuse/json) returned HTTP 404 when checked on 2026-10-29. This is only a point-in-time name availability observation and neither reserves the name nor grants permission to publish. Recheck before any future release review.

## Documentation improvements

The README now summarizes alpha status, implemented scope, and major boundaries. Supporting pages cover requirements, methodology, architecture, threat model, limitations, traceability, benchmark evidence, repository structure, release process, and SBOM handling. Every new claim points to implementation or evidence where possible. No SDG alignment file was created: the repository demonstrates software engineering activity but has no measured societal outcome or evidence that supports a specific SDG impact claim.

## Research improvements

The repository scan is described as a pinned, descriptive evaluation. It records its question, dataset, method, variables, measures, scope, failure cases, and threats to validity. Synthetic fixtures, repository regression data, and separately maintained holdout cohorts remain distinct. No field precision, recall, or vulnerability prevalence is claimed. There is no comparative benchmark against other products.

## Reproducibility improvements

The new methodology page gives install, scan, test, and fixture-check commands. Existing manifests pin repositories and scopes. The package workflow builds wheel and sdist, checks metadata, installs into a clean environment, and runs CLI smoke checks. A FUSE SBOM generation path is documented, but no SBOM was produced because Syft is unavailable locally and no static SBOM was generated that could become stale.

## Traceability status

`docs/traceability.md` maps requirements to objectives, decisions, implementation files, verification, and evidence. Optional executable integrations and the non-execution guarantee are marked partially verified where local evidence does not justify a stronger claim. The matrix does not equate test success with product security.

## Remaining limitations

- No representative independent ground-truth corpus or field accuracy estimate.
- The latest remote CI run is green across Ubuntu, Windows, and macOS. Browser rendering and interaction of the finding-model figure remain unverified.
- No compiler-semantic C/C++ analysis, general firmware extraction, device testing, or hardware-in-the-loop validation.
- Optional analyzers were not installed and tested end to end.
- No configured static type checker and no complete dependency vulnerability audit.
- No rendered Mermaid browser check; the validator checks local link targets, code fences, and Mermaid block types, not full renderer semantics. The new SVGs were structurally validated, but visual browser review remains outstanding.
- Custom license and distribution terms require owner and qualified legal review before registry or release distribution.
- Browser-based visual and interaction review of the new finding-model figure remains outstanding.

## Initial maturity score

Scores use the weights from the master prompt. The initial assessment is the workspace state at the start of this audit pass, which already included the previous local engineering improvements. Scores are qualitative engineering judgment, not a formal certification.

| Dimension | Weight | Initial score | Evidence at audit start |
| --- | ---: | ---: | --- |
| Architecture & Modularity | 15 | 13 | Modular Python package and architecture notes; no Mermaid operational views or ADRs |
| Documentation | 15 | 11 | Extensive README and specialist docs; requirements, limitations, methodology, and traceability were fragmented or absent |
| Code Quality | 15 | 12 | Ruff lint, bounded components, and typed data models; no type-checking gate and formatting debt remained |
| Testing | 15 | 12 | Existing test suite, fixture benchmark, and CI; no docs-link validation gate |
| Security | 10 | 9 | Threat model, bounded inputs, explicit coverage, and security tests; external tool sandboxing and broad third-party audit absent |
| Reproducibility | 10 | 8 | Pinned scan manifests and package workflow; no consolidated methodology, SBOM record, or complete cross-platform evidence |
| Open Source Governance | 10 | 4 | Security and release docs existed; citation and root contribution guidance absent, and custom license restricts redistribution |
| Research Rigor & Traceability | 10 | 8 | Pinned scans, synthetic benchmark, holdout notes, and research docs; no unified traceability or experiment protocol |
| **Total** | **100** | **77** | |

## Final maturity score

| Dimension | Weight | Final score | Evidence and remaining gap |
| --- | ---: | ---: | --- |
| Architecture & Modularity | 15 | 14 | Mermaid data flow and hardware boundary plus four ADRs; hardware and product applicability remain limited |
| Documentation | 15 | 14 | Requirements, methods, limitations, benchmarks, structure, and audit are explicit; no SDG impact claim is supported |
| Code Quality | 15 | 12 | Product code was preserved; docs validator is tested and full-tree Ruff formatting now passes locally. Type checking remains |
| Testing | 15 | 13 | 186 local tests, 73% remote branch-aware coverage, fixture check, docs check, and a green Ubuntu/Windows/macOS matrix; field accuracy remains unmeasured |
| Security | 10 | 9 | Parser and output hardening retained; external tools are not sandboxed and were unavailable for end-to-end checks |
| Reproducibility | 10 | 9 | Pinned manifests, commands, CI package smoke checks, and evaluation protocol; optional tools and remote CI not reproduced here |
| Open Source Governance | 10 | 6 | Citation, contribution boundaries, issue forms, PR checklist, and release gates added; custom license and enforcement policy remain unresolved |
| Research Rigor & Traceability | 10 | 9 | Evidence types, limitations, cohort method, and traceability now documented; no representative accuracy estimate or product comparison |
| **Total** | **100** | **86** | |

## Recommended next actions

1. Review this local diff and run the configured GitHub Actions on a reviewed commit.
2. Resolve the license and allowed distribution channels before publishing a release or package.
3. Install and pin optional analyzers in a controlled environment, then validate their real outputs and failure states.
4. Extend independent, manually reviewed fixtures and retain difficult negatives before claiming field accuracy.
5. Add a reproducible performance and memory harness before reporting speed or throughput.
6. Defer device, hardware, and firmware-extraction claims until controlled hardware or isolated extraction environments are available.
