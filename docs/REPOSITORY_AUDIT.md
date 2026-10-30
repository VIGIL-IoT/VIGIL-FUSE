# Repository audit

**Audit date:** 2026-10-31
**Repository:** VIGIL-IoT/VIGIL-FUSE
**Code baseline before this increment:** `953b786`
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
- Added weekly Dependabot checks for pip and GitHub Actions, plus a separate dependency-audit workflow using pip-audit. The first audit identified the vulnerable pytest 8.x range and led to raising the test floor to 9.0.3.
- Updated the static site to describe FUSE's present analysis scope, remove the planned external lab handoff, and use a shared vertical-spacing scale across major sections.
- Added Mypy 2.4.1 as a development dependency and a strict type-checking CI gate across all 44 source modules plus the scan benchmark script. Strict Mypy passes without suppressing diagnostics.
- Added a deterministic CLI performance harness with wall-time and sampled process-tree RSS measurements, a versioned JSON report schema, a recorded local baseline, and CI smoke coverage. The benchmark uses only synthetic source and makes no general speed or accuracy claim.
- Added a manifest-driven sparse-checkout preparer and a manually dispatched Ubuntu, Windows, and macOS workflow for the same four pinned repository scopes. Each run validates and uploads a schema-checked report artifact. The workflow is implemented but has not yet produced cross-platform results.
- Verified Syft 1.55.0 and OSV-Scanner 2.7.0 against positive, clean, and no-package-source fixtures. Fixed the OSV adapter's handling of the real CLI's exit-128 no-source response and added a repeatable harness plus experiment record.
- Verified the Binwalk v2.3.3 identification adapter in WSL2 with a synthetic gzip positive and clean control. Added bounded help-banner version detection, a repeatable smoke harness, a regression test, and an experiment record. This is not a firmware-accuracy study.
- Manually reviewed the 23 signals in the separately pinned second fresh-validation snapshot. Added grouped, source-context dispositions while preserving redaction and stating that the review is not independent accuracy evidence. Placeholder-looking defaults remain candidates because an unchanged example can still be built.
- Preserved earlier engineering changes already in the workspace: analyzer module split, XML hardening, terminal control handling, subprocess input isolation, FUSE003 AST analysis, fixture benchmark, and stronger CI/package checks.

## Files added

- `CITATION.cff`, `CONTRIBUTING.md`, `.github/dependabot.yml`, `.github/workflows/dependency-audit.yml`
- `.github/ISSUE_TEMPLATE/bug_report.yml`, `.github/ISSUE_TEMPLATE/feature_request.yml`, `.github/PULL_REQUEST_TEMPLATE.md`
- `docs/REPOSITORY_AUDIT.md`, `docs/requirements.md`, `docs/methodology.md`, `docs/limitations.md`, `docs/traceability.md`, `docs/benchmarks.md`, `docs/repository-structure.md`, `docs/sbom.md`
- `docs/experiments/pilot-scan-2026-10.md`, `docs/experiments/dependency-adapters-e2e-2026-10-31.md`, `docs/experiments/binwalk-adapter-e2e-2026-10-31.md`, `reports/repository-scans/fresh-validation-next/triage.md`
- `docs/decisions/ADR-0001-cli-first-package.md`, `ADR-0002-bounded-non-executing-analysis.md`, `ADR-0003-normalized-findings-and-coverage.md`, `ADR-0004-optional-tool-adapters.md`
- `scripts/validate_docs.py`, `scripts/verify_dependency_adapters.py`, `scripts/verify_binwalk_adapter.py`, `scripts/prepare_repository_benchmark_cohort.py`, `tests/test_docs_validation.py`, `tests/test_dependency_policy.py`, `tests/test_repository_performance_workflow.py`, `.github/workflows/repository-performance.yml`
- `scripts/benchmark_scan.py`, `tests/test_performance_benchmark.py`, `reports/benchmark/scan-performance.json`, `reports/benchmark/scan-performance.schema.json`
- `scripts/build_finding_model_figure.mjs`, `scripts/vendor/anatomy/iso-kit.mjs`, `scripts/vendor/anatomy/LICENSE`, `scripts/vendor/anatomy/NOTICE.md`
- `docs/figures/fuse-finding-model.svg`, `docs/figures/fuse-finding-model-light.svg`, `site/diagrams/fuse-finding-model.html`
- Earlier workspace additions include focused analyzer modules, the native-rule fixture evaluator, rule fixtures, and `reports/benchmark/native-rule-fixtures.json`.

## Files modified

- `README.md`, `CHANGELOG.md`, `CONTRIBUTING.md`, `.github/workflows/ci.yml`, `pyproject.toml`, `docs/architecture.md`, `docs/benchmarks.md`, `docs/traceability.md`, `docs/contributing.md`, `docs/methodology.md`, `docs/requirements.md`, `docs/repository-structure.md`, `docs/sbom.md`, `docs/roadmap.md`, `docs/website.md`, and the static site files under `site/`
- The prior increments modified the Binwalk adapter and its verification docs; this increment adds manual review in `reports/repository-scans/fresh-validation-next/triage.md` and updates the cohort README, `docs/detection-benchmark.md`, and this audit record. Earlier engineering changes also touch `.gitignore`, `SECURITY.md`, `pyproject.toml`, scanner and analyzer modules, native TLS rule, reporting, terminal safety, parser and product context code, related tests, and report-building scripts.
- `LICENSE` was not modified.

## Testing performed

- The Syft/OSV adapter increment passed local `unittest` discovery with 182 test methods, Ruff lint and formatting across 76 files, Markdown validation across 55 files, and the path audit across 504 tracked files and Git history. This Python environment did not include pytest or Mypy, so the configured CI jobs remain authoritative for those gates.
- The Binwalk increment passed local `unittest` discovery with 183 test methods, Ruff lint and formatting across `src`, `tests`, and `scripts`, Markdown validation across 56 files, and the path audit across 506 tracked files and Git history. The real Binwalk v2.3.3 WSL2 smoke check passed before this documentation refresh; its temporary package extraction is not currently on `PATH`.
- FUSE CI run `41118660790` passed all eight jobs for `bd471b1`, including Ubuntu, Windows, and macOS test jobs, strict Mypy, repository path checks, documentation validation, package installation, and branch coverage. The second fresh-validation cohort's 23 findings were manually reviewed against clean checkouts at their pinned commits; this is a source-context review, not an independent evaluation.
- FUSE CI run `41119431946` passed all eight jobs for `953b786`, including the manual-triage documentation links, repository path check, package installation, platform tests, strict Mypy, and branch coverage.
- This documentation increment passed Markdown validation across 57 files, the repository path audit across 509 tracked files and Git history, and `git diff --check`.
- The pinned repository cohort increment passed 202 local pytest tests plus 81 subtests, Ruff, strict Mypy, fixture benchmark validation, documentation validation, report-schema validation, and the personal-path audit. Its three sequential commits each passed their FUSE CI workflow.
- The cross-platform workflow increment is locally validated for manifest safety and workflow configuration. Run `41125057256` completed pinned scans but failed report construction because FUSE was not installed in the job. Run `41125641349` passed all three hosts after that fix. Artifact review then found that the same manifest had different raw-byte hashes on Windows and Unix because of checkout line endings. The digest now normalizes line endings, and the final verified run is pending. No cross-platform timing claim or maturity-score increase is recorded yet.
- Full pytest suite, including dependency policy and docs validation tests, plus the focused security and input-handling subset.
- Branch-aware coverage report and threshold check.
- Ruff lint and focused formatting check.
- Synthetic native-rule fixture benchmark.
- Local Markdown path and Mermaid block validation.
- Mermaid rendering follow-up on 2026-10-31: rendered the one README diagram and all five diagrams in `docs/architecture.md` with Mermaid 12.0.0 in headless Chromium. All six produced SVGs and were visually inspected at desktop width. Labels and connectors were legible, with no clipping. GitHub's architecture page lazy-loads its diagram frames; after scrolling and waiting for hydration, all five diagrams rendered.
- Gitleaks history adapter end-to-end check on 2026-10-31: verified the official Gitleaks 8.30.0 Windows x64 release asset by SHA-256, then ran a synthetic positive fixture and clean control. The positive case returned two redacted signals, the clean control returned none, and the generated value was absent from every report and captured output. The reproducible harness and limits are in [the experiment record](experiments/gitleaks-adapter-e2e-2026-10-31.md) and [verification script](../scripts/verify_gitleaks_adapter.py).
- Syft and OSV-Scanner end-to-end check on 2026-10-31: verified the official Syft 1.55.0 and OSV-Scanner 2.7.0 Windows x64 asset SHA-256 digests, then ran a vulnerable dependency, a clean dependency control, and a no-package-source project through FUSE. The first two produced 11 and zero OSV findings with completed adapter status. The no-source case produced the expected partial OSV status, no fabricated results artifact, and CLI exit code 2. See the [experiment record](experiments/dependency-adapters-e2e-2026-10-31.md) and [verification script](../scripts/verify_dependency_adapters.py).
- YAML parsing for workflow and issue-form configuration; citation metadata YAML parsing.
- Package wheel and source distribution build, Twine metadata check, clean virtual environment wheel install, CLI version/doctor/help checks, and installed-package scan smoke test.
- FUSE local self-scan with network and optional external analyzers disabled: discovery completed across 235 selected files with zero findings; the report inventoried three hardware artifacts.
- pip-audit against an isolated virtual environment created from the declared development extras.
- Git diff whitespace check and changed-file punctuation review.
- Anatomy generator syntax, generated inline JavaScript parsing, SVG XML structure, and Shields.io badge response checks.
- Static-site screenshots reviewed at 1440, 768, and 390 pixel widths. The browser reported no console errors or horizontal overflow. The desktop full-page inspector returned a load timeout after producing screenshots; its separate style heuristics still report 8 failures and 5 warnings, including the intentionally scrollable report-fragment row.
- Website visual follow-up on 2026-10-30: raised the small text scale, removed chart index labels and excess metric dividers, improved tablet metric layout and dark-theme link contrast, and corrected the scan date context. The scoped Taste linter reports 0 failures and 0 warnings. Browser review at 1440x900, 768x1024, and 390x844 found no page overflow or console errors. The theme toggle, report carousel, repository and capability disclosures, and embedded dark Archify workflow were exercised. The separate finding model was rendered in dark and light themes, its severity and confidence controls were changed independently, and its mobile corner-label overlap was fixed in the generator. The full-page Taste inspector saved screenshots but stalled before writing its report, so no automated visual score is claimed.
- Strict Mypy checking of all 44 source modules and the scan benchmark script using the same configuration run by CI.
- Deterministic 128-file scan benchmark with one warm-up, five measured runs, complete discovery, zero findings, and sampled process-tree RSS.
- JSON Schema validation of the saved performance report and process-free schema validation in the benchmark test.

## Test results

For the preceding dependency adapter increment, local `python -m unittest discover -s tests` passed 182 test methods, including the no-package regression test. The real-tool harness passed with Syft 1.55.0 and OSV-Scanner 2.7.0, returning 11 positive findings, zero clean-control findings, and the expected partial status for a project without package sources. The Binwalk increment added one regression test and passed all 183 local test methods. Its real-tool harness passed with Binwalk v2.3.3, detecting the gzip signature in the positive control only, recording the version, and producing no extraction output. FUSE CI run `41118660790` passed all eight jobs for `bd471b1`. The second fresh-validation cohort contained 23 signals; all were reviewed against pinned source context and categorized without asserting exploitability, credential validity, or release applicability. FUSE CI run `41119431946` then passed all eight jobs for `953b786`, including the docs-only triage increment.

The full suite passes locally with **193 tests** and **73 subtests** on Windows and Python 3.14.7 using pytest 9.2.0. Workflow run #231 on `ee957cf` passed all eight jobs, all **187 tests**, and measured **75%** branch-aware coverage against the 70% gate. Adding PyYAML to the test extra enabled all four ESP-IDF YAML checks in CI. The synthetic fixture benchmark reports 16 cases across seven native rules, all matching their labels; these are synthetic fixtures and do not measure field accuracy. The documentation validator uses Git's tracked and non-ignored untracked file list, so local validation covers **53 Markdown files**, matching CI. Package build and clean-install smoke checks passed on `dd1c043`. Run #232 on `1ade772` passed all eight jobs with **190 tests**, **73 subtests**, and **75%** branch-aware coverage. Its quality job scanned 206 files with zero findings, validated 53 Markdown files, and passed the path audit over 497 tracked files and Git history. The Python dependency audit found no known vulnerabilities in the resolved development dependencies and skipped the editable FUSE checkout itself. Runs #237 on `5bf4d69`, #238 on `54e9359`, #239 on `afaa7ad`, #240 on `c6f7f5d`, and #241 on `17cd1ff` passed all eight CI jobs; corresponding Vercel checks succeeded for the website changes and latest revision. Run #239 passed strict Mypy on the 10 native-rule modules. Run #241 passed strict Mypy on the 11 configured source files, and all 14 baseline-focused tests passed locally. The separate dependency audit for `17cd1ff` passed. The Anatomy builder reports 56 named parts; the generator, inline JavaScript, and both SVG files pass structural checks. Type-checking increments through run #255 on `2a9d548` passed FUSE CI and the separate Python dependency audit. Run #256 on `683c190` passed with the expanded 23-file strict Mypy gate. Run #257 on `d451213` passed with strict Mypy covering all 44 source modules, and dependency audit #19 for the same revision also succeeded. Run #260 on `b2f971a` passed the platform test matrix, the benchmark smoke check, strict Mypy on the 44 source modules plus the benchmark script, the 70% coverage gate, package smoke, path and documentation validation, and the self-scan. Python dependency audit #20 for the same revision passed. FUSE CI runs #41106198114 for `1b9acdb` and #41109722395 for `2c5afa8` each passed all eight configured jobs across Ubuntu, Windows, and macOS. The local suite now passes **193 tests** and **73 subtests**; strict Mypy reports no issues in **45 files**, Ruff lint and formatting pass across `src`, `tests`, and `scripts`, and the path audit passes across **502 tracked files** and Git history. The current FUSE self-scan completed discovery across 235 selected files with zero findings.

The saved synthetic performance baseline is pinned to `00bb3f2`, Windows 11 build `10.0.26300`, Python 3.14.7, and psutil 7.2.2. It scans 128 generated files and 8,990 bytes with one warm-up and five measured runs. Median wall time was **1.192724 seconds**, with **107.317 files/second** and maximum sampled process-tree RSS of **52,838,400 bytes**. Discovery completed and no findings were produced. These are descriptive measurements for one synthetic input on one machine, not field performance claims. The report and its JSON Schema are checked in under `reports/benchmark/`.

The original full-tree Ruff check identified 42 files for reformatting. Four were formatted with the path fix, and the remaining 38 are formatted in `121c74e`. CI now checks formatting across all Python files under `src`, `tests`, and `scripts`. Run #226 on `0f8d4ef` failed documentation validation because the README linked to supporting docs not yet in that commit. The docs increment resolved those links, and run #227 on `dd1c043` succeeded. Run #228 on `d219d1e` exercised the new Windows and macOS Python 3.11 jobs and exposed path-alias failures in four tests on each OS. The fix uses file identity to recognize OS aliases to the project root, checks in-target path components for symlinks, and adds regression cases for both behaviors. Run #229 on `fd15878` passed all eight jobs across Ubuntu Python 3.11 to 3.14, Windows Python 3.11, macOS Python 3.11, quality, and package smoke. The next run on `121c74e` also passed all eight jobs, including full-tree formatting and YAML-enabled tests. The subsequent website and finding-model browser checks are recorded above.

## Security findings

- No license changes or credentials were introduced by this pass. FUSE's own self-scan and focused security tests are part of local validation.
- pip-audit found `PYSEC-2026-1845` / `CVE-2025-71176` in pytest 8.4.2. The [GitHub-reviewed advisory](https://github.com/advisories/GHSA-6w46-j5rx-g56g) marks versions below 9.0.3 affected, and [pytest 9.0.3 release notes](https://github.com/pytest-dev/pytest/releases/tag/9.0.3) list the fix. FUSE's test and development extras now require pytest `>=9.0.3,<10`.
- KiCad XML parsing rejects DTD/entity declarations and enforces size, element, and depth limits. Terminal output escapes control and bidi characters. Optional analyzer subprocesses receive no inherited interactive stdin.
- The rule and scan reports are candidate evidence. They do not prove exploitability, reachability, or deployed-product applicability.
- External analyzers parse their own inputs and are not sandboxed. Gitleaks 8.30.0, Syft 1.55.0, OSV-Scanner 2.7.0, and Binwalk v2.3.3 passed bounded local smoke checks with synthetic fixtures. The Binwalk check covered WSL2 Ubuntu only. These checks do not establish detector accuracy, credential validity, exploitability, or reachability.
- The custom license permits commercial use but restricts sharing and redistribution, including package registry uploads without written permission. Do not treat the successful package build as distribution authorization.

## Dependency findings

The core runtime dependency list is empty. `pyproject.toml` declares Python `>=3.11`, setuptools as the PEP 517 build backend, an optional PyYAML extra for ESP-IDF lock parsing, and bounded test/development dependency ranges. Mypy is a development-only tool and is not installed for end users. The isolated pip-audit run checked resolved development distributions and reported no known advisories after the pytest floor was raised. FUSE was installed editable and skipped as expected. Syft, OSV-Scanner, Binwalk, and Gitleaks are external executables, not Python runtime dependencies, and are outside pip-audit coverage. Official Windows x64 SHA-256 digests were verified for the Gitleaks, Syft, and OSV-Scanner release assets used in the recorded checks.

The Python development environment has a clean point-in-time pip-audit result. System libraries, external analyzer binaries, malicious-package behavior, and all optional dependency configurations are not covered by that scan. The [PyPI JSON endpoint for `vigil-fuse`](https://pypi.org/pypi/vigil-fuse/json) returned HTTP 404 when checked on 2026-10-29. This is only a point-in-time name availability observation and neither reserves the name nor grants permission to publish. Recheck before any future release review.

## Documentation improvements

The README now summarizes alpha status, implemented scope, and major boundaries. Supporting pages cover requirements, methodology, architecture, threat model, limitations, traceability, benchmark evidence, repository structure, release process, and SBOM handling. Every new claim points to implementation or evidence where possible. No SDG alignment file was created: the repository demonstrates software engineering activity but has no measured societal outcome or evidence that supports a specific SDG impact claim.

## Research improvements

The repository scan is described as a pinned, descriptive evaluation. It records its question, dataset, method, variables, measures, scope, failure cases, and threats to validity. Synthetic fixtures, repository regression data, and separately maintained holdout cohorts remain distinct. No field precision, recall, or vulnerability prevalence is claimed. There is no comparative benchmark against other products.

## Reproducibility improvements

The new methodology page gives install, scan, test, and fixture-check commands. Existing manifests pin repositories and scopes. The package workflow builds wheel and sdist, checks metadata, installs into a clean environment, and runs CLI smoke checks. Gitleaks has a repeatable synthetic positive and negative smoke harness. Syft and OSV-Scanner have a repeatable positive, clean, and no-source adapter harness. Binwalk has a repeatable gzip-positive and clean-control identification harness. No static SBOM is committed, avoiding a stale generated inventory.

## Traceability status

`docs/traceability.md` maps requirements to objectives, decisions, implementation files, verification, and evidence. Optional executable integrations and the non-execution guarantee are marked partially verified where local evidence does not justify a stronger claim. The matrix does not equate test success with product security.

## Remaining limitations

- No representative independent ground-truth corpus or field accuracy estimate.
- FUSE CI run #41106198114 for `1b9acdb` passed all eight configured jobs across Ubuntu, Windows, and macOS. The README and architecture diagrams were rendered and inspected manually, but Mermaid rendering is not yet a CI regression gate.
- No compiler-semantic C/C++ analysis, general firmware extraction, device testing, or hardware-in-the-loop validation.
- Gitleaks 8.30.0, Syft 1.55.0, and OSV-Scanner 2.7.0 passed local Windows smoke checks. Binwalk v2.3.3 passed a WSL2 Ubuntu smoke check only; Windows-native execution, Binwalk v3.1.0, broader signatures, and real firmware remain untested. These checks do not measure field precision, recall, exploitability, reachability, or the validity of real credentials.
- Performance evidence includes a synthetic C baseline and a repeatable pinned cohort over four selected embedded/IoT repository scopes on one Windows 11 / Python 3.14.7 machine. The cohort uses one warm-up and three measured runs per scope and records skips and native-analysis status; two scopes were partial because selected files exceeded the scanner's file-size limit. Cross-platform comparisons, memory measurement on the real-project cohort, and timing thresholds remain unmeasured. The synthetic process-tree RSS estimate can double-count shared pages and miss brief peaks.
- Strict Mypy covers all 44 source modules and both benchmark scripts; the 46-file check passed in CI run #41122163492. Dependency audit #20 passed on its recorded revision. pip-audit covers only the resolved Python development environment and does not assess system packages or external analyzer binaries.
- The Markdown validator checks local link targets, code fences, and Mermaid block types, not full renderer semantics. The six current Mermaid diagrams passed manual rendering and visual review. The finding-model SVGs passed structural validation and the interactive figure received browser review.
- Custom license and distribution terms require owner and qualified legal review before registry or release distribution.

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
| Code Quality | 15 | 14 | Full-tree Ruff checks and strict Mypy over 44 source modules plus both benchmark runners; CI run #41122163492 passed on `0f11e7c`. External tools have only bounded smoke evidence |
| Testing | 15 | 14 | 202 local pytest tests plus 81 subtests; CI run #41122163492 passed all eight Ubuntu, Windows, macOS, quality, and package jobs. Field accuracy remains unmeasured |
| Security | 10 | 9 | Parser and output hardening retained; Gitleaks, Syft, OSV-Scanner, and Binwalk have bounded real-tool smoke checks, while external tools are not sandboxed |
| Reproducibility | 10 | 9 | Pinned manifests, commands, CI package smoke checks, evaluation protocol, repeatable Gitleaks, dependency, and Binwalk harnesses, and three-run timing samples for four pinned project scopes; other platforms and broader accuracy remain unverified |
| Open Source Governance | 10 | 6 | Citation, contribution boundaries, issue forms, PR checklist, and release gates added; custom license and enforcement policy remain unresolved |
| Research Rigor & Traceability | 10 | 9 | Evidence types, limitations, cohort method, and 23-signal source-context triage are documented; the triage is not independent adjudication and there is no representative accuracy estimate or product comparison |
| **Total** | **100** | **89** | |

## Recommended next actions

1. Resolve the license and allowed distribution channels with the owner and qualified legal review before publishing a release or package.
2. Extend the Binwalk smoke evidence to supported versions and native platforms while retaining positive and clean controls for Gitleaks, Syft, and OSV-Scanner.
3. Extend independent, manually reviewed fixtures and retain difficult negatives before claiming field accuracy.
4. Run the pinned repository performance workflow on Linux, Windows, and macOS, inspect partial coverage and timing variability, then consider real-project memory measurements. Do not set timing thresholds until repeated measurements are stable.
5. Defer device, hardware, and firmware-extraction claims until controlled hardware or isolated extraction environments are available.

## Evidence update, 2026-10-31

Commits `0acde65` and `0f11e7c` add a repeatable performance harness and measured results for four selected pinned repository scopes. CI run #41122163492 passed all eight jobs on `0f11e7c`. The [experiment record](experiments/repository-scan-performance-2026-10-31.md) and [versioned JSON report](../reports/benchmark/repository-scan-performance.json) preserve the inputs, three-run samples, coverage status, and skipped-file reasons. The 89/100 maturity assessment remains unchanged because this evidence covers one Windows machine and does not supply independent finding adjudication, Linux/macOS comparison, or a representative accuracy corpus.

The manually dispatched cross-platform workflow is added in `.github/workflows/repository-performance.yml`. Run `41125057256` failed report construction because the job had not installed FUSE. Run `41125641349` passed across Ubuntu, macOS, and Windows, but artifact review found OS-dependent manifest hashes from line-ending conversion. A follow-up normalizes manifest line endings before hashing. The score remains 89/100 until reports with a matching cross-platform input fingerprint are reviewed.
